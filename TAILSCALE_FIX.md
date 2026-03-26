# Traefik Tailscale Fix - Deploy.py Update

## What Was Fixed

### Problem
When running `deploy.py`, the Traefik service would lose its Tailscale external IP because:
1. The default k3s Traefik service doesn't have `loadBalancerClass: tailscale`
2. Annotations alone aren't enough - Tailscale operator requires `loadBalancerClass: tailscale` in the spec
3. Modifying the existing Traefik service is impossible (`loadBalancerClass` is immutable)

### Solution
**Created a NEW `traefik-tailscale` service** that:
- Points to the same Traefik pods (via selector)
- Has `loadBalancerClass: tailscale` 
- Is completely separate from k3s's default Traefik service
- Won't break or disrupt existing traffic

## Changes Made to deploy.py

### 1. New Function: `ensure_traefik_tailscale(cfg)`
- Creates/updates `traefik-tailscale` service with Tailscale config
- Waits up to 60 seconds for external IP assignment
- Automatically updates CoreDNS with the Tailscale IP
- Safe to run multiple times (idempotent)

### 2. New Function: `update_coredns_tailscale_ip(hostname, ip)`
- Updates CoreDNS ConfigMap to map hostname → Tailscale IP
- Works with CoreDNS in `analyse` or `kube-system` namespace
- Restarts CoreDNS to apply changes
- Prevents duplicate entries

### 3. Updated Main Flow
```python
# 5. Ensure Traefik ingress
ensure_traefik_ingress()

# 5b. Configure Tailscale LoadBalancer ← NEW
ensure_traefik_tailscale(cfg)

# 6. Continue with rest of deployment...
```

## How It Works

### Service Creation
```yaml
apiVersion: v1
kind: Service
metadata:
  name: traefik-tailscale
  namespace: kube-system
  annotations:
    tailscale.com/hostname: "forensics.local"
spec:
  type: LoadBalancer
  loadBalancerClass: tailscale  # ← This triggers Tailscale operator
  externalTrafficPolicy: Cluster
  ports:
    - name: web
      port: 80
      targetPort: web
    - name: websecure
      port: 443
      targetPort: websecure
  selector:
    app.kubernetes.io/name: traefik  # ← Points to existing Traefik pods
    app.kubernetes.io/instance: traefik-kube-system
```

### CoreDNS Update
```coredns
hosts {
    100.65.71.107 forensics.local  # ← Added automatically
    fallthrough
}
```

## What Happens on Deploy

```
1. Check if traefik-tailscale service exists
   ├─ Yes + has IP → Skip (already configured)
   ├─ Yes + no IP → Wait for IP
   └─ No → Create service

2. Wait for Tailscale to assign external IP (up to 60s)
   ├─ Got IP → Continue
   └─ Timeout → Warn but continue

3. Update CoreDNS ConfigMap
   ├─ Add hosts entry: <IP> <hostname>
   ├─ Patch ConfigMap
   └─ Restart CoreDNS deployment

4. Deployment continues normally
```

## Benefits

### ✅ Safe
- Doesn't modify existing Traefik service
- No k3s restart required
- No pod deletions
- Zero downtime

### ✅ Automatic
- Runs on every deploy
- Idempotent (safe to re-run)
- Auto-updates CoreDNS if IP changes

### ✅ Resilient
- Handles IP changes gracefully
- Works with any Tailscale hostname
- Compatible with k3s auto-reconciliation

## Testing

After running `python3 deploy.py`:

```bash
# 1. Check both services exist
kubectl get svc -n kube-system | grep traefik
# Should show:
# traefik              LoadBalancer   10.43.131.57   <pending>     80:32238/TCP,443:31624/TCP
# traefik-tailscale    LoadBalancer   10.43.200.15   100.65.71.107 80:32238/TCP,443:31624/TCP

# 2. Check Tailscale proxy pod
kubectl get pods -n tailscale | grep ts-traefik
# Should show: ts-traefik-tailscale-xxxxx

# 3. Check CoreDNS has the entry
kubectl get configmap coredns -n analyse -o yaml | grep forensics.local
# Should show: 100.65.71.107 forensics.local

# 4. Test connectivity
curl -k https://forensics.local/api/v1/health
# Should return: {"status": "healthy"}
```

## Troubleshooting

### Tailscale IP not assigned after 60 seconds
```bash
# Check Tailscale operator is running
kubectl get pods -n tailscale

# Check operator logs
kubectl logs -n tailscale -l app=operator --tail=50

# Manually check service
kubectl get svc traefik-tailscale -n kube-system -o yaml
```

### CoreDNS not resolving
```bash
# Check CoreDNS ConfigMap
kubectl get configmap coredns -n analyse -o yaml

# Restart CoreDNS
kubectl rollout restart deployment/coredns -n analyse

# Test DNS resolution
kubectl run test --rm -it --image=busybox --restart=Never -- nslookup forensics.local
```

### Service exists but no Tailscale proxy pod
```bash
# Check if Tailscale operator saw the service
kubectl get svc traefik-tailscale -n kube-system -o yaml | grep -A5 "loadBalancer"

# Force reconciliation by touching annotation
kubectl annotate svc traefik-tailscale -n kube-system \
  tailscale.com/reconcile=$(date +%s) --overwrite
```

## Future Enhancements

### Optional: Add to config.json
```json
{
  "tailscale": {
    "enabled": true,
    "hostname": "forensics.local",
    "auto_update_coredns": true
  }
}
```

### Optional: Add health check
```python
def verify_tailscale_connectivity(hostname):
    """Test that the Tailscale endpoint is reachable."""
    import requests
    try:
        r = requests.get(f"https://{hostname}/api/v1/health", 
                        verify=False, timeout=10)
        return r.status_code == 200
    except:
        return False
```

## Rollback

If something goes wrong (unlikely since this is non-destructive):

```bash
# Remove the Tailscale service
kubectl delete svc traefik-tailscale -n kube-system

# Remove CoreDNS entry (manual edit)
kubectl edit configmap coredns -n analyse
# Remove the hosts entry for forensics.local

# Restart CoreDNS
kubectl rollout restart deployment/coredns -n analyse
```

Your original Traefik service and all traffic remain unaffected.
