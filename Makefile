.PHONY: help dev build push deploy undeploy logs

REGISTRY   ?= localhost:5000
TAG        ?= latest
NAMESPACE  := forensics-operator

help:
	@echo "ForensicsOperator — Kubernetes forensics analysis platform"
	@echo ""
	@echo "  make dev          Start local dev stack with docker-compose"
	@echo "  make build        Build all Docker images"
	@echo "  make push         Push images to registry (REGISTRY=...)"
	@echo "  make deploy       Apply all K8s manifests"
	@echo "  make undeploy     Delete all K8s resources"
	@echo "  make logs-api     Stream API logs"
	@echo "  make logs-proc    Stream processor logs"
	@echo "  make reload-plugins  Hot-reload plugins in running cluster"
	@echo "  make shell-api    Shell into API pod"
	@echo "  make shell-proc   Shell into processor pod"

# ── Local development ──────────────────────────────────────────────────────────
dev:
	docker compose up --build

dev-down:
	docker compose down -v

# ── Build images ───────────────────────────────────────────────────────────────
build:
	docker build -t $(REGISTRY)/forensics-operator/api:$(TAG) ./api
	docker build -t $(REGISTRY)/forensics-operator/processor:$(TAG) ./processor
	docker build -t $(REGISTRY)/forensics-operator/frontend:$(TAG) ./frontend

push: build
	docker push $(REGISTRY)/forensics-operator/api:$(TAG)
	docker push $(REGISTRY)/forensics-operator/processor:$(TAG)
	docker push $(REGISTRY)/forensics-operator/frontend:$(TAG)

# ── Kubernetes deployment ──────────────────────────────────────────────────────
deploy:
	kubectl apply -f k8s/namespace.yaml
	kubectl apply -f k8s/storage/
	kubectl apply -f k8s/redis/
	kubectl apply -f k8s/minio/
	kubectl apply -f k8s/elasticsearch/
	kubectl apply -f k8s/kibana/
	kubectl apply -f k8s/configmaps/
	kubectl apply -f k8s/api/
	kubectl apply -f k8s/processor/
	kubectl apply -f k8s/frontend/
	kubectl apply -f k8s/ingress/
	@echo "Deployment complete. Waiting for pods..."
	kubectl rollout status deployment/api -n $(NAMESPACE)
	kubectl rollout status deployment/processor -n $(NAMESPACE)
	kubectl rollout status deployment/frontend -n $(NAMESPACE)

undeploy:
	kubectl delete namespace $(NAMESPACE) --ignore-not-found

status:
	kubectl get all -n $(NAMESPACE)

# ── Logs ───────────────────────────────────────────────────────────────────────
logs-api:
	kubectl logs -n $(NAMESPACE) -l app=api -f --tail=100

logs-proc:
	kubectl logs -n $(NAMESPACE) -l app=processor -f --tail=100

logs-frontend:
	kubectl logs -n $(NAMESPACE) -l app=frontend -f --tail=100

# ── Debugging ──────────────────────────────────────────────────────────────────
shell-api:
	kubectl exec -it -n $(NAMESPACE) deploy/api -- bash

shell-proc:
	kubectl exec -it -n $(NAMESPACE) deploy/processor -- bash

reload-plugins:
	curl -X POST http://localhost:8000/api/v1/plugins/reload
	@echo ""
	@echo "Plugins reloaded."

# ── Plugin management ──────────────────────────────────────────────────────────
# Example: make copy-plugin PLUGIN=./my_plugin/my_plugin_plugin.py
copy-plugin:
	@PROC_POD=$$(kubectl get pod -n $(NAMESPACE) -l app=processor -o jsonpath='{.items[0].metadata.name}'); \
	kubectl cp $(PLUGIN) $(NAMESPACE)/$$PROC_POD:/app/plugins/
	$(MAKE) reload-plugins
