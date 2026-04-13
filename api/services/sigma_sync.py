"""Sigma HQ rules synchronization service."""
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional

from config import settings, get_redis

try:
    from sigma.collection import SigmaCollection
    from sigma.backends.elasticsearch import LuceneBackend
    _SIGMA_AVAILABLE = True
except ImportError:
    _SIGMA_AVAILABLE = False

logger = logging.getLogger(__name__)

SIGMA_LOCAL_PATH = Path("/tmp/sigma_rules")


class SigmaSyncService:
    """Service for syncing Sigma HQ rules."""
    
    def __init__(self):
        self.redis = get_redis()
        self.backend = LuceneBackend() if _SIGMA_AVAILABLE else None
        self.rules_key = "fo:alert_rules:_global:sigma"
        self.last_sync_key = "fo:alert_rules:_global:sigma:last_sync"
    
    def sync_sigma_rules(
        self,
        categories: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        levels: Optional[List[str]] = None
    ) -> Dict:
        """
        Sync rules from Sigma HQ repository.
        
        Args:
            categories: Filter by Sigma categories (e.g., ['malware', 'ransomware'])
            tags: Filter by MITRE ATT&CK tags (e.g., ['attack.persistence'])
            levels: Filter by severity (e.g., ['high', 'critical'])
        
        Returns:
            Sync result with imported/skipped counts
        """
        if not _SIGMA_AVAILABLE:
            raise RuntimeError("Sigma libraries not installed. Run: pip install pysigma pysigma-backend-elasticsearch")
        
        # Download Sigma rules
        sigma_rules_path = self._download_sigma_rules()
        
        # Load and filter rules
        logger.info(f"Loading Sigma rules from {sigma_rules_path}")
        sigma_collection = SigmaCollection.load_ruleset(
            sigma_rules_path,
            on_beforeload=lambda p: self._should_load_rule(p, categories, tags, levels),
            on_load=lambda p, r: logger.debug(f"Loaded rule: {r.title}")
        )
        
        logger.info(f"Loaded {len(sigma_collection.rules)} Sigma rules")
        
        # Convert to Elasticsearch queries
        converted_rules = []
        errors = []
        
        for rule in sigma_collection.rules:
            try:
                es_query = self.backend.convert(rule)
                converted_rules.append(self._convert_to_internal_format(rule, es_query))
            except Exception as e:
                errors.append({
                    "rule_id": rule.id,
                    "rule_title": rule.title,
                    "error": str(e)
                })
                logger.warning(f"Failed to convert rule {rule.title}: {e}")
        
        # Store in Redis
        existing_rules = json.loads(self.redis.get(self.rules_key) or "[]")
        existing_ids = {r.get("sigma_id") for r in existing_rules}
        
        new_rules = [r for r in converted_rules if r["sigma_id"] not in existing_ids]
        existing_rules.extend(new_rules)
        
        self.redis.set(self.rules_key, json.dumps(existing_rules))
        self.redis.set(self.last_sync_key, datetime.now(timezone.utc).isoformat())
        
        logger.info(f"Sync complete: {len(new_rules)} new rules, {len(existing_rules)} total")
        
        return {
            "imported": len(new_rules),
            "skipped": len(converted_rules) - len(new_rules),
            "errors": len(errors),
            "total_rules": len(existing_rules),
            "error_details": errors[:10]  # First 10 errors only
        }
    
    def _download_sigma_rules(self) -> Path:
        """Download Sigma HQ rules from GitHub."""
        import tempfile
        import zipfile
        import requests
        
        SIGMA_REPO_URL = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
        
        # Download
        logger.info("Downloading Sigma HQ rules...")
        response = requests.get(SIGMA_REPO_URL, stream=True, timeout=120)
        response.raise_for_status()
        
        # Extract
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            for chunk in response.iter_content(chunk_size=8192):
                tmp.write(chunk)
            tmp_path = tmp.name
        
        extract_path = SIGMA_LOCAL_PATH / "sigma-master"
        if extract_path.exists():
            import shutil
            shutil.rmtree(extract_path)
        
        with zipfile.ZipFile(tmp_path, 'r') as zip_ref:
            zip_ref.extractall(SIGMA_LOCAL_PATH)
        
        Path(tmp_path).unlink()
        
        logger.info(f"Extracted Sigma rules to {extract_path}")
        
        return extract_path / "rules"
    
    def _should_load_rule(
        self,
        path: Path,
        categories: Optional[List[str]],
        tags: Optional[List[str]],
        levels: Optional[List[str]]
    ) -> bool:
        """Filter rules based on criteria."""
        if not path.suffix in ['.yml', '.yaml']:
            return False
        
        # Skip deprecated rules
        if 'deprecated' in str(path).parts:
            return False
        
        # Level filter (high/critical only by default)
        if levels:
            path_str = str(path).lower()
            if not any(level.lower() in path_str for level in levels):
                # Check in file content if level not in path
                pass  # We'll filter after loading
        
        return True
    
    def _convert_to_internal_format(self, rule, es_query: str) -> Dict:
        """Convert Sigma rule to internal format."""
        # Extract MITRE ATT&CK tags
        mitre_tags = []
        if rule.tags:
            mitre_tags = [str(t) for t in rule.tags if str(t).startswith('attack.')]
        
        # Map Sigma logsource to artifact_type
        artifact_type = self._map_logsource(rule.logsource)
        
        # Get query string from ES backend result
        query_str = es_query[0] if isinstance(es_query, list) else str(es_query)
        
        return {
            "id": str(uuid.uuid4())[:8],
            "sigma_id": rule.id or f"sigma-{uuid.uuid4().hex[:8]}",
            "sigma_source": "sigma_hq",
            "name": rule.title,
            "description": rule.description or "",
            "category": self._get_category(rule),
            "artifact_type": artifact_type,
            "query": query_str,
            "threshold": 1,
            "rule_type": "sigma",
            "sigma_yaml": str(rule.source) if rule.source else "",
            "sigma_level": rule.level.value if rule.level else "",
            "sigma_tags": mitre_tags,
            "sigma_status": rule.status.value if rule.status else "",
            "sigma_author": rule.author or [],
            "sigma_date": rule.date or "",
            "sigma_modified": rule.modified or "",
            "sigma_references": rule.references or [],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    
    def _map_logsource(self, logsource) -> str:
        """Map Sigma logsource to artifact_type."""
        if not logsource:
            return ""
        
        product = logsource.product.lower() if logsource.product else ""
        service = logsource.service.lower() if logsource.service else ""
        category = logsource.category.lower() if logsource.category else ""
        
        # Windows Event Logs
        if product == 'windows':
            if service in ['security', 'system', 'application', 'powershell', 'sysmon']:
                return 'evtx'
            return 'evtx'
        
        # Linux
        if product in ['linux', 'ubuntu', 'debian', 'centos', 'rhel']:
            return 'syslog'
        
        # Network logs
        if category in ['firewall', 'proxy', 'dns']:
            return 'suricata'
        
        # Web servers
        if category == 'webserver':
            return 'syslog'
        
        # Azure
        if product == 'azure':
            return 'syslog'
        
        # macOS
        if product == 'macos':
            return 'syslog'
        
        return ""
    
    def _get_category(self, rule) -> str:
        """Extract category from Sigma rule."""
        # Try MITRE ATT&CK tactic from tags
        if rule.tags:
            tactic_map = {
                'attack.persistence': 'Persistence',
                'attack.privilege_escalation': 'Privilege Escalation',
                'attack.defense_evasion': 'Defense Evasion',
                'attack.credential_access': 'Credential Access',
                'attack.discovery': 'Discovery',
                'attack.lateral_movement': 'Lateral Movement',
                'attack.execution': 'Execution',
                'attack.command_and_control': 'Command & Control',
                'attack.exfiltration': 'Exfiltration',
                'attack.collection': 'Collection',
                'attack.initial_access': 'Initial Access',
                'attack.impact': 'Impact',
            }
            for tag in rule.tags:
                tag_str = str(tag).lower()
                if tag_str in tactic_map:
                    return tactic_map[tag_str]
        
        # Fallback to logsource category
        if rule.logsource and rule.logsource.category:
            return rule.logsource.category.title()
        
        return "Other"
    
    def get_sync_status(self) -> Dict:
        """Get last sync status."""
        last_sync = self.redis.get(self.last_sync_key)
        rule_count = len(json.loads(self.redis.get(self.rules_key) or "[]"))
        
        return {
            "last_sync": last_sync,
            "sigma_rules_count": rule_count,
            "sigma_available": _SIGMA_AVAILABLE
        }
    
    def clear_sigma_rules(self) -> Dict:
        """Clear all synced Sigma rules."""
        count = len(json.loads(self.redis.get(self.rules_key) or "[]"))
        self.redis.delete(self.rules_key)
        self.redis.delete(self.last_sync_key)
        
        return {"cleared": count}
