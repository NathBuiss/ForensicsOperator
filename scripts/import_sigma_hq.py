#!/usr/bin/env python3
"""
Import Sigma HQ rules and save as YAML files in the project.

This script downloads Sigma HQ rules from GitHub, converts them to
Elasticsearch queries, and saves them as organized YAML files in
api/alert_rules/sigma_hq/

Usage:
    python3 scripts/import_sigma_hq.py [--levels critical,high] [--output-dir path]

Examples:
    # Import only critical severity rules
    python3 scripts/import_sigma_hq.py --levels critical

    # Import high and critical severity rules
    python3 scripts/import_sigma_hq.py --levels high,critical

    # Import all rules (may be 4000+)
    python3 scripts/import_sigma_hq.py --levels ""
"""
import argparse
import json
import logging
import os
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Any
import uuid

# Add api directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "api"))

try:
    import requests
    from sigma.collection import SigmaCollection
    from sigma.backends.elasticsearch import LuceneBackend
except ImportError as e:
    print(f"Error: Missing required library: {e}")
    print("\nInstall required packages:")
    print("  pip install requests pysigma pysigma-backend-elasticsearch")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# MITRE ATT&CK tactic mapping
TACTIC_MAP = {
    'attack.initial_access': '01_initial_access',
    'attack.execution': '02_execution',
    'attack.persistence': '03_persistence',
    'attack.privilege_escalation': '04_privilege_escalation',
    'attack.defense_evasion': '05_defense_evasion',
    'attack.credential_access': '06_credential_access',
    'attack.discovery': '07_discovery',
    'attack.lateral_movement': '08_lateral_movement',
    'attack.collection': '09_collection',
    'attack.command_and_control': '10_command_control',
    'attack.exfiltration': '11_exfiltration',
    'attack.impact': '12_impact',
}

# Logsource to artifact_type mapping
ARTIFACT_MAPPING = {
    ('windows', 'security'): 'evtx',
    ('windows', 'system'): 'evtx',
    ('windows', 'application'): 'evtx',
    ('windows', 'powershell'): 'evtx',
    ('windows', 'sysmon'): 'evtx',
    ('linux', None): 'syslog',
    ('ubuntu', None): 'syslog',
    ('debian', None): 'syslog',
    ('centos', None): 'syslog',
    ('rhel', None): 'syslog',
    ('macos', None): 'syslog',
    ('firewall', None): 'suricata',
    ('proxy', None): 'suricata',
    ('dns', None): 'suricata',
    ('webserver', None): 'access_log',
    ('azure', None): 'syslog',
}


def download_sigma_rules() -> Path:
    """Download Sigma HQ rules from GitHub."""
    SIGMA_REPO_URL = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
    
    logger.info("Downloading Sigma HQ rules...")
    response = requests.get(SIGMA_REPO_URL, stream=True, timeout=120)
    response.raise_for_status()
    
    # Download to temp file
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        for chunk in response.iter_content(chunk_size=8192):
            tmp.write(chunk)
        tmp_path = tmp.name
    
    # Extract
    extract_path = Path(tempfile.mkdtemp(prefix="sigma_"))
    logger.info(f"Extracting to {extract_path}")
    
    with zipfile.ZipFile(tmp_path, 'r') as zip_ref:
        zip_ref.extractall(extract_path)
    
    Path(tmp_path).unlink()
    
    return extract_path / "sigma-master" / "rules"


def filter_rule(rule_path: Path, levels: List[str]) -> bool:
    """Check if rule should be included based on filters."""
    # Skip deprecated
    if 'deprecated' in str(rule_path).lower():
        return False
    
    # Skip retired
    if 'retired' in str(rule_path).lower():
        return False
    
    # Level filter
    if levels:
        path_str = str(rule_path).lower()
        if not any(level.lower() in path_str for level in levels):
            # Try to read level from file
            try:
                content = rule_path.read_text()
                if 'level:' in content:
                    for line in content.split('\n'):
                        if line.strip().startswith('level:'):
                            rule_level = line.split(':')[1].strip().lower()
                            if rule_level not in [l.lower() for l in levels]:
                                return False
                            break
            except:
                pass
    
    return True


def map_logsource(logsource) -> str:
    """Map Sigma logsource to artifact_type."""
    if not logsource:
        return ''
    
    product = (logsource.product or '').lower()
    service = (logsource.service or '').lower()
    category = (logsource.category or '').lower()
    
    # Check exact matches first
    key = (product, service if service else None)
    if key in ARTIFACT_MAPPING:
        return ARTIFACT_MAPPING[key]
    
    # Check product only
    if (product, None) in ARTIFACT_MAPPING:
        return ARTIFACT_MAPPING[(product, None)]
    
    # Check category
    if category in ['firewall', 'proxy', 'dns']:
        return 'suricata'
    
    if category == 'webserver':
        return 'access_log'
    
    # Defaults
    if product in ['linux', 'ubuntu', 'debian', 'centos', 'rhel', 'macos', 'azure']:
        return 'syslog'
    
    if product == 'windows':
        return 'evtx'
    
    return ''


def get_tactic_filename(rule) -> str:
    """Get filename based on MITRE ATT&CK tactic."""
    if rule.tags:
        for tag in rule.tags:
            tag_str = str(tag).lower()
            if tag_str in TACTIC_MAP:
                return TACTIC_MAP[tag_str]
    
    # Fallback to generic
    return '99_other'


def convert_rule(rule, backend: LuceneBackend) -> Optional[Dict]:
    """Convert Sigma rule to internal format."""
    try:
        # Convert to ES query
        es_query = backend.convert(rule)
        query_str = es_query[0] if isinstance(es_query, list) else str(es_query)
        
        # Extract MITRE tags
        mitre_tags = []
        if rule.tags:
            mitre_tags = [str(t) for t in rule.tags if str(t).startswith('attack.')]
        
        # Map artifact type
        artifact_type = map_logsource(rule.logsource)
        
        # Get category/filename
        filename = get_tactic_filename(rule)
        
        # Build rule dict
        rule_dict = {
            'name': rule.title,
            'description': rule.description or '',
            'artifact_type': artifact_type,
            'query': query_str,
            'threshold': 1,
        }
        
        # Add metadata as comments
        metadata = {
            'sigma_id': rule.id,
            'sigma_level': rule.level.value if rule.level else '',
            'sigma_status': rule.status.value if rule.status else '',
            'sigma_tags': mitre_tags,
            'sigma_references': rule.references or [],
            'sigma_author': rule.author if isinstance(rule.author, list) else [rule.author] if rule.author else [],
            'sigma_date': rule.date or '',
            'sigma_modified': rule.modified or '',
        }
        
        return {
            'filename': filename,
            'rule': rule_dict,
            'metadata': metadata,
        }
        
    except Exception as e:
        logger.warning(f"Failed to convert rule '{rule.title}': {e}")
        return None


def save_rules_to_yaml(rules_by_category: Dict[str, List[Dict]], output_dir: Path):
    """Save rules to YAML files organized by category."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    for category, rules in sorted(rules_by_category.items()):
        if not rules:
            continue
        
        filename = output_dir / f"{category}.yaml"
        
        with open(filename, 'w') as f:
            f.write(f"# Sigma HQ Rules - {category.replace('_', ' ').title()}\n")
            f.write(f"# Imported: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"# Total rules: {len(rules)}\n")
            f.write(f"#\n")
            f.write(f"# These rules were automatically imported from Sigma HQ\n")
            f.write(f"# and converted to Elasticsearch query_string syntax.\n")
            f.write(f"#\n")
            f.write(f"# Source: https://github.com/SigmaHQ/sigma\n")
            f.write(f"#\n\n")
            
            f.write("category: Sigma HQ\n\n")
            f.write("rules:\n")
            
            for item in rules:
                rule = item['rule']
                meta = item['metadata']
                
                # Write rule
                f.write(f"  - name: {rule['name']}\n")
                f.write(f"    description: >-\n")
                # Word wrap description
                desc_lines = rule['description'].split('\n')
                for line in desc_lines:
                    if line.strip():
                        f.write(f"      {line.strip()}\n")
                    else:
                        f.write(f"      \n")
                
                f.write(f"    artifact_type: {rule['artifact_type']}\n")
                f.write(f"    query: {json.dumps(rule['query'])}\n")
                f.write(f"    threshold: {rule['threshold']}\n")
                
                # Write metadata as comment
                if meta['sigma_id']:
                    f.write(f"    # sigma_id: {meta['sigma_id']}\n")
                if meta['sigma_level']:
                    f.write(f"    # level: {meta['sigma_level']}\n")
                if meta['sigma_status']:
                    f.write(f"    # status: {meta['sigma_status']}\n")
                if meta['sigma_tags']:
                    f.write(f"    # tags: {', '.join(meta['sigma_tags'])}\n")
                if meta['sigma_author']:
                    f.write(f"    # authors: {', '.join(str(a) for a in meta['sigma_author'][:3])}{'...' if len(meta['sigma_author']) > 3 else ''}\n")
                if meta['sigma_references']:
                    for ref in meta['sigma_references'][:2]:  # First 2 refs
                        f.write(f"    # ref: {ref}\n")
                
                f.write("\n")
        
        logger.info(f"Saved {len(rules)} rules to {filename.name}")


def main():
    parser = argparse.ArgumentParser(
        description='Import Sigma HQ rules and save as YAML files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        '--levels',
        type=str,
        default='critical,high',
        help='Comma-separated list of severity levels to import (default: critical,high). Use empty string "" for all levels.'
    )
    
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path(__file__).parent.parent / "api" / "alert_rules" / "sigma_hq",
        help='Output directory for YAML files (default: api/alert_rules/sigma_hq)'
    )
    
    parser.add_argument(
        '--skip-download',
        action='store_true',
        help='Skip download and use existing rules in /tmp/sigma_rules'
    )
    
    args = parser.parse_args()
    
    # Parse levels
    levels = [l.strip() for l in args.levels.split(',') if l.strip()] if args.levels else []
    
    logger.info(f"Import configuration:")
    logger.info(f"  Levels: {levels or 'ALL'}")
    logger.info(f"  Output: {args.output_dir}")
    
    # Download or use existing
    if args.skip_download:
        rules_path = Path("/tmp/sigma_rules/sigma-master/rules")
        if not rules_path.exists():
            logger.error("Rules not found at /tmp/sigma_rules. Run without --skip-download first.")
            sys.exit(1)
    else:
        try:
            rules_path = download_sigma_rules()
        except Exception as e:
            logger.error(f"Failed to download Sigma rules: {e}")
            sys.exit(1)
    
    # Initialize backend
    logger.info("Initializing Elasticsearch backend...")
    backend = LuceneBackend()
    
    # Collect and filter rules
    logger.info(f"Scanning rules in {rules_path}...")
    yaml_files = list(rules_path.rglob("*.yml")) + list(rules_path.rglob("*.yaml"))
    logger.info(f"Found {len(yaml_files)} potential rule files")
    
    # Filter files
    filtered_files = [f for f in yaml_files if filter_rule(f, levels)]
    logger.info(f"After filtering: {len(filtered_files)} files")
    
    # Load and convert rules
    logger.info("Loading and converting rules...")
    rules_by_category = {}
    converted = 0
    errors = 0
    
    for yaml_file in filtered_files:
        try:
            sigma_collection = SigmaCollection.from_yaml(yaml_file.read_text())
            
            for rule in sigma_collection.rules:
                result = convert_rule(rule, backend)
                if result:
                    category = result['filename']
                    if category not in rules_by_category:
                        rules_by_category[category] = []
                    rules_by_category[category].append(result)
                    converted += 1
                    
        except Exception as e:
            logger.debug(f"Error processing {yaml_file.name}: {e}")
            errors += 1
    
    logger.info(f"Converted {converted} rules, {errors} errors")
    
    # Save to YAML files
    logger.info("Saving rules to YAML files...")
    save_rules_to_yaml(rules_by_category, args.output_dir)
    
    # Summary
    total_rules = sum(len(rules) for rules in rules_by_category.values())
    logger.info(f"\n{'='*60}")
    logger.info(f"Import complete!")
    logger.info(f"  Total rules imported: {total_rules}")
    logger.info(f"  Categories: {len(rules_by_category)}")
    logger.info(f"  Output directory: {args.output_dir}")
    logger.info(f"{'='*60}")
    
    # Print category summary
    logger.info("\nRules by category:")
    for category, rules in sorted(rules_by_category.items()):
        logger.info(f"  {category}: {len(rules)} rules")


if __name__ == '__main__':
    main()
