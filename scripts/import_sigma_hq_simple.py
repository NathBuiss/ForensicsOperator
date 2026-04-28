#!/usr/bin/env python3
"""
Simple Sigma HQ importer - downloads and extracts rules to api/alert_rules/sigma_hq/

This script downloads Sigma HQ rules and saves them as YAML files WITHOUT conversion.
The rules will be converted to ES queries at runtime by the existing sigma_sync service.

Usage:
    source .venv/bin/activate
    python3 scripts/import_sigma_hq_simple.py --levels critical,high
"""
import argparse
import logging
import os
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

try:
    import requests
    import yaml
except ImportError as e:
    print(f"Error: Missing required library: {e}")
    print("\nInstall required packages:")
    print("  source .venv/bin/activate")
    print("  pip install requests pyyaml")
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


def get_tactic_filename(rule_data: dict) -> str:
    """Get filename based on MITRE ATT&CK tactic."""
    tags = rule_data.get('tags', [])
    if tags:
        for tag in tags:
            tag_str = str(tag).lower()
            if tag_str in TACTIC_MAP:
                return TACTIC_MAP[tag_str]
    
    # Fallback to generic
    return '99_other'


def copy_rules_by_category(rules_path: Path, output_dir: Path, levels: List[str]):
    """Copy Sigma rules to output directory organized by category."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Clean existing files
    for f in output_dir.glob("*.yaml"):
        f.unlink()
    
    logger.info(f"Scanning rules in {rules_path}...")
    yaml_files = list(rules_path.rglob("*.yml")) + list(rules_path.rglob("*.yaml"))
    logger.info(f"Found {len(yaml_files)} potential rule files")
    
    # Filter files
    filtered_files = [f for f in yaml_files if filter_rule(f, levels)]
    logger.info(f"After filtering: {len(filtered_files)} files")
    
    # Organize by category
    rules_by_category = {}
    copied = 0
    skipped = 0
    errors = 0
    
    for yaml_file in filtered_files:
        try:
            # Load rule to get metadata
            with open(yaml_file, 'r') as f:
                rule_data = yaml.safe_load(f)
            
            # Skip if not a valid rule
            if not rule_data or not isinstance(rule_data, dict) or 'title' not in rule_data:
                skipped += 1
                continue
            
            # Get category
            category = get_tactic_filename(rule_data)
            
            if category not in rules_by_category:
                rules_by_category[category] = []
            
            rules_by_category[category].append({
                'source': yaml_file,
                'data': rule_data,
            })
            copied += 1
            
        except Exception as e:
            logger.debug(f"Error processing {yaml_file.name}: {e}")
            errors += 1
    
    logger.info(f"Processed {copied} rules, {skipped} skipped, {errors} errors")
    
    # Save to YAML files
    logger.info("Organizing rules by category...")
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
            f.write(f"# and will be converted to Elasticsearch queries at runtime.\n")
            f.write(f"#\n")
            f.write(f"# Source: https://github.com/SigmaHQ/sigma\n")
            f.write(f"#\n\n")
            
            f.write("category: Sigma HQ\n\n")
            f.write("rules:\n")
            
            for item in rules:
                rule = item['data']
                source = item['source']
                
                # Write rule preserving original structure
                f.write(f"  # Source: {source.name}\n")
                
                # Write fields
                if 'title' in rule:
                    f.write(f"  - name: {rule['title']}\n")
                
                if 'description' in rule:
                    desc = rule['description']
                    if isinstance(desc, str):
                        f.write(f"    description: >-\n")
                        for line in str(desc).split('\n'):
                            if line.strip():
                                f.write(f"      {line.strip()}\n")
                            else:
                                f.write(f"      \n")
                
                if 'logsource' in rule:
                    logsource = rule['logsource']
                    if isinstance(logsource, dict):
                        product = logsource.get('product', '')
                        service = logsource.get('service', '')
                        category = logsource.get('category', '')
                        
                        # Map to artifact_type
                        artifact_type = ''
                        if product == 'windows' or service in ['security', 'system', 'powershell', 'sysmon']:
                            artifact_type = 'evtx'
                        elif product in ['linux', 'ubuntu', 'debian', 'centos', 'rhel', 'macos']:
                            artifact_type = 'syslog'
                        elif category in ['firewall', 'proxy', 'dns']:
                            artifact_type = 'suricata'
                        elif category == 'webserver':
                            artifact_type = 'access_log'
                        
                        if artifact_type:
                            f.write(f"    artifact_type: {artifact_type}\n")
                
                # Detection will be converted at runtime
                if 'detection' in rule:
                    f.write(f"    # detection: (will be converted at runtime)\n")
                    f.write(f"    sigma_detection: |\n")
                    detection_yaml = yaml.dump(rule['detection'], default_flow_style=False)
                    for line in detection_yaml.split('\n'):
                        f.write(f"      {line}\n")
                
                if 'level' in rule:
                    f.write(f"    # level: {rule['level']}\n")
                
                if 'tags' in rule:
                    tags = [str(t) for t in rule['tags'] if str(t).startswith('attack.')]
                    if tags:
                        f.write(f"    # tags: {', '.join(tags)}\n")
                
                if 'author' in rule:
                    authors = rule['author'] if isinstance(rule['author'], list) else [rule['author']]
                    f.write(f"    # authors: {', '.join(str(a) for a in authors[:3])}{'...' if len(authors) > 3 else ''}\n")
                
                if 'references' in rule:
                    for ref in rule['references'][:2]:
                        f.write(f"    # ref: {ref}\n")
                
                if 'id' in rule:
                    f.write(f"    # sigma_id: {rule['id']}\n")
                
                f.write("\n")
        
        logger.info(f"Saved {len(rules)} rules to {filename.name}")
    
    # Summary
    total_rules = sum(len(rules) for rules in rules_by_category.values())
    logger.info(f"\n{'='*60}")
    logger.info(f"Import complete!")
    logger.info(f"  Total rules imported: {total_rules}")
    logger.info(f"  Categories: {len(rules_by_category)}")
    logger.info(f"  Output directory: {output_dir}")
    logger.info(f"{'='*60}")
    
    # Print category summary
    logger.info("\nRules by category:")
    for category, rules in sorted(rules_by_category.items()):
        logger.info(f"  {category}: {len(rules)} rules")


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
    
    # Copy and organize rules
    copy_rules_by_category(rules_path, args.output_dir, levels)
    
    # Cleanup
    if not args.skip_download:
        logger.info("\nCleaning up temporary files...")
        try:
            shutil.rmtree(rules_path.parent.parent)
        except Exception as e:
            logger.debug(f"Could not cleanup: {e}")


if __name__ == '__main__':
    main()
