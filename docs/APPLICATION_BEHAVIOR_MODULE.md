# Application Behavior Report Module - Design Document

## Overview

This document describes how to implement an **Application Behavior Report** module that allows users to generate comprehensive reports about application activity on systems. The module will collect, analyze, and visualize application behaviors including:

- Process execution patterns
- File system modifications
- Registry changes (Windows)
- Network connections
- Persistence mechanisms
- User interactions

---

## Section 1: Architecture

### 1.1 High-Level Flow

```
User Request (Frontend)
        |
        v
API Router (api/routers/applications.py)
        |
        v
Application Service (api/services/applications.py)
        |
        +---> Query Elasticsearch for application events
        +---> Query Redis for application metadata
        +---> Generate report template
        |
        v
Report Generator (api/services/report_generator.py)
        |
        +---> Format data (JSON, PDF, HTML)
        +---> Add visualizations
        +---> Upload to MinIO
        |
        v
Return report URL to user
```

### 1.2 Database Schema

**Elasticsearch Indices:**
```
fo-case-{id}-process     # Process execution events
fo-case-{id}-file        # File system events
fo-case-{id}-registry    # Registry events (Windows)
fo-case-{id}-network     # Network connection events
fo-case-{id}-application # Application-specific events
```

**Redis Keys:**
```
fo:application:{app_name}              # Application metadata
fo:application:{app_name}:signatures   # Known behavior signatures
fo:case:{id}:applications              # Applications seen in case
fo:report:application:{report_id}      # Generated report metadata
```

---

## Section 2: Implementation

### 2.1 New Files to Create

```
api/
├── routers/
│   └── applications.py              # Application behavior endpoints
├── services/
│   ├── applications.py              # Application analysis service
│   └── report_generator.py          # Report generation service
└── models/
    └── application.py               # Pydantic models for applications

processor/
├── tasks/
│   └── application_task.py          # Celery task for app analysis
└── analyzers/
    ├── application_analyzer.py      # Core application analyzer
    ├── behavior_parser.py           # Parse behavior logs
    └── signature_matcher.py         # Match known behavior patterns

plugins/
└── application/
    ├── __init__.py
    ├── application_plugin.py        # Main application plugin
    ├── parsers/
    │   ├── windows_app_parser.py    # Windows application parser
    │   ├── linux_app_parser.py      # Linux application parser
    │   └── macos_app_parser.py      # macOS application parser
    └── signatures/
        ├── remote_access.json       # Remote access tool signatures
        ├── cloud_storage.json       # Cloud storage signatures
        ├── communication.json       # Communication app signatures
        └── malware.json             # Known malware signatures
```

### 2.2 API Endpoints

**File:** api/routers/applications.py

```python
"""Application behavior analysis and reporting."""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

from auth.dependencies import get_current_user, require_role
from services.applications import ApplicationService
from services.report_generator import ReportGenerator
from services.cases import get_case

router = APIRouter(tags=["applications"])


class ApplicationAnalysisRequest(BaseModel):
    case_id: str
    application_names: Optional[List[str]] = None
    include_processes: bool = True
    include_files: bool = True
    include_registry: bool = True
    include_network: bool = True
    include_persistence: bool = True
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None


class ApplicationReportResponse(BaseModel):
    report_id: str
    status: str
    applications_analyzed: int
    behaviors_found: int
    report_url: Optional[str] = None


@router.get("/cases/{case_id}/applications")
def list_case_applications(case_id: str, current_user: dict = Depends(get_current_user)):
    """List all applications detected in a case."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    service = ApplicationService()
    applications = service.get_case_applications(case_id)
    
    return {"applications": applications, "total": len(applications)}


@router.get("/cases/{case_id}/applications/{app_name}")
def get_application_details(
    case_id: str,
    app_name: str,
    current_user: dict = Depends(get_current_user)
):
    """Get detailed behavior report for a specific application."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    service = ApplicationService()
    details = service.get_application_details(case_id, app_name)
    
    if not details:
        raise HTTPException(status_code=404, detail="Application not found")
    
    return details


@router.post("/cases/{case_id}/applications/analyze", response_model=ApplicationReportResponse)
def analyze_applications(
    case_id: str,
    request: ApplicationAnalysisRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Analyze application behavior and generate report.
    
    This endpoint:
    1. Collects all events related to specified applications
    2. Analyzes behavior patterns
    3. Matches against known signatures
    4. Generates comprehensive report
    """
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    service = ApplicationService()
    report_id = service.create_analysis_job(case_id, request.dict(), current_user["username"])
    
    # Dispatch Celery task
    from services.celery_dispatcher import dispatch_task
    dispatch_task(
        task_name="application.analyze",
        args=[report_id, case_id, request.dict()],
        queue="modules"
    )
    
    return ApplicationReportResponse(
        report_id=report_id,
        status="PENDING",
        applications_analyzed=0,
        behaviors_found=0
    )


@router.get("/cases/{case_id}/applications/reports/{report_id}")
def get_analysis_report(
    case_id: str,
    report_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get application analysis report by ID."""
    service = ApplicationService()
    report = service.get_report(report_id)
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return report


@router.get("/cases/{case_id}/applications/reports/{report_id}/download")
def download_report(
    case_id: str,
    report_id: str,
    format: str = "pdf",
    current_user: dict = Depends(get_current_user)
):
    """Download application behavior report in specified format."""
    service = ApplicationService()
    report_data = service.get_report(report_id)
    
    if not report_data:
        raise HTTPException(status_code=404, detail="Report not found")
    
    generator = ReportGenerator()
    file_path = generator.generate_report(report_data, format)
    
    return generator.serve_file(file_path)


@router.get("/applications/signatures")
def list_signatures(current_user: dict = Depends(get_current_user)):
    """List all available application behavior signatures."""
    service = ApplicationService()
    signatures = service.list_signatures()
    
    return {"signatures": signatures, "total": len(signatures)}


@router.post("/applications/signatures")
def create_signature(
    signature_data: dict,
    current_user: dict = Depends(require_role("admin"))
):
    """Create custom application behavior signature."""
    service = ApplicationService()
    signature = service.create_signature(signature_data)
    
    return signature
```

### 2.3 Application Service

**File:** api/services/applications.py

```python
"""Application behavior analysis service."""
import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Optional

import redis as redis_lib
from config import settings
from services.elasticsearch import _request as es_req


class ApplicationService:
    """Service for application behavior analysis."""
    
    # Known application categories
    CATEGORIES = {
        "remote_access": ["AnyDesk", "TeamViewer", "Splashtop", "LogMeIn", "RustDesk"],
        "cloud_storage": ["OneDrive", "Dropbox", "Google Drive", "Box", "iCloud"],
        "communication": ["Skype", "Teams", "Slack", "Discord", "Telegram", "WhatsApp"],
        "browser": ["Chrome", "Firefox", "Edge", "Safari", "Opera"],
        "security": ["Defender", "CrowdStrike", "SentinelOne", "Symantec"],
        "productivity": ["Office", "Adobe", "Notion", "Evernote"],
    }
    
    def __init__(self):
        self.redis = redis_lib.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    
    def get_case_applications(self, case_id: str) -> List[Dict]:
        """Get all applications detected in a case."""
        # Query process index for unique applications
        query = {
            "size": 0,
            "aggs": {
                "applications": {
                    "terms": {
                        "field": "process.executable.keyword",
                        "size": 1000
                    }
                }
            }
        }
        
        try:
            response = es_req("POST", f"/fo-case-{case_id}-process/_search", query)
            buckets = response.get("aggregations", {}).get("applications", {}).get("buckets", [])
            
            applications = []
            for bucket in buckets:
                app_name = bucket["key"]
                count = bucket["doc_count"]
                
                # Categorize application
                category = self._categorize_application(app_name)
                
                applications.append({
                    "name": app_name,
                    "execution_count": count,
                    "category": category,
                    "risk_level": self._assess_risk(app_name, category)
                })
            
            return sorted(applications, key=lambda x: x["execution_count"], reverse=True)
        except Exception as e:
            return []
    
    def get_application_details(self, case_id: str, app_name: str) -> Dict:
        """Get detailed behavior for a specific application."""
        details = {
            "application": app_name,
            "case_id": case_id,
            "summary": {},
            "processes": [],
            "files": [],
            "registry": [],
            "network": [],
            "persistence": [],
            "risk_indicators": []
        }
        
        # Get process executions
        process_query = {
            "query": {
                "match": {"process.executable.keyword": app_name}
            },
            "size": 1000
        }
        
        try:
            response = es_req("POST", f"/fo-case-{case_id}-process/_search", process_query)
            details["processes"] = [hit["_source"] for hit in response["hits"]["hits"]]
            details["summary"]["process_count"] = len(details["processes"])
        except:
            pass
        
        # Get file operations
        file_query = {
            "query": {
                "match": {"process.executable.keyword": app_name}
            },
            "size": 1000
        }
        
        try:
            response = es_req("POST", f"/fo-case-{case_id}-file/_search", file_query)
            details["files"] = [hit["_source"] for hit in response["hits"]["hits"]]
            details["summary"]["file_operations"] = len(details["files"])
        except:
            pass
        
        # Get network connections
        network_query = {
            "query": {
                "match": {"process.executable.keyword": app_name}
            },
            "size": 1000
        }
        
        try:
            response = es_req("POST", f"/fo-case-{case_id}-network/_search", network_query)
            details["network"] = [hit["_source"] for hit in response["hits"]["hits"]]
            details["summary"]["network_connections"] = len(details["network"])
        except:
            pass
        
        # Assess risk
        details["risk_indicators"] = self._assess_application_risk(details)
        
        return details
    
    def create_analysis_job(self, case_id: str, request: Dict, username: str) -> str:
        """Create a new application analysis job."""
        report_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        
        job_data = {
            "report_id": report_id,
            "case_id": case_id,
            "requested_by": username,
            "status": "PENDING",
            "created_at": now,
            "started_at": "",
            "completed_at": "",
            "request": json.dumps(request),
            "result": "{}",
            "error": ""
        }
        
        self.redis.hset(f"fo:report:application:{report_id}", mapping=job_data)
        self.redis.expire(f"fo:report:application:{report_id}", 604800)  # 7 days
        
        return report_id
    
    def get_report(self, report_id: str) -> Optional[Dict]:
        """Get application analysis report."""
        data = self.redis.hgetall(f"fo:report:application:{report_id}")
        
        if not data:
            return None
        
        # Parse JSON fields
        data["request"] = json.loads(data.get("request", "{}"))
        data["result"] = json.loads(data.get("result", "{}"))
        
        return data
    
    def list_signatures(self) -> List[Dict]:
        """List all application behavior signatures."""
        signatures = []
        
        for category, apps in self.CATEGORIES.items():
            for app in apps:
                sig_key = f"fo:application:{app}:signature"
                sig_data = self.redis.hgetall(sig_key)
                
                if sig_data:
                    signatures.append({
                        "application": app,
                        "category": category,
                        "signature": json.loads(sig_data.get("signature", "{}"))
                    })
                else:
                    # Load default signature
                    signatures.append({
                        "application": app,
                        "category": category,
                        "signature": self._get_default_signature(app, category)
                    })
        
        return signatures
    
    def create_signature(self, signature_data: Dict) -> Dict:
        """Create or update application behavior signature."""
        app_name = signature_data.get("application")
        if not app_name:
            raise ValueError("Application name required")
        
        sig_key = f"fo:application:{app_name}:signature"
        
        signature = {
            "application": app_name,
            "category": signature_data.get("category", "unknown"),
            "behaviors": signature_data.get("behaviors", []),
            "indicators": signature_data.get("indicators", []),
            "risk_level": signature_data.get("risk_level", "medium"),
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        self.redis.hset(sig_key, mapping={"signature": json.dumps(signature)})
        
        return signature
    
    def _categorize_application(self, app_name: str) -> str:
        """Categorize application by name."""
        app_lower = app_name.lower()
        
        for category, apps in self.CATEGORIES.items():
            for app in apps:
                if app.lower() in app_lower:
                    return category
        
        return "other"
    
    def _assess_risk(self, app_name: str, category: str) -> str:
        """Assess risk level of application."""
        high_risk_categories = ["remote_access", "communication"]
        medium_risk_categories = ["cloud_storage", "browser"]
        
        if category in high_risk_categories:
            return "high"
        elif category in medium_risk_categories:
            return "medium"
        else:
            return "low"
    
    def _assess_application_risk(self, details: Dict) -> List[Dict]:
        """Assess risk indicators for application behavior."""
        indicators = []
        
        # Check for suspicious file operations
        sensitive_paths = [
            "\\AppData\\",
            "\\Temp\\",
            "\\Windows\\System32\\",
            "\\Program Files\\",
            "/etc/",
            "/root/",
            "/tmp/"
        ]
        
        for file_op in details.get("files", []):
            path = file_op.get("file.path", "")
            for sensitive in sensitive_paths:
                if sensitive in path:
                    indicators.append({
                        "type": "sensitive_file_access",
                        "severity": "medium",
                        "description": f"Accessed sensitive path: {path}"
                    })
                    break
        
        # Check for network connections
        for conn in details.get("network", []):
            dest_ip = conn.get("network.dest_ip", "")
            dest_port = conn.get("network.dest_port", "")
            
            # Check for non-standard ports
            if dest_port not in ["80", "443", "53"]:
                indicators.append({
                    "type": "non_standard_port",
                    "severity": "low",
                    "description": f"Connection to non-standard port: {dest_ip}:{dest_port}"
                })
        
        # Check for persistence mechanisms
        if details.get("registry"):
            indicators.append({
                "type": "registry_modification",
                "severity": "high",
                "description": "Application modified registry (potential persistence)"
            })
        
        return indicators
    
    def _get_default_signature(self, app_name: str, category: str) -> Dict:
        """Get default signature for known applications."""
        # This would load from JSON files in plugins/application/signatures/
        return {
            "application": app_name,
            "category": category,
            "behaviors": [],
            "indicators": []
        }
```

### 2.4 Celery Task for Analysis

**File:** processor/tasks/application_task.py

```python
"""Celery task for application behavior analysis."""
from celery_app import app
from datetime import datetime, timezone
import json
import os
import redis

from analyzers.application_analyzer import ApplicationAnalyzer
from services.report_generator import ReportGenerator

REDIS_URL = os.getenv("REDIS_URL", "redis://redis-service:6379/0")


def get_redis():
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


@app.task(bind=True, name="application.analyze", queue="modules")
def analyze_application_behavior(
    self,
    report_id: str,
    case_id: str,
    request: dict
):
    """
    Analyze application behavior and generate report.
    
    Args:
        report_id: Unique report identifier
        case_id: Case this analysis belongs to
        request: Analysis request parameters
    """
    r = get_redis()
    
    try:
        # Update status
        r.hset(f"fo:report:application:{report_id}", mapping={
            "status": "RUNNING",
            "started_at": datetime.now(timezone.utc).isoformat()
        })
        
        # Run analysis
        analyzer = ApplicationAnalyzer(case_id, request)
        results = analyzer.analyze()
        
        # Generate report
        generator = ReportGenerator()
        report_path = generator.generate_report(results, "pdf")
        
        # Upload to MinIO
        from services.storage import upload_file
        minio_key = f"cases/{case_id}/reports/{report_id}.pdf"
        upload_file(minio_key, report_path)
        
        # Update report
        r.hset(f"fo:report:application:{report_id}", mapping={
            "status": "COMPLETED",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "result": json.dumps(results),
            "report_url": minio_key
        })
        
        return {
            "status": "COMPLETED",
            "report_id": report_id,
            "report_url": minio_key,
            "applications_analyzed": results.get("applications_count", 0),
            "behaviors_found": results.get("behaviors_count", 0)
        }
        
    except Exception as e:
        r.hset(f"fo:report:application:{report_id}", mapping={
            "status": "FAILED",
            "error": str(e),
            "completed_at": datetime.now(timezone.utc).isoformat()
        })
        
        return {
            "status": "FAILED",
            "error": str(e)
        }
```

### 2.5 Application Analyzer

**File:** processor/analyzers/application_analyzer.py

```python
"""Application behavior analyzer."""
from typing import Dict, List, Optional
from services.elasticsearch import _request as es_req


class ApplicationAnalyzer:
    """Analyze application behavior from collected data."""
    
    def __init__(self, case_id: str, request: Dict):
        self.case_id = case_id
        self.request = request
        self.applications = request.get("application_names", [])
        self.time_start = request.get("time_range_start")
        self.time_end = request.get("time_range_end")
    
    def analyze(self) -> Dict:
        """Run complete application behavior analysis."""
        results = {
            "case_id": self.case_id,
            "applications": [],
            "summary": {
                "applications_count": 0,
                "behaviors_count": 0,
                "risk_indicators_count": 0
            }
        }
        
        # Get applications to analyze
        if not self.applications:
            self.applications = self._discover_applications()
        
        # Analyze each application
        for app_name in self.applications:
            app_analysis = self._analyze_application(app_name)
            results["applications"].append(app_analysis)
            results["summary"]["applications_count"] += 1
            results["summary"]["behaviors_count"] += len(app_analysis.get("behaviors", []))
            results["summary"]["risk_indicators_count"] += len(app_analysis.get("risk_indicators", []))
        
        return results
    
    def _discover_applications(self) -> List[str]:
        """Discover all applications in the case."""
        query = {
            "size": 0,
            "aggs": {
                "apps": {
                    "terms": {
                        "field": "process.executable.keyword",
                        "size": 100
                    }
                }
            }
        }
        
        try:
            response = es_req("POST", f"/fo-case-{self.case_id}-process/_search", query)
            buckets = response.get("aggregations", {}).get("apps", {}).get("buckets", [])
            return [b["key"] for b in buckets]
        except:
            return []
    
    def _analyze_application(self, app_name: str) -> Dict:
        """Analyze a single application."""
        analysis = {
            "name": app_name,
            "category": self._categorize(app_name),
            "executions": self._get_executions(app_name),
            "file_operations": self._get_file_operations(app_name),
            "network_connections": self._get_network_connections(app_name),
            "persistence": self._get_persistence(app_name),
            "behaviors": [],
            "risk_indicators": []
        }
        
        # Match behaviors
        analysis["behaviors"] = self._match_behaviors(analysis)
        
        # Assess risk
        analysis["risk_indicators"] = self._assess_risk(analysis)
        
        return analysis
    
    def _categorize(self, app_name: str) -> str:
        """Categorize application."""
        categories = {
            "AnyDesk": "remote_access",
            "TeamViewer": "remote_access",
            "OneDrive": "cloud_storage",
            "Chrome": "browser",
            # ... more mappings
        }
        
        for key, category in categories.items():
            if key.lower() in app_name.lower():
                return category
        
        return "other"
    
    def _get_executions(self, app_name: str) -> List[Dict]:
        """Get all executions of application."""
        query = {
            "query": {
                "match": {"process.executable.keyword": app_name}
            },
            "size": 1000,
            "sort": [{"timestamp": {"order": "asc"}}]
        }
        
        try:
            response = es_req("POST", f"/fo-case-{self.case_id}-process/_search", query)
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except:
            return []
    
    def _get_file_operations(self, app_name: str) -> List[Dict]:
        """Get file operations by application."""
        query = {
            "query": {
                "match": {"process.executable.keyword": app_name}
            },
            "size": 1000
        }
        
        try:
            response = es_req("POST", f"/fo-case-{self.case_id}-file/_search", query)
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except:
            return []
    
    def _get_network_connections(self, app_name: str) -> List[Dict]:
        """Get network connections by application."""
        query = {
            "query": {
                "match": {"process.executable.keyword": app_name}
            },
            "size": 1000
        }
        
        try:
            response = es_req("POST", f"/fo-case-{self.case_id}-network/_search", query)
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except:
            return []
    
    def _get_persistence(self, app_name: str) -> List[Dict]:
        """Get persistence mechanisms."""
        persistence = []
        
        # Check registry (Windows)
        registry_query = {
            "query": {
                "match": {"process.executable.keyword": app_name}
            },
            "size": 1000
        }
        
        try:
            response = es_req("POST", f"/fo-case-{self.case_id}-registry/_search", registry_query)
            for hit in response["hits"]["hits"]:
                source = hit["_source"]
                if any(key in source.get("registry.key", "") for key in ["Run", "RunOnce", "Services"]):
                    persistence.append({
                        "type": "registry",
                        "details": source
                    })
        except:
            pass
        
        return persistence
    
    def _match_behaviors(self, analysis: Dict) -> List[Dict]:
        """Match known behavior patterns."""
        behaviors = []
        
        # Check for remote access behavior
        if analysis["category"] == "remote_access":
            if analysis["network_connections"]:
                behaviors.append({
                    "name": "Network Communication",
                    "description": "Application established network connections",
                    "severity": "info"
                })
        
        # Check for file operations in sensitive locations
        sensitive_paths = ["\\AppData\\", "\\Temp\\", "/tmp/"]
        for file_op in analysis["file_operations"]:
            path = file_op.get("file.path", "")
            if any(s in path for s in sensitive_paths):
                behaviors.append({
                    "name": "Sensitive File Access",
                    "description": f"Accessed file in sensitive location: {path}",
                    "severity": "medium"
                })
        
        return behaviors
    
    def _assess_risk(self, analysis: Dict) -> List[Dict]:
        """Assess risk indicators."""
        indicators = []
        
        # High risk categories
        if analysis["category"] in ["remote_access", "communication"]:
            indicators.append({
                "type": "high_risk_category",
                "description": f"Application belongs to high-risk category: {analysis['category']}",
                "severity": "high"
            })
        
        # Check for persistence
        if analysis["persistence"]:
            indicators.append({
                "type": "persistence_mechanism",
                "description": "Application has persistence mechanisms",
                "severity": "high"
            })
        
        # Check for unusual network activity
        for conn in analysis["network_connections"]:
            port = conn.get("network.dest_port", "")
            if port not in ["80", "443", "53"]:
                indicators.append({
                    "type": "unusual_port",
                    "description": f"Connection to unusual port: {port}",
                    "severity": "medium"
                })
        
        return indicators
```

---

## Section 3: Report Templates

### 3.1 Report Structure

```
Application Behavior Report
============================

Case: {case_id}
Generated: {timestamp}
Requested by: {username}

EXECUTIVE SUMMARY
-----------------
Applications Analyzed: {count}
Behaviors Identified: {count}
Risk Indicators: {count}
Overall Risk Level: {low/medium/high}

APPLICATION OVERVIEW
--------------------
[Table of all applications with category, execution count, risk level]

DETAILED ANALYSIS
-----------------

1. {Application Name}
   Category: {category}
   Risk Level: {risk}
   
   Execution Timeline:
   [Timeline visualization]
   
   File Operations:
   [List of file operations]
   
   Network Connections:
   [List of network connections]
   
   Persistence Mechanisms:
   [List of persistence]
   
   Behaviors Matched:
   [List of matched behaviors]
   
   Risk Indicators:
   [List of risk indicators]

RECOMMENDATIONS
---------------
[Based on findings]

APPENDIX
--------
[Raw data, IOCs, etc.]
```

### 3.2 Visualization Components

1. **Timeline Chart** - Application executions over time
2. **Network Graph** - Connections between applications and destinations
3. **File Tree** - File system operations hierarchy
4. **Risk Matrix** - Applications plotted by frequency vs risk

---

## Section 4: Frontend Integration

### 4.1 New UI Components

```
src/components/applications/
├── ApplicationList.vue          # List applications in case
├── ApplicationDetail.vue        # Detailed view of single app
├── ApplicationReport.vue        # Generate and view reports
├── BehaviorTimeline.vue         # Timeline visualization
├── NetworkGraph.vue             # Network connections graph
└── SignatureManager.vue         # Manage behavior signatures
```

### 4.2 API Calls

```javascript
// List applications in case
GET /api/v1/cases/{case_id}/applications

// Get application details
GET /api/v1/cases/{case_id}/applications/{app_name}

// Generate behavior report
POST /api/v1/cases/{case_id}/applications/analyze
{
  "application_names": ["AnyDesk", "TeamViewer"],
  "include_processes": true,
  "include_files": true,
  "include_network": true
}

// Get report status
GET /api/v1/cases/{case_id}/applications/reports/{report_id}

// Download report
GET /api/v1/cases/{case_id}/applications/reports/{report_id}/download?format=pdf
```

---

## Section 5: Implementation Priority

### Phase 1 (Week 1-2)
- Create API endpoints (applications.py)
- Implement ApplicationService
- Create basic analyzer
- Add Celery task

### Phase 2 (Week 3)
- Create report generator
- Add PDF/HTML export
- Implement basic UI components

### Phase 3 (Week 4)
- Add behavior signatures
- Implement signature matching
- Add visualizations

### Phase 4 (Week 5+)
- Custom signature creation UI
- Advanced analytics
- Machine learning for anomaly detection

---

## Section 6: Example Use Cases

### Use Case 1: Investigate Unauthorized Remote Access

```
1. User selects case
2. Clicks "Applications" tab
3. Filters by category "remote_access"
4. Sees AnyDesk executed 15 times
5. Generates behavior report
6. Report shows:
   - 15 executions after hours
   - 3 file transfers
   - Network connections to external IPs
   - Registry persistence added
7. User exports PDF for incident report
```

### Use Case 2: Data Exfiltration Investigation

```
1. User generates report for cloud storage apps
2. Report shows OneDrive uploaded 500MB
3. File operations show access to sensitive folders
4. Network graph shows large outbound transfers
5. Timeline correlates with suspected breach time
```

---

*End of Application Behavior Module Design Document*
