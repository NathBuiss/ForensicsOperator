"""Sigma HQ synchronization endpoints."""
import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List

from config import settings, get_redis
from auth.dependencies import require_admin
from services.sigma_sync import SigmaSyncService

router = APIRouter(tags=["sigma-sync"])


class SigmaSyncRequest(BaseModel):
    categories: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    levels: Optional[List[str]] = None


class SigmaSyncResponse(BaseModel):
    imported: int
    skipped: int
    errors: int
    total_rules: int


@router.get("/sigma/status")
def get_sigma_status(current_user: dict = Depends(require_admin)):
    """Get Sigma HQ sync status."""
    service = SigmaSyncService()
    return service.get_sync_status()


@router.post("/sigma/sync", response_model=SigmaSyncResponse)
def sync_sigma_rules(
    request: SigmaSyncRequest,
    current_user: dict = Depends(require_admin)
):
    """
    Sync rules from Sigma HQ.
    
    This downloads the latest Sigma rules from GitHub and converts them
    to Elasticsearch queries. May take 2-5 minutes depending on filters.
    
    Recommended for production:
    - levels: ["critical"] (only critical severity rules)
    - levels: ["high", "critical"] (high and critical)
    """
    service = SigmaSyncService()
    
    # Default to critical only if no filters specified
    if not request.levels and not request.categories and not request.tags:
        request.levels = ["critical"]
    
    try:
        result = service.sync_sigma_rules(
            categories=request.categories,
            tags=request.tags,
            levels=request.levels
        )
        return SigmaSyncResponse(**result)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sync failed: {str(e)}")


@router.delete("/sigma/clear")
def clear_sigma_rules(current_user: dict = Depends(require_admin)):
    """Clear all synced Sigma HQ rules."""
    service = SigmaSyncService()
    result = service.clear_sigma_rules()
    return result


@router.get("/sigma/rules")
def list_sigma_rules(
    skip: int = 0,
    limit: int = 50,
    current_user: dict = Depends(require_admin)
):
    """List synced Sigma HQ rules."""
    redis_client = get_redis()
    rules = json.loads(redis_client.get("fo:alert_rules:_global:sigma") or "[]")
    
    return {
        "rules": rules[skip:skip+limit],
        "total": len(rules),
        "skip": skip,
        "limit": limit
    }
