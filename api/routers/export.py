"""Case data export — CSV download from Elasticsearch."""
import csv, io
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from services.elasticsearch import _request as es_req
import urllib.error

router = APIRouter(tags=["export"])

@router.get("/cases/{case_id}/export/csv")
def export_csv(case_id: str, artifact_type: str = "", flagged_only: bool = False, q: str = ""):
    """Export case events as CSV (max 10 000 rows)."""
    idx = f"fo-case-{case_id}-{artifact_type}" if artifact_type else f"fo-case-{case_id}-*"
    must = []
    if q:           must.append({"query_string": {"query": q, "default_operator": "AND"}})
    if flagged_only: must.append({"term": {"is_flagged": True}})
    body = {
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "sort": [{"timestamp": "asc"}], "size": 10000,
        "_source": ["timestamp","artifact_type","message","host","user","is_flagged","tags","analyst_note"],
    }
    try:
        resp = es_req("POST", f"/{idx}/_search", body)
    except Exception:
        resp = {"hits": {"hits": []}}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp","artifact_type","host","user","message","flagged","tags","analyst_note"])
    for h in resp["hits"]["hits"]:
        s = h["_source"]
        host = s.get("host") or {}
        user = s.get("user") or {}
        w.writerow([s.get("timestamp",""), s.get("artifact_type",""),
                    host.get("hostname","") if isinstance(host,dict) else host,
                    user.get("name","") if isinstance(user,dict) else user,
                    s.get("message",""), s.get("is_flagged",False),
                    ",".join(s.get("tags") or []), s.get("analyst_note","")])
    buf.seek(0)
    name = f"case-{case_id[:8]}-{artifact_type or 'all'}.csv"
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename={name}"})
