"""TraceX API — FastAPI entrypoint."""
import logging

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from routers import (
    cases, ingest, jobs, search, plugins, health,
    saved_searches, alert_rules, export, global_alert_rules,
    modules, collector, editor,
)
from routers import auth as auth_router
from auth.dependencies import get_current_user

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="TraceX API",
    description="Kubernetes-native digital forensics analysis platform",
    version="1.0.0",
)

# ── Middleware ─────────────────────────────────────────────────────────────────

app.add_middleware(GZipMiddleware, minimum_size=1024)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth dependency applied to all protected routes ───────────────────────────
# Health and auth endpoints are public; everything else requires a valid JWT.
_protected = [Depends(get_current_user)]

# ── Routers ────────────────────────────────────────────────────────────────────

# Public — no auth required
app.include_router(health.router,      prefix="/api/v1")
app.include_router(auth_router.router, prefix="/api/v1")

# Protected — require valid JWT (or AUTH_ENABLED=false for dev)
app.include_router(cases.router,              prefix="/api/v1", dependencies=_protected)
app.include_router(ingest.router,             prefix="/api/v1", dependencies=_protected)
app.include_router(jobs.router,               prefix="/api/v1", dependencies=_protected)
app.include_router(search.router,             prefix="/api/v1", dependencies=_protected)
app.include_router(plugins.router,            prefix="/api/v1", dependencies=_protected)
app.include_router(saved_searches.router,     prefix="/api/v1", dependencies=_protected)
app.include_router(alert_rules.router,        prefix="/api/v1", dependencies=_protected)
app.include_router(export.router,             prefix="/api/v1", dependencies=_protected)
app.include_router(global_alert_rules.router, prefix="/api/v1", dependencies=_protected)
app.include_router(modules.router,            prefix="/api/v1", dependencies=_protected)
app.include_router(collector.router,          prefix="/api/v1", dependencies=_protected)
app.include_router(editor.router,             prefix="/api/v1", dependencies=_protected)
