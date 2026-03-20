"""TraceX API — FastAPI entrypoint."""
import logging

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from routers import (
    cases, ingest, jobs, search, plugins, health,
    saved_searches, alert_rules, export, global_alert_rules,
    modules, collector, editor,
)
from routers import auth as auth_router
from auth.dependencies import get_current_user

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="TraceX API",
    description="Kubernetes-native digital forensics analysis platform",
    version="1.0.0",
)

# ── Global exception handler ──────────────────────────────────────────────────
# Catches anything that escapes FastAPI's built-in handlers (e.g. exceptions
# thrown inside middleware before the router runs, or errors during ASGI
# lifecycle) and ensures the response is always valid JSON — never plain text.

@app.exception_handler(Exception)
async def _unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal server error: {type(exc).__name__}: {exc}"},
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
