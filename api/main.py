"""TraceX API — FastAPI entrypoint."""
import asyncio
import collections
import logging
import time

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

# ── API request telemetry ─────────────────────────────────────────────────────
# Rolling window of (duration_ms, status_code) tuples for the last 2000 requests.
# Stored at module level so middleware and the metrics endpoint share it directly.
_REQUEST_WINDOW: collections.deque = collections.deque(maxlen=2000)
_REQUEST_TOTALS = {"count": 0, "errors": 0}   # monotonic counters, never reset

from config import settings

from routers import (
    cases, ingest, jobs, search, plugins, health,
    saved_searches, notes, alert_rules, export, global_alert_rules,
    modules, collector, editor, llm_config, s3_integration, metrics,
    cti, yara_rules, sigma_sync, case_files, harvest,
)
from routers import auth as auth_router
from auth.dependencies import get_current_user, require_admin, require_analyst_or_admin

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _bootstrap_admin() -> None:
    """
    Called at startup to:
    1. Migrate pre-RBAC user accounts that lack a 'role' field → promote to admin.
    2. Create a default admin user from env vars if Redis has no users at all.

    This is idempotent — safe to run on every restart.
    """
    from auth.service import (
        _redis as auth_redis, _USER_KEY, _USERS_SET,
        create_user, user_count,
    )
    try:
        r = auth_redis()

        # ── Step 1: patch existing users without a role (pre-RBAC migration) ──
        usernames = r.smembers(_USERS_SET)
        for username in usernames:
            key = _USER_KEY.format(username=username)
            if not r.hget(key, "role"):
                r.hset(key, "role", "admin")
                logger.info("Bootstrap: migrated user '%s' → role=admin", username)

        # ── Step 2: seed default admin if no users exist ───────────────────────
        if user_count() == 0:
            try:
                create_user(settings.ADMIN_USERNAME, settings.ADMIN_PASSWORD, role="admin")
                logger.info(
                    "Bootstrap: created default admin user '%s'. "
                    "Change the password immediately after first login.",
                    settings.ADMIN_USERNAME,
                )
            except ValueError:
                pass  # Already exists (race between replicas)
    except Exception as exc:
        # Redis may not be reachable during very early startup; the readinessProbe
        # ensures requests only arrive after Redis is up, so this is non-fatal.
        logger.warning("Bootstrap admin failed (Redis not ready?): %s", exc)


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

@app.middleware("http")
async def _telemetry_middleware(request: Request, call_next):
    t0  = time.perf_counter()
    res = await call_next(request)
    ms  = round((time.perf_counter() - t0) * 1000, 1)
    _REQUEST_WINDOW.append((ms, res.status_code))
    _REQUEST_TOTALS["count"]  += 1
    if res.status_code >= 500:
        _REQUEST_TOTALS["errors"] += 1
    return res

app.add_middleware(GZipMiddleware, minimum_size=1024)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Startup hook ─────────────────────────────────────────────────────────────

async def _metrics_background_loop():
    """Collect and persist a slim metrics snapshot every 30 s, forever."""
    import asyncio as _aio
    # Small initial delay so services are fully up before first scrape
    await _aio.sleep(10)
    while True:
        try:
            # Run the blocking collection in a thread so the event loop stays free
            await _aio.get_event_loop().run_in_executor(None, metrics.store_metrics_snapshot)
        except Exception:
            pass
        await _aio.sleep(30)


@app.on_event("startup")
async def _on_startup():
    _bootstrap_admin()
    asyncio.create_task(cti.start_cti_scheduler())
    asyncio.create_task(_metrics_background_loop())


# ── Auth dependencies for route protection ────────────────────────────────────
# Health and auth endpoints are public; everything else requires a valid JWT.
# Analyst-or-admin: regular forensic operations (cases, search, etc.)
# Admin-only: system configuration (LLM settings, global alert rules, etc.)
_analyst_or_admin = [Depends(require_analyst_or_admin)]
_admin_only       = [Depends(require_admin)]

# ── Routers ────────────────────────────────────────────────────────────────────

# Public — no auth required
app.include_router(health.router,      prefix="/api/v1")
app.include_router(auth_router.router, prefix="/api/v1")

# Protected — analyst or admin
app.include_router(cases.router,              prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(ingest.router,             prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(jobs.router,               prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(search.router,             prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(plugins.router,            prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(saved_searches.router,     prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(notes.router,              prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(alert_rules.router,        prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(export.router,             prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(modules.router,            prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(collector.router,          prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(editor.router,             prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(cti.router,               prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(yara_rules.router,        prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(case_files.router,        prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(harvest.router,           prefix="/api/v1", dependencies=_analyst_or_admin)

# Protected — analyst or admin (alert rules used by analysts too)
app.include_router(global_alert_rules.router, prefix="/api/v1", dependencies=_analyst_or_admin)

# Protected — admin only (system configuration)
# llm_config is registered with analyst_or_admin so analysts can use AI analysis.
# The /admin/llm-config CRUD routes carry their own require_admin dependency.
app.include_router(llm_config.router,         prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(s3_integration.router,     prefix="/api/v1", dependencies=_admin_only)
app.include_router(metrics.router,            prefix="/api/v1", dependencies=_analyst_or_admin)
app.include_router(sigma_sync.router,         prefix="/api/v1", dependencies=_admin_only)
