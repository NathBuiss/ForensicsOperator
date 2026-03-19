"""ForensicsOperator API — FastAPI entrypoint."""
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers import cases, ingest, jobs, search, plugins, health, saved_searches, alert_rules, export, global_alert_rules, modules, collector

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="ForensicsOperator API",
    description="Kubernetes-native forensics analysis platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api/v1")
app.include_router(cases.router, prefix="/api/v1")
app.include_router(ingest.router, prefix="/api/v1")
app.include_router(jobs.router, prefix="/api/v1")
app.include_router(search.router, prefix="/api/v1")
app.include_router(plugins.router, prefix="/api/v1")
app.include_router(saved_searches.router, prefix="/api/v1")
app.include_router(alert_rules.router, prefix="/api/v1")
app.include_router(export.router, prefix="/api/v1")
app.include_router(global_alert_rules.router, prefix="/api/v1")
app.include_router(modules.router, prefix="/api/v1")
app.include_router(collector.router, prefix="/api/v1")
