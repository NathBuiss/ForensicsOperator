"""Celery application factory."""
import os
from celery import Celery

REDIS_URL = os.getenv("REDIS_URL", "redis://redis-service:6379/0")

app = Celery(
    "forensics_processor",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["tasks.ingest_task"],
)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=3600,
    task_time_limit=7200,
    result_expires=604800,  # 7 days
)

if __name__ == "__main__":
    app.start()
