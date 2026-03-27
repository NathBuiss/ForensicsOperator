"""
Direct Celery task dispatch for the ForensicsOperator API.

Bypasses Celery's routing machinery (exchange + binding-table lookups) and
pushes Celery v5-compatible JSON messages straight to the Redis list that
processor workers consume via BLPOP.  This avoids the class of silent message
drops caused by exchange/routing-key mismatches between the minimal API Celery
app and the processor's 'forensics' direct exchange.
"""
from __future__ import annotations

import base64
import json
import logging
import uuid

import redis as _redis

from config import settings

logger = logging.getLogger(__name__)


def _push(queue: str, task_name: str, task_id: str, args: list) -> None:
    """
    Build a Celery v5 JSON message envelope and RPUSH it to *queue*.

    The processor workers consume from these Redis lists via Kombu's BLPOP
    loop.  Any well-formed Celery message pushed here will be received and
    executed by the worker regardless of exchange/binding configuration.
    """
    body_b64 = base64.b64encode(
        json.dumps(
            [args, {}, {"callbacks": None, "errbacks": None, "chain": None, "chord": None}]
        ).encode()
    ).decode()

    delivery_id = uuid.uuid4().hex

    envelope = json.dumps({
        "body": body_b64,
        "content-encoding": "utf-8",
        "content-type": "application/json",
        "headers": {
            "lang": "py",
            "task": task_name,
            "id": task_id,
            "shadow": None,
            "eta": None,
            "expires": None,
            "group": None,
            "group_index": None,
            "retries": 0,
            "timelimit": [None, None],
            "root_id": task_id,
            "parent_id": None,
            "origin": "api",
            "utc": True,
            "argsrepr": repr(args),
            "kwargsrepr": "{}",
        },
        "properties": {
            "correlation_id": task_id,
            "reply_to": delivery_id,
            "delivery_mode": 2,
            "delivery_info": {
                "exchange": "",
                "routing_key": queue,
            },
            "priority": 0,
            "body_encoding": "base64",
            "delivery_tag": delivery_id,
        },
    })

    r = _redis.Redis.from_url(settings.REDIS_URL)
    list_len = r.rpush(queue, envelope)
    logger.info("Dispatched %s[%s] → queue '%s' (depth now %d)", task_name, task_id, queue, list_len)


def dispatch_ingest(job_id: str, case_id: str, minio_key: str, filename: str) -> None:
    _push("ingest", "ingest.process_artifact", job_id,
          [job_id, case_id, minio_key, filename])


def dispatch_module(run_id: str, case_id: str, module_id: str,
                    source_files: list, params: dict) -> None:
    _push("modules", "module.run", run_id,
          [run_id, case_id, module_id, source_files, params])
