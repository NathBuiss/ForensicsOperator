"""
LLM Integration — configuration and result analysis.

Administrators configure an LLM backend (OpenAI, Anthropic, Ollama, or any
OpenAI-compatible endpoint) once; analysts can then trigger AI analysis on
completed module run results via POST /module-runs/{run_id}/analyze.

Configuration is stored in Redis (encrypted at rest by the operator's Redis
ACLs). The API key is redacted in GET responses.

Supported providers:
  openai    — api.openai.com (gpt-4o, gpt-4-turbo, gpt-3.5-turbo …)
  anthropic — api.anthropic.com (claude-3-5-sonnet-20241022 …)
  ollama    — local Ollama server (llama3, mistral, gemma2 …)
  custom    — any OpenAI-compatible endpoint (LiteLLM, vLLM, LM Studio …)
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import redis as redis_lib
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from config import settings
from services import module_runs as run_svc

logger = logging.getLogger(__name__)
router = APIRouter(tags=["llm"])

_LLM_CONFIG_KEY = "fo:llm_config"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _redis() -> redis_lib.Redis:
    return redis_lib.from_url(settings.REDIS_URL, decode_responses=True)


def _get_config(r: redis_lib.Redis) -> dict:
    raw = r.get(_LLM_CONFIG_KEY)
    return json.loads(raw) if raw else {}


# ── Pydantic models ───────────────────────────────────────────────────────────

class LLMConfigIn(BaseModel):
    provider: str                  # openai | anthropic | ollama | custom
    model: str                     # gpt-4o | claude-3-5-sonnet-20241022 | llama3
    api_key: str = ""              # empty for ollama
    base_url: str = ""             # required for ollama/custom, optional for others
    enabled: bool = True


class LLMConfigOut(BaseModel):
    provider: str
    model: str
    api_key_set: bool              # true if key is configured
    base_url: str
    enabled: bool


# ── Config endpoints ──────────────────────────────────────────────────────────

@router.get("/admin/llm-config", response_model=LLMConfigOut)
def get_llm_config():
    """Return current LLM configuration (API key redacted)."""
    r = _redis()
    cfg = _get_config(r)
    return LLMConfigOut(
        provider=cfg.get("provider", ""),
        model=cfg.get("model", ""),
        api_key_set=bool(cfg.get("api_key")),
        base_url=cfg.get("base_url", ""),
        enabled=cfg.get("enabled", False),
    )


@router.put("/admin/llm-config", response_model=LLMConfigOut)
def update_llm_config(body: LLMConfigIn):
    """Save LLM configuration. Merges with existing config so the key is not
    cleared when only model/provider is updated and api_key is left empty."""
    r = _redis()
    existing = _get_config(r)

    cfg = {
        "provider": body.provider,
        "model":    body.model,
        "base_url": body.base_url,
        "enabled":  body.enabled,
        # Keep existing key if new request sends empty string
        "api_key":  body.api_key if body.api_key else existing.get("api_key", ""),
    }
    r.set(_LLM_CONFIG_KEY, json.dumps(cfg))
    return LLMConfigOut(
        provider=cfg["provider"],
        model=cfg["model"],
        api_key_set=bool(cfg["api_key"]),
        base_url=cfg["base_url"],
        enabled=cfg["enabled"],
    )


@router.delete("/admin/llm-config", status_code=204)
def clear_llm_config():
    """Remove LLM configuration."""
    _redis().delete(_LLM_CONFIG_KEY)


@router.post("/admin/llm-config/test")
def test_llm_config():
    """
    Send a trivial one-token prompt to verify the LLM backend is reachable.
    Uses the saved configuration; save first, then test.
    Returns {"ok": true, "response": "..."} on success, HTTP 502 on failure.
    """
    r = _redis()
    cfg = _get_config(r)
    if not cfg or not cfg.get("provider"):
        raise HTTPException(status_code=400, detail="No LLM configuration saved yet.")

    try:
        reply = _call_llm_test(cfg)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LLM test failed: {exc}")

    return {"ok": True, "provider": cfg.get("provider"), "model": cfg.get("model"), "response": reply[:300]}


# ── Analysis endpoint ─────────────────────────────────────────────────────────

_SIGMA_GEN_PROMPT = """You are an expert threat detection engineer who writes Sigma detection rules.
Sigma is a generic signature format for SIEM systems.
Output ONLY valid Sigma YAML — no markdown fences, no explanations, just the YAML.
Required keys: title, status, description, logsource, detection, level.
Optional but encouraged: id (UUIDv4), tags (MITRE ATT&CK), falsepositives.

Example structure:
title: Suspicious PowerShell Encoded Command
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects PowerShell with encoded command arguments often used by attackers
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    CommandLine|contains: '-EncodedCommand'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
falsepositives:
  - Legitimate administrative automation"""


_SYSTEM_PROMPT = """You are an expert digital forensic analyst reviewing the output of an automated analysis module.
Analyze the provided detections and produce a structured forensic summary.

Your response MUST be a JSON object with exactly these keys:
{
  "summary": "2-4 sentence executive summary of what happened",
  "severity": "critical | high | medium | low | informational",
  "timeline": ["key event 1", "key event 2", ...],
  "indicators": ["IOC or notable indicator 1", "IOC 2", ...],
  "mitre_techniques": ["T1059.001 - PowerShell", ...],
  "recommendations": ["Immediate action 1", "Action 2", ...],
  "confidence": "high | medium | low"
}

Be concise and actionable. Focus on what matters for incident response.
Do not include markdown, only return the raw JSON object."""


def _call_llm_test(cfg: dict) -> str:
    """Send a minimal prompt with a short timeout to verify connectivity."""
    provider = cfg.get("provider", "").lower()
    model    = cfg.get("model", "")
    api_key  = cfg.get("api_key", "")
    base_url = cfg.get("base_url", "").rstrip("/")

    msg = "Reply with exactly the word: OK"

    if provider == "anthropic":
        import urllib.request
        headers = {
            "Content-Type":      "application/json",
            "x-api-key":         api_key,
            "anthropic-version": "2023-06-01",
        }
        body = json.dumps({
            "model": model, "max_tokens": 10,
            "messages": [{"role": "user", "content": msg}],
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=body, headers=headers, method="POST",
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
        return data["content"][0]["text"]

    elif provider == "ollama":
        import urllib.request
        url = base_url or "http://localhost:11434"
        body = json.dumps({
            "model": model, "stream": False,
            "messages": [{"role": "user", "content": msg}],
        }).encode()
        req = urllib.request.Request(
            f"{url}/api/chat", data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        return data["message"]["content"]

    else:  # openai or custom
        import urllib.request
        url = base_url or "https://api.openai.com/v1"
        headers = {
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {api_key}",
        }
        body = json.dumps({
            "model": model, "max_tokens": 10,
            "messages": [{"role": "user", "content": msg}],
        }).encode()
        req = urllib.request.Request(
            f"{url}/chat/completions", data=body, headers=headers, method="POST",
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]


def _call_llm(cfg: dict, prompt: str) -> str:
    """Route to the appropriate LLM provider and return the raw text response."""
    provider  = cfg.get("provider", "").lower()
    model     = cfg.get("model", "")
    api_key   = cfg.get("api_key", "")
    base_url  = cfg.get("base_url", "").rstrip("/")

    if provider == "anthropic":
        return _call_anthropic(api_key, model, prompt)
    elif provider == "ollama":
        url = base_url or "http://localhost:11434"
        return _call_ollama(url, model, prompt)
    else:
        # openai or custom (OpenAI-compatible)
        url = base_url or "https://api.openai.com/v1"
        return _call_openai_compat(url, api_key, model, prompt)


def _call_openai_compat(base_url: str, api_key: str, model: str, prompt: str) -> str:
    """Call any OpenAI-compatible /chat/completions endpoint."""
    import urllib.request
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        "temperature": 0.1,
        "max_tokens": 1200,
    }).encode()

    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=body,
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=90) as resp:
        data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"]


def _call_anthropic(api_key: str, model: str, prompt: str) -> str:
    """Call Anthropic Messages API."""
    import urllib.request
    headers = {
        "Content-Type":   "application/json",
        "x-api-key":      api_key,
        "anthropic-version": "2023-06-01",
    }
    body = json.dumps({
        "model": model,
        "system": _SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1200,
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=90) as resp:
        data = json.loads(resp.read())
    return data["content"][0]["text"]


def _call_ollama(base_url: str, model: str, prompt: str) -> str:
    """Call a local Ollama server."""
    import urllib.request
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        "stream": False,
    }).encode()
    req = urllib.request.Request(
        f"{base_url}/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read())
    return data["message"]["content"]


def _build_prompt(run: dict) -> str:
    """Build the analyst prompt from module run data."""
    module_id    = run.get("module_id", "unknown")
    total_hits   = run.get("total_hits", "0")
    hits_by_level = run.get("hits_by_level", {})
    if isinstance(hits_by_level, str):
        try:
            hits_by_level = json.loads(hits_by_level)
        except Exception:
            hits_by_level = {}

    preview_raw = run.get("results_preview", "[]")
    if isinstance(preview_raw, str):
        try:
            preview = json.loads(preview_raw)
        except Exception:
            preview = []
    else:
        preview = preview_raw or []

    # Build a concise representation of the top hits
    hits_text = ""
    for i, hit in enumerate(preview[:50], 1):
        lvl   = hit.get("level", "informational").upper()
        title = hit.get("rule_title", "")
        ts    = hit.get("timestamp", "")
        host  = hit.get("computer", "")
        details = hit.get("details_raw", "")[:200]
        hits_text += f"{i}. [{lvl}] {title}"
        if host:
            hits_text += f" | host:{host}"
        if ts:
            hits_text += f" | {ts}"
        if details:
            hits_text += f"\n   {details}"
        hits_text += "\n"

    level_summary = ", ".join(f"{k}:{v}" for k, v in sorted(hits_by_level.items()))
    if not level_summary:
        level_summary = "no breakdown available"

    return (
        f"Module: {module_id}\n"
        f"Total detections: {total_hits}  ({level_summary})\n\n"
        f"Top detections (up to 50 shown):\n"
        f"{hits_text or '(none)'}\n\n"
        "Analyze the above forensic findings and respond with the JSON structure as instructed."
    )


def _build_alert_prompt(rule_name: str, rule_query: str, match_count: int, sample_events: list) -> str:
    """Build a prompt for LLM analysis of alert rule results."""
    events_text = ""
    for i, ev in enumerate(sample_events[:30], 1):
        ts  = ev.get("timestamp", "")
        msg = ev.get("message", "")[:300]
        events_text += f"{i}. [{ts}] {msg}\n"

    return (
        f"Alert Rule: {rule_name}\n"
        f"Query: {rule_query}\n"
        f"Total matches: {match_count}\n\n"
        f"Sample events ({min(len(sample_events), 30)} shown):\n"
        f"{events_text or '(no sample events)'}\n\n"
        "Analyze the above alert matches and respond with the JSON structure as instructed."
    )


def generate_sigma_yaml(description: str, context: str = "") -> str:
    """Call the configured LLM to generate a Sigma rule YAML from a text description."""
    r = _redis()
    cfg = _get_config(r)
    if not cfg or not cfg.get("provider"):
        raise ValueError("LLM not configured. Go to Settings → AI Analysis first.")

    provider = cfg.get("provider", "").lower()
    model    = cfg.get("model", "")
    api_key  = cfg.get("api_key", "")
    base_url = cfg.get("base_url", "").rstrip("/")

    user_msg = f"Write a Sigma detection rule for: {description}"
    if context:
        user_msg += f"\nAdditional context: {context}"

    import urllib.request

    if provider == "anthropic":
        headers = {
            "Content-Type":      "application/json",
            "x-api-key":         api_key,
            "anthropic-version": "2023-06-01",
        }
        body = json.dumps({
            "model": model, "max_tokens": 1200,
            "system": _SIGMA_GEN_PROMPT,
            "messages": [{"role": "user", "content": user_msg}],
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=body, headers=headers, method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())["content"][0]["text"]

    elif provider == "ollama":
        url = base_url or "http://localhost:11434"
        body = json.dumps({
            "model": model, "stream": False,
            "messages": [
                {"role": "system",  "content": _SIGMA_GEN_PROMPT},
                {"role": "user",    "content": user_msg},
            ],
        }).encode()
        req = urllib.request.Request(
            f"{url}/api/chat", data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())["message"]["content"]

    else:  # openai or custom
        url = base_url or "https://api.openai.com/v1"
        headers = {
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {api_key}",
        }
        body = json.dumps({
            "model": model, "max_tokens": 1200, "temperature": 0.3,
            "messages": [
                {"role": "system", "content": _SIGMA_GEN_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
        }).encode()
        req = urllib.request.Request(
            f"{url}/chat/completions", data=body, headers=headers, method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())["choices"][0]["message"]["content"]


class AlertAnalyzeRequest(BaseModel):
    rule_name: str
    rule_query: str = ""
    match_count: int = 0
    sample_events: list = []


@router.post("/alert-rules/analyze")
def analyze_alert_rule_result(req: AlertAnalyzeRequest) -> Any:
    """
    Run AI analysis on alert rule results (fired matches).
    Accepts the rule metadata + sample events; returns a structured forensic report.
    """
    r = _redis()
    cfg = _get_config(r)
    if not cfg or not cfg.get("enabled"):
        raise HTTPException(
            status_code=400,
            detail="LLM not configured. Go to Settings → AI Analysis.",
        )

    prompt = _build_alert_prompt(
        req.rule_name, req.rule_query, req.match_count, req.sample_events
    )
    try:
        raw = _call_llm(cfg, prompt)
    except Exception as exc:
        logger.error("LLM call failed for alert analysis: %s", exc)
        raise HTTPException(status_code=502, detail=f"LLM call failed: {exc}")

    try:
        clean = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[1] if "\n" in clean else clean[3:]
            clean = clean.rstrip("`").strip()
        analysis: dict = json.loads(clean)
    except (json.JSONDecodeError, ValueError):
        analysis = {
            "summary": raw[:1000], "severity": "unknown",
            "timeline": [], "indicators": [], "mitre_techniques": [],
            "recommendations": [], "confidence": "low", "_raw": raw[:2000],
        }

    analysis["analyzed_at"] = datetime.now(timezone.utc).isoformat()
    analysis["model_used"]  = f"{cfg.get('provider', '?')}/{cfg.get('model', '?')}"
    return {"analysis": analysis}


@router.post("/module-runs/{run_id}/analyze")
def analyze_module_run(run_id: str) -> Any:
    """
    Run AI analysis on a completed module run.

    The LLM reads the results_preview (top detections) and produces a
    structured forensic report: summary, severity, timeline, IOCs,
    MITRE techniques, and recommendations.

    The analysis is stored in the module run Redis record and returned in
    subsequent GET /module-runs/{run_id} calls.
    """
    r = _redis()

    # ── Check LLM is configured ───────────────────────────────────────────────
    cfg = _get_config(r)
    if not cfg or not cfg.get("enabled"):
        raise HTTPException(
            status_code=400,
            detail="LLM not configured. Go to Settings → AI Analysis to set up a provider.",
        )

    # ── Load run ──────────────────────────────────────────────────────────────
    run = run_svc.get_module_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Module run not found")
    if run.get("status") != "COMPLETED":
        raise HTTPException(
            status_code=400,
            detail=f"Module run is not completed (status: {run.get('status')})",
        )

    # ── Call LLM ──────────────────────────────────────────────────────────────
    prompt = _build_prompt(run)
    try:
        raw_response = _call_llm(cfg, prompt)
    except Exception as exc:
        logger.error("LLM call failed for run %s: %s", run_id, exc)
        raise HTTPException(
            status_code=502,
            detail=f"LLM call failed: {exc}",
        )

    # ── Parse JSON response ───────────────────────────────────────────────────
    try:
        # Strip potential markdown code fences
        clean = raw_response.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[1] if "\n" in clean else clean[3:]
            if clean.endswith("```"):
                clean = clean[:-3]
        analysis: dict = json.loads(clean)
    except (json.JSONDecodeError, ValueError):
        # If the LLM didn't return valid JSON, wrap the raw text
        analysis = {
            "summary": raw_response[:1000],
            "severity": "unknown",
            "timeline": [],
            "indicators": [],
            "mitre_techniques": [],
            "recommendations": [],
            "confidence": "low",
            "_raw": raw_response[:2000],
        }

    analysis["analyzed_at"] = datetime.now(timezone.utc).isoformat()
    analysis["model_used"]   = f"{cfg.get('provider', '?')}/{cfg.get('model', '?')}"

    # ── Store in Redis ────────────────────────────────────────────────────────
    run_svc.update_module_run(run_id, llm_analysis=json.dumps(analysis))

    return {"analysis": analysis, "run_id": run_id}
