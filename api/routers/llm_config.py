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

import redis
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth.dependencies import require_admin
from config import settings, get_redis as _redis
from services import module_runs as run_svc

logger = logging.getLogger(__name__)
router = APIRouter(tags=["llm"])

# Shorthand: applied to each /admin/llm-config route so only admins can touch config.
# The router itself is registered with analyst_or_admin in main.py so that
# analysts can reach the /analyze and /generate endpoints.
_admin_dep = [Depends(require_admin)]

_LLM_CONFIG_KEY = "fo:llm_config"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_config(r: redis.Redis) -> dict:
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

@router.get("/admin/llm-config", response_model=LLMConfigOut, dependencies=_admin_dep)
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


@router.put("/admin/llm-config", response_model=LLMConfigOut, dependencies=_admin_dep)
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


@router.delete("/admin/llm-config", status_code=204, dependencies=_admin_dep)
def clear_llm_config():
    """Remove LLM configuration."""
    _redis().delete(_LLM_CONFIG_KEY)


@router.post("/admin/llm-config/test", dependencies=_admin_dep)
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


_SYSTEM_PROMPT = """You are a digital forensic analyst documenting findings on an information system.
Your job is to describe what the evidence shows — not to assume malice. Most activity on a real IS is routine.

Your response MUST be a JSON object with exactly these keys:
{
  "summary": "2-4 sentences describing what the data shows in plain terms. Describe actual observed behaviour, not speculation.",
  "anomaly_level": "none | low | medium | high — only elevate if there is a concrete, specific reason: unknown binaries, unusual hours, known-bad indicators, lateral movement patterns. Default to 'none' or 'low' for typical system activity.",
  "anomaly_reason": "One sentence explaining why you chose that anomaly_level. If 'none', state what makes this activity expected.",
  "notable_findings": ["Specific, concrete finding 1 (e.g. 'User searched for salary data on 3 occasions')", "Finding 2", ...],
  "context_needed": ["What additional evidence would help interpret this — e.g. 'Check if this process is part of standard software deployment'"],
  "mitre_techniques": ["Only include if there is a clear, specific match — T1059.001 - PowerShell. Leave empty [] if uncertain."],
  "confidence": "high | medium | low — reflects data quality and completeness, not threat level"
}

Key principles:
- Browser history, prefetch, MFT, and registry entries are normal system artefacts. Describe what was used/accessed, not whether it is suspicious.
- Do not invent IOCs or threats not present in the data.
- Be proportionate: a single unusual event is not an incident.
- Use precise language: "the user accessed X" not "the attacker executed X".
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


_MODULE_CONTEXT = {
    "hindsight":        "Browser forensics — history, cookies, downloads, form data from Chrome/Firefox/Edge. This is routine user activity data.",
    "browser_report":   "Browser history report — aggregated URL visits, searches, and downloads. This is routine user activity data.",
    "exiftool":         "File metadata extraction — timestamps, GPS, author fields, camera make/model. Most metadata is benign.",
    "strings":          "Printable string extraction from a binary or unknown file. Strings alone are not indicators of compromise.",
    "strings_analysis": "Categorised string extraction with IOC pattern matching. A match is a candidate for further investigation, not a confirmed threat.",
    "regripper":        "Windows Registry analysis — installed software, user activity, system configuration, autorun entries.",
    "hayabusa":         "Sigma-based threat hunting against Windows Event Logs. Hayabusa assigns its own severity — treat 'informational' hits as background noise.",
    "yara":             "YARA rule scan — pattern matching against file content. A YARA hit means the pattern was present, not that the file is malicious.",
    "pe_analysis":      "PE executable analysis — imports, exports, sections, entropy. High entropy or unusual imports warrant further investigation.",
    "oletools":         "Office document macro/OLE analysis. Macros are common in enterprise environments; evaluate in context.",
    "volatility3":      "Memory forensics — running processes, network connections, loaded modules from a RAM image.",
    "grep_search":      "Regex/keyword pattern search across evidence. A hit means the pattern appears, not that it is malicious.",
    "cti_match":        "IOC matching against the CTI database. A match means the indicator was seen in threat intelligence feeds.",
    "wintriage":        "Windows triage collection — system info, user accounts, network config, scheduled tasks, services.",
    "access_log_analysis": "Web/proxy access log analysis — HTTP requests, status codes, user agents, source IPs.",
}


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

    # Serialize each hit as full JSON — include every field so the LLM has
    # complete visibility. Long string fields are capped at 800 chars to
    # stay within token budgets while preserving all structure.
    hits_text = ""
    for i, hit in enumerate(preview[:50], 1):
        compact = {
            k: (v[:800] if isinstance(v, str) and len(v) > 800 else v)
            for k, v in hit.items()
            if v or v == 0
        }
        try:
            hit_json = json.dumps(compact, ensure_ascii=False, default=str)
        except Exception:
            hit_json = str(compact)
        hits_text += f"{i}. {hit_json}\n"

    level_summary = ", ".join(f"{k}:{v}" for k, v in sorted(hits_by_level.items()))
    if not level_summary:
        level_summary = "no breakdown available"

    module_ctx = _MODULE_CONTEXT.get(module_id, "")
    context_line = f"Module context: {module_ctx}\n" if module_ctx else ""

    return (
        f"Module: {module_id}\n"
        f"{context_line}"
        f"Total findings: {total_hits}  ({level_summary})\n\n"
        f"Findings (up to 50 shown, full JSON — analyze all fields):\n"
        f"{hits_text or '(none)'}\n\n"
        "Analyze all fields in every JSON object above. "
        "Describe what these findings show about the system or user activity, and respond with the JSON structure as instructed."
    )


def _build_alert_prompt(rule_name: str, rule_query: str, match_count: int, sample_events: list) -> str:
    """Build a prompt for LLM analysis of alert rule results."""
    events_text = ""
    for i, ev in enumerate(sample_events[:30], 1):
        compact = {
            k: (v[:800] if isinstance(v, str) and len(v) > 800 else v)
            for k, v in ev.items()
            if v or v == 0
        }
        try:
            ev_json = json.dumps(compact, ensure_ascii=False, default=str)
        except Exception:
            ev_json = str(compact)
        events_text += f"{i}. {ev_json}\n"

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


# ── Event / log explanation ───────────────────────────────────────────────────

_EVENT_EXPLAIN_PROMPT = """You are a digital forensic analyst explaining evidence found on an information system.
Describe what these event(s) show in plain language. Most events represent normal system activity.

For each event state:
  • What happened — describe the actual action or activity recorded
  • Whether this is expected or unusual for a typical IS — be specific about why
  • The key fields that are most meaningful for understanding what occurred

Be concise (3-6 sentences total). Only mention MITRE ATT&CK techniques if there is a clear, specific match — not as a reflexive annotation of every event.
Respond in plain text — no JSON, no markdown headers."""


class EventExplainRequest(BaseModel):
    events: list              # list of event dicts from ES
    context: str = ""         # optional analyst context ("this host was compromised")


@router.post("/events/explain")
def explain_events(req: EventExplainRequest) -> Any:
    """
    Use the configured LLM to explain one or more timeline events in plain language.

    Designed for the Timeline view: analyst selects events → clicks "Explain" →
    gets a human-readable interpretation.
    """
    r = _redis()
    cfg = _get_config(r)
    if not cfg or not cfg.get("enabled"):
        raise HTTPException(
            status_code=400,
            detail="LLM not configured. Go to Settings → AI Analysis.",
        )

    # Build a compact event summary for the prompt
    events_text = ""
    for i, ev in enumerate(req.events[:20], 1):
        ts   = ev.get("timestamp", "")
        msg  = ev.get("message", "")[:400]
        host = (ev.get("host") or {}).get("hostname", "")
        user = (ev.get("user") or {}).get("name", "")
        atype = ev.get("artifact_type", "")
        events_text += f"{i}. [{atype}] {ts}"
        if host: events_text += f" | host:{host}"
        if user: events_text += f" | user:{user}"
        events_text += f"\n   {msg}\n"

    user_msg = f"Forensic events to explain:\n\n{events_text}"
    if req.context:
        user_msg += f"\nAnalyst context: {req.context}"

    try:
        provider = cfg.get("provider", "").lower()
        model    = cfg.get("model", "")
        api_key  = cfg.get("api_key", "")
        base_url = cfg.get("base_url", "").rstrip("/")

        import urllib.request as _ur

        if provider == "anthropic":
            body = json.dumps({
                "model": model, "max_tokens": 800,
                "system": _EVENT_EXPLAIN_PROMPT,
                "messages": [{"role": "user", "content": user_msg}],
            }).encode()
            req_http = _ur.Request(
                "https://api.anthropic.com/v1/messages", data=body,
                headers={"Content-Type": "application/json", "x-api-key": api_key,
                         "anthropic-version": "2023-06-01"}, method="POST",
            )
            with _ur.urlopen(req_http, timeout=60) as resp:
                explanation = json.loads(resp.read())["content"][0]["text"]

        elif provider == "ollama":
            url = base_url or "http://localhost:11434"
            body = json.dumps({
                "model": model, "stream": False,
                "messages": [{"role": "system", "content": _EVENT_EXPLAIN_PROMPT},
                             {"role": "user", "content": user_msg}],
            }).encode()
            req_http = _ur.Request(f"{url}/api/chat", data=body,
                                   headers={"Content-Type": "application/json"}, method="POST")
            with _ur.urlopen(req_http, timeout=90) as resp:
                explanation = json.loads(resp.read())["message"]["content"]

        else:  # openai / custom
            url = base_url or "https://api.openai.com/v1"
            body = json.dumps({
                "model": model, "max_tokens": 800, "temperature": 0.2,
                "messages": [{"role": "system", "content": _EVENT_EXPLAIN_PROMPT},
                             {"role": "user", "content": user_msg}],
            }).encode()
            req_http = _ur.Request(f"{url}/chat/completions", data=body,
                                   headers={"Content-Type": "application/json",
                                            "Authorization": f"Bearer {api_key}"}, method="POST")
            with _ur.urlopen(req_http, timeout=60) as resp:
                explanation = json.loads(resp.read())["choices"][0]["message"]["content"]

    except Exception as exc:
        logger.error("LLM call failed for event explanation: %s", exc)
        raise HTTPException(status_code=502, detail=f"LLM call failed: {exc}")

    return {
        "explanation": explanation,
        "model_used": f"{cfg.get('provider', '?')}/{cfg.get('model', '?')}",
        "events_count": len(req.events),
    }


# ── Sigma rule generation ─────────────────────────────────────────────────────

# ── Search AI assistant ────────────────────────────────────────────────────────

_SEARCH_ASSIST_PROMPT = """You are an expert Elasticsearch query builder for ForensicsOperator, a digital forensics SIEM/timeline platform.

## Index schema — all searchable fields

### Core fields (present on every event)
- timestamp          ISO 8601 event time
- message            Full-text event description — PRIMARY search target for bare terms
- artifact_type      Ingester: evtx, prefetch, mft, registry, lnk, syslog, hayabusa, browser, plaso, amcache, wlan-profile, windows-task, wer, etw, suricata, zeek, plist, csv, strings, generic
- fo_id              Unique event ID
- ingest_job_id      Job that produced the event
- ingested_at        When the file was ingested (not the event time)
- is_flagged         boolean — analyst-flagged event
- tags               keyword array — analyst-applied tags
- analyst_note       free-text analyst annotation

### Host & identity
- host.hostname, host.domain, host.ip, host.os
- user.name, user.domain, user.sid

### Process
- process.name, process.cmdline, process.args, process.pid, process.path, process.parent_name, process.parent_pid

### Network
- network.src_ip, network.dst_ip, network.dst_port, network.protocol

### Windows Event Log (EVTX / Hayabusa)
- evtx.event_id, evtx.channel, evtx.provider_name
- hayabusa.level (critical|high|medium|low|informational), hayabusa.rule_title, hayabusa.tags

### Registry (NTUSER.DAT, Amcache.hve, SYSTEM, SOFTWARE)
- registry.key_path, registry.value_name, registry.value_data

### Prefetch (.pf files)
- prefetch.executable, prefetch.run_count, prefetch.last_run, prefetch.volumes

### LNK (Windows shortcut files)
- lnk.target_path, lnk.machine_id, lnk.volume_label

### MFT ($MFT filesystem timeline)
- mft.filename, mft.path, mft.size, mft.is_deleted, mft.created, mft.modified, mft.mft_modified, mft.accessed

### Web / access logs
- access_log.status, access_log.method, access_log.uri, access_log.ip, access_log.user_agent

### Browser history (Hindsight / browser module)
- browser.url, browser.title, browser.visit_count, browser.profile

### Syslog / text logs (CBS.log, DISM.log, AnyDesk .trace, Windows Update log)
- (parsed into message; use bare terms or message:* wildcards)

### Plaso (log2timeline super-timeline)
- plaso.source, plaso.source_long, plaso.pe_type

### Additional artifact types (newer ingesters)
- artifact_type:syslog — Windows text logs (CBS.log, DISM.log, WindowsUpdate.log, AnyDesk/TeamViewer traces, setup logs)
- artifact_type:wlan-profile — Wi-Fi profile XML (SSID, authentication, key management)
- artifact_type:windows-task — Scheduled Task XML from System32/SysWOW64 (persistence evidence)
- artifact_type:wer — Windows Error Reporting crash records
- artifact_type:amcache — Amcache.hve execution evidence (SHA1, PE metadata, install/link times)
- artifact_type:suricata — Suricata IDS EVE JSON alerts (network.src_ip, network.dst_ip, message contains alert signature)
- artifact_type:zeek — Zeek network log events (conn.log, dns.log, http.log, ssl.log)
- artifact_type:plist — macOS preference/property list values
- artifact_type:browser — Browser history from Chrome, Edge, Firefox, Brave, Opera; also OneDrive/cloud sync SQLite metadata (browser.url, browser.title, browser.visit_count, browser.profile)

## How queries work
Normal mode (default): query_string searching message, host.hostname, user.name, process.name, process.cmdline, process.args.
Regexp mode (.*toggle): ES regexp on message.keyword (full raw string). Supports . .* [a-z] (a|b) a+ a? a{n,m} — does NOT support \\d \\w \\s — use [0-9] [a-zA-Z] [ \\t] instead.

## query_string syntax
- bare term: searches message + key fields: failed logon
- field=value: evtx.event_id:4624
- phrase: message:"lateral movement"
- wildcard: process.name:cmd*
- boolean AND: evtx.event_id:4625 AND host.hostname:DC*
- OR group: evtx.event_id:(4625 OR 4771 OR 4776)
- range: evtx.event_id:[4624 TO 4634]
- NOT: NOT evtx.event_id:4672
- is_flagged:true — only analyst-flagged events
- tags:lateral-movement — events with a specific tag

## Common forensics investigation patterns

### Authentication & account activity
- Failed logins: evtx.event_id:4625
- Successful logins: evtx.event_id:4624
- Kerberos TGT request: evtx.event_id:4768
- Kerberos TGS request: evtx.event_id:4769
- Pass-the-hash / NTLM: evtx.event_id:4776
- Account created: evtx.event_id:4720
- Account locked: evtx.event_id:4740
- Privilege use: evtx.event_id:(4672 OR 4673)

### Process & execution
- Process creation (Security): evtx.event_id:4688
- Process creation (Sysmon): evtx.event_id:1 AND evtx.channel:Microsoft-Windows-Sysmon/Operational
- PowerShell script block: evtx.event_id:4104 AND evtx.channel:*PowerShell*
- PowerShell general: process.name:powershell* OR message:*powershell*
- Encoded command: message:*-EncodedCommand* OR message:*-enc*
- Prefetch evidence: artifact_type:prefetch AND prefetch.executable:*

### Lateral movement
- Remote logins: evtx.event_id:4624 AND evtx.channel:Security AND message:*Network*
- Anonymous / pass-the-hash: evtx.event_id:4624 AND user.name:ANONYMOUS*
- RDP connection: evtx.event_id:(4624 OR 4778) AND message:*RemoteInteractive*
- SMB/admin share: message:(*IPC$* OR *ADMIN$* OR *C$*)

### Persistence
- Scheduled task created: evtx.event_id:(4698 OR 4702)
- Service installed: evtx.event_id:7045 AND evtx.channel:System
- Registry run keys: registry.key_path:*Run*
- Autorun (Amcache): artifact_type:amcache AND message:*

### Credential dumping
- LSASS access: message:(*lsass* OR *mimikatz* OR *sekurlsa* OR *WCE*)
- SAM dump: message:(*reg save* AND *SAM*)

### File system (MFT)
- Deleted files: artifact_type:mft AND mft.is_deleted:true
- Recently created: artifact_type:mft AND mft.filename:*
- Specific file: artifact_type:mft AND mft.filename:cmd.exe

### Event log tampering
- Log cleared (Security): evtx.event_id:1102
- Log cleared (System): evtx.event_id:104
- Audit policy changed: evtx.event_id:4719

### Network / web
- 404 errors: access_log.status:404
- POST requests: access_log.method:POST
- Suspicious user agent: access_log.user_agent:*curl* OR access_log.user_agent:*python*

### Hayabusa threat levels
- Critical findings: artifact_type:hayabusa AND hayabusa.level:critical
- High severity: artifact_type:hayabusa AND hayabusa.level:high
- All alerts: artifact_type:hayabusa AND hayabusa.level:(critical OR high OR medium)

### Newer artifact types
- Scheduled task persistence: artifact_type:windows-task
- Wi-Fi connection history: artifact_type:wlan-profile
- Windows text/setup logs: artifact_type:syslog
- Suricata IDS alerts: artifact_type:suricata
- Zeek network logs: artifact_type:zeek
- macOS plists: artifact_type:plist
- Browser / cloud sync history: artifact_type:browser AND browser.url:*
- Amcache execution: artifact_type:amcache

## UI features the analyst has access to
- **Normal mode** (default): query_string against message + host/user/process fields. Best for field-level queries.
- **Regexp mode** (.*): ES regexp on full message.keyword. Suggest this when the user wants to match a pattern like cmd\.exe, 4[6-9][0-9]{2}, or (mimikatz|sekurlsa).
- **Facet filters**: Host, User, Event ID, Channel can be filtered via sidebar chips (separate from the query). Do NOT include these in the query string unless the user explicitly targets a field.
- **Date range**: Applied separately via date pickers — do NOT add timestamp range to the query.

## Output instructions
Convert the user's natural language request into a query_string expression (or regexp if appropriate).
Return ONLY a JSON object with exactly these keys:
{"query": "the expression", "explanation": "one-sentence description of what the query finds", "regexp": false}
Set "regexp" to true only when the pattern requires ES regexp semantics (special chars, character classes, quantifiers).
No markdown, no extra text — raw JSON only."""


class SearchAssistRequest(BaseModel):
    query: str          # "find all failed logins from last week"
    case_id: str = ""   # optional: restrict to a specific case


@router.post("/search/ai-assist")
def ai_search_assist(req: SearchAssistRequest) -> Any:
    """
    Translate a natural-language search intent into an Elasticsearch query_string.
    Used by the Search page's AI helper to let analysts search without learning ES syntax.
    """
    r = _redis()
    cfg = _get_config(r)
    if not cfg or not cfg.get("enabled"):
        raise HTTPException(status_code=400, detail="LLM not configured. Go to Settings → AI Analysis.")

    user_msg = f"Search request: {req.query}"
    if req.case_id:
        user_msg += f"\nCase ID: {req.case_id}"
        # Enrich with case artifact types so the AI can tailor suggestions
        try:
            from services.elasticsearch import list_artifact_types
            types = list_artifact_types(req.case_id)
            if types:
                user_msg += f"\nArtifact types in this case: {', '.join(types)}"
        except Exception:
            pass

    try:
        raw = _call_llm_with_system(cfg, _SEARCH_ASSIST_PROMPT, user_msg)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LLM call failed: {exc}")

    try:
        clean = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        result = json.loads(clean)
    except (json.JSONDecodeError, ValueError):
        result = {"query": req.query, "explanation": "Could not parse LLM response. Using your input as-is."}

    result["model_used"] = f"{cfg.get('provider', '?')}/{cfg.get('model', '?')}"
    return result


class GenerateRuleRequest(BaseModel):
    description: str          # "detect failed logon attempts above threshold"
    context: str = ""         # optional: artifact type, log source, example event


@router.post("/alert-rules/generate")
def generate_alert_rule(req: GenerateRuleRequest) -> Any:
    """
    Use the configured LLM to generate an Elasticsearch query_string for an alert rule.

    Returns {query, name, description, artifact_type} ready to prefill the rule form.
    """
    r = _redis()
    cfg = _get_config(r)
    if not cfg or not cfg.get("enabled"):
        raise HTTPException(
            status_code=400,
            detail="LLM not configured. Go to Settings → AI Analysis.",
        )

    _RULE_GEN_PROMPT = (
        "You are an expert Elasticsearch query builder for a digital forensics SIEM.\n"
        "Generate an Elasticsearch query_string (not Sigma YAML) that detects the described threat.\n"
        "Return ONLY a JSON object with these exact keys:\n"
        '{"name": "Short rule name", "description": "One sentence description", '
        '"artifact_type": "evtx|prefetch|access_log|... (leave empty for all)", '
        '"query": "field:value AND field2:value2 (query_string syntax)", '
        '"threshold": 1}\n'
        "For EVTX rules use evtx.event_id, evtx.channel, evtx.provider_name.\n"
        "For access logs use access_log.status, access_log.method, access_log.uri.\n"
        "No markdown, no explanation — raw JSON only."
    )

    user_msg = f"Write a detection rule for: {req.description}"
    if req.context:
        user_msg += f"\nContext: {req.context}"

    try:
        raw = _call_llm_with_system(cfg, _RULE_GEN_PROMPT, user_msg)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LLM call failed: {exc}")

    try:
        clean = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        result = json.loads(clean)
    except (json.JSONDecodeError, ValueError):
        result = {"query": raw[:500], "name": req.description[:60], "description": "", "artifact_type": "", "threshold": 1}

    result["generated_at"] = datetime.now(timezone.utc).isoformat()
    result["model_used"]   = f"{cfg.get('provider', '?')}/{cfg.get('model', '?')}"
    return result


def _call_llm_with_system(cfg: dict, system_prompt: str, user_msg: str, max_tokens: int = 600) -> str:
    """Generic LLM call with a custom system prompt."""
    provider = cfg.get("provider", "").lower()
    model    = cfg.get("model", "")
    api_key  = cfg.get("api_key", "")
    base_url = cfg.get("base_url", "").rstrip("/")

    import urllib.request as _ur

    if provider == "anthropic":
        body = json.dumps({
            "model": model, "max_tokens": max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_msg}],
        }).encode()
        req_http = _ur.Request(
            "https://api.anthropic.com/v1/messages", data=body,
            headers={"Content-Type": "application/json", "x-api-key": api_key,
                     "anthropic-version": "2023-06-01"}, method="POST",
        )
        with _ur.urlopen(req_http, timeout=60) as resp:
            return json.loads(resp.read())["content"][0]["text"]
    elif provider == "ollama":
        url = base_url or "http://localhost:11434"
        body = json.dumps({
            "model": model, "stream": False,
            "messages": [{"role": "system", "content": system_prompt},
                         {"role": "user", "content": user_msg}],
        }).encode()
        req_http = _ur.Request(f"{url}/api/chat", data=body,
                               headers={"Content-Type": "application/json"}, method="POST")
        with _ur.urlopen(req_http, timeout=90) as resp:
            return json.loads(resp.read())["message"]["content"]
    else:
        url = base_url or "https://api.openai.com/v1"
        body = json.dumps({
            "model": model, "max_tokens": max_tokens, "temperature": 0.2,
            "messages": [{"role": "system", "content": system_prompt},
                         {"role": "user", "content": user_msg}],
        }).encode()
        req_http = _ur.Request(f"{url}/chat/completions", data=body,
                               headers={"Content-Type": "application/json",
                                        "Authorization": f"Bearer {api_key}"}, method="POST")
        with _ur.urlopen(req_http, timeout=60) as resp:
            return json.loads(resp.read())["choices"][0]["message"]["content"]


# ── YARA rule generation ───────────────────────────────────────────────────────

class GenerateYaraRequest(BaseModel):
    description: str   # "detect Cobalt Strike beacon loading into memory"
    context: str = ""  # optional: known strings, hex patterns, file type hints


_YARA_GEN_PROMPT = """\
You are an expert malware analyst and YARA rule author specializing in digital forensics.
Generate a complete, syntactically valid YARA rule that detects the described threat.

Rules for the YARA rule:
- Include a meta section with description, author = "AI", and date
- Include a strings section with relevant ASCII strings, wide strings, or hex byte patterns
- Include a meaningful condition (not just "any of them" unless truly appropriate)
- Use rule names in UpperCamelCase with no spaces

Return ONLY a JSON object with these exact keys, no markdown, no explanation:
{"name": "RuleName", "description": "One sentence description", "tags": ["malware", "apt"], "content": "rule RuleName {\\n    meta:\\n        ...\\n    strings:\\n        ...\\n    condition:\\n        ...\\n}"}
"""


@router.post("/yara-rules/generate")
def generate_yara_rule(req: GenerateYaraRequest) -> Any:
    """Use the configured LLM to generate a complete YARA rule from a description."""
    r = _redis()
    cfg = _get_config(r)
    if not cfg or not cfg.get("enabled"):
        raise HTTPException(
            status_code=400,
            detail="LLM not configured. Go to Settings → AI Analysis.",
        )

    user_msg = f"Write a YARA rule to detect: {req.description}"
    if req.context:
        user_msg += f"\nAdditional context / hints: {req.context}"

    try:
        raw = _call_llm_with_system(cfg, _YARA_GEN_PROMPT, user_msg, max_tokens=1500)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LLM call failed: {exc}")

    try:
        clean = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        result = json.loads(clean)
    except (json.JSONDecodeError, ValueError):
        # Fallback: the raw text is likely the YARA rule itself
        result = {
            "name":        req.description[:60].replace(" ", "_"),
            "description": req.description,
            "tags":        [],
            "content":     raw,
        }

    result["generated_at"] = datetime.now(timezone.utc).isoformat()
    result["model_used"]   = f"{cfg.get('provider', '?')}/{cfg.get('model', '?')}"
    return result
