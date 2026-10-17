
"""Shared, sanitized JSONL audit helpers for Tripline.

The existing security and domain logs remain separate to preserve their
legacy event schemas. This module provides a common safe writer and reader.
"""
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from agent.data_protection import redact_text

ROOT = Path(__file__).resolve().parent.parent
LOG_PATHS = {
    "security": ROOT / "data" / "audit.jsonl",
    "domain": ROOT / "data" / "domain_audit.jsonl",
}
_MAX_TEXT = 300
_SENSITIVE_KEYS = {
    "prompt", "raw_prompt", "content", "password", "passwd", "token",
    "access_token", "refresh_token", "api_key", "apikey", "secret",
    "authorization", "private_key", "credential", "credentials",
}
_WRITE_LOCK = threading.Lock()


def _safe_text(value):
    text = str(value)
    try:
        text = redact_text(text)[0]
    except Exception:
        return "<redacted>"
    return text[:_MAX_TEXT]


def sanitize(value, key=None, depth=0):
    """Return a JSON-safe copy with secrets and raw prompt/content fields removed."""
    if depth > 6:
        return "<truncated>"
    if key is not None:
        normalized = str(key).strip().lower().replace("-", "_")
        if normalized in _SENSITIVE_KEYS or any(
            part in normalized for part in ("api_key", "password", "secret", "token")
        ):
            return "<redacted>"
        if normalized in {"prompt", "raw_prompt", "content", "input_text"}:
            return "<omitted>"
    if isinstance(value, str):
        return _safe_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, dict):
        return {
            _safe_text(k): sanitize(v, key=str(k), depth=depth + 1)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize(item, depth=depth + 1) for item in value]
    return f"<{type(value).__name__}>"


def write_event(event, log_type="security", path=None):
    """Append a sanitized event to the selected existing JSONL log.

    Raises on invalid log_type or I/O errors so security callers can fail closed.
    """
    if log_type not in LOG_PATHS:
        raise ValueError("log_type must be 'security' or 'domain'")
    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")
    safe_event = sanitize(event)
    safe_event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    path = Path(path) if path is not None else LOG_PATHS[log_type]
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(safe_event, ensure_ascii=True, default=str)
    with _WRITE_LOCK:
        with path.open("a", encoding="utf-8") as file:
            file.write(line + "\n")
    return safe_event


def read_events(log_type="security", limit=None):
    """Read valid events newest-first; skip malformed lines without crashing."""
    if log_type not in LOG_PATHS:
        raise ValueError("log_type must be 'security' or 'domain'")
    if limit is not None and (not isinstance(limit, int) or limit < 0):
        raise ValueError("limit must be a non-negative integer or None")
    path = LOG_PATHS[log_type]
    if not path.exists() or limit == 0:
        return []
    events = []
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(item, dict):
                events.append(item)
    events.reverse()
    return events if limit is None else events[:limit]


def normalize_event(event, log_type="security"):
    """Return a display-friendly common view while retaining the original event."""
    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")
    decision = event.get("policy_decision", event.get("decision", "UNKNOWN"))
    if decision == "ASK":
        decision = "REVIEW"
    return {
        "timestamp": event.get("timestamp"),
        "source": "security" if log_type == "security" else "domain",
        "action": event.get("tool", event.get("action", "unknown")),
        "decision": decision,
        "reason": event.get("reason", ""),
        "executed": bool(event.get("executed", False)),
        "stage": event.get("stage", "domain" if log_type == "domain" else "unknown"),
        "risk": event.get("risk_score", event.get("risk_level")),
        "rule": event.get("rule_id", ", ".join(event.get("rule_ids", []))),
    }
