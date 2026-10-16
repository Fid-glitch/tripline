
"""Reusable, sanitized audit logging for Tripline."""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUDIT_FILE = ROOT / "data" / "audit.jsonl"

SENSITIVE_KEYS = {
    "prompt",
    "raw_prompt",
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "authorization",
    "private_key",
    "client_secret",
    "credential",
}

SENSITIVE_KEY_PARTS = (
    "password",
    "secret",
    "token",
    "api_key",
    "private_key",
    "credential",
)

BEARER_PATTERN = re.compile(
    r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"
)

ASSIGNMENT_PATTERN = re.compile(
    r"""(?i)\b(api[_-]?key|access[_-]?token|client[_-]?secret|
    password|passwd|authorization)\s*[:=]\s*"""
    r"""(?:"[^"]*"|'[^']*'|[^\s,;]+)""",
    re.VERBOSE,
)

PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?"
    r"-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_").replace(" ", "_")

    return (
        normalized in SENSITIVE_KEYS
        or any(part in normalized for part in SENSITIVE_KEY_PARTS)
    )


def sanitize(value: Any, key: str = "") -> Any:
    """Sanitize values before they are written to audit storage."""

    if key and _is_sensitive_key(key):
        return "[REDACTED]"

    if isinstance(value, dict):
        return {
            str(item_key): sanitize(item_value, str(item_key))
            for item_key, item_value in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [sanitize(item) for item in value]

    if isinstance(value, str):
        value = PRIVATE_KEY_PATTERN.sub(
            "[REDACTED_PRIVATE_KEY]", value
        )
        value = BEARER_PATTERN.sub("Bearer [REDACTED]", value)
        value = ASSIGNMENT_PATTERN.sub(
            lambda match: match.group(0).split(":")[0].split("=")[0]
            + "=[REDACTED]",
            value,
        )
        value = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", value)
        return value

    if value is None or isinstance(value, (bool, int, float)):
        return value

    return "[UNSUPPORTED_VALUE]"


def create_event(
    *,
    action: str,
    decision: str,
    reason: str,
    tool: str | None = None,
    request_id: str | None = None,
    organization_id: str | None = None,
    team_id: str | None = None,
    user_id: str | None = None,
    application_id: str | None = None,
    risk_score: float | None = None,
    risk_level: str | None = None,
    risk_signals: list[str] | dict[str, Any] | None = None,
    policy_id: str | None = None,
    rule_id: str | None = None,
    attempted: bool = True,
    executed: bool = False,
    approval_status: str = "NOT_REQUIRED",
    simulation_status: str = "REAL",
    outcome: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a sanitized structured event."""

    if not action or not isinstance(action, str):
        raise ValueError("action must be a non-empty string")

    if not decision or not isinstance(decision, str):
        raise ValueError("decision must be a non-empty string")

    if not isinstance(reason, str):
        raise ValueError("reason must be a string")

    if risk_score is not None:
        if isinstance(risk_score, bool) or not isinstance(
            risk_score, (int, float)
        ):
            raise ValueError("risk_score must be numeric or None")

        if not 0 <= risk_score <= 1:
            raise ValueError("risk_score must be between 0 and 1")

    if not isinstance(attempted, bool) or not isinstance(executed, bool):
        raise ValueError("attempted and executed must be booleans")

    if executed and not attempted:
        raise ValueError("An executed action must have been attempted")

    if approval_status.upper() == "PENDING" and executed:
        raise ValueError(
            "A pending approval must never be treated as permission to execute"
        )

    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "organization_id": organization_id,
        "team_id": team_id,
        "user_id": user_id,
        "application_id": application_id,
        "action": action,
        "tool": tool or action,
        "decision": decision.upper(),
        "reason": reason,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_signals": risk_signals or [],
        "policy_id": policy_id,
        "rule_id": rule_id,
        "attempted": attempted,
        "executed": executed,
        "approval_status": approval_status.upper(),
        "simulation_status": simulation_status.upper(),
        "outcome": outcome,
        "details": details or {},
    }

    return sanitize(event)


def write_event(
    event: dict[str, Any],
    audit_file: str | Path = DEFAULT_AUDIT_FILE,
) -> dict[str, Any]:
    """Append a sanitized event to a JSONL audit file."""

    if not isinstance(event, dict):
        raise ValueError("event must be a dictionary")

    safe_event = sanitize(event)
    destination = Path(audit_file)
    destination.parent.mkdir(parents=True, exist_ok=True)

    with destination.open("a", encoding="utf-8") as file:
        file.write(
            json.dumps(safe_event, ensure_ascii=False) + "\n"
        )

    return safe_event


def read_events(
    audit_file: str | Path = DEFAULT_AUDIT_FILE,
) -> list[dict[str, Any]]:
    """Read valid JSON object events, newest first."""

    destination = Path(audit_file)

    if not destination.exists():
        return []

    events = []

    with destination.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if isinstance(event, dict):
                events.append(sanitize(event))

    return list(reversed(events))


def calculate_audit_metrics(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate aggregate metrics from actual stored audit events."""

    total = len(events)
    if total == 0:
        return {
            "total_events": 0,
            "blocked": 0,
            "allowed": 0,
            "review": 0,
            "simulated": 0,
            "real": 0,
            "pending_approvals": 0,
            "block_rate_pct": 0.0,
            "unique_organizations": 0,
            "unique_users": 0,
        }

    blocked = sum(1 for e in events if str(e.get("decision", "")).upper() == "BLOCK")
    allowed = sum(1 for e in events if str(e.get("decision", "")).upper() == "ALLOW")
    review = sum(1 for e in events if str(e.get("decision", "")).upper() == "REVIEW")

    simulated = sum(
        1 for e in events
        if str(e.get("simulation_status", "")).upper() == "SIMULATED"
        or (isinstance(e.get("result"), dict) and e.get("result", {}).get("status") == "simulated")
    )
    real = total - simulated

    pending_approvals = sum(
        1 for e in events
        if str(e.get("approval_status", "")).upper() == "PENDING"
        or (str(e.get("decision", "")).upper() == "REVIEW" and not e.get("executed"))
    )

    unique_orgs = len({e.get("organization_id") for e in events if e.get("organization_id")})
    unique_users = len({e.get("user_id") for e in events if e.get("user_id")})

    return {
        "total_events": total,
        "blocked": blocked,
        "allowed": allowed,
        "review": review,
        "simulated": simulated,
        "real": real,
        "pending_approvals": pending_approvals,
        "block_rate_pct": round((blocked / total) * 100, 1) if total > 0 else 0.0,
        "unique_organizations": unique_orgs,
        "unique_users": unique_users,
    }


