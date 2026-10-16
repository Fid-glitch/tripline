"""Reusable, sanitized audit logging and governance metrics for Tripline."""

from __future__ import annotations

import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUDIT_LOG = Path(os.environ.get("TRIPLINE_AUDIT_LOG", ROOT / "logs" / "audit.jsonl"))

# Attempt read-only import of optional teammate sanitizer hook
try:
    from agent.data_protection import sanitize as _data_protection_sanitizer  # type: ignore
except ImportError:
    _data_protection_sanitizer = None


class AuditWriteError(Exception):
    """Raised when an audit event fails to write to disk, ensuring fail-closed callers."""
    pass


class AuditInvariantViolation(ValueError):
    """Raised when an audit event violates security invariants (e.g., executing a blocked action)."""
    pass


# Sensitive keys to redact/drop
SENSITIVE_KEY_NAMES = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "authorization",
    "private_key",
    "cookie",
    "prompt",
    "raw_prompt",
    "content",
    "body",
    "messages",
    "credentials",
    "client_secret",
}

SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "auth",
    "cookie",
    "private_key",
    "credential",
)

# Regex patterns for sensitive text redaction
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
API_KEY_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9_-]{10,}\b"),
]
ASSIGNMENT_PATTERN = re.compile(
    r"""(?i)\b(api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|authorization|secret)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)"""
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

ALLOWED_DECISIONS = {"ALLOW", "REDACT", "ASK", "BLOCK"}
ALLOWED_APPROVAL_STATUSES = {None, "not_required", "pending", "approved", "denied", "expired"}


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_").replace(" ", "_")
    return (
        normalized in SENSITIVE_KEY_NAMES
        or any(part in normalized for part in SENSITIVE_KEY_SUBSTRINGS)
    )


def sanitize(value: Any, key: str = "", *, custom_hook: Callable[[Any, str], Any] | None = None) -> Any:
    """Sanitize strings, dictionaries, lists, and metadata before logging."""
    if custom_hook is not None:
        try:
            return custom_hook(value, key)
        except Exception:
            pass

    if _data_protection_sanitizer is not None:
        try:
            return _data_protection_sanitizer(value, key)
        except Exception:
            pass

    if key and _is_sensitive_key(key):
        return "[REDACTED]"

    if isinstance(value, dict):
        sanitized_dict = {}
        for k, v in value.items():
            str_k = str(k)
            if _is_sensitive_key(str_k):
                sanitized_dict[str_k] = "[REDACTED]"
            else:
                sanitized_dict[str_k] = sanitize(v, str_k, custom_hook=custom_hook)
        return sanitized_dict

    if isinstance(value, (list, tuple)):
        # Cap list sizes to 50 items to prevent log bloat
        items = list(value[:50])
        return [sanitize(item, key, custom_hook=custom_hook) for item in items]

    if isinstance(value, str):
        # Truncate strings longer than 2000 characters
        if len(value) > 2000:
            value = value[:2000] + "...[TRUNCATED]"

        value = PRIVATE_KEY_PATTERN.sub("[REDACTED_PRIVATE_KEY]", value)
        value = BEARER_PATTERN.sub("Bearer [REDACTED]", value)
        for pattern in API_KEY_PATTERNS:
            value = pattern.sub("[REDACTED_API_KEY]", value)
        value = ASSIGNMENT_PATTERN.sub(
            lambda match: match.group(0).split(":")[0].split("=")[0] + "=[REDACTED]",
            value,
        )
        value = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", value)
        return value

    if value is None or isinstance(value, (bool, int, float)):
        return value

    return "[UNSUPPORTED_VALUE]"


class AuditLog:
    """
    Append-only, thread-safe, fsync-enforced JSONL audit logger.
    """

    def __init__(
        self,
        log_path: str | Path | None = None,
        *,
        sanitizer_hook: Callable[[Any, str], Any] | None = None,
    ) -> None:
        if log_path is not None:
            self.log_path = Path(log_path)
        else:
            env_path = os.environ.get("TRIPLINE_AUDIT_LOG")
            self.log_path = Path(env_path) if env_path else DEFAULT_AUDIT_LOG

        self.sanitizer_hook = sanitizer_hook
        self._lock = threading.Lock()

    def record(
        self,
        action_type: str,
        decision: str,
        reason: str,
        *,
        tool_name: str | None = None,
        user_id: str | None = None,
        team_id: str | None = None,
        org_id: str | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        signals: list[Any] | dict[str, Any] | None = None,
        risk_score: float | None = None,
        policy_id: str | None = None,
        attempted: bool = True,
        executed: bool = False,
        approval_status: str | None = None,
        simulation_mode: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record an audit event, strictly validating invariants and sanitizing all fields."""
        if not action_type or not isinstance(action_type, str):
            raise ValueError("action_type must be a non-empty string")

        if not decision or not isinstance(decision, str):
            raise ValueError("decision must be a non-empty string")

        decision_upper = decision.upper()
        # Backward compatibility for REVIEW -> ASK
        if decision_upper == "REVIEW":
            decision_upper = "ASK"

        if decision_upper not in ALLOWED_DECISIONS:
            raise ValueError(f"Invalid decision '{decision}'. Must be one of {ALLOWED_DECISIONS}")

        norm_approval = approval_status.lower() if approval_status is not None else None
        if norm_approval == "not_required":
            norm_approval = "not_required"
        elif norm_approval not in ALLOWED_APPROVAL_STATUSES:
            raise ValueError(f"Invalid approval_status '{approval_status}'. Must be one of {ALLOWED_APPROVAL_STATUSES}")

        if risk_score is not None:
            if isinstance(risk_score, bool) or not isinstance(risk_score, (int, float)):
                raise ValueError("risk_score must be numeric or None")
            if not 0.0 <= float(risk_score) <= 1.0:
                raise ValueError("risk_score must be between 0.0 and 1.0")

        if not isinstance(attempted, bool) or not isinstance(executed, bool):
            raise ValueError("attempted and executed must be booleans")

        if executed and not attempted:
            raise AuditInvariantViolation("An executed action must have been attempted.")

        # Invariant: reject any event where executed=true and (decision=BLOCK, or decision=ASK without approval_status=approved)
        if executed:
            if decision_upper == "BLOCK":
                raise AuditInvariantViolation("Invariant violation: An action with decision BLOCK must never be recorded as executed.")
            if decision_upper == "ASK" and norm_approval != "approved":
                raise AuditInvariantViolation(
                    f"Invariant violation: decision ASK requires approval_status='approved' to execute (was '{norm_approval}'). A pending approval is never permission to execute."
                )

        raw_event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "organization_id": org_id,
            "team_id": team_id,
            "user_id": user_id,
            "session_id": session_id,
            "request_id": request_id,
            "action_type": action_type,
            "tool_name": tool_name or action_type,
            "decision": decision_upper,
            "reason": str(reason),
            "risk_score": float(risk_score) if risk_score is not None else None,
            "policy_id": policy_id,
            "signals": signals if signals is not None else [],
            "attempted": attempted,
            "executed": executed,
            "approval_status": norm_approval if norm_approval is not None else "not_required",
            "simulation_mode": bool(simulation_mode),
            "metadata": metadata if metadata is not None else {},
            # Backward compatibility fields
            "action": action_type,
            "tool": tool_name or action_type,
            "simulation_status": "SIMULATED" if simulation_mode else "REAL",
        }

        safe_event = sanitize(raw_event, custom_hook=self.sanitizer_hook)

        with self._lock:
            try:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(safe_event, ensure_ascii=False) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
            except Exception as e:
                raise AuditWriteError(f"Failed to append to audit log at {self.log_path}: {e}") from e

        return safe_event

    def read_events(self) -> list[dict[str, Any]]:
        """Read all events from log file, skipping corrupt/invalid lines."""
        if not self.log_path.exists():
            return []

        events: list[dict[str, Any]] = []
        with self._lock:
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line_str = line.strip()
                        if not line_str:
                            continue
                        try:
                            item = json.loads(line_str)
                            if isinstance(item, dict):
                                events.append(item)
                        except json.JSONDecodeError:
                            continue
            except OSError:
                return []

        return events


def compute_metrics(events: list[dict[str, Any]], mode: str = "all") -> dict[str, Any]:
    """
    Compute governance metrics strictly from actual stored events.
    mode: 'all', 'real', or 'simulated'
    """
    if mode not in {"all", "real", "simulated"}:
        mode = "all"

    all_total = len(events)
    if all_total == 0:
        return {
            "total_events": 0,
            "real_events": 0,
            "simulated_events": 0,
            "by_decision": {"ALLOW": 0, "BLOCK": 0, "ASK": 0, "REDACT": 0},
            "blocked_attempts": 0,
            "blocks_enforced": 0,
            "executed": 0,
            "pending_approvals": 0,
            "approved": 0,
            "denied": 0,
            "integrity_violations": 0,
            "by_tool": {},
            "top_policies": {},
            # Backward-compatibility metrics
            "blocked": 0,
            "allowed": 0,
            "review": 0,
            "simulated": 0,
            "real": 0,
            "block_rate_pct": 0.0,
            "unique_organizations": 0,
            "unique_users": 0,
        }

    real_events_count = 0
    simulated_events_count = 0
    integrity_violations = 0

    for e in events:
        is_sim = bool(e.get("simulation_mode")) or str(e.get("simulation_status", "")).upper() == "SIMULATED" or (
            isinstance(e.get("result"), dict) and e.get("result", {}).get("status") == "simulated"
        )
        if is_sim:
            simulated_events_count += 1
        else:
            real_events_count += 1

        # Check invariant violations in log
        executed = bool(e.get("executed"))
        decision = str(e.get("decision", "")).upper()
        if decision == "REVIEW":
            decision = "ASK"
        approval = str(e.get("approval_status", "")).lower()

        if executed and (decision == "BLOCK" or (decision == "ASK" and approval != "approved")):
            integrity_violations += 1

    # Filter by mode
    filtered: list[dict[str, Any]] = []
    for e in events:
        is_sim = bool(e.get("simulation_mode")) or str(e.get("simulation_status", "")).upper() == "SIMULATED" or (
            isinstance(e.get("result"), dict) and e.get("result", {}).get("status") == "simulated"
        )
        if mode == "real" and is_sim:
            continue
        if mode == "simulated" and not is_sim:
            continue
        filtered.append(e)

    total_events = len(filtered)
    by_decision = {"ALLOW": 0, "BLOCK": 0, "ASK": 0, "REDACT": 0}
    by_tool: dict[str, int] = {}
    top_policies: dict[str, int] = {}
    blocked_attempts = 0
    blocks_enforced = 0
    executed_count = 0

    # Track approvals per request_id (or latest status)
    request_approvals: dict[str, str] = {}
    standalone_approvals: list[str] = []

    unique_orgs = set()
    unique_users = set()

    for e in filtered:
        dec = str(e.get("decision", "")).upper()
        if dec == "REVIEW":
            dec = "ASK"
        if dec in by_decision:
            by_decision[dec] += 1
        else:
            by_decision[dec] = 1

        tool = e.get("tool_name") or e.get("tool") or e.get("action_type") or e.get("action")
        if tool:
            by_tool[str(tool)] = by_tool.get(str(tool), 0) + 1

        pol = e.get("policy_id") or e.get("rule_id")
        if pol:
            top_policies[str(pol)] = top_policies.get(str(pol), 0) + 1

        is_exec = bool(e.get("executed"))
        if is_exec:
            executed_count += 1

        if dec == "BLOCK":
            blocked_attempts += 1
            if not is_exec:
                blocks_enforced += 1

        req_id = e.get("request_id")
        app_status = str(e.get("approval_status", "")).lower()
        if app_status in {"pending", "approved", "denied"}:
            if req_id:
                request_approvals[req_id] = app_status
            else:
                standalone_approvals.append(app_status)

        if e.get("organization_id"):
            unique_orgs.add(e.get("organization_id"))
        if e.get("user_id"):
            unique_users.add(e.get("user_id"))

    pending_approvals = sum(1 for s in request_approvals.values() if s == "pending") + sum(
        1 for s in standalone_approvals if s == "pending"
    )
    approved = sum(1 for s in request_approvals.values() if s == "approved") + sum(
        1 for s in standalone_approvals if s == "approved"
    )
    denied = sum(1 for s in request_approvals.values() if s == "denied") + sum(
        1 for s in standalone_approvals if s == "denied"
    )

    block_rate = round((blocked_attempts / total_events) * 100, 1) if total_events > 0 else 0.0

    return {
        "total_events": total_events,
        "real_events": real_events_count,
        "simulated_events": simulated_events_count,
        "by_decision": by_decision,
        "blocked_attempts": blocked_attempts,
        "blocks_enforced": blocks_enforced,
        "executed": executed_count,
        "pending_approvals": pending_approvals,
        "approved": approved,
        "denied": denied,
        "integrity_violations": integrity_violations,
        "by_tool": by_tool,
        "top_policies": top_policies,
        # Backward-compatibility keys
        "blocked": blocked_attempts,
        "allowed": by_decision.get("ALLOW", 0),
        "review": by_decision.get("ASK", 0),
        "simulated": simulated_events_count,
        "real": real_events_count,
        "block_rate_pct": block_rate,
        "unique_organizations": len(unique_orgs),
        "unique_users": len(unique_users),
    }


# Global default logger instance
_default_logger = AuditLog()


# Module-level aliases for backwards compatibility
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
    norm_status = approval_status.lower() if approval_status else None
    if norm_status == "not_required":
        norm_status = "not_required"

    is_sim = simulation_status.upper() == "SIMULATED"

    # Strict invariant validation
    if norm_status == "pending" and executed:
        raise ValueError("A pending approval must never be treated as permission to execute")

    if executed and decision.upper() == "BLOCK":
        raise ValueError("Invariant violation: executed=True with decision=BLOCK")

    meta = details.copy() if isinstance(details, dict) else {}
    if application_id:
        meta["application_id"] = application_id
    if risk_level:
        meta["risk_level"] = risk_level
    if outcome:
        meta["outcome"] = outcome

    raw_event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "organization_id": organization_id,
        "team_id": team_id,
        "user_id": user_id,
        "action_type": action,
        "action": action,
        "tool_name": tool or action,
        "tool": tool or action,
        "decision": decision.upper(),
        "reason": reason,
        "risk_score": float(risk_score) if risk_score is not None else None,
        "policy_id": policy_id or rule_id,
        "rule_id": rule_id or policy_id,
        "signals": risk_signals if risk_signals is not None else [],
        "risk_signals": risk_signals if risk_signals is not None else [],
        "attempted": attempted,
        "executed": executed,
        "approval_status": approval_status.upper(),
        "simulation_mode": is_sim,
        "simulation_status": simulation_status.upper(),
        "details": sanitize(meta),
        "metadata": sanitize(meta),
    }
    return sanitize(raw_event)


def write_event(
    event: dict[str, Any],
    audit_file: str | Path | None = None,
) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("event must be a dictionary")

    logger = AuditLog(audit_file) if audit_file else _default_logger
    safe_event = sanitize(event)

    with logger._lock:
        try:
            logger.log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(logger.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(safe_event, ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            raise AuditWriteError(f"Failed to append event: {e}") from e

    return safe_event


def read_events(audit_file: str | Path | None = None) -> list[dict[str, Any]]:
    logger = AuditLog(audit_file) if audit_file else _default_logger
    events = logger.read_events()
    return list(reversed(events))


def calculate_audit_metrics(events: list[dict[str, Any]]) -> dict[str, Any]:
    return compute_metrics(events, mode="all")
