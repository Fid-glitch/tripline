
import copy
import hashlib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from agent import tools
from agent.data_protection import redact_text
from agent.audit import write_event, read_events


ROOT = Path(__file__).resolve().parent.parent
AUDIT_LOG = ROOT / "data" / "audit.jsonl"

ALLOWED_COMMANDS = {
    ("python", "--version"),
    ("python3", "--version"),
    ("git", "--version"),
}

SENSITIVE_FILES = {
    ".env",
    ".env.local",
    "credentials.json",
    "secrets.json",
    "id_rsa",
    "id_ed25519",
}

ALLOWED_TOOLS = {"read_file", "run_shell", "http_request"}

# Only explicitly declared free-text DATA arguments may be redacted.
# Paths, URLs, methods, and commands must never be redacted and executed.
REDACTABLE_FIELDS = {}

# Demo-only approval expiry.
APPROVAL_TTL_SECONDS = 900

_ORDER = ("ALLOW", "REDACT", "ASK", "BLOCK")
_LEGACY_LABEL = {
    "ALLOW": "ALLOW",
    "REDACT": "REDACT",
    "ASK": "REVIEW",
    "BLOCK": "BLOCK",
}
_MAX_AUDIT_TEXT = 300

# Demo-only in-memory approvals.
_PENDING_APPROVALS = {}


def evaluate_policy(tool_name, args):
    """Evaluate a request without executing its tool."""
    if tool_name not in ALLOWED_TOOLS:
        return "BLOCK", "Unknown tool"

    if not isinstance(args, dict):
        return "BLOCK", "Arguments must be a dictionary"

    if tool_name == "read_file":
        if set(args) != {"path"} or not isinstance(args["path"], str):
            return "BLOCK", "Invalid file arguments"

        try:
            path = tools._safe_path(args["path"])
        except (ValueError, TypeError, OSError):
            return "BLOCK", "Path is outside the sandbox or invalid"

        if path.name.lower() in SENSITIVE_FILES:
            return "BLOCK", "Sensitive file access denied"

        return "ALLOW", "File path is inside the sandbox"

    if tool_name == "run_shell":
        if set(args) != {"command"}:
            return "BLOCK", "Invalid command arguments"

        command = args["command"]
        if not isinstance(command, (list, tuple)):
            return "BLOCK", "Command must be a list of arguments"

        if tuple(command) not in ALLOWED_COMMANDS:
            return "BLOCK", "Command is not allowlisted"

        return "ALLOW", "Command is allowlisted"

    if tool_name == "http_request":
        if set(args) != {"method", "url"}:
            return "BLOCK", "Invalid HTTP arguments"

        method = args["method"]
        url = args["url"]

        if not isinstance(method, str) or not isinstance(url, str):
            return "BLOCK", "HTTP method and URL must be strings"

        method = method.upper()
        if method not in {"GET", "POST", "PUT", "DELETE"}:
            return "BLOCK", "HTTP method is not allowed"

        parsed = urlparse(url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return "BLOCK", "Invalid or unsafe HTTP URL"

        if method != "GET":
            return "REVIEW", "Non-GET request requires approval"

        return "ALLOW", "Simulated GET request is allowed"

    return "BLOCK", "No policy matched"


def _safe_text(text):
    """Redact sensitive patterns from text and cap its length for logging."""
    return redact_text(text)[0][:_MAX_AUDIT_TEXT]


def _sanitize_for_audit(value, depth=0):
    """Copy a value for logging with sensitive text redacted."""
    if depth > 4:
        return "<truncated>"
    if isinstance(value, str):
        return _safe_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, dict):
        return {
            _safe_text(str(key)): _sanitize_for_audit(item, depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize_for_audit(item, depth + 1) for item in value]
    return f"<{type(value).__name__}>"


def _write_audit(tool_name, args, decision, reason, executed, outcome, **extra):
    """Append one structured audit event through the shared writer."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": _sanitize_for_audit(tool_name),
        "arguments": _sanitize_for_audit(args),
        "decision": decision,
        "reason": _sanitize_for_audit(reason),
        "executed": executed,
        "outcome": outcome,
    }
    event.update(_sanitize_for_audit(extra))
    # Keep AUDIT_LOG patchable for existing tests and callers.
    write_event(event, log_type="security", path=AUDIT_LOG)


def _try_audit(*args, **kwargs):
    """Write an audit event; report failure instead of raising."""
    try:
        _write_audit(*args, **kwargs)
        return True
    except Exception:
        return False


# --- Approvals (demo-grade) -------------------------------------------------

def _now():
    return datetime.now(timezone.utc)


def _expired(record):
    age = (_now() - record["created_at"]).total_seconds()
    return age > APPROVAL_TTL_SECONDS


def _fingerprint(tool_name, args):
    try:
        payload = json.dumps([tool_name, args], sort_keys=True, default=str)
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _get_or_create_pending(tool_name, args, reason):
    fingerprint = _fingerprint(tool_name, args)
    if fingerprint is None:
        return None

    expired_ids = [
        key for key, value in _PENDING_APPROVALS.items() if _expired(value)
    ]
    for approval_id in expired_ids:
        del _PENDING_APPROVALS[approval_id]

    for approval_id, record in _PENDING_APPROVALS.items():
        if (
            record["fingerprint"] == fingerprint
            and record["status"] == "pending"
        ):
            return approval_id

    approval_id = "apr-" + secrets.token_hex(8)
    _PENDING_APPROVALS[approval_id] = {
        "fingerprint": fingerprint,
        "tool": _sanitize_for_audit(tool_name),
        "arguments": _sanitize_for_audit(args),
        "reason": _sanitize_for_audit(reason),
        "status": "pending",
        "created_at": _now(),
        "approver": None,
    }
    return approval_id


def _approval_is_valid(approval_id, tool_name, args):
    if not isinstance(approval_id, str):
        return False

    record = _PENDING_APPROVALS.get(approval_id)
    if (
        record is None
        or record["status"] != "approved"
        or _expired(record)
    ):
        return False

    fingerprint = _fingerprint(tool_name, args)
    return fingerprint is not None and fingerprint == record["fingerprint"]


def list_pending_approvals():
    """Return pending requests with already-sanitized arguments."""
    return [
        {
            "approval_id": approval_id,
            "tool": record["tool"],
            "arguments": record["arguments"],
            "reason": record["reason"],
            "created_at": record["created_at"].isoformat(),
        }
        for approval_id, record in _PENDING_APPROVALS.items()
        if record["status"] == "pending" and not _expired(record)
    ]


def approve_pending(approval_id, approver):
    """Approve a pending request in this process (demo only).

    This does not authenticate the approver. Approval is single-use, expires,
    and applies only to the exact arguments that were reviewed.
    """
    if not isinstance(approval_id, str):
        return False
    if not isinstance(approver, str) or not approver.strip():
        return False

    record = _PENDING_APPROVALS.get(approval_id)
    if (
        record is None
        or record["status"] != "pending"
        or _expired(record)
    ):
        return False

    record["status"] = "approved"
    record["approver"] = _safe_text(approver.strip())
    _try_audit(
        record["tool"],
        record["arguments"],
        "REVIEW",
        "Approval granted",
        False,
        "approved",
        stage="approval",
        approval_id=approval_id,
        approver=record["approver"],
    )
    return True


# --- Decision and execution -------------------------------------------------

def _blocked(reason, rule_id):
    return {
        "decision": "BLOCK",
        "reason": reason,
        "rules": [rule_id],
        "score": 100,
        "can_execute": False,
        "exec_args": None,
        "redacted": False,
        "redaction_count": 0,
    }


def _decide(tool_name, args):
    """Decide without executing. Unexpected errors fail closed."""
    try:
        from agent import policy_engine as pe

        field = (
            REDACTABLE_FIELDS.get(tool_name)
            if isinstance(tool_name, str)
            else None
        )
        has_field = (
            bool(field) and isinstance(args, dict) and field in args
        )
        core_args = (
            {key: value for key, value in args.items() if key != field}
            if has_field
            else args
        )

        legacy_label, legacy_reason = evaluate_policy(tool_name, core_args)
        legacy = pe.normalize_decision(legacy_label)

        request = {"tool_name": tool_name, "args": core_args}
        if has_field:
            request["content"] = args[field]

        result = pe.evaluate_request(request)
        if (
            not isinstance(result, pe.PolicyResult)
            or result.decision not in _ORDER
        ):
            raise TypeError("Unexpected policy engine result")

        decision = result.decision
        reason = result.reason
        rules = list(result.applied_rules)

        if _ORDER.index(legacy) > _ORDER.index(decision):
            decision = legacy
            reason = f"Gateway policy: {legacy_reason}"
            rules.append(f"LEGACY-POLICY-{legacy}")

        outcome = {
            "decision": decision,
            "reason": reason,
            "rules": rules,
            "score": result.risk_score,
            "can_execute": False,
            "exec_args": None,
            "redacted": False,
            "redaction_count": 0,
        }

        if decision == "ALLOW":
            outcome["can_execute"] = True
            outcome["exec_args"] = args

        elif decision == "REDACT":
            sanitized = result.sanitized_content
            if has_field and isinstance(sanitized, str):
                recheck = pe.evaluate_request({
                    "tool_name": tool_name,
                    "args": core_args,
                    "content": sanitized,
                })
                if (
                    isinstance(recheck, pe.PolicyResult)
                    and recheck.decision == "ALLOW"
                ):
                    outcome["can_execute"] = True
                    outcome["exec_args"] = {**args, field: sanitized}
                    outcome["redacted"] = True
                    outcome["redaction_count"] = len(result.redactions)
                else:
                    outcome["decision"] = "BLOCK"
                    outcome["reason"] = (
                        "Redacted content still failed the policy re-check"
                    )
                    outcome["rules"].append(
                        "GATEWAY-REDACTION-RECHECK-001"
                    )
            else:
                outcome["reason"] = (
                    reason
                    + " (no redactable argument is declared for this tool, "
                    "so nothing was executed)"
                )

        return outcome

    except Exception:
        return _blocked(
            "Policy evaluation failed unexpectedly; request denied (fail closed)",
            "GATEWAY-ERROR-001",
        )


def _build(
    d,
    reason,
    executed,
    audit_ok,
    pending_id=None,
    approval_id=None,
    approved=False,
    **more,
):
    out = {
        "decision": _LEGACY_LABEL[d["decision"]],
        "policy_decision": d["decision"],
        "reason": reason,
        "risk_score": d["score"],
        "rule_ids": list(d["rules"]),
        "executed": executed,
        "result": None,
        "redacted": d["redacted"],
        "approved": approved,
        "pending_approval": pending_id is not None,
        "approval_id": pending_id or approval_id,
        "audit_ok": audit_ok,
    }
    out.update(more)
    return out


def execute_tool(tool_name, args, approval_id=None):
    """Evaluate policy, audit intent, and execute only permitted operations.

    ALLOW runs. REDACT runs only after a successful policy re-check. ASK
    requires a valid approval. BLOCK never runs. The legacy decision label
    uses REVIEW for ASK.
    """
    try:
        snapshot = copy.deepcopy(args)
    except Exception:
        snapshot = None
        decision = _blocked(
            "Arguments could not be copied safely", "GATEWAY-ARGS-001"
        )
    else:
        decision = _decide(tool_name, snapshot)

    approved = False
    pending_id = None
    if decision["decision"] == "ASK":
        if _approval_is_valid(approval_id, tool_name, snapshot):
            approved = True
        else:
            pending_id = _get_or_create_pending(
                tool_name, snapshot, decision["reason"]
            )

    label = _LEGACY_LABEL[decision["decision"]]
    extra = {
        "policy_decision": decision["decision"],
        "risk_score": decision["score"],
        "rule_ids": decision["rules"],
        "redacted": decision["redacted"],
        "redaction_count": decision["redaction_count"],
        "approval_id": pending_id or (approval_id if approved else None),
    }

    if not (decision["can_execute"] or approved):
        outcome = "pending_approval" if pending_id else "not_executed"
        audit_ok = _try_audit(
            tool_name,
            snapshot,
            label,
            decision["reason"],
            False,
            outcome,
            stage="decision",
            **extra,
        )
        return _build(
            decision,
            decision["reason"],
            False,
            audit_ok,
            pending_id=pending_id,
        )

    # Fail closed: if intent cannot be recorded, do not execute.
    if not _try_audit(
        tool_name,
        snapshot,
        label,
        decision["reason"],
        False,
        "authorized",
        stage="pre_execution",
        **extra,
    ):
        denied = _blocked(
            "Audit log unavailable; execution refused (fail closed)",
            "AUDIT-UNAVAILABLE-001",
        )
        return _build(denied, denied["reason"], False, False)

    exec_args = snapshot if approved else decision["exec_args"]
    if approved:
        _PENDING_APPROVALS[approval_id]["status"] = "used"

    try:
        if tool_name == "read_file":
            result = tools.read_file(**exec_args)
        elif tool_name == "run_shell":
            result = tools.run_shell(**exec_args)
        else:
            result = tools.http_request(**exec_args)
    except Exception as error:
        audit_ok = _try_audit(
            tool_name,
            snapshot,
            label,
            decision["reason"],
            True,
            "error",
            stage="outcome",
            **extra,
        )
        return _build(
            decision,
            decision["reason"],
            True,
            audit_ok,
            approval_id=approval_id,
            approved=approved,
            error=_safe_text(str(error)),
        )

    audit_ok = _try_audit(
        tool_name,
        snapshot,
        label,
        decision["reason"],
        True,
        "success",
        stage="outcome",
        **extra,
    )
    return _build(
        decision,
        decision["reason"],
        True,
        audit_ok,
        approval_id=approval_id,
        approved=approved,
        result=result,
    )


def read_audit_log():
    """Return security audit events newest-first, skipping malformed lines."""
    if AUDIT_LOG == (ROOT / "data" / "audit.jsonl"):
        return read_events("security")

    if not AUDIT_LOG.exists():
        return []

    events = []
    with AUDIT_LOG.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                events.append(event)
    return list(reversed(events))
