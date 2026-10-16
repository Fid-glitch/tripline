
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from agent import tools


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


def _write_audit(tool_name, args, decision, reason, executed, outcome):
    """Append one structured audit event."""

    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool_name,
        "arguments": args,
        "decision": decision,
        "reason": reason,
        "executed": executed,
        "outcome": outcome,
    }

    with AUDIT_LOG.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event, default=str) + "\n")


def execute_tool(tool_name, args):
    """Evaluate policy first; execute only requests marked ALLOW."""

    decision, reason = evaluate_policy(tool_name, args)

    if decision != "ALLOW":
        _write_audit(
            tool_name, args, decision, reason, False, "not_executed"
        )
        return {
            "decision": decision,
            "reason": reason,
            "executed": False,
            "result": None,
        }

    try:
        if tool_name == "read_file":
            result = tools.read_file(**args)
        elif tool_name == "run_shell":
            result = tools.run_shell(**args)
        else:
            result = tools.http_request(**args)

        _write_audit(
            tool_name, args, decision, reason, True, "success"
        )
        return {
            "decision": decision,
            "reason": reason,
            "executed": True,
            "result": result,
        }

    except Exception as error:
        _write_audit(
            tool_name, args, decision, reason, True, "error"
        )
        return {
            "decision": decision,
            "reason": reason,
            "executed": True,
            "error": str(error),
        }


def read_audit_log():
    """Return audit events, newest first."""

    if not AUDIT_LOG.exists():
        return []

    events = []

    with AUDIT_LOG.open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                events.append(json.loads(line))

    return list(reversed(events))
