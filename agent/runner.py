
import json
from datetime import datetime, timezone
from pathlib import Path

from agent.domain_policies import evaluate_domain_policy_trace
from agent.audit import write_event, read_events


ROOT = Path(__file__).resolve().parent.parent
AUDIT_LOG = ROOT / "data" / "domain_audit.jsonl"


def _mock_action(domain, action):
    """Simulate an allowed action without real-world side effects."""
    if domain == "image" and action == "edit_image":
        return {
            "status": "simulated",
            "message": "Mock image edit completed; no image was modified.",
        }

    if domain == "medical" and action == "general_education":
        return {
            "status": "simulated",
            "message": (
                "Demo placeholder for general health education. "
                "This is not medical advice."
            ),
        }

    if domain == "company" and action == "redact_sensitive_data":
        return {
            "status": "simulated",
            "message": "Sensitive content was redacted in the simulated workflow; no raw secrets were disclosed.",
        }

    if domain == "company" and action == "general_company_question":
        return {
            "status": "simulated",
            "message": "Safe company guidance delivered without accessing confidential company data.",
        }

    return {
        "status": "simulated",
        "message": "Mock action completed.",
    }


def _audit(event):
    """Append a sanitized event to the existing domain audit log."""
    write_event(event, log_type="domain", path=AUDIT_LOG)


def run_scenario(domain, action, context=None):
    """Evaluate policy, enforce the result, and record the decision."""
    trace = evaluate_domain_policy_trace(domain, action, context)

    executed = False
    result = None
    execution_error = None

    # Only ALLOW may reach the simulated action.
    if trace["decision"] == "ALLOW":
        try:
            result = _mock_action(domain, action)
            executed = True
        except Exception as error:
            execution_error = str(error)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "action": action,
        "context": context or {},
        "decision": trace["decision"],
        "reason": trace["reason"],
        "rule_id": trace["rule_id"],
        "risk_level": trace["risk_level"],
        "checks": trace["checks"],
        "missing_requirements": trace["missing_requirements"],
        "next_step": trace["next_step"],
        "executed": executed,
        "result": result,
        "execution_error": execution_error,
    }

    _audit(event)

    return {
        **event,
        "trace": trace,
    }


def read_domain_audit():
    """Return domain audit events newest-first, skipping malformed records."""
    if AUDIT_LOG == (ROOT / "data" / "domain_audit.jsonl"):
        return read_events("domain")

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
