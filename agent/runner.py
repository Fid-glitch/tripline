
import json
from datetime import datetime, timezone
from pathlib import Path

from agent.domain_policies import evaluate_domain_policy_trace


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

    return {
        "status": "simulated",
        "message": "Mock action completed.",
    }


def _audit(event):
    """Append one event to the domain audit log."""

    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)

    with AUDIT_LOG.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")


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
    """Return domain audit events, newest first."""

    if not AUDIT_LOG.exists():
        return []

    events = []

    with AUDIT_LOG.open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                events.append(json.loads(line))

    return list(reversed(events))
