
from datetime import datetime, timezone

def evaluate_policy(context):
    """Return a structured, explainable policy decision."""

    if context is None:
        context = {}

    if not isinstance(context, dict):
        return {
            "decision": "BLOCK",
            "reason": "Context must be a dictionary",
            "rule_id": "INPUT-001",
            "risk_level": "HIGH",
            "checks": [
                {"name": "Context validation", "passed": False,
                 "detail": "Expected a dictionary"}
            ],
            "missing_requirements": [],
            "next_step": "Provide valid scenario context",
        }

    def result(decision, reason, rule_id, risk, checks,
               missing=None, next_step="No further action required"):
        return {
            "decision": decision,
            "reason": reason,
            "rule_id": rule_id,
            "risk_level": risk,
            "checks": checks,
            "missing_requirements": missing or [],
            "next_step": next_step,
        }

# Demo fixtures only. These are NOT real-world consent records.
# A real product would use a trusted identity/consent provider.
TRUSTED_EVIDENCE = {
    "mock-consent-001": {
        "issuer": "tripline_demo_verifier",
        "subject_id": "person-123",
        "asset_id": "image-123",
        "purpose": "portrait_edit",
        "status": "verified",
        "expires_at": "2030-01-01T00:00:00+00:00",
        "revoked": False,
    }
}


def verify_evidence(
    evidence_id,
    subject_id,
    asset_id,
    purpose,
    now=None,
):
    """Verify a registered evidence record and its scope."""

    evidence = TRUSTED_EVIDENCE.get(evidence_id)

    if evidence is None:
        return {
            "valid": False,
            "reason": "Evidence was not found in the trusted registry",
        }

    if evidence["issuer"] != "tripline_demo_verifier":
        return {
            "valid": False,
            "reason": "Evidence issuer is not trusted",
        }

    if evidence["status"] != "verified":
        return {
            "valid": False,
            "reason": "Evidence is not verified",
        }

    if evidence["revoked"]:
        return {
            "valid": False,
            "reason": "Evidence has been revoked",
        }

    if evidence["subject_id"] != subject_id:
        return {
            "valid": False,
            "reason": "Evidence does not match the subject",
        }

    if evidence["asset_id"] != asset_id:
        return {
            "valid": False,
            "reason": "Evidence does not match the asset",
        }

    if evidence["purpose"] != purpose:
        return {
            "valid": False,
            "reason": "Evidence does not cover this purpose",
        }

    current_time = now or datetime.now(timezone.utc)

    expiry = datetime.fromisoformat(evidence["expires_at"])

    if expiry.tzinfo is None:
        return {
            "valid": False,
            "reason": "Evidence expiry has an invalid timezone",
        }

    if current_time >= expiry:
        return {
            "valid": False,
            "reason": "Evidence has expired",
        }

    return {
        "valid": True,
        "reason": "Registered evidence matches the requested scope",
    }
