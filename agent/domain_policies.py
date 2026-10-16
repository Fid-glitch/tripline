
from agent.evidence import verify_evidence


def evaluate_domain_policy_trace(domain, action, context=None):
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
                {
                    "name": "Context validation",
                    "passed": False,
                    "detail": "Expected a dictionary",
                }
            ],
            "missing_requirements": [],
            "next_step": "Provide valid scenario context",
        }

    def result(
        decision,
        reason,
        rule_id,
        risk,
        checks,
        missing=None,
        next_step="No further action required",
    ):
        return {
            "decision": decision,
            "reason": reason,
            "rule_id": rule_id,
            "risk_level": risk,
            "checks": checks,
            "missing_requirements": missing or [],
            "next_step": next_step,
        }

    if domain == "image":
        if action != "edit_image":
            return result(
                "BLOCK",
                "Unknown image action",
                "IMAGE-001",
                "HIGH",
                [
                    {
                        "name": "Action validation",
                        "passed": False,
                        "detail": "Action is not supported",
                    }
                ],
                next_step="Use a supported image action",
            )

        # Explicit denial must never be overridden by evidence.
        if context.get("consent_status") == "denied":
            return result(
                "BLOCK",
                "The subject has denied consent",
                "IMAGE-CONSENT-002",
                "HIGH",
                [
                    {
                        "name": "Consent denial",
                        "passed": False,
                        "detail": "The request indicates that consent was denied",
                    }
                ],
                next_step="Do not perform the image edit",
            )

        # Verify registered evidence; caller-supplied flags are not proof.
        try:
            evidence_result = verify_evidence(
                evidence_id=context.get("evidence_id"),
                subject_id=context.get("subject_id"),
                asset_id=context.get("asset_id"),
                purpose=context.get("purpose"),
            )

            evidence_valid = (
                isinstance(evidence_result, dict)
                and evidence_result.get("valid") is True
                and isinstance(evidence_result.get("reason"), str)
            )

            evidence_reason = (
                evidence_result["reason"]
                if evidence_valid
                else "Evidence verification returned an invalid result"
            )

        except Exception:
            evidence_valid = False
            evidence_reason = "Evidence verification failed safely"

        checks = [
            {
                "name": "Registered consent evidence",
                "passed": evidence_valid,
                "detail": evidence_reason,
            }
        ]

        if not evidence_valid:
            return result(
                "REVIEW",
                "Registered consent evidence could not be verified",
                "IMAGE-CONSENT-001",
                "HIGH",
                checks,
                [
                    "Valid registered evidence matching the subject, asset, and purpose"
                ],
                "Obtain or correct the evidence, then reevaluate before execution",
            )

        return result(
            "ALLOW",
            "Registered consent evidence passed all verification checks",
            "IMAGE-CONSENT-001",
            "HIGH",
            checks,
        )

    if domain == "medical":
        if action == "general_education":
            return result(
                "ALLOW",
                "The request is classified as general health education",
                "MED-EDU-001",
                "LOW",
                [
                    {
                        "name": "Action classification",
                        "passed": True,
                        "detail": "General education is within demo scope",
                    }
                ],
                next_step=(
                    "Provide general information without personalized diagnosis or dosing"
                ),
            )

        if action == "personalized_dosage":
            return result(
                "BLOCK",
                "Personalized medication dosing is outside demo scope",
                "MED-DOSE-001",
                "HIGH",
                [
                    {
                        "name": "Dosage safety rule",
                        "passed": False,
                        "detail": "Personalized dosage generation is prohibited",
                    }
                ],
                next_step=(
                    "Refer the user to a qualified healthcare professional or pharmacist"
                ),
            )

        if action == "high_risk_symptoms":
            return result(
                "REVIEW",
                "High-risk symptoms require urgent professional assessment",
                "MED-URGENT-001",
                "CRITICAL",
                [
                    {
                        "name": "High-risk symptom rule",
                        "passed": False,
                        "detail": (
                            "Automated handling is not permitted by this demo policy"
                        ),
                    }
                ],
                ["Qualified assessment of the reported symptoms"],
                "Direct the user to appropriate urgent or emergency care when indicated",
            )

        if action == "personalized_treatment":
            return result(
                "REVIEW",
                "Personalized treatment requires qualified clinical review",
                "MED-TREAT-001",
                "HIGH",
                [
                    {
                        "name": "Treatment review requirement",
                        "passed": False,
                        "detail": "Qualified clinical review has not been established",
                    }
                ],
                ["Qualified clinical review"],
                "Refer the case to an appropriate qualified healthcare professional",
            )

        return result(
            "BLOCK",
            "Unknown medical action",
            "MED-INPUT-001",
            "HIGH",
            [
                {
                    "name": "Action validation",
                    "passed": False,
                    "detail": "Action is not supported",
                }
            ],
            next_step="Use a supported medical action",
        )

    return result(
        "BLOCK",
        "Unknown policy domain",
        "POLICY-001",
        "HIGH",
        [
            {
                "name": "Domain validation",
                "passed": False,
                "detail": "No policy exists for this domain",
            }
        ],
        next_step="Configure an explicit policy before allowing this action",
    )


def evaluate_domain_policy(domain, action, context=None):
    """Backward-compatible decision and reason interface."""
    trace = evaluate_domain_policy_trace(domain, action, context)
    return trace["decision"], trace["reason"]
