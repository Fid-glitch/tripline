
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

    if domain == "image":
        if action != "edit_image":
            return result(
                "BLOCK", "Unknown image action", "IMAGE-001", "HIGH",
                [{"name": "Action validation", "passed": False,
                  "detail": "Action is not supported"}],
                next_step="Use a supported image action",
            )

        consent = context.get("consent_status")
        authorized = context.get("subject_authorized") is True

        checks = [
            {
                "name": "Consent evidence",
                "passed": consent == "verified",
                "detail": (
                    "Consent is marked verified"
                    if consent == "verified"
                    else "Verified consent was not provided"
                ),
            },
            {
                "name": "Subject authorization",
                "passed": authorized,
                "detail": (
                    "Authorization is marked verified"
                    if authorized
                    else "Verified subject authorization was not provided"
                ),
            },
        ]

        if consent == "denied":
            return result(
                "BLOCK",
                "The subject has denied consent",
                "IMAGE-CONSENT-002",
                "HIGH",
                checks,
                next_step="Do not perform the image edit",
            )

        missing = []
        if consent != "verified":
            missing.append("Verified consent evidence")
        if not authorized:
            missing.append("Verified subject authorization")

        if missing:
            return result(
                "REVIEW",
                "Required authorization conditions are not satisfied",
                "IMAGE-CONSENT-001",
                "HIGH",
                checks,
                missing,
                "Obtain and verify the required evidence before reevaluation",
            )

        return result(
            "ALLOW",
            "Required consent and authorization checks passed",
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
                    {"name": "Action classification", "passed": True,
                     "detail": "General education is within demo scope"}
                ],
                next_step="Provide general information without personalized diagnosis or dosing",
            )

        if action == "personalized_dosage":
            return result(
                "BLOCK",
                "Personalized medication dosing is outside demo scope",
                "MED-DOSE-001",
                "HIGH",
                [
                    {"name": "Dosage safety rule", "passed": False,
                     "detail": "Personalized dosage generation is prohibited"}
                ],
                next_step="Refer the user to a qualified healthcare professional or pharmacist",
            )

        if action == "high_risk_symptoms":
            return result(
                "REVIEW",
                "High-risk symptoms require urgent professional assessment",
                "MED-URGENT-001",
                "CRITICAL",
                [
                    {"name": "High-risk symptom rule", "passed": False,
                     "detail": "Automated handling is not permitted by this demo policy"}
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
                    {"name": "Treatment review requirement", "passed": False,
                     "detail": "Qualified clinical review has not been established"}
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
                {"name": "Action validation", "passed": False,
                 "detail": "Action is not supported"}
            ],
            next_step="Use a supported medical action",
        )

    return result(
        "BLOCK",
        "Unknown policy domain",
        "POLICY-001",
        "HIGH",
        [
            {"name": "Domain validation", "passed": False,
             "detail": "No policy exists for this domain"}
        ],
        next_step="Configure an explicit policy before allowing this action",
    )


def evaluate_domain_policy(domain, action, context=None):
    """Backward-compatible decision and reason interface."""
    trace = evaluate_domain_policy_trace(domain, action, context)
    return trace["decision"], trace["reason"]
