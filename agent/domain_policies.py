
from agent.evidence import verify_evidence


def evaluate_domain_policy_trace(domain, action, context=None):
    """Return a structured, explainable policy decision."""

    if context is None:
        context = {}

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

    if not isinstance(context, dict):
        return result(
            "BLOCK",
            "Context must be a dictionary",
            "INPUT-001",
            "HIGH",
            [{
                "name": "Context validation",
                "passed": False,
                "detail": "Expected a dictionary",
            }],
            next_step="Provide valid scenario context",
        )

    # -----------------------------------------------------
    # COMPANY POLICIES
    # -----------------------------------------------------
    if domain == "company":

        if action == "general_company_question":
            return result(
                "ALLOW",
                "General company questions are permitted",
                "COMP-GEN-001",
                "LOW",
                [{
                    "name": "Request scope",
                    "passed": True,
                    "detail": (
                        "General information only; no private company "
                        "resource is accessed or modified"
                    ),
                }],
                next_step=(
                    "Provide general guidance without disclosing "
                    "confidential company information"
                ),
            )

        if action == "summarize_internal_document":
            authorized = bool(
                context.get("document_access_verified")
                or context.get("trusted_authorization")
            )
            if not authorized:
                return result(
                    "REVIEW",
                    "Internal document processing requires verified access to the source document",
                    "COMP-DOC-001",
                    "MEDIUM",
                    [{
                        "name": "Document access",
                        "passed": False,
                        "detail": (
                            "No trusted record establishes that the requester "
                            "may access the document"
                        ),
                    }],
                    [
                        "Verified access to the source document",
                        "Document classification and permitted processing purpose",
                    ],
                    "Verify document permissions before providing its contents to an AI service",
                )
            return result(
                "ALLOW",
                "The request is limited to a documented, permissioned summary workflow",
                "COMP-DOC-002",
                "LOW",
                [{
                    "name": "Document access",
                    "passed": True,
                    "detail": "Trusted access checks were present for the source document",
                }],
                next_step="Use the approved summary workflow and do not disclose confidential details beyond the approved scope",
            )

        if action == "handle_personal_data":
            return result(
                "REVIEW",
                "Customer or employee personal data requires minimization, redaction, and verified purpose",
                "COMP-DATA-002",
                "CRITICAL",
                [{
                    "name": "Personal data review",
                    "passed": False,
                    "detail": (
                        "The request processes personal data and lacks a trusted "
                        "authorization and minimization workflow"
                    ),
                }],
                [
                    "Verified business purpose",
                    "Minimum necessary data scope",
                    "Redaction or anonymization workflow",
                    "Authorized recipient and retention limits",
                ],
                "Do not export or reveal personal data until the data minimization and authorization checks are confirmed",
            )

        if action == "expose_credentials":
            return result(
                "BLOCK",
                "Disclosing credentials, tokens, or secrets is prohibited",
                "COMP-SECRET-001",
                "CRITICAL",
                [{
                    "name": "Credential exposure",
                    "passed": False,
                    "detail": "The request would expose secrets or credentials to the AI service",
                }],
                [
                    "A secure secret-management workflow",
                    "Authorized debugging or review context",
                    "Safe redaction and credential rotation guidance",
                ],
                "Do not paste or reveal the credential; use a secure vault or redacted placeholder instead",
            )

        if action == "redact_sensitive_data":
            authorized = bool(
                context.get("approved_redaction_workflow")
                or context.get("trusted_authorization")
            )
            if not authorized:
                return result(
                    "REVIEW",
                    "Sensitive-data redaction requires verification of the approved workflow and scope",
                    "COMP-REDACT-001",
                    "HIGH",
                    [{
                        "name": "Redaction workflow",
                        "passed": False,
                        "detail": "The request is not paired with a trusted redaction or approval mechanism",
                    }],
                    [
                        "Approved redaction workflow",
                        "Verified classification of the source data",
                        "Confirmation that the output is not a direct disclosure",
                    ],
                    "Use a verified redaction workflow and confirm the output is a sanitized transformation before sharing",
                )
            return result(
                "ALLOW",
                "The request limits exposure by redacting sensitive content before sharing or export",
                "COMP-REDACT-002",
                "LOW",
                [{
                    "name": "Redaction workflow",
                    "passed": True,
                    "detail": "The request refers to a safe redaction path that reduces exposure",
                }],
                next_step="Perform the redaction in a verified toolchain and confirm the output still matches the intended scope",
            )

        if action == "prompt_injection":
            return result(
                "BLOCK",
                "Prompt injection attempts are untrusted and must be rejected",
                "COMP-INJECT-001",
                "CRITICAL",
                [{
                    "name": "Instruction integrity",
                    "passed": False,
                    "detail": "The request attempts to override policy, impersonate an admin, or evade security controls",
                }],
                [
                    "Verified instruction hierarchy",
                    "Company policy enforcement remains authoritative",
                    "Safe, non-privileged user interaction",
                ],
                "Reject the override attempt and continue with the approved company policy workflow",
            )

        if action == "delete_audit_logs":
            return result(
                "BLOCK",
                "Deleting or hiding logs is prohibited because it destroys evidence and undermines the audit trail",
                "COMP-AUDIT-001",
                "CRITICAL",
                [{
                    "name": "Audit integrity",
                    "passed": False,
                    "detail": "The request attempts to remove audit evidence or alter the retention record",
                }],
                [
                    "A governed security incident process",
                    "Explicit retention or legal hold direction",
                    "Proper review and approval for any evidence change",
                ],
                "Do not delete logs; preserve the audit trail and escalate through the approved incident process",
            )

        if action == "external_data_transfer":
            destination = str(context.get("destination_type", "")).lower()
            if destination in {"personal", "external", "public"}:
                return result(
                    "BLOCK",
                    "External or unapproved destinations are blocked for sensitive company data",
                    "COMP-XFER-001",
                    "CRITICAL",
                    [{
                        "name": "Destination trust",
                        "passed": False,
                        "detail": "The destination is external, personal, or public and not approved for this data",
                    },
                    {
                        "name": "Data loss prevention",
                        "passed": False,
                        "detail": "The request would transfer sensitive data outside the approved channel",
                    }],
                    [
                        "Approved destination",
                        "Verified data classification and purpose",
                        "Authorized recipient and retention controls",
                    ],
                    "Do not perform the transfer. Use the approved company-controlled channel and a verified public-safe export path if needed.",
                )
            return result(
                "REVIEW",
                "Data transfer requires verification of destination trust and authorization",
                "COMP-XFER-002",
                "HIGH",
                [{
                    "name": "Transfer authorization",
                    "passed": False,
                    "detail": "No trusted record confirms the destination is allowed for this data",
                }],
                [
                    "Verified destination trust",
                    "Approved transfer purpose",
                    "Data minimization and retention controls",
                ],
                "Verify the destination, authorization, and approved purpose before any transfer",
            )

        if action == "share_confidential_document":
            destination = str(context.get("destination_type", "")).lower()

            if destination in {"personal", "external", "public"}:
                return result(
                    "BLOCK",
                    "Sharing confidential company documents with a personal, external, or public destination is prohibited by demo policy",
                    "COMP-DLP-001",
                    "CRITICAL",
                    [
                        {
                            "name": "Destination policy",
                            "passed": False,
                            "detail": (
                                "The destination is personal, external, "
                                "or public"
                            ),
                        },
                        {
                            "name": "Data loss prevention",
                            "passed": False,
                            "detail": (
                                "Confidential data must not be disclosed "
                                "to an unapproved destination"
                            ),
                        },
                    ],
                    ["An approved destination and authorized sharing workflow"],
                    "Do not send the document; use an approved company channel",
                )

            return result(
                "REVIEW",
                "Sharing a confidential document requires destination and authorization verification",
                "COMP-DLP-002",
                "HIGH",
                [{
                    "name": "Sharing authorization",
                    "passed": False,
                    "detail": (
                        "This chat has no trusted record verifying the "
                        "recipient, destination, or sharing permission"
                    ),
                }],
                [
                    "Verified employee identity and role",
                    "Document classification",
                    "Verified recipient and approved destination",
                    "Required approval, if applicable",
                ],
                "Verify the sharing request through the company's trusted access-control system",
            )

        if action == "export_customer_data":
            return result(
                "REVIEW",
                "Exporting customer data requires verified access and a documented business purpose",
                "COMP-DATA-001",
                "CRITICAL",
                [{
                    "name": "Customer data authorization",
                    "passed": False,
                    "detail": (
                        "No trusted identity, role, purpose, or export "
                        "approval record was provided"
                    ),
                }],
                [
                    "Verified employee identity and role",
                    "Approved business purpose",
                    "Minimum necessary data scope",
                    "Required privacy or compliance approval",
                ],
                "Do not export data until the required checks are verified",
            )

        if action == "access_restricted_system":
            return result(
                "REVIEW",
                "Access to a restricted system requires verified identity and permissions",
                "COMP-ACCESS-001",
                "HIGH",
                [{
                    "name": "Access control",
                    "passed": False,
                    "detail": (
                        "The chat cannot verify the requester's identity "
                        "or system permissions"
                    ),
                }],
                [
                    "Verified identity",
                    "Role-based permission for the requested resource",
                    "Approved purpose for access",
                ],
                "Verify access through the company's identity and access management system",
            )

        if action == "disable_security_monitoring":
            return result(
                "BLOCK",
                "Disabling security monitoring or bypassing safeguards is prohibited by demo policy",
                "COMP-SEC-001",
                "CRITICAL",
                [{
                    "name": "Security control protection",
                    "passed": False,
                    "detail": (
                        "The request would disable monitoring, bypass "
                        "security controls, or erase audit evidence"
                    ),
                }],
                ["A separately governed administrative change process, if a legitimate exception exists"],
                "Do not execute this request through the AI agent",
            )

        if action == "deploy_code":
            return result(
                "REVIEW",
                "Code deployment requires an approved release and verified permissions",
                "COMP-CHANGE-001",
                "HIGH",
                [{
                    "name": "Change management",
                    "passed": False,
                    "detail": (
                        "No trusted release approval, test result, or "
                        "deployment permission is available to this chat"
                    ),
                }],
                [
                    "Authorized deployer",
                    "Approved release or change record",
                    "Required tests and checks",
                ],
                "Use the company's approved deployment workflow",
            )

        if action == "summarize_internal_document":
            return result(
                "REVIEW",
                "Internal document processing requires verified access to the source document",
                "COMP-DOC-001",
                "MEDIUM",
                [{
                    "name": "Document access",
                    "passed": False,
                    "detail": (
                        "No trusted record establishes that the requester "
                        "may access the document"
                    ),
                }],
                [
                    "Verified access to the source document",
                    "Document classification and permitted processing purpose",
                ],
                "Verify document permissions before providing its contents to an AI service",
            )

        return result(
            "BLOCK",
            "Unknown company action",
            "COMP-INPUT-001",
            "HIGH",
            [{
                "name": "Action validation",
                "passed": False,
                "detail": "No explicit company policy exists for this action",
            }],
            next_step="Define and test an explicit policy before supporting this action",
        )

    # -----------------------------------------------------
    # LEGACY IMAGE POLICY
    # -----------------------------------------------------
    if domain == "image":
        if action != "edit_image":
            return result(
                "BLOCK",
                "Unknown image action",
                "IMAGE-001",
                "HIGH",
                [{
                    "name": "Action validation",
                    "passed": False,
                    "detail": "Action is not supported",
                }],
                next_step="Use a supported image action",
            )

        if context.get("consent_status") == "denied":
            return result(
                "BLOCK",
                "The subject has denied consent",
                "IMAGE-CONSENT-002",
                "HIGH",
                [{
                    "name": "Consent denial",
                    "passed": False,
                    "detail": "Consent was explicitly denied",
                }],
                next_step="Do not perform the image edit",
            )

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

        checks = [{
            "name": "Registered consent evidence",
            "passed": evidence_valid,
            "detail": evidence_reason,
        }]

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
                "Obtain or correct evidence, then reevaluate before execution",
            )

        return result(
            "ALLOW",
            "Registered consent evidence passed all verification checks",
            "IMAGE-CONSENT-001",
            "HIGH",
            checks,
        )

    # -----------------------------------------------------
    # LEGACY MEDICAL POLICY
    # -----------------------------------------------------
    if domain == "medical":
        if action == "general_education":
            return result(
                "ALLOW",
                "The request is classified as general health education",
                "MED-EDU-001",
                "LOW",
                [{
                    "name": "Action classification",
                    "passed": True,
                    "detail": "General education is within demo scope",
                }],
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
                [{
                    "name": "Dosage safety rule",
                    "passed": False,
                    "detail": "Personalized dosage generation is prohibited",
                }],
                next_step="Refer to a qualified healthcare professional or pharmacist",
            )

        if action == "high_risk_symptoms":
            return result(
                "REVIEW",
                "High-risk symptoms require urgent professional assessment",
                "MED-URGENT-001",
                "CRITICAL",
                [{
                    "name": "High-risk symptom rule",
                    "passed": False,
                    "detail": "Automated handling is not permitted by demo policy",
                }],
                ["Qualified assessment of reported symptoms"],
                "Direct the user to appropriate urgent or emergency care when indicated",
            )

        if action == "personalized_treatment":
            return result(
                "REVIEW",
                "Personalized treatment requires qualified clinical review",
                "MED-TREAT-001",
                "HIGH",
                [{
                    "name": "Treatment review requirement",
                    "passed": False,
                    "detail": "Qualified clinical review has not been established",
                }],
                ["Qualified clinical review"],
                "Refer to an appropriate qualified healthcare professional",
            )

        return result(
            "BLOCK",
            "Unknown medical action",
            "MED-INPUT-001",
            "HIGH",
            [{
                "name": "Action validation",
                "passed": False,
                "detail": "Action is not supported",
            }],
            next_step="Use a supported medical action",
        )

    return result(
        "BLOCK",
        "Unknown policy domain",
        "POLICY-001",
        "HIGH",
        [{
            "name": "Domain validation",
            "passed": False,
            "detail": "No policy exists for this domain",
        }],
        next_step="Configure an explicit policy before allowing this action",
    )


def evaluate_domain_policy(domain, action, context=None):
    """Backward-compatible decision and reason interface."""
    trace = evaluate_domain_policy_trace(domain, action, context)
    return trace["decision"], trace["reason"]
