
import unittest

from agent.domain_policies import evaluate_domain_policy


class TestDomainPolicies(unittest.TestCase):

    def test_verified_image_consent(self):
        decision, _ = evaluate_domain_policy(
            "image",
            "edit_image",
            {
                "evidence_id": "mock-consent-001",
                "subject_id": "person-123",
                "asset_id": "image-123",
                "purpose": "portrait_edit",
            },
        )

        self.assertEqual(decision, "ALLOW")

    def test_caller_flags_do_not_prove_consent(self):
        decision, _ = evaluate_domain_policy(
            "image",
            "edit_image",
            {
                "consent_status": "verified",
                "subject_authorized": True,
            },
        )

        self.assertEqual(decision, "REVIEW")

    def test_missing_image_consent_requires_review(self):
        decision, _ = evaluate_domain_policy(
            "image",
            "edit_image",
            {"consent_status": "missing"},
        )

        self.assertEqual(decision, "REVIEW")

    def test_checkbox_does_not_prove_consent(self):
        decision, _ = evaluate_domain_policy(
            "image",
            "edit_image",
            {
                "consent_status": "checkbox",
                "subject_authorized": True,
            },
        )

        self.assertEqual(decision, "REVIEW")

    def test_denied_image_consent_is_blocked(self):
        decision, _ = evaluate_domain_policy(
            "image",
            "edit_image",
            {"consent_status": "denied"},
        )

        self.assertEqual(decision, "BLOCK")

    def test_general_medical_education_allowed(self):
        decision, _ = evaluate_domain_policy(
            "medical",
            "general_education",
        )

        self.assertEqual(decision, "ALLOW")

    def test_personalized_dosage_blocked(self):
        decision, _ = evaluate_domain_policy(
            "medical",
            "personalized_dosage",
        )

        self.assertEqual(decision, "BLOCK")

    def test_high_risk_symptoms_require_review(self):
        decision, _ = evaluate_domain_policy(
            "medical",
            "high_risk_symptoms",
        )

        self.assertEqual(decision, "REVIEW")

    def test_personalized_treatment_requires_review(self):
        decision, _ = evaluate_domain_policy(
            "medical",
            "personalized_treatment",
        )

        self.assertEqual(decision, "REVIEW")

    def test_unknown_domain_blocked(self):
        decision, _ = evaluate_domain_policy(
            "unknown",
            "do_something",
        )

        self.assertEqual(decision, "BLOCK")

    def test_general_company_question_allowed(self):
        decision, _ = evaluate_domain_policy(
            "company",
            "general_company_question",
            {},
        )

        self.assertEqual(decision, "ALLOW")

    def test_confidential_document_to_personal_email_blocked(self):
        decision, _ = evaluate_domain_policy(
            "company",
            "share_confidential_document",
            {"destination_type": "personal"},
        )

        self.assertEqual(decision, "BLOCK")

    def test_prompt_injection_blocked(self):
        decision, _ = evaluate_domain_policy(
            "company",
            "prompt_injection",
            {},
        )

        self.assertEqual(decision, "BLOCK")

    def test_sensitive_redaction_requires_verified_workflow(self):
        decision, _ = evaluate_domain_policy(
            "company",
            "redact_sensitive_data",
            {},
        )

        self.assertEqual(decision, "REVIEW")


if __name__ == "__main__":
    unittest.main()
