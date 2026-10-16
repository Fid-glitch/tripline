import unittest

from agent.data_protection import DLPConfig, mask_value, redact_text, scan_text


class TestDataProtection(unittest.TestCase):
    def test_detect_email_and_phone(self):
        findings = scan_text("Email a.person@example.com or call +1 (212) 555-0199.")
        kinds = {f.detector_type for f in findings}
        self.assertIn("email", kinds)
        self.assertIn("phone", kinds)

    def test_detect_credentials_without_exposing_values(self):
        sample = "api_key=sk_test_123456789 password='hunter2'"
        findings = scan_text(sample)
        self.assertTrue(any(f.detector_type == "api_key" for f in findings))
        self.assertTrue(any(f.detector_type == "password_assignment" for f in findings))
        for finding in findings:
            self.assertNotIn("sk_test_123456789", repr(finding))
            self.assertNotIn("hunter2", repr(finding))

    def test_private_key_and_authorization(self):
        text = "Authorization: Bearer abcdefghijklmnop\n-----BEGIN PRIVATE KEY-----"
        kinds = {f.detector_type for f in scan_text(text)}
        self.assertIn("authorization_header", kinds)
        self.assertIn("private_key", kinds)

    def test_configurable_terms(self):
        config = DLPConfig(
            customer_identifiers=("CUST-9912",),
            confidential_terms=("Project Aurora",),
            internal_project_markers=("TRIPLINE_INTERNAL",),
        )
        findings = scan_text("CUST-9912 Project Aurora TRIPLINE_INTERNAL", config)
        self.assertEqual(
            {f.detector_type for f in findings},
            {"customer_identifier", "confidential_term", "internal_project_marker"},
        )

    def test_redaction_preserves_unrelated_text(self):
        text = "Contact a.person@example.com for help."
        sanitized, redactions = redact_text(text)
        self.assertEqual(sanitized, "Contact [REDACTED_CONFIDENTIAL] for help.")
        self.assertEqual(len(redactions), 1)

    def test_overlapping_matches_are_merged(self):
        text = "secret-token-123456"
        config = DLPConfig(
            customer_identifiers=("secret-token",),
            confidential_terms=("token-123456",),
        )
        findings = scan_text(text, config)
        sanitized, redactions = redact_text(text, findings)
        self.assertEqual(sanitized, "[REDACTED_CONFIDENTIAL]")
        self.assertTrue(redactions)

    def test_ordinary_text_unchanged(self):
        text = "Please summarize this public article."
        self.assertEqual(scan_text(text), [])
        self.assertEqual(redact_text(text)[0], text)

    def test_invalid_input_safe(self):
        self.assertEqual(scan_text(None), [])
        self.assertEqual(scan_text({"secret": "value"}), [])
        with self.assertRaises(TypeError):
            redact_text(None)
        with self.assertRaises(TypeError):
            mask_value(None)

    def test_mask_value(self):
        self.assertEqual(mask_value("1234567890"), "********90")
        self.assertEqual(mask_value("abc", visible=0), "***")
        self.assertEqual(mask_value("ab", visible=2), "**")


if __name__ == "__main__":
    unittest.main()
