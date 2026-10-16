
import unittest

from agent.evidence import verify_evidence


class TestEvidence(unittest.TestCase):

    def test_matching_evidence_is_valid(self):
        result = verify_evidence(
            "mock-consent-001",
            "person-123",
            "image-123",
            "portrait_edit",
        )
        self.assertTrue(result["valid"])

    def test_unknown_evidence_is_rejected(self):
        result = verify_evidence(
            "fake-evidence",
            "person-123",
            "image-123",
            "portrait_edit",
        )
        self.assertFalse(result["valid"])

    def test_wrong_subject_is_rejected(self):
        result = verify_evidence(
            "mock-consent-001",
            "person-999",
            "image-123",
            "portrait_edit",
        )
        self.assertFalse(result["valid"])

    def test_wrong_asset_is_rejected(self):
        result = verify_evidence(
            "mock-consent-001",
            "person-123",
            "image-999",
            "portrait_edit",
        )
        self.assertFalse(result["valid"])

    def test_wrong_purpose_is_rejected(self):
        result = verify_evidence(
            "mock-consent-001",
            "person-123",
            "image-123",
            "public_distribution",
        )
        self.assertFalse(result["valid"])


if __name__ == "__main__":
    unittest.main()
