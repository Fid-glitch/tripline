
import unittest
from unittest.mock import patch

from agent.runner import run_scenario


class TestScenarioRunner(unittest.TestCase):

    def test_verified_image_consent_runs_mock(self):
        result = run_scenario(
            "image",
            "edit_image",
            {
                "consent_status": "verified",
                "subject_authorized": True,
            },
        )

        self.assertEqual(result["decision"], "ALLOW")
        self.assertTrue(result["executed"])
        self.assertEqual(result["result"]["status"], "simulated")

    def test_missing_consent_does_not_execute(self):
        with patch("agent.runner._mock_action") as mock_action:
            result = run_scenario(
                "image",
                "edit_image",
                {"consent_status": "missing"},
            )

        self.assertEqual(result["decision"], "REVIEW")
        self.assertFalse(result["executed"])
        self.assertIsNone(result["result"])
        mock_action.assert_not_called()

    def test_personalized_dosage_does_not_execute(self):
        with patch("agent.runner._mock_action") as mock_action:
            result = run_scenario(
                "medical", "personalized_dosage"
            )

        self.assertEqual(result["decision"], "BLOCK")
        self.assertFalse(result["executed"])
        mock_action.assert_not_called()

    def test_general_education_runs_mock(self):
        result = run_scenario(
            "medical", "general_education"
        )

        self.assertEqual(result["decision"], "ALLOW")
        self.assertTrue(result["executed"])
        self.assertEqual(result["result"]["status"], "simulated")


if __name__ == "__main__":
    unittest.main()

