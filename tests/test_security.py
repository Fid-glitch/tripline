
import unittest
from unittest.mock import patch

from agent.security import evaluate_policy, execute_tool


class TestSecurityGateway(unittest.TestCase):

    def test_allowed_file_read(self):
        decision, _ = evaluate_policy(
            "read_file", {"path": "hello.txt"}
        )
        self.assertEqual(decision, "ALLOW")

    def test_block_path_traversal(self):
        decision, _ = evaluate_policy(
            "read_file", {"path": "../secret.txt"}
        )
        self.assertEqual(decision, "BLOCK")

    def test_block_sensitive_file(self):
        decision, _ = evaluate_policy(
            "read_file", {"path": ".env"}
        )
        self.assertEqual(decision, "BLOCK")

    def test_block_unknown_tool(self):
        decision, _ = evaluate_policy(
            "delete_database", {}
        )
        self.assertEqual(decision, "BLOCK")

    def test_block_unapproved_command(self):
        decision, _ = evaluate_policy(
            "run_shell",
            {"command": ["python", "-c", "print('unsafe')"]},
        )
        self.assertEqual(decision, "BLOCK")

    def test_blocked_tool_is_not_executed(self):
        with patch("agent.security.tools.run_shell") as mock_tool:
            result = execute_tool(
                "run_shell",
                {"command": ["python", "-c", "print('unsafe')"]},
            )

        self.assertEqual(result["decision"], "BLOCK")
        self.assertFalse(result["executed"])
        mock_tool.assert_not_called()

    def test_post_requires_review(self):
        decision, _ = evaluate_policy(
            "http_request",
            {"method": "POST", "url": "https://example.com"},
        )
        self.assertEqual(decision, "REVIEW")

    def test_review_request_is_not_executed(self):
        with patch("agent.security.tools.http_request") as mock_tool:
            result = execute_tool(
                "http_request",
                {"method": "POST", "url": "https://example.com"},
            )

        self.assertEqual(result["decision"], "REVIEW")
        self.assertFalse(result["executed"])
        mock_tool.assert_not_called()

    def test_allowed_get_is_simulated(self):
        result = execute_tool(
            "http_request",
            {"method": "GET", "url": "https://example.com"},
        )
        self.assertEqual(result["decision"], "ALLOW")
        self.assertTrue(result["executed"])
        self.assertEqual(result["result"]["status"], "simulated")


if __name__ == "__main__":
    unittest.main()
