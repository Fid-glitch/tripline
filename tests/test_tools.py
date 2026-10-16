
import unittest

from agent.tools import read_file, run_shell, http_request, _safe_path


class TestTriplineTools(unittest.TestCase):

    def test_read_file(self):
        content = read_file("hello.txt")
        self.assertIn("Hello from Tripline!", content)

    def test_block_path_traversal(self):
        with self.assertRaises(ValueError):
            _safe_path("../secret.txt")

    def test_allowed_command(self):
        result = run_shell(["python", "--version"])
        self.assertEqual(result["returncode"], 0)

    def test_block_command(self):
        with self.assertRaises(ValueError):
            run_shell(["python", "-c", "print('unsafe')"])

    def test_simulated_http(self):
        result = http_request("GET", "https://example.com")
        self.assertEqual(result["status"], "simulated")
        self.assertTrue(result["request"]["simulated"])


if __name__ == "__main__":
    unittest.main()
