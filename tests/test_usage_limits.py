
import unittest
from datetime import datetime, timedelta, timezone

from agent.usage_limits import check_and_record, reset_usage_limits


class TestUsageLimits(unittest.TestCase):
    def setUp(self):
        reset_usage_limits()
        self.now = datetime(2026, 10, 17, 0, 0, tzinfo=timezone.utc)

    def tearDown(self):
        reset_usage_limits()

    def check(self, at=None, limit=2, window=60):
        return check_and_record("user", "test-user", limit, window, now=at or self.now)

    def test_allows_attempts_until_limit(self):
        first = self.check()
        second = self.check()
        self.assertTrue(first["allowed"])
        self.assertTrue(second["allowed"])
        self.assertEqual(second["used"], 2)
        self.assertEqual(second["remaining"], 0)

    def test_over_limit_attempt_is_counted(self):
        self.check()
        self.check()
        third = self.check()
        self.assertFalse(third["allowed"])
        self.assertEqual(third["used"], 3)
        self.assertEqual(third["remaining"], 0)
        self.assertEqual(third["reason"], "limit_exceeded")

    def test_old_attempts_expire_at_window_boundary(self):
        self.check()
        later = self.now + timedelta(seconds=61)
        result = self.check(at=later)
        self.assertTrue(result["allowed"])
        self.assertEqual(result["used"], 1)

    def test_scopes_are_isolated(self):
        self.check()
        other = check_and_record("user", "another-user", 1, 60, now=self.now)
        self.assertTrue(other["allowed"])
        self.assertEqual(other["used"], 1)

    def test_invalid_arguments_are_rejected(self):
        with self.assertRaises(ValueError):
            check_and_record("tenant", "x", 1, 60, now=self.now)
        with self.assertRaises(ValueError):
            check_and_record("user", "x", 0, 60, now=self.now)


if __name__ == "__main__":
    unittest.main()
