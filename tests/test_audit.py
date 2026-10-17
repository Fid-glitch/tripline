
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent import audit


class TestAudit(unittest.TestCase):
    def test_writer_preserves_event_fields_and_sanitizes_sensitive_values(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "events.jsonl"
            audit.write_event({
                "tool": "demo",
                "decision": "BLOCK",
                "arguments": {"api_key": "top-secret", "prompt": "private prompt"},
            }, path=path)
            event = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(event["tool"], "demo")
        self.assertEqual(event["decision"], "BLOCK")
        self.assertEqual(event["arguments"]["api_key"], "<redacted>")
        self.assertEqual(event["arguments"]["prompt"], "<redacted>")

    def test_reader_skips_malformed_lines_and_limits_newest_first(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "events.jsonl"
            path.write_text('{"n":1}\nnot-json\n{"n":2}\n', encoding="utf-8")
            with patch.dict(audit.LOG_PATHS, {"security": path}):
                self.assertEqual(audit.read_events("security", limit=1), [{"n": 2}])

    def test_normalize_event_maps_ask_to_review(self):
        result = audit.normalize_event({
            "tool": "http_request", "policy_decision": "ASK",
            "executed": False, "stage": "decision",
        })
        self.assertEqual(result["decision"], "REVIEW")
        self.assertEqual(result["action"], "http_request")


if __name__ == "__main__":
    unittest.main()
