import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from agent import policy_engine, security

SECRET = "sk_test_123456789"
EMAIL = "a.person@example.com"
GET = {"method": "GET", "url": "https://example.com"}
POST = {"method": "POST", "url": "https://example.com"}


def engine_result(decision, **overrides):
    values = dict(
        decision=decision,
        risk_score=0,
        risk_signals=(),
        applied_rules=("TEST-RULE",),
        reason="forced for test",
        execution_permitted=(decision == "ALLOW"),
    )
    values.update(overrides)
    return policy_engine.PolicyResult(**values)


class GatewayTestCase(unittest.TestCase):
    """Isolates the audit log and approvals, and mocks every real tool."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.audit_path = Path(tmp.name) / "audit.jsonl"

        for patcher in (
            patch.object(security, "AUDIT_LOG", self.audit_path),
            patch.dict(security._PENDING_APPROVALS, {}, clear=True),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        self.read_file = self._mock("agent.security.tools.read_file")
        self.run_shell = self._mock("agent.security.tools.run_shell")
        self.http_request = self._mock("agent.security.tools.http_request")
        self.http_request.return_value = {"status": "simulated"}
        self.read_file.return_value = "file text"

    def _mock(self, target):
        patcher = patch(target)
        mock = patcher.start()
        self.addCleanup(patcher.stop)
        return mock

    def assert_no_tool_ran(self):
        self.read_file.assert_not_called()
        self.run_shell.assert_not_called()
        self.http_request.assert_not_called()

    def audit_text(self):
        return self.audit_path.read_text(encoding="utf-8") if self.audit_path.exists() else ""

    def audit_events(self):
        return [json.loads(line) for line in self.audit_text().splitlines() if line.strip()]


class TestAllowedCalls(GatewayTestCase):
    def test_safe_calls_still_execute(self):
        result = security.execute_tool("read_file", {"path": "hello.txt"})
        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["policy_decision"], "ALLOW")
        self.assertTrue(result["executed"])
        self.assertEqual(result["result"], "file text")
        self.read_file.assert_called_once_with(path="hello.txt")

        result = security.execute_tool("http_request", GET)
        self.assertTrue(result["executed"])
        self.http_request.assert_called_once_with(**GET)

    def test_legacy_result_keys_are_preserved(self):
        result = security.execute_tool("read_file", {"path": "hello.txt"})
        for key in ("decision", "reason", "executed", "result"):
            self.assertIn(key, result)

    def test_allowed_call_writes_pre_and_outcome_audit_records(self):
        security.execute_tool("read_file", {"path": "hello.txt"})
        stages = [event["stage"] for event in self.audit_events()]
        self.assertEqual(stages, ["pre_execution", "outcome"])
        self.assertTrue(self.audit_events()[-1]["executed"])

    def test_tool_errors_are_reported_and_audited(self):
        self.read_file.side_effect = FileNotFoundError("File not found inside sandbox")
        result = security.execute_tool("read_file", {"path": "missing.txt"})
        self.assertTrue(result["executed"])
        self.assertIn("File not found", result["error"])
        self.assertEqual(self.audit_events()[-1]["outcome"], "error")


class TestBlockedCalls(GatewayTestCase):
    def test_blocked_requests_never_execute(self):
        blocked = [
            ("delete_database", {}),
            ("read_file", {"path": "../secret.txt"}),
            ("read_file", {"path": ".env"}),
            ("run_shell", {"command": ["python", "-c", "print('unsafe')"]}),
            ("http_request", {"method": "PATCH", "url": "https://example.com"}),
            ("read_file", None),
            ("read_file", ["hello.txt"]),
        ]
        for tool_name, args in blocked:
            with self.subTest(tool=tool_name, args=repr(args)):
                result = security.execute_tool(tool_name, args)
                self.assertEqual(result["decision"], "BLOCK")
                self.assertEqual(result["policy_decision"], "BLOCK")
                self.assertFalse(result["executed"])
                self.assertTrue(result["reason"])
        self.assert_no_tool_ran()

    def test_unhashable_tool_name_fails_closed(self):
        result = security.execute_tool(["read_file"], {"path": "hello.txt"})
        self.assertEqual(result["decision"], "BLOCK")
        self.assertFalse(result["executed"])
        self.assert_no_tool_ran()

    def test_credential_in_outbound_request_is_blocked(self):
        args = {"method": "GET", "url": f"https://example.com/?api_key={SECRET}"}
        result = security.execute_tool("http_request", args)
        self.assertEqual(result["policy_decision"], "BLOCK")
        self.assertFalse(result["executed"])
        self.assertIn("DLP-RESTRICTED-EXFIL-001", result["rule_ids"])
        self.http_request.assert_not_called()

    def test_caller_flags_in_arguments_are_rejected(self):
        for extra in (
            {"consent_status": "verified"},
            {"subject_authorized": True},
            {"approved": True},
        ):
            with self.subTest(extra=extra):
                result = security.execute_tool("read_file", {"path": "hello.txt", **extra})
                self.assertEqual(result["decision"], "BLOCK")
                self.assertFalse(result["executed"])
        self.assert_no_tool_ran()

    def test_original_policy_still_blocks_if_engine_says_allow(self):
        with patch("agent.policy_engine.evaluate_request",
                   return_value=engine_result("ALLOW")):
            for tool_name, args in (
                ("run_shell", {"command": ["python", "-c", "print('unsafe')"]}),
                ("read_file", {"path": "../secret.txt"}),
                ("read_file", {"path": ".env"}),
            ):
                with self.subTest(tool=tool_name):
                    result = security.execute_tool(tool_name, args)
                    self.assertEqual(result["decision"], "BLOCK")
                    self.assertFalse(result["executed"])
                    self.assertIn("LEGACY-POLICY-BLOCK", result["rule_ids"])
        self.assert_no_tool_ran()


class TestAskAndApproval(GatewayTestCase):
    def test_ask_does_not_execute_and_returns_pending_approval(self):
        result = security.execute_tool("http_request", POST)
        self.assertEqual(result["decision"], "REVIEW")      # legacy label
        self.assertEqual(result["policy_decision"], "ASK")
        self.assertFalse(result["executed"])
        self.assertTrue(result["pending_approval"])
        self.assertTrue(result["approval_id"].startswith("apr-"))
        self.http_request.assert_not_called()

    def test_same_request_reuses_the_pending_approval(self):
        first = security.execute_tool("http_request", POST)
        second = security.execute_tool("http_request", POST)
        self.assertEqual(first["approval_id"], second["approval_id"])
        self.assertEqual(len(security.list_pending_approvals()), 1)

    def test_unapproved_or_made_up_approval_ids_do_not_execute(self):
        pending = security.execute_tool("http_request", POST)
        for approval_id in (pending["approval_id"], "apr-madeup", "", None, 123, True):
            with self.subTest(approval_id=repr(approval_id)):
                result = security.execute_tool("http_request", POST, approval_id=approval_id)
                self.assertFalse(result["executed"])
        self.http_request.assert_not_called()

    def test_valid_approval_allows_exactly_one_execution(self):
        approval_id = security.execute_tool("http_request", POST)["approval_id"]
        self.assertTrue(security.approve_pending(approval_id, "reviewer"))

        result = security.execute_tool("http_request", POST, approval_id=approval_id)
        self.assertTrue(result["executed"])
        self.assertTrue(result["approved"])
        self.assertEqual(result["policy_decision"], "ASK")
        self.http_request.assert_called_once_with(**POST)

        again = security.execute_tool("http_request", POST, approval_id=approval_id)
        self.assertFalse(again["executed"])
        self.http_request.assert_called_once()

    def test_approval_does_not_transfer_to_different_arguments(self):
        approval_id = security.execute_tool("http_request", POST)["approval_id"]
        security.approve_pending(approval_id, "reviewer")
        other = {"method": "POST", "url": "https://example.org"}
        result = security.execute_tool("http_request", other, approval_id=approval_id)
        self.assertFalse(result["executed"])
        self.http_request.assert_not_called()

    def test_expired_approval_is_rejected(self):
        approval_id = security.execute_tool("http_request", POST)["approval_id"]
        security.approve_pending(approval_id, "reviewer")
        security._PENDING_APPROVALS[approval_id]["created_at"] = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        )
        result = security.execute_tool("http_request", POST, approval_id=approval_id)
        self.assertFalse(result["executed"])
        self.http_request.assert_not_called()

    def test_invalid_approvals_are_refused(self):
        approval_id = security.execute_tool("http_request", POST)["approval_id"]
        self.assertFalse(security.approve_pending(approval_id, ""))
        self.assertFalse(security.approve_pending(approval_id, "   "))
        self.assertFalse(security.approve_pending(approval_id, None))
        self.assertFalse(security.approve_pending("apr-unknown", "reviewer"))
        self.assertFalse(security.approve_pending(None, "reviewer"))
        result = security.execute_tool("http_request", POST, approval_id=approval_id)
        self.assertFalse(result["executed"])

    def test_a_blocked_request_cannot_be_approved(self):
        blocked = security.execute_tool("run_shell", {"command": ["python", "-c", "x"]})
        self.assertIsNone(blocked["approval_id"])
        self.assertFalse(security.approve_pending("apr-anything", "reviewer"))
        result = security.execute_tool(
            "run_shell", {"command": ["python", "-c", "x"]}, approval_id="apr-anything"
        )
        self.assertFalse(result["executed"])
        self.run_shell.assert_not_called()

    def test_pending_list_does_not_expose_secrets(self):
        args = {"path": f"{EMAIL}.txt"}
        result = security.execute_tool("read_file", args)
        self.assertEqual(result["policy_decision"], "ASK")
        listing = json.dumps(security.list_pending_approvals())
        self.assertNotIn(EMAIL, listing)
        self.read_file.assert_not_called()


class TestRedaction(GatewayTestCase):
    def setUp(self):
        super().setUp()
        patcher = patch.dict(security.REDACTABLE_FIELDS, {"http_request": "body"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_downstream_tool_receives_redacted_content(self):
        args = {**GET, "body": f"mail {EMAIL} please"}
        result = security.execute_tool("http_request", args)

        self.assertEqual(result["policy_decision"], "REDACT")
        self.assertTrue(result["executed"])
        self.assertTrue(result["redacted"])
        self.http_request.assert_called_once_with(
            method="GET", url="https://example.com",
            body="mail [REDACTED_CONFIDENTIAL] please",
        )
        self.assertNotIn(EMAIL, repr(self.http_request.call_args))

    def test_control_fields_are_never_rewritten(self):
        args = {"method": "GET", "url": f"https://example.com/{EMAIL}", "body": "hi"}
        result = security.execute_tool("http_request", args)
        self.assertFalse(result["executed"])
        self.http_request.assert_not_called()

    def test_blocked_content_is_not_converted_into_allowed(self):
        for body in ("-----BEGIN PRIVATE KEY-----", f"api_key={SECRET}"):
            with self.subTest(body=body[:12]):
                result = security.execute_tool("http_request", {**GET, "body": body})
                self.assertEqual(result["policy_decision"], "BLOCK")
                self.assertFalse(result["executed"])
        self.http_request.assert_not_called()

    def test_failed_recheck_after_redaction_blocks(self):
        first = engine_result("REDACT", sanitized_content="still unsafe", redactions=())
        second = engine_result("BLOCK")
        with patch("agent.policy_engine.evaluate_request", side_effect=[first, second]):
            result = security.execute_tool("http_request", {**GET, "body": "text"})
        self.assertEqual(result["policy_decision"], "BLOCK")
        self.assertFalse(result["executed"])
        self.assertIn("GATEWAY-REDACTION-RECHECK-001", result["rule_ids"])
        self.http_request.assert_not_called()

    def test_redact_without_declared_field_does_not_execute(self):
        with patch.dict(security.REDACTABLE_FIELDS, {}, clear=True):
            with patch("agent.policy_engine.evaluate_request",
                       return_value=engine_result("REDACT", sanitized_content="x")):
                result = security.execute_tool("http_request", GET)
        self.assertEqual(result["policy_decision"], "REDACT")
        self.assertFalse(result["executed"])
        self.http_request.assert_not_called()

    def test_audit_records_redaction_without_the_original_value(self):
        security.execute_tool("http_request", {**GET, "body": f"mail {EMAIL} please"})
        self.assertNotIn(EMAIL, self.audit_text())
        last = self.audit_events()[-1]
        self.assertTrue(last["redacted"])
        self.assertEqual(last["redaction_count"], 1)


class TestAuditContent(GatewayTestCase):
    def test_secrets_are_not_written_to_the_audit_log(self):
        security.execute_tool(
            "http_request", {"method": "GET", "url": f"https://example.com/?api_key={SECRET}"}
        )
        security.execute_tool("read_file", {"path": f"{EMAIL}.txt"})
        security.execute_tool("read_file", {"path": f"password=hunter2hunter2"})
        text = self.audit_text()
        for secret in (SECRET, EMAIL, "hunter2hunter2"):
            self.assertNotIn(secret, text)

    def test_audit_records_contain_the_required_fields(self):
        security.execute_tool("http_request", POST)
        event = self.audit_events()[-1]
        for key in ("timestamp", "tool", "decision", "policy_decision", "risk_score",
                    "rule_ids", "reason", "executed", "outcome", "redacted"):
            self.assertIn(key, event)
        self.assertEqual(event["tool"], "http_request")
        self.assertEqual(event["policy_decision"], "ASK")
        self.assertEqual(event["outcome"], "pending_approval")

    def test_audit_text_is_length_limited_and_types_are_safe(self):
        security.execute_tool("read_file", {"path": "a" * 5000})
        self.assertLess(len(self.audit_text()), 3000)
        security.execute_tool("read_file", {"path": object()})
        self.assertEqual(self.audit_events()[-1]["arguments"]["path"], "<object>")


class TestFailClosed(GatewayTestCase):
    def test_engine_exception_blocks(self):
        with patch("agent.policy_engine.evaluate_request", side_effect=RuntimeError("boom")):
            result = security.execute_tool("read_file", {"path": "hello.txt"})
        self.assertEqual(result["decision"], "BLOCK")
        self.assertFalse(result["executed"])
        self.assertIn("GATEWAY-ERROR-001", result["rule_ids"])
        self.assert_no_tool_ran()

    def test_unexpected_engine_results_block(self):
        for bogus in (None, "ALLOW", {"decision": "ALLOW"}, object()):
            with self.subTest(result=repr(bogus)):
                with patch("agent.policy_engine.evaluate_request", return_value=bogus):
                    result = security.execute_tool("read_file", {"path": "hello.txt"})
                self.assertEqual(result["decision"], "BLOCK")
                self.assertFalse(result["executed"])
        self.assert_no_tool_ran()

    def test_unknown_decision_from_engine_blocks(self):
        bogus = engine_result("MAYBE")
        with patch("agent.policy_engine.evaluate_request", return_value=bogus):
            result = security.execute_tool("read_file", {"path": "hello.txt"})
        self.assertEqual(result["decision"], "BLOCK")
        self.read_file.assert_not_called()

    def test_legacy_review_label_still_means_pending_approval(self):
        with patch("agent.security.evaluate_policy",
                   return_value=("REVIEW", "forced review")):
            result = security.execute_tool("read_file", {"path": "hello.txt"})
        self.assertEqual(result["decision"], "REVIEW")
        self.assertEqual(result["policy_decision"], "ASK")
        self.assertFalse(result["executed"])
        self.read_file.assert_not_called()


class TestAuditFailures(GatewayTestCase):
    def test_denied_request_stays_denied_when_audit_fails(self):
        with patch("agent.security._write_audit", side_effect=OSError("disk full")):
            result = security.execute_tool("delete_database", {})
        self.assertEqual(result["decision"], "BLOCK")
        self.assertFalse(result["executed"])
        self.assertFalse(result["audit_ok"])

    def test_ask_request_is_not_executed_when_audit_fails(self):
        with patch("agent.security._write_audit", side_effect=OSError("disk full")):
            result = security.execute_tool("http_request", POST)
        self.assertEqual(result["policy_decision"], "ASK")
        self.assertFalse(result["executed"])
        self.http_request.assert_not_called()

    def test_allowed_request_is_refused_when_intent_cannot_be_audited(self):
        with patch("agent.security._write_audit", side_effect=OSError("disk full")):
            result = security.execute_tool("http_request", GET)
        self.assertEqual(result["decision"], "BLOCK")
        self.assertFalse(result["executed"])
        self.assertIn("AUDIT-UNAVAILABLE-001", result["rule_ids"])
        self.http_request.assert_not_called()

    def test_unwritable_audit_location_refuses_execution(self):
        blocker = self.audit_path.parent / "not_a_folder"
        blocker.write_text("x")
        with patch.object(security, "AUDIT_LOG", blocker / "audit.jsonl"):
            result = security.execute_tool("http_request", GET)
        self.assertFalse(result["executed"])
        self.http_request.assert_not_called()

    def test_failed_outcome_audit_is_reported_but_result_is_kept(self):
        calls = {"count": 0}
        real_write = security._write_audit

        def flaky(*args, **kwargs):
            calls["count"] += 1
            if calls["count"] > 1:
                raise OSError("disk full")
            return real_write(*args, **kwargs)

        with patch("agent.security._write_audit", side_effect=flaky):
            result = security.execute_tool("http_request", GET)
        self.assertTrue(result["executed"])
        self.assertFalse(result["audit_ok"])

    def test_failed_approval_audit_does_not_consume_or_grant_extra_rights(self):
        approval_id = security.execute_tool("http_request", POST)["approval_id"]
        security.approve_pending(approval_id, "reviewer")
        with patch("agent.security._write_audit", side_effect=OSError("disk full")):
            result = security.execute_tool("http_request", POST, approval_id=approval_id)
        self.assertFalse(result["executed"])
        self.http_request.assert_not_called()
        retry = security.execute_tool("http_request", POST, approval_id=approval_id)
        self.assertTrue(retry["executed"])


class TestEvaluationHasNoSideEffects(GatewayTestCase):
    def test_policy_engine_evaluation_does_not_touch_the_gateway(self):
        with patch("agent.security.execute_tool") as execute, \
             patch("agent.security._write_audit") as audit:
            policy_engine.evaluate_request({"tool_name": "http_request", "args": GET})
        execute.assert_not_called()
        audit.assert_not_called()
        self.assert_no_tool_ran()


if __name__ == "__main__":
    unittest.main()