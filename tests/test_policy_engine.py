import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from agent.data_protection import DLPConfig
from agent.evidence import TRUSTED_EVIDENCE
from agent.policy_engine import (
    ALLOW,
    ASK,
    BLOCK,
    REDACT,
    PolicyConfig,
    PolicyResult,
    evaluate_request,
    normalize_decision,
)

API_KEY_TEXT = "deploy with api_key=sk_test_123456789 now"
SECRET_VALUE = "sk_test_123456789"
PRIVATE_KEY_TEXT = "-----BEGIN PRIVATE KEY-----"
SAFE_GET = {"method": "GET", "url": "https://example.com"}

VALID_CONTEXT = {
    "evidence_id": "mock-consent-001",
    "subject_id": "person-123",
    "asset_id": "image-123",
    "purpose": "portrait_edit",
}


def image_request(**context_overrides):
    context = {**VALID_CONTEXT, **context_overrides}
    return {"domain": "image", "action": "edit_image", "context": context}


class TestDecisions(unittest.TestCase):
    def test_benign_content_is_allowed_with_score_zero(self):
        result = evaluate_request({"content": "Please summarize this public article."})
        self.assertEqual(result.decision, ALLOW)
        self.assertEqual(result.risk_score, 0)
        self.assertTrue(result.execution_permitted)
        self.assertIsNone(result.sanitized_content)
        self.assertIn("does not prove", result.reason)

    def test_benign_tool_request_is_allowed(self):
        result = evaluate_request(
            {"tool_name": "read_file", "args": {"path": "hello.txt"}}
        )
        self.assertEqual(result.decision, ALLOW)
        self.assertEqual(result.risk_score, 0)
        self.assertTrue(result.execution_permitted)

    def test_redact_decision(self):
        result = evaluate_request({"content": "Contact a.person@example.com for help."})
        self.assertEqual(result.decision, REDACT)
        self.assertEqual(result.sanitized_content, "Contact [REDACTED_CONFIDENTIAL] for help.")
        self.assertFalse(result.execution_permitted)
        self.assertEqual(len(result.redactions), 1)
        self.assertEqual(
            set(result.redactions[0]),
            {"detector_type", "start", "end", "placeholder", "finding_id"},
        )

    def test_ask_decision_from_review_label(self):
        result = evaluate_request(
            {"tool_name": "http_request",
             "args": {"method": "POST", "url": "https://example.com"}}
        )
        self.assertEqual(result.decision, ASK)
        self.assertFalse(result.execution_permitted)

    def test_block_decision(self):
        result = evaluate_request({"tool_name": "delete_database", "args": {}})
        self.assertEqual(result.decision, BLOCK)
        self.assertFalse(result.execution_permitted)
        self.assertEqual(result.risk_score, 100)

    def test_result_has_predictable_types(self):
        result = evaluate_request({"content": "Contact a.person@example.com"})
        self.assertIsInstance(result, PolicyResult)
        self.assertIsInstance(result.decision, str)
        self.assertIsInstance(result.risk_score, int)
        self.assertIsInstance(result.risk_signals, tuple)
        self.assertIsInstance(result.applied_rules, tuple)
        self.assertIsInstance(result.reason, str)
        self.assertIsInstance(result.execution_permitted, bool)
        self.assertTrue(0 <= result.risk_score <= 100)
        json.dumps(result.to_dict())  # must be JSON-serializable

    def test_evaluation_is_deterministic(self):
        request = {"content": API_KEY_TEXT}
        self.assertEqual(evaluate_request(request), evaluate_request(request))


class TestDlpFindings(unittest.TestCase):
    def test_restricted_content_is_redacted_without_leaking(self):
        result = evaluate_request({"content": API_KEY_TEXT})
        self.assertEqual(result.decision, REDACT)
        self.assertEqual(result.sanitized_content, "deploy with [REDACTED_RESTRICTED] now")
        self.assertNotIn(SECRET_VALUE, repr(result))
        self.assertNotIn(SECRET_VALUE, json.dumps(result.to_dict()))

    def test_internal_marker_asks_even_with_low_score(self):
        config = PolicyConfig(dlp=DLPConfig(internal_project_markers=("TRIPLINE_INTERNAL",)))
        result = evaluate_request({"content": "notes TRIPLINE_INTERNAL"}, config)
        self.assertEqual(result.decision, ASK)
        self.assertLess(result.risk_score, config.ask_threshold)
        self.assertIsNone(result.sanitized_content)

    def test_configured_customer_identifier_is_redacted(self):
        config = PolicyConfig(dlp=DLPConfig(customer_identifiers=("CUST-9912",)))
        result = evaluate_request({"content": "Order for CUST-9912 shipped"}, config)
        self.assertEqual(result.decision, REDACT)
        self.assertNotIn("CUST-9912", result.sanitized_content)

    def test_ask_and_block_do_not_return_sanitized_content(self):
        result = evaluate_request({"content": PRIVATE_KEY_TEXT})
        self.assertIsNone(result.sanitized_content)
        self.assertEqual(result.redactions, ())

    def test_credentials_in_tool_arguments_are_not_executable(self):
        result = evaluate_request(
            {"tool_name": "http_request",
             "args": {"method": "GET", "url": "https://example.com/?api_key=abcdefgh1234"}}
        )
        self.assertEqual(result.decision, BLOCK)

    def test_confidential_data_in_arguments_asks_instead_of_redacting(self):
        result = evaluate_request(
            {"tool_name": "read_file", "args": {"path": "a.person@example.com.txt"}}
        )
        self.assertEqual(result.decision, ASK)
        self.assertIsNone(result.sanitized_content)


class TestHardRulesAndScores(unittest.TestCase):
    def test_private_key_scores_100_and_blocks(self):
        result = evaluate_request({"content": PRIVATE_KEY_TEXT})
        self.assertEqual(result.decision, BLOCK)
        self.assertEqual(result.risk_score, 100)
        self.assertIn("DLP-PRIVATE-KEY-001", result.applied_rules)

    def test_hard_rule_overrides_low_score(self):
        config = PolicyConfig(ask_threshold=100, block_threshold=100)
        result = evaluate_request(
            {"tool_name": "http_request", "args": SAFE_GET, "content": API_KEY_TEXT},
            config,
        )
        self.assertEqual(result.decision, BLOCK)
        self.assertLess(result.risk_score, 100)
        self.assertIn("DLP-RESTRICTED-EXFIL-001", result.applied_rules)

    def test_score_alone_can_require_approval(self):
        config = PolicyConfig(ask_threshold=30)
        result = evaluate_request(image_request(), config)
        self.assertEqual(result.decision, ASK)
        self.assertIn("SCORE-ASK-THRESHOLD", result.applied_rules)

    def test_default_thresholds_allow_verified_image_edit(self):
        result = evaluate_request(image_request())
        self.assertEqual(result.decision, ALLOW)
        self.assertLess(result.risk_score, 40)

    def test_score_can_escalate_redact_to_block(self):
        config = PolicyConfig(ask_threshold=30, block_threshold=50)
        result = evaluate_request({"content": API_KEY_TEXT}, config)
        self.assertEqual(result.decision, BLOCK)
        self.assertIn("SCORE-BLOCK-THRESHOLD", result.applied_rules)

    def test_score_never_lowers_a_decision(self):
        config = PolicyConfig(ask_threshold=100, block_threshold=100)
        result = evaluate_request({"tool_name": "delete_database", "args": {}}, config)
        self.assertEqual(result.decision, BLOCK)

    def test_invalid_config_values_are_rejected(self):
        with self.assertRaises(ValueError):
            PolicyConfig(ask_threshold=-1)
        with self.assertRaises(ValueError):
            PolicyConfig(block_threshold=101)
        with self.assertRaises(ValueError):
            PolicyConfig(ask_threshold=90, block_threshold=50)
        with self.assertRaises(ValueError):
            PolicyConfig(weights={"RESTRICTED": 101})
        with self.assertRaises(ValueError):
            PolicyConfig(weights={"NOT_A_WEIGHT": 5})
        with self.assertRaises(TypeError):
            PolicyConfig(ask_threshold=True)
        with self.assertRaises(TypeError):
            PolicyConfig(ask_threshold="50")
        with self.assertRaises(TypeError):
            PolicyConfig(weights=[("RESTRICTED", 5)])
        with self.assertRaises(TypeError):
            PolicyConfig(dlp="not a config")

    def test_score_boundaries_zero_and_hundred_are_accepted(self):
        PolicyConfig(ask_threshold=0, block_threshold=100)
        PolicyConfig(ask_threshold=100, block_threshold=100)

    def test_custom_weights_change_the_score(self):
        config = PolicyConfig(weights={"RESTRICTED": 10})
        result = evaluate_request({"content": API_KEY_TEXT}, config)
        self.assertEqual(result.risk_score, 10)
        self.assertEqual(result.decision, REDACT)

    def test_wrong_config_type_fails_closed(self):
        result = evaluate_request({"content": "hello"}, config={"ask_threshold": 1})
        self.assertEqual(result.decision, BLOCK)
        self.assertIn("CONFIG-001", result.applied_rules)


class TestInvalidInput(unittest.TestCase):
    def test_invalid_requests_block_and_never_raise(self):
        bad_requests = [
            None,
            "a string",
            ["list"],
            42,
            {},
            {"unknown_field": 1},
            {"tool_name": 5},
            {"tool_name": "read_file", "args": ["path"]},
            {"args": {"path": "x"}},
            {"content": b"bytes"},
            {"content": 123},
            {"domain": "image"},
            {"action": "edit_image"},
            {"domain": "image", "action": "edit_image", "context": "not a dict"},
        ]
        for request in bad_requests:
            with self.subTest(request=repr(request)):
                result = evaluate_request(request)
                self.assertEqual(result.decision, BLOCK)
                self.assertFalse(result.execution_permitted)
                self.assertIn("REQ-001", result.applied_rules)

    def test_invalid_now_fails_closed(self):
        for bad_now in ("2030-01-01", 12345, datetime(2030, 1, 1)):
            with self.subTest(now=repr(bad_now)):
                result = evaluate_request(image_request(), now=bad_now)
                self.assertEqual(result.decision, BLOCK)

    def test_unexpected_internal_error_fails_closed(self):
        with patch("agent.policy_engine.scan_text", side_effect=RuntimeError("boom")):
            result = evaluate_request({"content": "hello"})
        self.assertEqual(result.decision, BLOCK)
        self.assertIn("ENGINE-ERROR-001", result.applied_rules)
        self.assertFalse(result.execution_permitted)


class TestConsentEvidence(unittest.TestCase):
    def test_valid_evidence_allows_image_edit(self):
        result = evaluate_request(image_request())
        self.assertEqual(result.decision, ALLOW)
        self.assertTrue(result.execution_permitted)
        self.assertIn("EVIDENCE-VALID-001", result.applied_rules)

    def test_missing_evidence_asks(self):
        for request in (
            {"domain": "image", "action": "edit_image"},
            {"domain": "image", "action": "edit_image", "context": {}},
        ):
            with self.subTest(request=repr(request)):
                result = evaluate_request(request)
                self.assertEqual(result.decision, ASK)
                self.assertFalse(result.execution_permitted)

    def test_unknown_evidence_asks(self):
        result = evaluate_request(image_request(evidence_id="no-such-id"))
        self.assertEqual(result.decision, ASK)

    def test_mismatched_subject_asset_or_purpose_ask(self):
        for field_name, value in (
            ("subject_id", "someone-else"),
            ("asset_id", "image-999"),
            ("purpose", "advertising"),
        ):
            with self.subTest(field=field_name):
                result = evaluate_request(image_request(**{field_name: value}))
                self.assertEqual(result.decision, ASK)
                self.assertFalse(result.execution_permitted)

    def test_non_string_evidence_fields_ask(self):
        result = evaluate_request(image_request(evidence_id=["mock-consent-001"]))
        self.assertEqual(result.decision, ASK)

    def test_expired_evidence_asks(self):
        late = datetime(2031, 1, 1, tzinfo=timezone.utc)
        result = evaluate_request(image_request(), now=late)
        self.assertEqual(result.decision, ASK)
        self.assertFalse(result.execution_permitted)

    def test_revoked_evidence_blocks(self):
        revoked = {**TRUSTED_EVIDENCE["mock-consent-001"], "revoked": True}
        with patch.dict(TRUSTED_EVIDENCE, {"mock-consent-001": revoked}):
            result = evaluate_request(image_request())
        self.assertEqual(result.decision, BLOCK)
        self.assertIn("EVIDENCE-REVOKED-001", result.applied_rules)

    def test_denied_consent_blocks_even_with_valid_evidence(self):
        result = evaluate_request(image_request(consent_status="denied"))
        self.assertEqual(result.decision, BLOCK)
        self.assertFalse(result.execution_permitted)
        self.assertIn("CONSENT-DENIED-001", result.applied_rules)

    def test_caller_flags_without_evidence_do_not_allow(self):
        request = {
            "domain": "image",
            "action": "edit_image",
            "context": {"consent_status": "verified", "subject_authorized": True},
        }
        result = evaluate_request(request)
        self.assertEqual(result.decision, ASK)
        self.assertFalse(result.execution_permitted)

    def test_caller_flags_with_mismatched_evidence_do_not_allow(self):
        result = evaluate_request(
            image_request(
                subject_id="someone-else",
                consent_status="verified",
                subject_authorized=True,
            )
        )
        self.assertEqual(result.decision, ASK)

    def test_demo_fixture_is_not_described_as_real_verification(self):
        result = evaluate_request(image_request())
        self.assertIn("demo", result.reason.lower())


class TestLegacyCompatibility(unittest.TestCase):
    def test_label_mapping(self):
        self.assertEqual(normalize_decision("ALLOW"), ALLOW)
        self.assertEqual(normalize_decision("BLOCK"), BLOCK)
        self.assertEqual(normalize_decision("REVIEW"), ASK)
        self.assertEqual(normalize_decision("REDACT"), REDACT)
        self.assertEqual(normalize_decision("ASK"), ASK)

    def test_unknown_labels_fail_closed(self):
        for label in ("bogus", "allow", None, 5, ["ALLOW"], {"a": 1}):
            with self.subTest(label=repr(label)):
                self.assertEqual(normalize_decision(label), BLOCK)

    def test_domain_review_maps_to_ask(self):
        result = evaluate_request({"domain": "medical", "action": "high_risk_symptoms"})
        self.assertEqual(result.decision, ASK)

    def test_domain_block_is_never_softened(self):
        for request in (
            {"domain": "medical", "action": "personalized_dosage"},
            {"domain": "unknown_domain", "action": "anything"},
            {"domain": "medical", "action": "made_up_action"},
        ):
            with self.subTest(request=repr(request)):
                self.assertEqual(evaluate_request(request).decision, BLOCK)

    def test_domain_allow_is_preserved(self):
        result = evaluate_request({"domain": "medical", "action": "general_education"})
        self.assertEqual(result.decision, ALLOW)

    def test_blocked_tool_label_stays_block(self):
        with patch("agent.policy_engine.security.evaluate_policy",
                   return_value=("BLOCK", "forced")):
            result = evaluate_request({"tool_name": "read_file", "args": {"path": "x"}})
        self.assertEqual(result.decision, BLOCK)

    def test_tool_review_label_maps_to_ask(self):
        with patch("agent.policy_engine.security.evaluate_policy",
                   return_value=("REVIEW", "forced")):
            result = evaluate_request({"tool_name": "read_file", "args": {"path": "x"}})
        self.assertEqual(result.decision, ASK)

    def test_unrecognised_legacy_label_from_tool_policy_blocks(self):
        with patch("agent.policy_engine.security.evaluate_policy",
                   return_value=("MAYBE", "forced")):
            result = evaluate_request({"tool_name": "read_file", "args": {"path": "x"}})
        self.assertEqual(result.decision, BLOCK)


class TestNoExecution(unittest.TestCase):
    def test_evaluation_never_executes_tools_or_writes_audit(self):
        requests = [
            {"tool_name": "read_file", "args": {"path": "hello.txt"}},
            {"tool_name": "run_shell", "args": {"command": ["python", "--version"]}},
            {"tool_name": "http_request", "args": SAFE_GET},
            {"tool_name": "http_request",
             "args": {"method": "POST", "url": "https://example.com"}},
            {"tool_name": "delete_database", "args": {}},
            {"content": API_KEY_TEXT},
        ]
        with patch("agent.tools.read_file") as read_file, \
             patch("agent.tools.run_shell") as run_shell, \
             patch("agent.tools.http_request") as http_request, \
             patch("agent.tools.subprocess.run") as subprocess_run, \
             patch("agent.security.execute_tool") as execute_tool, \
             patch("agent.security._write_audit") as write_audit:
            for request in requests:
                evaluate_request(request)

        read_file.assert_not_called()
        run_shell.assert_not_called()
        http_request.assert_not_called()
        subprocess_run.assert_not_called()
        execute_tool.assert_not_called()
        write_audit.assert_not_called()


if __name__ == "__main__":
    unittest.main()