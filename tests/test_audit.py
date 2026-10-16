import json
import pytest

from agent.audit import create_event, read_events, write_event


def test_create_event_has_required_fields():
    event = create_event(
        action="tool_call",
        decision="ALLOW",
        reason="Policy permitted the action",
        request_id="req-001",
        organization_id="org-001",
        attempted=True,
        executed=False,
    )

    assert event["event_id"]
    assert event["timestamp"]
    assert event["action"] == "tool_call"
    assert event["decision"] == "ALLOW"
    assert event["attempted"] is True
    assert event["executed"] is False


def test_governance_fields_and_pending_approval_safety():
    event = create_event(
        action="read_file",
        tool="file_reader",
        decision="REVIEW",
        reason="Human in the loop approval required",
        organization_id="org-acme",
        team_id="team-sec",
        user_id="user-123",
        risk_score=0.85,
        risk_level="HIGH",
        risk_signals=["unusual_access_time", "bulk_read"],
        approval_status="PENDING",
        simulation_status="SIMULATED",
        attempted=True,
        executed=False,
    )

    assert event["tool"] == "file_reader"
    assert event["team_id"] == "team-sec"
    assert event["approval_status"] == "PENDING"
    assert event["simulation_status"] == "SIMULATED"
    assert "bulk_read" in event["risk_signals"]

    # Pending approval must NEVER be treated as permission to execute
    with pytest.raises(ValueError, match="pending approval"):
        create_event(
            action="read_file",
            decision="REVIEW",
            reason="Awaiting supervisor approval",
            approval_status="PENDING",
            attempted=True,
            executed=True,
        )


def test_sensitive_dictionary_fields_are_redacted():
    event = create_event(
        action="authentication",
        decision="BLOCK",
        reason="Credentials rejected",
        details={
            "api_key": "sample-secret-value",
            "username": "sample-user",
        },
    )

    serialized = json.dumps(event)

    assert "sample-secret-value" not in serialized
    assert event["details"]["api_key"] == "[REDACTED]"
    assert event["details"]["username"] == "sample-user"


def test_bearer_token_and_private_keys_are_redacted():
    event = create_event(
        action="http_request",
        decision="BLOCK",
        reason="Bearer abc123.secret456 is invalid",
        details={
            "key_dump": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----",
            "header": "api_key=my-super-secret-key-999",
        },
    )

    serialized = json.dumps(event)

    assert "abc123.secret456" not in serialized
    assert "MIIEowIBAAKCAQEA0" not in serialized
    assert "my-super-secret-key-999" not in serialized
    assert "[REDACTED_PRIVATE_KEY]" in serialized


def test_write_and_read_events(tmp_path):
    audit_file = tmp_path / "audit.jsonl"

    event = create_event(
        action="tool_call",
        decision="BLOCK",
        reason="Operation denied",
    )

    write_event(event, audit_file)
    events = read_events(audit_file)

    assert len(events) == 1
    assert events[0]["event_id"] == event["event_id"]


def test_missing_file_returns_empty_list(tmp_path):
    assert read_events(tmp_path / "missing.jsonl") == []


def test_malformed_lines_are_skipped(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    audit_file.write_text(
        '{"event_id": "valid"}\ninvalid-json\n',
        encoding="utf-8",
    )

    events = read_events(audit_file)

    assert len(events) == 1
    assert events[0]["event_id"] == "valid"
