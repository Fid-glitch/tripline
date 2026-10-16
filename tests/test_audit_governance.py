"""Comprehensive verification of Tripline Audit, Monitoring and Governance backend."""

import json
import time
import pytest
from pathlib import Path

from agent.audit import (
    AuditLog,
    AuditWriteError,
    AuditInvariantViolation,
    compute_metrics,
)
from agent.usage_limits import (
    UsageTracker,
    LimitConfig,
    LimitResult,
    UsageLimitExceeded,
)


def test_record_and_read_round_trip_unique_event_ids(tmp_path: Path):
    log_file = tmp_path / "audit_test.jsonl"
    logger = AuditLog(log_file)

    e1 = logger.record(
        action_type="tool_execution",
        decision="ALLOW",
        reason="Operation permitted",
        tool_name="read_file",
        user_id="user_alice",
        request_id="req-101",
        attempted=True,
        executed=True,
    )

    e2 = logger.record(
        action_type="tool_execution",
        decision="BLOCK",
        reason="Security policy violation",
        tool_name="run_shell",
        user_id="user_bob",
        request_id="req-102",
        attempted=True,
        executed=False,
    )

    assert e1["event_id"] != e2["event_id"]

    events = logger.read_events()
    assert len(events) == 2
    event_ids = [ev["event_id"] for ev in events]
    assert len(set(event_ids)) == 2
    assert e1["event_id"] in event_ids
    assert e2["event_id"] in event_ids


def test_secrets_never_appear_in_raw_log_file(tmp_path: Path):
    log_file = tmp_path / "secrets_audit.jsonl"
    logger = AuditLog(log_file)

    raw_sk = "sk-live-1234567890abcdef12345"
    raw_akia = "AKIAIOSFODNN7EXAMPLE"
    raw_ghp = "ghp_1234567890123456789012345"
    raw_xox = "xoxb-1234567890-abcdefghij"
    raw_bearer = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    raw_private_key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y1234567890abcdef\n"
        "-----END RSA PRIVATE KEY-----"
    )
    raw_email = "victim_admin@corporate-domain.internal"
    raw_secret_value = "super-secret-password-123"

    logger.record(
        action_type="llm_prompt",
        decision="BLOCK",
        reason=f"Exfiltration attempt using {raw_bearer} and {raw_sk}",
        metadata={
            "password": raw_secret_value,
            "api_key": raw_sk,
            "aws_key": raw_akia,
            "github_token": raw_ghp,
            "slack_token": raw_xox,
            "private_key": raw_private_key,
            "prompt": "Sensitive prompt payload here",
            "messages": [{"role": "user", "content": "Ignore instructions"}],
            "raw_text": f"Contact me at {raw_email} or use password={raw_secret_value}",
        },
    )

    # Read the RAW file bytes / text directly from disk
    raw_content = log_file.read_text(encoding="utf-8")

    assert raw_sk not in raw_content
    assert raw_akia not in raw_content
    assert raw_ghp not in raw_content
    assert raw_xox not in raw_content
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in raw_content
    assert "MIIEowIBAAKCAQEA0Y1234567890abcdef" not in raw_content
    assert raw_email not in raw_content
    assert raw_secret_value not in raw_content
    assert "Sensitive prompt payload here" not in raw_content


def test_block_or_unapproved_ask_cannot_be_recorded_as_executed(tmp_path: Path):
    log_file = tmp_path / "invariants.jsonl"
    logger = AuditLog(log_file)

    # 1. BLOCK with executed=True must raise
    with pytest.raises((ValueError, AuditInvariantViolation)):
        logger.record(
            action_type="shell_exec",
            decision="BLOCK",
            reason="Malicious binary detected",
            attempted=True,
            executed=True,
        )

    # 2. ASK with pending approval and executed=True must raise
    with pytest.raises((ValueError, AuditInvariantViolation)):
        logger.record(
            action_type="data_export",
            decision="ASK",
            reason="Export requires secondary approval",
            approval_status="pending",
            attempted=True,
            executed=True,
        )

    # 3. ASK with no approval (None / not_required) and executed=True must raise
    with pytest.raises((ValueError, AuditInvariantViolation)):
        logger.record(
            action_type="data_export",
            decision="ASK",
            reason="Export requires secondary approval",
            approval_status="not_required",
            attempted=True,
            executed=True,
        )

    # 4. ASK with approval_status="approved" and executed=True IS valid
    logger.record(
        action_type="data_export",
        decision="ASK",
        reason="Supervisor approved export",
        approval_status="approved",
        attempted=True,
        executed=True,
    )


def test_metrics_derive_from_events_split_real_and_simulated_and_empty():
    # Empty input returns zeroes
    empty_metrics = compute_metrics([])
    assert empty_metrics["total_events"] == 0
    assert empty_metrics["real_events"] == 0
    assert empty_metrics["simulated_events"] == 0
    assert empty_metrics["blocked_attempts"] == 0
    assert empty_metrics["blocks_enforced"] == 0
    assert empty_metrics["executed"] == 0
    assert empty_metrics["pending_approvals"] == 0

    events = [
        # Real events
        {
            "event_id": "r1",
            "request_id": "req-1",
            "decision": "ALLOW",
            "approval_status": "not_required",
            "executed": True,
            "simulation_mode": False,
            "tool_name": "db_query",
            "policy_id": "pol-read",
        },
        {
            "event_id": "r2",
            "request_id": "req-2",
            "decision": "BLOCK",
            "approval_status": "not_required",
            "executed": False,
            "simulation_mode": False,
            "tool_name": "shell",
            "policy_id": "pol-sec",
        },
        {
            "event_id": "r3",
            "request_id": "req-3",
            "decision": "ASK",
            "approval_status": "pending",
            "executed": False,
            "simulation_mode": False,
            "tool_name": "file_write",
            "policy_id": "pol-approval",
        },
        # Simulated events
        {
            "event_id": "s1",
            "request_id": "req-sim-1",
            "decision": "ALLOW",
            "approval_status": "not_required",
            "executed": True,
            "simulation_mode": True,
            "tool_name": "mock_tool",
            "policy_id": "pol-mock",
        },
        {
            "event_id": "s2",
            "request_id": "req-sim-2",
            "decision": "BLOCK",
            "approval_status": "not_required",
            "executed": False,
            "simulation_mode": True,
            "tool_name": "mock_tool",
            "policy_id": "pol-mock",
        },
    ]

    all_metrics = compute_metrics(events, mode="all")
    assert all_metrics["total_events"] == 5
    assert all_metrics["real_events"] == 3
    assert all_metrics["simulated_events"] == 2
    assert all_metrics["blocked_attempts"] == 2
    assert all_metrics["blocks_enforced"] == 2
    assert all_metrics["executed"] == 2
    assert all_metrics["pending_approvals"] == 1

    real_metrics = compute_metrics(events, mode="real")
    assert real_metrics["total_events"] == 3
    assert real_metrics["blocked_attempts"] == 1
    assert real_metrics["executed"] == 1

    sim_metrics = compute_metrics(events, mode="simulated")
    assert sim_metrics["total_events"] == 2
    assert sim_metrics["blocked_attempts"] == 1
    assert sim_metrics["executed"] == 1


def test_limits_enforced_before_execution_and_window_reset(tmp_path: Path):
    usage_log = tmp_path / "usage_test.jsonl"
    tracker = UsageTracker(
        default_user_limit=LimitConfig(max_requests=2, window_seconds=1),
        persistence_path=usage_log,
    )

    # User consumes 2 requests
    r1 = tracker.check_and_consume("request", user_id="user_carol")
    assert r1.allowed is True
    assert r1.remaining == 1

    r2 = tracker.check_and_consume("request", user_id="user_carol")
    assert r2.allowed is True
    assert r2.remaining == 0

    # 3rd request is blocked before execution
    r3 = tracker.check_and_consume("request", user_id="user_carol")
    assert r3.allowed is False
    assert r3.remaining == 0

    # enforce() raises UsageLimitExceeded
    with pytest.raises(UsageLimitExceeded):
        tracker.enforce("request", user_id="user_carol")

    # Window reset: wait 1.1s for window to lapse
    time.sleep(1.1)

    # After reset, user can request again
    r_reset = tracker.check_and_consume("request", user_id="user_carol")
    assert r_reset.allowed is True


def test_simulated_vs_real_limit_separation(tmp_path: Path):
    tracker = UsageTracker(
        default_user_limit=LimitConfig(max_requests=1),
        persistence_path=tmp_path / "sim_sep.jsonl",
    )

    # Simulated consumption
    sim_res = tracker.check_and_consume("request", user_id="user_dave", simulated=True)
    assert sim_res.allowed is True

    # Real quota for user_dave must still have capacity and not be exhausted
    real_res = tracker.check_and_consume("request", user_id="user_dave", simulated=False)
    assert real_res.allowed is True

    # Real quota now exhausted
    real_res2 = tracker.check_and_consume("request", user_id="user_dave", simulated=False)
    assert real_res2.allowed is False


def test_fail_closed_on_unknown_kind_missing_user_and_persistence_failure(tmp_path: Path):
    tracker = UsageTracker(
        default_user_limit=LimitConfig(max_requests=10),
        persistence_path=tmp_path / "valid.jsonl",
    )

    # 1. Missing user fails closed
    res_no_user = tracker.check_and_consume("request", user_id=None)
    assert res_no_user.allowed is False
    assert "user_id is required" in res_no_user.reason

    # 2. Unknown kind fails closed
    res_bad_kind = tracker.check_and_consume("unknown_kind_foo", user_id="user_eve")
    assert res_bad_kind.allowed is False
    assert "unknown kind" in res_bad_kind.reason

    # 3. Persistence failure fails closed
    read_only_dir = tmp_path / "unwritable_dir"
    read_only_dir.mkdir()
    # Point persistence path to a directory instead of a file to cause write failure
    bad_tracker = UsageTracker(
        default_user_limit=LimitConfig(max_requests=10),
        persistence_path=read_only_dir,
    )
    res_persist_fail = bad_tracker.check_and_consume("request", user_id="user_eve")
    assert res_persist_fail.allowed is False
    assert "persistence error" in res_persist_fail.reason


def test_reported_cost_usd_stays_none_without_real_cost_data(tmp_path: Path):
    tracker = UsageTracker(persistence_path=tmp_path / "cost_test.jsonl")
    tracker.check_and_consume("request", user_id="user_frank", tokens=150)
    tracker.check_and_consume("tool_call", user_id="user_frank", tokens=300)

    summary = tracker.summary()
    assert summary["request_count"] == 1
    assert summary["tool_call_count"] == 1
    assert summary["measured_tokens"] == 450
    # Cost MUST remain None - never fabricate or estimate monetary savings
    assert summary["reported_cost_usd"] is None


def test_dashboard_metric_functions_return_correct_values_from_seeded_temp_log(tmp_path: Path):
    seed_file = tmp_path / "seeded_audit.jsonl"
    logger = AuditLog(seed_file)

    # Seed 1: Benign real allow
    logger.record(
        action_type="query_docs",
        decision="ALLOW",
        reason="Safe documentation read",
        tool_name="read_file",
        user_id="analyst_1",
        request_id="req-seed-1",
        attempted=True,
        executed=True,
        simulation_mode=False,
    )

    # Seed 2: Blocked real attack
    logger.record(
        action_type="shell_run",
        decision="BLOCK",
        reason="Malicious exfiltration command",
        tool_name="run_shell",
        user_id="attacker_1",
        request_id="req-seed-2",
        attempted=True,
        executed=False,
        simulation_mode=False,
    )

    # Seed 3: Pending approval
    logger.record(
        action_type="export_pii",
        decision="ASK",
        reason="Requires legal officer signoff",
        tool_name="http_post",
        user_id="analyst_2",
        request_id="req-seed-3",
        attempted=True,
        executed=False,
        approval_status="pending",
        simulation_mode=False,
    )

    # Seed 4: Simulated event
    logger.record(
        action_type="mock_scenario",
        decision="ALLOW",
        reason="Simulation demo",
        tool_name="mock_tool",
        user_id="demo_user",
        request_id="req-seed-4",
        attempted=True,
        executed=True,
        simulation_mode=True,
    )

    events = logger.read_events()
    metrics = compute_metrics(events, mode="all")

    assert metrics["total_events"] == 4
    assert metrics["real_events"] == 3
    assert metrics["simulated_events"] == 1
    assert metrics["blocked_attempts"] == 1
    assert metrics["blocks_enforced"] == 1
    assert metrics["executed"] == 2
    assert metrics["pending_approvals"] == 1
    assert metrics["integrity_violations"] == 0
