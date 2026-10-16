from agent.audit import calculate_audit_metrics
from agent.usage_limits import calculate_usage_metrics


def test_empty_audit_metrics():
    metrics = calculate_audit_metrics([])
    assert metrics["total_events"] == 0
    assert metrics["blocked"] == 0
    assert metrics["allowed"] == 0
    assert metrics["review"] == 0
    assert metrics["simulated"] == 0
    assert metrics["real"] == 0
    assert metrics["pending_approvals"] == 0
    assert metrics["block_rate_pct"] == 0.0


def test_audit_metrics_from_actual_events():
    events = [
        {
            "event_id": "1",
            "decision": "ALLOW",
            "approval_status": "APPROVED",
            "simulation_status": "SIMULATED",
            "executed": True,
            "organization_id": "org-1",
            "user_id": "user-a",
        },
        {
            "event_id": "2",
            "decision": "BLOCK",
            "approval_status": "NOT_REQUIRED",
            "simulation_status": "REAL",
            "executed": False,
            "organization_id": "org-1",
            "user_id": "user-b",
        },
        {
            "event_id": "3",
            "decision": "REVIEW",
            "approval_status": "PENDING",
            "simulation_status": "REAL",
            "executed": False,
            "organization_id": "org-2",
            "user_id": "user-c",
        },
    ]

    metrics = calculate_audit_metrics(events)
    assert metrics["total_events"] == 3
    assert metrics["allowed"] == 1
    assert metrics["blocked"] == 1
    assert metrics["review"] == 1
    assert metrics["simulated"] == 1
    assert metrics["real"] == 2
    assert metrics["pending_approvals"] == 1
    assert metrics["unique_organizations"] == 2
    assert metrics["unique_users"] == 3
    assert metrics["block_rate_pct"] == 33.3


def test_usage_metrics_from_real_records():
    records = [
        {
            "scope_type": "organization",
            "scope_id": "org-1",
            "limit_type": "request",
            "used": 10,
            "limit": 10,
            "remaining": 0,
        },
        {
            "scope_type": "team",
            "scope_id": "team-sec",
            "limit_type": "tool_call",
            "used": 3,
            "limit": 5,
            "remaining": 2,
        },
        {
            "scope_type": "user",
            "scope_id": "user-x",
            "limit_type": "request",
            "used": 4,
            "limit": None,
            "remaining": None,
        },
    ]

    metrics = calculate_usage_metrics(records)
    assert metrics["total_configured_scopes"] == 3
    assert metrics["total_used"] == 17
    assert metrics["scopes_at_limit"] == 1
    assert metrics["scopes_with_capacity"] == 2
