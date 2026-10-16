import pytest

from agent.usage_limits import (
    UsageLimiter,
    check_limit_safely,
    enforce_limit_before_execution,
)


def test_requests_are_allowed_until_limit():
    limiter = UsageLimiter()

    limiter.configure_limit(
        scope_type="organization",
        scope_id="org-001",
        limit=2,
    )

    first = limiter.check_and_record(
        scope_type="organization",
        scope_id="org-001",
    )
    second = limiter.check_and_record(
        scope_type="organization",
        scope_id="org-001",
    )
    third = limiter.check_and_record(
        scope_type="organization",
        scope_id="org-001",
    )

    assert first.allowed is True
    assert second.allowed is True
    assert third.allowed is False
    assert third.used == 2


def test_denied_request_does_not_increase_usage():
    limiter = UsageLimiter()

    limiter.configure_limit(
        scope_type="organization",
        scope_id="org-001",
        limit=1,
    )

    limiter.check_and_record(
        scope_type="organization",
        scope_id="org-001",
    )

    limiter.check_and_record(
        scope_type="organization",
        scope_id="org-001",
    )

    usage = limiter.get_usage(
        scope_type="organization",
        scope_id="org-001",
    )

    assert usage["used"] == 1


def test_organizations_have_independent_counters():
    limiter = UsageLimiter()

    for org in ("org-001", "org-002"):
        limiter.configure_limit(
            scope_type="organization",
            scope_id=org,
            limit=1,
        )

    # org-001 consumes its limit
    org1_first = limiter.check_and_record(
        scope_type="organization",
        scope_id="org-001",
    )
    assert org1_first.allowed is True

    # org-001 is now blocked
    org1_second = limiter.check_and_record(
        scope_type="organization",
        scope_id="org-001",
    )
    assert org1_second.allowed is False

    # org-002 quota remains intact and allowed
    org2_first = limiter.check_and_record(
        scope_type="organization",
        scope_id="org-002",
    )
    assert org2_first.allowed is True

    # org-002 is now also at limit
    org2_second = limiter.check_and_record(
        scope_type="organization",
        scope_id="org-002",
    )
    assert org2_second.allowed is False


def test_team_and_user_budgets():
    limiter = UsageLimiter()

    limiter.configure_limit(
        scope_type="team",
        scope_id="team-nlp",
        limit=2,
    )
    limiter.configure_limit(
        scope_type="user",
        scope_id="user-alice",
        limit=1,
    )

    assert limiter.check_and_record(scope_type="team", scope_id="team-nlp").allowed is True
    assert limiter.check_and_record(scope_type="team", scope_id="team-nlp").allowed is True
    assert limiter.check_and_record(scope_type="team", scope_id="team-nlp").allowed is False

    assert limiter.check_and_record(scope_type="user", scope_id="user-alice").allowed is True
    assert limiter.check_and_record(scope_type="user", scope_id="user-alice").allowed is False


def test_tool_call_limits_independent_of_request_limits():
    limiter = UsageLimiter()

    limiter.configure_limit(
        scope_type="organization",
        scope_id="org-001",
        limit=1,
        limit_type="tool_call",
    )
    limiter.configure_limit(
        scope_type="organization",
        scope_id="org-001",
        limit=5,
        limit_type="request",
    )

    tool_call_1 = limiter.check_and_record(
        scope_type="organization",
        scope_id="org-001",
        limit_type="tool_call",
    )
    assert tool_call_1.allowed is True

    tool_call_2 = limiter.check_and_record(
        scope_type="organization",
        scope_id="org-001",
        limit_type="tool_call",
    )
    assert tool_call_2.allowed is False

    # Request limit remains unaffected
    req_call = limiter.check_and_record(
        scope_type="organization",
        scope_id="org-001",
        limit_type="request",
    )
    assert req_call.allowed is True


def test_check_limit_safely_fails_closed():
    # If limiter is None, fails safely without crashing
    decision = check_limit_safely(
        None,
        scope_type="organization",
        scope_id="org-001",
    )
    assert decision.allowed is False
    assert "unavailable" in decision.reason

    # If invalid scope is passed, fails safely rather than raising uncaught exception
    limiter = UsageLimiter()
    decision_invalid = check_limit_safely(
        limiter,
        scope_type="unsupported_scope",
        scope_id="org-001",
    )
    assert decision_invalid.allowed is False
    assert "failed safely" in decision_invalid.reason


def test_enforce_limit_before_execution_blocks_execution():
    limiter = UsageLimiter()
    limiter.configure_limit(
        scope_type="user",
        scope_id="user-bob",
        limit=1,
    )

    executed_count = 0

    def protected_action():
        nonlocal executed_count
        executed_count += 1
        return "action_complete"

    # First attempt: allowed and executed
    res1 = enforce_limit_before_execution(
        limiter,
        scope_type="user",
        scope_id="user-bob",
        operation_fn=protected_action,
    )
    assert res1["allowed"] is True
    assert res1["executed"] is True
    assert res1["result"] == "action_complete"
    assert executed_count == 1

    # Second attempt: blocked BEFORE execution
    res2 = enforce_limit_before_execution(
        limiter,
        scope_type="user",
        scope_id="user-bob",
        operation_fn=protected_action,
    )
    assert res2["allowed"] is False
    assert res2["executed"] is False
    assert res2["result"] is None
    # Function was NEVER called
    assert executed_count == 1


def test_zero_limit_denies_request():
    limiter = UsageLimiter()

    limiter.configure_limit(
        scope_type="organization",
        scope_id="org-001",
        limit=0,
    )

    result = limiter.check_and_record(
        scope_type="organization",
        scope_id="org-001",
    )

    assert result.allowed is False


def test_unconfigured_scope_has_no_limit():
    limiter = UsageLimiter()

    result = limiter.check_and_record(
        scope_type="user",
        scope_id="user-001",
    )

    assert result.allowed is True
    assert result.limit is None
    assert result.remaining is None


def test_invalid_limit_is_rejected():
    limiter = UsageLimiter()

    with pytest.raises(ValueError):
        limiter.configure_limit(
            scope_type="organization",
            scope_id="org-001",
            limit=-1,
        )
