
"""Process-local sliding-window usage limits for the Tripline prototype."""
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import threading

_ALLOWED_SCOPES = {"organization", "user", "application", "org", "app"}
_ATTEMPTS = defaultdict(deque)
_LOCK = threading.Lock()


def _as_utc(now):
    if now is None:
        return datetime.now(timezone.utc)
    if not isinstance(now, datetime):
        raise TypeError("now must be a datetime or None")
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def reset_usage_limits():
    """Clear counters; intended for tests and explicit demo resets."""
    with _LOCK:
        _ATTEMPTS.clear()


def check_and_record(scope_type, scope_id, limit, window_seconds, now=None):
    """Count every attempt, then decide based on prior attempts in the window.

    A request that exceeds the limit is still recorded. Counters are in-memory,
    process-local, and not shared between workers or persisted across restarts.
    """
    if not isinstance(scope_type, str) or scope_type.lower() not in _ALLOWED_SCOPES:
        raise ValueError("scope_type must identify an organization, user, or application")
    if scope_id is None or not str(scope_id).strip():
        raise ValueError("scope_id must be a non-empty identifier")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer")
    if isinstance(window_seconds, bool) or not isinstance(window_seconds, (int, float)) or window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    current = _as_utc(now)
    window = timedelta(seconds=window_seconds)
    key = (scope_type.lower(), str(scope_id))
    with _LOCK:
        attempts = _ATTEMPTS[key]
        cutoff = current - window
        while attempts and attempts[0] <= cutoff:
            attempts.popleft()
        used_before = len(attempts)
        allowed = used_before < limit
        attempts.append(current)
        used = len(attempts)
        reset_at = attempts[0] + window
    return {
        "allowed": allowed,
        "limit": limit,
        "used": used,
        "remaining": max(0, limit - used),
        "reset_at": reset_at.isoformat(),
        "reason": "within_limit" if allowed else "limit_exceeded",
    }
