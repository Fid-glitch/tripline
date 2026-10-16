"""In-memory request and tool-call usage limits for Tripline."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from threading import Lock
from typing import Any, Callable


SUPPORTED_SCOPES = {
    "organization",
    "team",
    "user",
    "application",
}


@dataclass(frozen=True)
class UsageDecision:
    allowed: bool
    scope_type: str
    scope_id: str
    used: int
    limit: int | None
    remaining: int | None
    reason: str
    limit_type: str = "request"


class UsageLimiter:
    """
    Thread-safe in-memory request and tool-call limiter.

    Counters reset when the process restarts.
    This implementation is not distributed rate limiting.
    """

    def __init__(self) -> None:
        self._usage: dict[tuple[str, str, str], int] = defaultdict(int)
        self._limits: dict[tuple[str, str, str], int] = {}
        self._lock = Lock()

    @staticmethod
    def _validate_scope(
        scope_type: str,
        scope_id: str,
    ) -> None:
        if scope_type not in SUPPORTED_SCOPES:
            raise ValueError(f"Unsupported scope_type: {scope_type}")

        if not isinstance(scope_id, str) or not scope_id.strip():
            raise ValueError("scope_id must be a non-empty string")

    def configure_limit(
        self,
        *,
        scope_type: str,
        scope_id: str,
        limit: int,
        limit_type: str = "request",
    ) -> None:
        """Set a non-negative limit for a scope and limit type."""

        self._validate_scope(scope_type, scope_id)

        if not isinstance(limit_type, str) or not limit_type.strip():
            raise ValueError("limit_type must be a non-empty string")

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("limit must be an integer")

        if limit < 0:
            raise ValueError("limit cannot be negative")

        key = (scope_type, scope_id, limit_type)

        with self._lock:
            self._limits[key] = limit

    def check_and_record(
        self,
        *,
        scope_type: str,
        scope_id: str,
        limit_type: str = "request",
    ) -> UsageDecision:
        """
        Atomically check the limit and count an allowed request or tool-call.

        A denied request does not increase the counter.
        """

        self._validate_scope(scope_type, scope_id)

        if not isinstance(limit_type, str) or not limit_type.strip():
            raise ValueError("limit_type must be a non-empty string")

        key = (scope_type, scope_id, limit_type)

        with self._lock:
            limit = self._limits.get(key)

            if limit is None:
                return UsageDecision(
                    allowed=True,
                    scope_type=scope_type,
                    scope_id=scope_id,
                    used=self._usage[key],
                    limit=None,
                    remaining=None,
                    reason=f"No {limit_type} limit configured",
                    limit_type=limit_type,
                )

            used = self._usage[key]

            if used >= limit:
                return UsageDecision(
                    allowed=False,
                    scope_type=scope_type,
                    scope_id=scope_id,
                    used=used,
                    limit=limit,
                    remaining=0,
                    reason=f"{limit_type.capitalize()} limit reached",
                    limit_type=limit_type,
                )

            self._usage[key] += 1
            used += 1

            return UsageDecision(
                allowed=True,
                scope_type=scope_type,
                scope_id=scope_id,
                used=used,
                limit=limit,
                remaining=limit - used,
                reason=f"{limit_type.capitalize()} allowed",
                limit_type=limit_type,
            )

    def get_usage(
        self,
        *,
        scope_type: str,
        scope_id: str,
        limit_type: str = "request",
    ) -> dict[str, int | str | None]:
        """Return usage information for one scope and limit type."""

        self._validate_scope(scope_type, scope_id)
        key = (scope_type, scope_id, limit_type)

        with self._lock:
            used = self._usage[key]
            limit = self._limits.get(key)

        return {
            "scope_type": scope_type,
            "scope_id": scope_id,
            "limit_type": limit_type,
            "used": used,
            "limit": limit,
            "remaining": (
                None if limit is None else max(0, limit - used)
            ),
        }

    def reset(
        self,
        *,
        scope_type: str,
        scope_id: str,
        limit_type: str = "request",
    ) -> None:
        """Reset one scope counter for a limit type."""

        self._validate_scope(scope_type, scope_id)
        key = (scope_type, scope_id, limit_type)

        with self._lock:
            self._usage[key] = 0

    def get_all_usage(self) -> list[dict[str, Any]]:
        """Return a snapshot of all configured and active usages."""

        with self._lock:
            all_keys = set(self._limits.keys()) | set(self._usage.keys())
            records = []
            for scope_type, scope_id, limit_type in sorted(all_keys):
                used = self._usage[(scope_type, scope_id, limit_type)]
                limit = self._limits.get((scope_type, scope_id, limit_type))
                records.append({
                    "scope_type": scope_type,
                    "scope_id": scope_id,
                    "limit_type": limit_type,
                    "used": used,
                    "limit": limit,
                    "remaining": None if limit is None else max(0, limit - used),
                })
            return records


def check_limit_safely(
    limiter: UsageLimiter | None,
    *,
    scope_type: str,
    scope_id: str,
    limit_type: str = "request",
) -> UsageDecision:
    """
    Fail-safe check that fails closed (allowed=False) if the check cannot complete.

    If limiter is None or check raises any exception, the protected operation is denied.
    """
    if limiter is None:
        return UsageDecision(
            allowed=False,
            scope_type=scope_type,
            scope_id=scope_id,
            used=0,
            limit=0,
            remaining=0,
            reason="Limit check failed safely: limiter service unavailable",
            limit_type=limit_type,
        )

    try:
        return limiter.check_and_record(
            scope_type=scope_type,
            scope_id=scope_id,
            limit_type=limit_type,
        )
    except Exception as exc:
        return UsageDecision(
            allowed=False,
            scope_type=scope_type,
            scope_id=scope_id,
            used=0,
            limit=0,
            remaining=0,
            reason=f"Limit check failed safely: {exc}",
            limit_type=limit_type,
        )


def enforce_limit_before_execution(
    limiter: UsageLimiter | None,
    *,
    scope_type: str,
    scope_id: str,
    operation_fn: Callable[..., Any],
    limit_type: str = "request",
    args: tuple[Any, ...] | None = None,
    kwargs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Ensure a limit is checked before a protected operation executes.

    Fails safely if the limit check cannot be completed.
    Never executes the operation if the limit decision is not allowed.
    """
    decision = check_limit_safely(
        limiter,
        scope_type=scope_type,
        scope_id=scope_id,
        limit_type=limit_type,
    )

    call_args = args or ()
    call_kwargs = kwargs or {}

    if not decision.allowed:
        return {
            "allowed": False,
            "executed": False,
            "reason": decision.reason,
            "usage": {
                "used": decision.used,
                "limit": decision.limit,
                "remaining": decision.remaining,
                "scope_type": decision.scope_type,
                "scope_id": decision.scope_id,
                "limit_type": decision.limit_type,
            },
            "result": None,
        }

    try:
        result = operation_fn(*call_args, **call_kwargs)
        return {
            "allowed": True,
            "executed": True,
            "reason": decision.reason,
            "usage": {
                "used": decision.used,
                "limit": decision.limit,
                "remaining": decision.remaining,
                "scope_type": decision.scope_type,
                "scope_id": decision.scope_id,
                "limit_type": decision.limit_type,
            },
            "result": result,
        }
    except Exception as exc:
        return {
            "allowed": True,
            "executed": True,
            "reason": decision.reason,
            "usage": {
                "used": decision.used,
                "limit": decision.limit,
                "remaining": decision.remaining,
                "scope_type": decision.scope_type,
                "scope_id": decision.scope_id,
                "limit_type": decision.limit_type,
            },
            "execution_error": str(exc),
            "result": None,
        }


def calculate_usage_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Calculate aggregate usage metrics from real tracked records.

    Does not fabricate monetary savings or unmeasured values.
    """
    total_scopes = len(records)
    if total_scopes == 0:
        return {
            "total_configured_scopes": 0,
            "total_used": 0,
            "scopes_at_limit": 0,
            "scopes_with_capacity": 0,
        }

    total_used = sum(int(r.get("used", 0) or 0) for r in records)
    at_limit = sum(
        1 for r in records
        if r.get("limit") is not None and int(r.get("used", 0) or 0) >= int(r.get("limit", 0) or 0)
    )
    with_capacity = sum(
        1 for r in records
        if r.get("limit") is None or int(r.get("used", 0) or 0) < int(r.get("limit", 0) or 0)
    )

    return {
        "total_configured_scopes": total_scopes,
        "total_used": total_used,
        "scopes_at_limit": at_limit,
        "scopes_with_capacity": with_capacity,
    }

