"""Usage tracking, quota governance, and fail-closed limit enforcement for Tripline."""

from __future__ import annotations

import json
import os
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_USAGE_LOG = Path(os.environ.get("TRIPLINE_USAGE_LOG", ROOT / "logs" / "usage.jsonl"))

SUPPORTED_SCOPES = {
    "org",
    "organization",
    "team",
    "user",
    "application",
}


def _normalize_scope_type(scope_type: str) -> str:
    s = str(scope_type).lower().strip()
    if s in {"org", "organization"}:
        return "org"
    return s


class UsageLimitExceeded(Exception):
    """Raised when request, tool-call, or token limits are exceeded."""
    pass


@dataclass
class LimitConfig:
    max_requests: int | None = None
    max_tool_calls: int | None = None
    max_tokens: int | None = None
    window_seconds: int | None = None


@dataclass(frozen=True)
class LimitResult:
    allowed: bool
    reason: str
    scope: str
    remaining: int | None = None


@dataclass
class _ScopeBucket:
    requests: int = 0
    tool_calls: int = 0
    tokens: int = 0
    window_start: float = field(default_factory=time.time)

    def check_and_reset_window(self, window_seconds: int | None, now: float) -> None:
        if window_seconds is not None and window_seconds > 0:
            if now - self.window_start >= window_seconds:
                self.requests = 0
                self.tool_calls = 0
                self.tokens = 0
                self.window_start = now


class UsageTracker:
    """
    Atomic, thread-safe usage tracker with scope-based limits, window resets,
    fail-closed guarantees, and offline persistence.
    """

    def __init__(
        self,
        default_user_limit: LimitConfig | None = None,
        persistence_path: str | Path | None = None,
    ) -> None:
        self.default_user_limit = default_user_limit

        if persistence_path is not None:
            self.persistence_path: Path | None = Path(persistence_path)
        else:
            self.persistence_path = DEFAULT_USAGE_LOG

        self._lock = threading.Lock()

        # Real usage: scope_key -> _ScopeBucket
        self._real_usage: dict[str, _ScopeBucket] = defaultdict(_ScopeBucket)
        # Simulated usage: scope_key -> _ScopeBucket
        self._sim_usage: dict[str, _ScopeBucket] = defaultdict(_ScopeBucket)

        # Configured limits: scope_key -> LimitConfig
        self._scope_limits: dict[str, LimitConfig] = {}

        # Recorded real costs (None unless explicitly recorded)
        self._recorded_cost_usd: float | None = None

        # Per-user aggregate tracking
        self._per_user_real: dict[str, dict[str, int]] = defaultdict(lambda: {"requests": 0, "tool_calls": 0, "tokens": 0})
        self._per_user_sim: dict[str, dict[str, int]] = defaultdict(lambda: {"requests": 0, "tool_calls": 0, "tokens": 0})

    def set_scope_limit(self, scope_type: str, scope_id: str, config: LimitConfig) -> None:
        """Configure a limit for a specific user, team, or org."""
        norm_type = _normalize_scope_type(scope_type)
        scope_key = f"{norm_type}:{scope_id}"
        with self._lock:
            self._scope_limits[scope_key] = config

    def check_and_consume(
        self,
        kind: str,
        *,
        user_id: str | None = None,
        team_id: str | None = None,
        org_id: str | None = None,
        simulated: bool = False,
        tokens: int = 0,
    ) -> LimitResult:
        """
        Atomically check and consume quota.
        Persists the usage record BEFORE returning allowed.
        Fails closed on any error, missing user, unknown kind, or persistence failure.
        """
        try:
            if not user_id or not isinstance(user_id, str) or not user_id.strip():
                return LimitResult(
                    allowed=False,
                    reason="limit_check_failed: user_id is required",
                    scope="user",
                    remaining=None,
                )

            if kind not in {"request", "tool_call"}:
                return LimitResult(
                    allowed=False,
                    reason=f"limit_check_failed: unknown kind '{kind}'",
                    scope="user",
                    remaining=None,
                )

            if not isinstance(tokens, int) or tokens < 0:
                tokens = 0

            with self._lock:
                now = time.time()
                scopes_to_check: list[tuple[str, LimitConfig]] = []

                # 1. User scope
                user_key = f"user:{user_id}"
                user_cfg = self._scope_limits.get(user_key, self.default_user_limit)
                if user_cfg:
                    scopes_to_check.append((user_key, user_cfg))

                # 2. Team scope (applies only if configured)
                if team_id:
                    team_key = f"team:{team_id}"
                    if team_key in self._scope_limits:
                        scopes_to_check.append((team_key, self._scope_limits[team_key]))

                # 3. Org scope (applies only if configured)
                if org_id:
                    org_key = f"org:{org_id}"
                    if org_key in self._scope_limits:
                        scopes_to_check.append((org_key, self._scope_limits[org_key]))

                # Evaluate limits against usage
                min_remaining: int | None = None
                evaluated_scopes: list[tuple[str, _ScopeBucket, LimitConfig]] = []

                for scope_key, cfg in scopes_to_check:
                    bucket = self._sim_usage[scope_key] if simulated else self._real_usage[scope_key]
                    bucket.check_and_reset_window(cfg.window_seconds, now)

                    # Check max requests
                    if kind == "request" and cfg.max_requests is not None:
                        if bucket.requests >= cfg.max_requests:
                            return LimitResult(
                                allowed=False,
                                reason=f"limit_exceeded: {scope_key} max_requests ({cfg.max_requests}) reached",
                                scope=scope_key,
                                remaining=0,
                            )
                        rem = cfg.max_requests - bucket.requests - 1
                        min_remaining = rem if min_remaining is None else min(min_remaining, rem)

                    # Check max tool calls
                    if kind == "tool_call" and cfg.max_tool_calls is not None:
                        if bucket.tool_calls >= cfg.max_tool_calls:
                            return LimitResult(
                                allowed=False,
                                reason=f"limit_exceeded: {scope_key} max_tool_calls ({cfg.max_tool_calls}) reached",
                                scope=scope_key,
                                remaining=0,
                            )
                        rem = cfg.max_tool_calls - bucket.tool_calls - 1
                        min_remaining = rem if min_remaining is None else min(min_remaining, rem)

                    # Check max tokens
                    if tokens > 0 and cfg.max_tokens is not None:
                        if bucket.tokens + tokens > cfg.max_tokens:
                            return LimitResult(
                                allowed=False,
                                reason=f"limit_exceeded: {scope_key} max_tokens ({cfg.max_tokens}) reached",
                                scope=scope_key,
                                remaining=max(0, cfg.max_tokens - bucket.tokens),
                            )

                    evaluated_scopes.append((scope_key, bucket, cfg))

                # Persistence BEFORE returning allowed
                if self.persistence_path:
                    try:
                        self.persistence_path.parent.mkdir(parents=True, exist_ok=True)
                        record_data = {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "user_id": user_id,
                            "team_id": team_id,
                            "org_id": org_id,
                            "kind": kind,
                            "tokens": tokens,
                            "simulated": simulated,
                            "allowed": True,
                        }
                        with open(self.persistence_path, "a", encoding="utf-8") as f:
                            f.write(json.dumps(record_data) + "\n")
                            f.flush()
                            os.fsync(f.fileno())
                    except Exception as persist_err:
                        return LimitResult(
                            allowed=False,
                            reason=f"limit_check_failed: persistence error: {persist_err}",
                            scope="user",
                            remaining=None,
                        )

                # Consume usage (simulated usage never consumes real budgets)
                # If no limit config exists for a scope, we still track the bucket for metrics
                if not evaluated_scopes:
                    # Unconfigured scopes still track used count
                    user_bucket = self._sim_usage[user_key] if simulated else self._real_usage[user_key]
                    if kind == "request":
                        user_bucket.requests += 1
                    elif kind == "tool_call":
                        user_bucket.tool_calls += 1
                    if tokens > 0:
                        user_bucket.tokens += tokens
                else:
                    for scope_key, bucket, cfg in evaluated_scopes:
                        if kind == "request":
                            bucket.requests += 1
                        elif kind == "tool_call":
                            bucket.tool_calls += 1
                        if tokens > 0:
                            bucket.tokens += tokens

                # Also track team/org buckets if provided even without limits
                if team_id and not any(s[0] == f"team:{team_id}" for s in evaluated_scopes):
                    team_key = f"team:{team_id}"
                    tb = self._sim_usage[team_key] if simulated else self._real_usage[team_key]
                    if kind == "request":
                        tb.requests += 1
                    elif kind == "tool_call":
                        tb.tool_calls += 1
                    if tokens > 0:
                        tb.tokens += tokens
                if org_id and not any(s[0] == f"org:{org_id}" for s in evaluated_scopes):
                    org_key = f"org:{org_id}"
                    ob = self._sim_usage[org_key] if simulated else self._real_usage[org_key]
                    if kind == "request":
                        ob.requests += 1
                    elif kind == "tool_call":
                        ob.tool_calls += 1
                    if tokens > 0:
                        ob.tokens += tokens

                # Update per-user aggregates
                user_store = self._per_user_sim[user_id] if simulated else self._per_user_real[user_id]
                if kind == "request":
                    user_store["requests"] += 1
                elif kind == "tool_call":
                    user_store["tool_calls"] += 1
                if tokens > 0:
                    user_store["tokens"] += tokens

                primary_scope = evaluated_scopes[0][0] if evaluated_scopes else f"user:{user_id}"

                return LimitResult(
                    allowed=True,
                    reason="allowed",
                    scope=primary_scope,
                    remaining=min_remaining,
                )

        except Exception as e:
            return LimitResult(
                allowed=False,
                reason=f"limit_check_failed: unexpected error: {e}",
                scope="user",
                remaining=None,
            )

    def enforce(
        self,
        kind: str,
        *,
        user_id: str | None = None,
        team_id: str | None = None,
        org_id: str | None = None,
        simulated: bool = False,
        tokens: int = 0,
    ) -> LimitResult:
        """Check and consume quota, raising UsageLimitExceeded if denied."""
        res = self.check_and_consume(
            kind,
            user_id=user_id,
            team_id=team_id,
            org_id=org_id,
            simulated=simulated,
            tokens=tokens,
        )
        if not res.allowed:
            raise UsageLimitExceeded(res.reason)
        return res

    def summary(self, mode: str = "all") -> dict[str, Any]:
        """
        Return structured summary of usage metrics.
        Never estimates or fabricates monetary savings or unmeasured costs.
        """
        with self._lock:
            now = time.time()
            for b in self._real_usage.values():
                b.check_and_reset_window(None, now)
            for b in self._sim_usage.values():
                b.check_and_reset_window(None, now)

            total_reqs = 0
            total_tools = 0
            total_tokens = 0
            per_user: dict[str, dict[str, int]] = defaultdict(lambda: {"requests": 0, "tool_calls": 0, "tokens": 0})

            if mode in {"all", "real"}:
                for u, counts in self._per_user_real.items():
                    per_user[u]["requests"] += counts["requests"]
                    per_user[u]["tool_calls"] += counts["tool_calls"]
                    per_user[u]["tokens"] += counts["tokens"]
                    total_reqs += counts["requests"]
                    total_tools += counts["tool_calls"]
                    total_tokens += counts["tokens"]

            if mode in {"all", "simulated"}:
                for u, counts in self._per_user_sim.items():
                    per_user[u]["requests"] += counts["requests"]
                    per_user[u]["tool_calls"] += counts["tool_calls"]
                    per_user[u]["tokens"] += counts["tokens"]
                    if mode == "simulated":
                        total_reqs += counts["requests"]
                        total_tools += counts["tool_calls"]
                        total_tokens += counts["tokens"]
                    elif mode == "all":
                        total_reqs += counts["requests"]
                        total_tools += counts["tool_calls"]
                        total_tokens += counts["tokens"]

            limit_remaining: dict[str, Any] = {}
            for scope_key, cfg in self._scope_limits.items():
                bucket = self._real_usage[scope_key]
                limit_remaining[scope_key] = {
                    "max_requests": cfg.max_requests,
                    "used_requests": bucket.requests,
                    "remaining_requests": max(0, cfg.max_requests - bucket.requests) if cfg.max_requests is not None else None,
                    "max_tool_calls": cfg.max_tool_calls,
                    "used_tool_calls": bucket.tool_calls,
                    "remaining_tool_calls": max(0, cfg.max_tool_calls - bucket.tool_calls) if cfg.max_tool_calls is not None else None,
                }

            return {
                "request_count": total_reqs,
                "tool_call_count": total_tools,
                "measured_tokens": total_tokens,
                "per_user": dict(per_user),
                "reported_cost_usd": self._recorded_cost_usd,  # None unless real data recorded
                "limit_remaining": limit_remaining,
            }

    # Backward compatibility with existing tests and app.py
    def configure_limit(
        self,
        *,
        scope_type: str,
        scope_id: str,
        limit: int,
        limit_type: str = "request",
    ) -> None:
        if limit < 0:
            raise ValueError("limit cannot be negative")
        norm_type = _normalize_scope_type(scope_type)
        scope_key = f"{norm_type}:{scope_id}"
        cfg = self._scope_limits.get(scope_key, LimitConfig())
        if limit_type == "request":
            new_cfg = LimitConfig(
                max_requests=limit,
                max_tool_calls=cfg.max_tool_calls,
                max_tokens=cfg.max_tokens,
                window_seconds=cfg.window_seconds,
            )
        else:
            new_cfg = LimitConfig(
                max_requests=cfg.max_requests,
                max_tool_calls=limit,
                max_tokens=cfg.max_tokens,
                window_seconds=cfg.window_seconds,
            )
        self.set_scope_limit(norm_type, scope_id, new_cfg)

    def check_and_record(
        self,
        *,
        scope_type: str,
        scope_id: str,
        limit_type: str = "request",
    ) -> UsageDecision:
        norm_type = _normalize_scope_type(scope_type)
        user_id = scope_id if norm_type == "user" else f"user_{scope_id}"
        team_id = scope_id if norm_type == "team" else None
        org_id = scope_id if norm_type == "org" else None

        scope_key = f"{norm_type}:{scope_id}"
        cfg = self._scope_limits.get(scope_key)
        lim_val = None
        if cfg:
            lim_val = cfg.max_requests if limit_type == "request" else cfg.max_tool_calls

        res = self.check_and_consume(
            limit_type,
            user_id=user_id,
            team_id=team_id,
            org_id=org_id,
        )

        with self._lock:
            bucket = self._real_usage[scope_key]
            used = bucket.requests if limit_type == "request" else bucket.tool_calls

        rem = None
        if lim_val is not None:
            rem = max(0, lim_val - used)

        return UsageDecision(
            allowed=res.allowed,
            scope_type=scope_type,
            scope_id=scope_id,
            used=used,
            limit=lim_val,
            remaining=rem,
            reason=res.reason,
            limit_type=limit_type,
        )

    def get_usage(
        self,
        *,
        scope_type: str,
        scope_id: str,
        limit_type: str = "request",
    ) -> dict[str, int | str | None]:
        norm_type = _normalize_scope_type(scope_type)
        scope_key = f"{norm_type}:{scope_id}"
        with self._lock:
            bucket = self._real_usage[scope_key]
            used = bucket.requests if limit_type == "request" else bucket.tool_calls
            cfg = self._scope_limits.get(scope_key)
            limit = None
            if cfg:
                limit = cfg.max_requests if limit_type == "request" else cfg.max_tool_calls

        return {
            "scope_type": scope_type,
            "scope_id": scope_id,
            "limit_type": limit_type,
            "used": used,
            "limit": limit,
            "remaining": None if limit is None else max(0, limit - used),
        }

    def reset(
        self,
        *,
        scope_type: str,
        scope_id: str,
        limit_type: str = "request",
    ) -> None:
        norm_type = _normalize_scope_type(scope_type)
        scope_key = f"{norm_type}:{scope_id}"
        with self._lock:
            bucket = self._real_usage[scope_key]
            if limit_type == "request":
                bucket.requests = 0
            else:
                bucket.tool_calls = 0

    def get_all_usage(self) -> list[dict[str, Any]]:
        with self._lock:
            records = []
            for scope_key, cfg in sorted(self._scope_limits.items()):
                stype, sid = scope_key.split(":", 1)
                display_type = "organization" if stype == "org" else stype
                bucket = self._real_usage[scope_key]
                if cfg.max_requests is not None:
                    records.append({
                        "scope_type": display_type,
                        "scope_id": sid,
                        "limit_type": "request",
                        "used": bucket.requests,
                        "limit": cfg.max_requests,
                        "remaining": max(0, cfg.max_requests - bucket.requests),
                    })
                if cfg.max_tool_calls is not None:
                    records.append({
                        "scope_type": display_type,
                        "scope_id": sid,
                        "limit_type": "tool_call",
                        "used": bucket.tool_calls,
                        "limit": cfg.max_tool_calls,
                        "remaining": max(0, cfg.max_tool_calls - bucket.tool_calls),
                    })
            return records


# Backward compatibility classes & helpers
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


UsageLimiter = UsageTracker


def check_limit_safely(
    limiter: UsageTracker | None,
    *,
    scope_type: str,
    scope_id: str,
    limit_type: str = "request",
) -> UsageDecision:
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
        norm = _normalize_scope_type(scope_type)
        if norm not in {"org", "team", "user", "application"}:
            return UsageDecision(
                allowed=False,
                scope_type=scope_type,
                scope_id=scope_id,
                used=0,
                limit=0,
                remaining=0,
                reason=f"Limit check failed safely: unsupported scope {scope_type}",
                limit_type=limit_type,
            )
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
    limiter: UsageTracker | None,
    *,
    scope_type: str,
    scope_id: str,
    operation_fn: Callable[..., Any],
    limit_type: str = "request",
    args: tuple[Any, ...] | None = None,
    kwargs: dict[str, Any] | None = None,
) -> dict[str, Any]:
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
