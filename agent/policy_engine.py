
"""Tripline Phase 3: an independent, side-effect-free policy engine.

The engine evaluates requests only. It never executes tools, sends network
requests, or writes audit logs.

Decision strictness: ALLOW < REDACT < ASK < BLOCK.
A risk score can make a decision stricter, never less strict.

TRUSTED_EVIDENCE contains demo fixtures only. It does not provide real-world
identity verification or establish real consent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping, Optional

from agent import security
from agent.data_protection import DLPConfig, redact_text, scan_text
from agent.domain_policies import evaluate_domain_policy_trace
from agent.evidence import verify_evidence

ALLOW = "ALLOW"
REDACT = "REDACT"
ASK = "ASK"
BLOCK = "BLOCK"

DECISIONS = (ALLOW, REDACT, ASK, BLOCK)
_STRICTNESS = {decision: rank for rank, decision in enumerate(DECISIONS)}

_LEGACY_TO_NORMALIZED = {
    "ALLOW": ALLOW,
    "REVIEW": ASK,
    "BLOCK": BLOCK,
    "REDACT": REDACT,
    "ASK": ASK,
}

DEFAULT_WEIGHTS = {
    "INTERNAL": 10,
    "CONFIDENTIAL": 30,
    "RESTRICTED": 60,
    "PRIVATE_KEY": 100,
    "ALLOW": 0,
    "REVIEW": 60,
    "BLOCK": 100,
    "LOW": 5,
    "MEDIUM": 20,
    "HIGH": 35,
    "CRITICAL": 70,
    "EXTRA_SIGNAL": 5,
}

_DECISION_WEIGHT_KEY = {
    ALLOW: "ALLOW",
    REDACT: "REVIEW",
    ASK: "REVIEW",
    BLOCK: "BLOCK",
}

_ALLOWED_REQUEST_KEYS = {
    "tool_name", "args", "content", "domain", "action", "context"
}


def normalize_decision(label: Any) -> str:
    """Normalize legacy decision labels; unknown labels fail closed."""
    if isinstance(label, str):
        return _LEGACY_TO_NORMALIZED.get(label, BLOCK)
    return BLOCK


def _check_score(value: Any, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value <= 100:
        raise ValueError(f"{name} must be between 0 and 100")


@dataclass(frozen=True)
class PolicyConfig:
    """Configurable thresholds, weights, and DLP rules."""

    ask_threshold: int = 40
    block_threshold: int = 80
    weights: Mapping[str, int] = field(default_factory=dict)
    dlp: DLPConfig = field(default_factory=DLPConfig)

    def __post_init__(self):
        _check_score(self.ask_threshold, "ask_threshold")
        _check_score(self.block_threshold, "block_threshold")

        if self.ask_threshold > self.block_threshold:
            raise ValueError("ask_threshold must not exceed block_threshold")
        if not isinstance(self.dlp, DLPConfig):
            raise TypeError("dlp must be a DLPConfig")
        if not isinstance(self.weights, Mapping):
            raise TypeError("weights must be a mapping")

        merged = dict(DEFAULT_WEIGHTS)
        for key, value in self.weights.items():
            if key not in DEFAULT_WEIGHTS:
                raise ValueError("Unknown weight name")
            _check_score(value, f"weight {key}")
            merged[key] = value

        object.__setattr__(self, "weights", MappingProxyType(merged))


@dataclass(frozen=True)
class PolicyResult:
    """Structured result of one policy evaluation."""

    decision: str
    risk_score: int
    risk_signals: tuple
    applied_rules: tuple
    reason: str
    execution_permitted: bool
    sanitized_content: Optional[str] = None
    redactions: tuple = ()

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "risk_score": self.risk_score,
            "risk_signals": [dict(s) for s in self.risk_signals],
            "applied_rules": list(self.applied_rules),
            "reason": self.reason,
            "execution_permitted": self.execution_permitted,
            "sanitized_content": self.sanitized_content,
            "redactions": [dict(r) for r in self.redactions],
        }


def _fail_closed(rule_id: str, reason: str) -> PolicyResult:
    return PolicyResult(
        decision=BLOCK,
        risk_score=100,
        risk_signals=(
            {
                "name": "fail_closed",
                "weight": 100,
                "why": reason,
                "source": "engine",
            },
        ),
        applied_rules=(rule_id,),
        reason=reason,
        execution_permitted=False,
    )


class _Collector:
    """Collect rule decisions and risk signals for one request."""

    def __init__(self, config: PolicyConfig):
        self.config = config
        self.hits = []
        self.signals = []

    def hit(self, rule_id: str, decision: str, reason: str) -> None:
        if not any(existing[0] == rule_id for existing in self.hits):
            self.hits.append((rule_id, decision, reason))

    def signal(self, name: str, weight: int, why: str, source: str) -> None:
        if weight > 0:
            self.signals.append(
                {
                    "name": name,
                    "weight": weight,
                    "why": why,
                    "source": source,
                }
            )

    def decision_weight(self, decision: str) -> int:
        return self.config.weights[_DECISION_WEIGHT_KEY[decision]]


def _validate_request(request: Any) -> Optional[str]:
    """Return an input validation error, or None."""
    if not isinstance(request, dict):
        return "Request must be a dictionary"
    if set(request) - _ALLOWED_REQUEST_KEYS:
        return "Request contains unsupported fields"

    for key in ("tool_name", "content", "domain", "action"):
        value = request.get(key)
        if value is not None and not isinstance(value, str):
            return f"{key} must be a string"

    for key in ("args", "context"):
        value = request.get(key)
        if value is not None and not isinstance(value, dict):
            return f"{key} must be a dictionary"

    if request.get("args") is not None and request.get("tool_name") is None:
        return "args requires tool_name"

    if (request.get("domain") is None) != (request.get("action") is None):
        return "domain and action must be provided together"

    if all(request.get(k) is None for k in ("tool_name", "domain", "content")):
        return "Request has nothing to evaluate"

    return None


def _arg_strings(args: Any):
    """Yield string values and strings inside argument lists."""
    if not isinstance(args, dict):
        return

    for value in args.values():
        if isinstance(value, str):
            yield value
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, str):
                    yield item


def _apply_tool_policy(
    col: _Collector, tool_name: str, args: Optional[dict]
) -> None:
    """Reuse the existing side-effect-free tool policy."""
    legacy_decision, why = security.evaluate_policy(
        tool_name, {} if args is None else args
    )
    decision = normalize_decision(legacy_decision)
    col.hit(
        f"TOOL-POLICY-{decision}",
        decision,
        f"Tool policy: {why}",
    )
    col.signal(
        "tool_policy",
        col.decision_weight(decision),
        why,
        "tool",
    )


def _image_edit_context(
    col: _Collector, context: Optional[dict], now
) -> dict:
    """Validate registered demo evidence without trusting caller flags."""
    ctx = {} if context is None else context

    ids = [
        ctx.get("evidence_id"),
        ctx.get("subject_id"),
        ctx.get("asset_id"),
        ctx.get("purpose"),
    ]
    identifiers_valid = all(
        isinstance(value, str) and value for value in ids
    )

    if not identifiers_valid:
        valid = False
        evidence_reason = "Evidence identifiers are missing or invalid"
    else:
        outcome = verify_evidence(*ids, now=now)
        valid = outcome.get("valid") is True
        evidence_reason = str(
            outcome.get("reason", "Evidence was not accepted")
        )

    revoked = not valid and "revoked" in evidence_reason.lower()
    denied = ctx.get("consent_status") == "denied"

    if valid:
        col.hit(
            "EVIDENCE-VALID-001",
            ALLOW,
            "Registered demo evidence matches the subject, asset, and purpose",
        )
    elif revoked:
        col.hit(
            "EVIDENCE-REVOKED-001",
            BLOCK,
            "Consent evidence has been revoked",
        )
        col.signal(
            "consent_evidence",
            col.decision_weight(BLOCK),
            evidence_reason,
            "evidence",
        )
    else:
        col.hit(
            "EVIDENCE-INVALID-001",
            ASK,
            f"Consent evidence not accepted: {evidence_reason}",
        )
        col.signal(
            "consent_evidence",
            col.decision_weight(ASK),
            evidence_reason,
            "evidence",
        )

    if denied:
        col.hit(
            "CONSENT-DENIED-001",
            BLOCK,
            "Consent was reported as denied; valid evidence does not override a denial",
        )
        col.signal(
            "consent_denied",
            col.decision_weight(BLOCK),
            "Consent denied",
            "context",
        )

    if denied or revoked:
        consent_status = "denied"
    elif valid:
        consent_status = "verified"
    else:
        consent_status = "unverified"

    # Never forward malformed identifiers to the domain policy.
    # Invalid evidence remains unverified and cannot authorize the request.
    safe_ids = {
        key: value if identifiers_valid else None
        for key, value in zip(
            ("evidence_id", "subject_id", "asset_id", "purpose"),
            ids,
        )
    }

    return {
        **safe_ids,
        "consent_status": consent_status,
        "subject_authorized": valid and not denied,
    }


def _apply_domain_policy(col, domain, action, context, now) -> None:
    domain_context = context

    if domain == "image" and action == "edit_image":
        domain_context = _image_edit_context(col, context, now)

    trace = evaluate_domain_policy_trace(domain, action, domain_context)
    decision = normalize_decision(trace.get("decision"))
    rule_id = str(trace.get("rule_id", "DOMAIN-UNKNOWN"))
    domain_reason = str(trace.get("reason", "no reason given"))

    col.hit(
        rule_id,
        decision,
        f"Domain policy: {domain_reason}",
    )

    valid_image_evidence = (
        domain == "image"
        and action == "edit_image"
        and domain_context.get("consent_status") == "verified"
    )

    if not valid_image_evidence:
        col.signal(
            "domain_policy",
            col.decision_weight(decision),
            domain_reason,
            "domain",
        )

    level = str(trace.get("risk_level"))
    level_weight = col.config.weights.get(
        level, col.config.weights["HIGH"]
    )
    col.signal(
        "domain_risk_level",
        level_weight,
        f"Domain risk level {level}",
        "domain",
    )


def _apply_dlp(col: _Collector, tool_name, content, args) -> list:
    """Scan content and tool arguments; return content findings."""
    config = col.config
    scanned = []

    if content is not None:
        scanned += [
            ("content", finding)
            for finding in scan_text(content, config.dlp)
        ]

    for text in _arg_strings(args):
        scanned += [
            ("args", finding)
            for finding in scan_text(text, config.dlp)
        ]

    groups = {}
    for source, finding in scanned:
        key = (source, finding.detector_type, finding.classification)
        groups.setdefault(key, []).append(finding)

    for (source, detector, classification), items in groups.items():
        is_private_key = detector == "private_key"

        weight = (
            config.weights["PRIVATE_KEY"]
            if is_private_key
            else config.weights.get(
                classification, config.weights["RESTRICTED"]
            )
        )

        col.signal(
            detector,
            weight,
            f"{len(items)} potential {detector.replace('_', ' ')} finding(s), "
            f"classified {classification}",
            source,
        )

        if is_private_key:
            col.hit(
                "DLP-PRIVATE-KEY-001",
                BLOCK,
                "Potential private-key material detected; this is never permitted",
            )
        elif classification == "RESTRICTED":
            if tool_name == "http_request":
                col.hit(
                    "DLP-RESTRICTED-EXFIL-001",
                    BLOCK,
                    "Potential restricted credential in a request that could leave the system",
                )
            elif source == "args":
                col.hit(
                    "DLP-RESTRICTED-ARGS-001",
                    ASK,
                    "Potential restricted credential in tool arguments, which cannot be sanitized here",
                )
            else:
                col.hit(
                    "DLP-RESTRICTED-001",
                    REDACT,
                    "Potential restricted credential detected in content",
                )
        elif classification == "CONFIDENTIAL":
            if source == "args":
                col.hit(
                    "DLP-CONFIDENTIAL-ARGS-001",
                    ASK,
                    "Potential confidential data in tool arguments, which cannot be sanitized here",
                )
            else:
                col.hit(
                    "DLP-CONFIDENTIAL-001",
                    REDACT,
                    "Potential confidential data detected in content",
                )
        else:
            col.hit(
                "DLP-INTERNAL-001",
                ASK,
                "Potential internal-only marker detected; review recommended",
            )

    return [
        finding for source, finding in scanned if source == "content"
    ]


def _score(col: _Collector) -> int:
    weights = [signal["weight"] for signal in col.signals]
    if not weights:
        return 0

    total = (
        max(weights)
        + col.config.weights["EXTRA_SIGNAL"] * (len(weights) - 1)
    )
    return min(100, total)


def _finalize(col: _Collector, content, content_findings) -> PolicyResult:
    config = col.config
    score = _score(col)

    decision = ALLOW
    for _, vote, _ in col.hits:
        if _STRICTNESS[vote] > _STRICTNESS[decision]:
            decision = vote

    if score >= config.block_threshold and decision != BLOCK:
        decision = BLOCK
        col.hit(
            "SCORE-BLOCK-THRESHOLD",
            BLOCK,
            f"Risk score {score} reached the block threshold "
            f"({config.block_threshold})",
        )
    elif decision == ALLOW and score >= config.ask_threshold:
        decision = ASK
        col.hit(
            "SCORE-ASK-THRESHOLD",
            ASK,
            f"Risk score {score} reached the approval threshold "
            f"({config.ask_threshold})",
        )

    if not col.hits:
        col.hit(
            "NO-RESTRICTIVE-RULE-001",
            ALLOW,
            "No restrictive rule matched",
        )

    reasons = [
        text for _, vote, text in col.hits if vote == decision
    ]
    reason = "; ".join(reasons)

    if decision == ALLOW:
        reason += (
            ". Rule-based result only: a low risk score does not prove "
            "the request is safe"
        )

    if any(
        rule_id == "EVIDENCE-VALID-001"
        for rule_id, _, _ in col.hits
    ):
        reason += (
            ". Evidence is a demo fixture; this is not real-world identity "
            "or consent verification"
        )

    sanitized = None
    redactions = ()

    if decision == REDACT and content is not None and content_findings:
        sanitized, applied = redact_text(content, content_findings)
        redactions = tuple(
            {
                "detector_type": item.detector_type,
                "start": item.start,
                "end": item.end,
                "placeholder": item.placeholder,
                "finding_id": item.finding_id,
            }
            for item in applied
        )

    return PolicyResult(
        decision=decision,
        risk_score=score,
        risk_signals=tuple(col.signals),
        applied_rules=tuple(
            rule_id for rule_id, _, _ in col.hits
        ),
        reason=reason,
        execution_permitted=(decision == ALLOW),
        sanitized_content=sanitized,
        redactions=redactions,
    )


def _evaluate(request, config, now) -> PolicyResult:
    if config is None:
        config = PolicyConfig()
    elif not isinstance(config, PolicyConfig):
        return _fail_closed(
            "CONFIG-001",
            "Invalid policy configuration",
        )

    if now is not None and (
        not isinstance(now, datetime) or now.tzinfo is None
    ):
        return _fail_closed(
            "REQ-002",
            "now must be a timezone-aware datetime",
        )

    problem = _validate_request(request)
    if problem:
        return _fail_closed("REQ-001", problem)

    tool_name = request.get("tool_name")
    args = request.get("args")
    content = request.get("content")
    domain = request.get("domain")
    action = request.get("action")
    context = request.get("context")

    col = _Collector(config)

    if tool_name is not None:
        _apply_tool_policy(col, tool_name, args)

    if domain is not None:
        _apply_domain_policy(col, domain, action, context, now)

    content_findings = _apply_dlp(col, tool_name, content, args)
    return _finalize(col, content, content_findings)


def evaluate_request(
    request: Any,
    config: Optional[PolicyConfig] = None,
    now: Optional[datetime] = None,
) -> PolicyResult:
    """Evaluate a request without executing it.

    Image-edit requests must provide registered evidence identifiers:
    evidence_id, subject_id, asset_id, and purpose. Caller-provided flags
    alone never establish authorization.

    Invalid input and unexpected errors fail closed to BLOCK.
    """
    try:
        return _evaluate(request, config, now)
    except Exception:
        return _fail_closed(
            "ENGINE-ERROR-001",
            "Policy evaluation failed unexpectedly; request denied "
            "(fail closed)",
        )
