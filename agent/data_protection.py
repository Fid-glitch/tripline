"""Deterministic, rule-based DLP helpers for Tripline.

Limitations:
- These rules are an MVP, not a complete secret scanner.
- Formats vary; false positives and false negatives are expected.
- Detection does not establish intent or prove that a value is valid.
- Configure customer identifiers and confidential terms for the deployment.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Iterable, Optional


CLASSIFICATIONS = ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED")
_SEVERITY = {
    "PUBLIC": "LOW",
    "INTERNAL": "LOW",
    "CONFIDENTIAL": "HIGH",
    "RESTRICTED": "CRITICAL",
}


@dataclass(frozen=True)
class DLPConfig:
    """Configurable rules; configured terms are matched case-insensitively."""
    customer_identifiers: tuple[str, ...] = ()
    confidential_terms: tuple[str, ...] = ()
    internal_project_markers: tuple[str, ...] = ()
    redact_emails: bool = True
    redact_phones: bool = True


@dataclass(frozen=True)
class Finding:
    """A finding deliberately excludes the matched raw value."""
    detector_type: str
    severity: str
    classification: str
    start: int
    end: int
    recommended_action: str
    confidence: float
    finding_id: str
    # Safe descriptive metadata only; never place matched text here.
    description: str


@dataclass(frozen=True)
class Redaction:
    detector_type: str
    start: int
    end: int
    placeholder: str
    finding_id: str


_PATTERNS = (
    ("private_key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        re.IGNORECASE), "RESTRICTED", 0.99),
    ("authorization_header", re.compile(
        r"(?im)\b(?:authorization|proxy-authorization)\s*:\s*(?:bearer|basic)\s+[^\s,;]+"),
     "RESTRICTED", 0.99),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
     "RESTRICTED", 0.97),
    ("api_key", re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{8,}['\"]?"),
     "RESTRICTED", 0.92),
    ("password_assignment", re.compile(
        r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s,;]{4,}['\"]?"),
     "RESTRICTED", 0.90),
    ("email", re.compile(
        r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
     "CONFIDENTIAL", 0.96),
    ("phone", re.compile(
        r"(?<!\w)(?:\+?\d[\d ().-]{7,}\d)(?!\w)"),
     "CONFIDENTIAL", 0.72),
)


def _term_pattern(term: str) -> Optional[re.Pattern]:
    if not isinstance(term, str) or not term.strip():
        return None
    # Escape configured strings: they are literal terms, not regex patterns.
    return re.compile(re.escape(term.strip()), re.IGNORECASE)


def _safe_text(value) -> Optional[str]:
    # Avoid invoking arbitrary user-defined __str__ methods.
    return value if isinstance(value, str) else None


def scan_text(text: str, config: Optional[DLPConfig] = None) -> list[Finding]:
    """Scan text and return findings with character offsets, never raw matches."""
    text = _safe_text(text)
    if text is None:
        return []
    config = config or DLPConfig()
    if not isinstance(config, DLPConfig):
        return []

    candidates = []
    for detector, pattern, classification, confidence in _PATTERNS:
        if detector == "email" and not config.redact_emails:
            # Detection remains enabled; this flag controls redaction only.
            pass
        for match in pattern.finditer(text):
            candidates.append((match.start(), match.end(), detector,
                              classification, confidence))

    for detector, terms, classification, confidence in (
        ("customer_identifier", config.customer_identifiers, "CONFIDENTIAL", 0.94),
        ("confidential_term", config.confidential_terms, "CONFIDENTIAL", 0.90),
        ("internal_project_marker", config.internal_project_markers, "INTERNAL", 0.90),
    ):
        for term in terms:
            pattern = _term_pattern(term)
            if pattern:
                for match in pattern.finditer(text):
                    candidates.append((match.start(), match.end(), detector,
                                       classification, confidence))

    # Deterministic finding IDs depend on detector and location, not secret content.
    findings = []
    for index, (start, end, detector, classification, confidence) in enumerate(
        sorted(candidates, key=lambda item: (item[0], -(item[1] - item[0]), item[2]))
    ):
        findings.append(Finding(
            detector_type=detector,
            severity=_SEVERITY[classification],
            classification=classification,
            start=start,
            end=end,
            recommended_action="REDACT" if classification != "INTERNAL" else "REVIEW",
            confidence=confidence,
            finding_id=f"DLP-{detector.upper()}-{start}-{end}-{index}",
            description=f"Potential {detector.replace('_', ' ')} detected",
        ))
    return findings


def redact_text(
    text: str,
    findings: Optional[Iterable[Finding]] = None,
    config: Optional[DLPConfig] = None,
) -> tuple[str, list[Redaction]]:
    """Redact detected spans while preserving unrelated text.

    Overlaps are merged into one span. The strongest classification determines
    the placeholder. Placeholders are deterministic for a given input/finding set.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    config = config or DLPConfig()
    findings = list(findings if findings is not None else scan_text(text, config))
    valid = []
    for finding in findings:
        if not isinstance(finding, Finding):
            continue
        if 0 <= finding.start < finding.end <= len(text):
            valid.append(finding)

    # Merge overlapping or touching ranges so replacement never corrupts offsets.
    valid.sort(key=lambda f: (f.start, f.end))
    groups = []
    for finding in valid:
        if groups and finding.start < max(f.end for f in groups[-1]):
            groups[-1].append(finding)
        else:
            groups.append([finding])

    replacements = []
    redactions = []
    rank = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}
    for group in groups:
        start = min(f.start for f in group)
        end = max(f.end for f in group)
        strongest = max(group, key=lambda f: rank.get(f.classification, 3))
        placeholder = f"[REDACTED_{strongest.classification}]"
        replacements.append((start, end, placeholder))
        for f in group:
            redactions.append(Redaction(
                detector_type=f.detector_type, start=f.start, end=f.end,
                placeholder=placeholder, finding_id=f.finding_id,
            ))

    output = text
    for start, end, placeholder in reversed(replacements):
        output = output[:start] + placeholder + output[end:]
    return output, redactions


def mask_value(value: str, visible: int = 2, mask_char: str = "*") -> str:
    """Mask a string without logging or returning the original value."""
    if not isinstance(value, str):
        raise TypeError("value must be a string")
    if not isinstance(visible, int) or visible < 0:
        raise ValueError("visible must be a non-negative integer")
    if not isinstance(mask_char, str) or len(mask_char) != 1:
        raise ValueError("mask_char must be exactly one character")
    if len(value) <= visible:
        return mask_char * len(value)
    return mask_char * (len(value) - visible) + value[-visible:] if visible else mask_char * len(value)
