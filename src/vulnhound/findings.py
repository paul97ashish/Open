"""Central findings model shared by every scan mode and reporter.

This is the frozen contract that the sast/, deps/, dast/, web/ and reporter
modules all build against. Keep it stable.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable


class Severity(enum.IntEnum):
    """Ordered severity. Higher int == more severe (sortable, thresholdable)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: Any) -> "Severity":
        """Tolerant parse: unknown / missing -> INFO."""
        if isinstance(value, Severity):
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            try:
                return cls(value)
            except ValueError:
                return cls.INFO
        if value is None:
            return cls.INFO
        key = str(value).strip().upper()
        # accept a few common aliases
        aliases = {
            "INFORMATIONAL": "INFO",
            "NONE": "INFO",
            "MODERATE": "MEDIUM",
            "MED": "MEDIUM",
            "WARNING": "MEDIUM",
            "ERROR": "HIGH",
            "SEVERE": "CRITICAL",
            "CRIT": "CRITICAL",
        }
        key = aliases.get(key, key)
        return cls.__members__.get(key, cls.INFO)

    @property
    def label(self) -> str:
        return self.name.lower()


# Allowed values for Finding.source
SOURCES = ("sast", "deps", "dast")


@dataclass
class Finding:
    """A single vulnerability finding.

    Conventions by source:
      - "sast": ``file`` is a repo-relative path; ``start_line``/``end_line`` set.
      - "deps": ``file`` is the manifest path; package name/version live in ``extra``
                (keys ``package``, ``version``, ``ecosystem``, ``fixed_version``).
      - "dast": ``file`` is the affected URL; lines are usually 0.
    """

    title: str
    severity: Severity
    source: str
    description: str
    recommendation: str = ""
    cwe: str = ""
    file: str = ""
    start_line: int = 0
    end_line: int = 0
    confidence: float = 0.5
    references: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Be forgiving about how callers pass severity.
        if not isinstance(self.severity, Severity):
            self.severity = Severity.from_str(self.severity)
        if self.source not in SOURCES:
            # Don't raise; keep pipelines resilient, but normalise empties.
            self.source = self.source or "sast"
        self.cwe = _norm_cwe(self.cwe)
        if self.end_line and self.start_line and self.end_line < self.start_line:
            self.start_line, self.end_line = self.end_line, self.start_line

    # -- serialization -----------------------------------------------------
    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = dict(d or {})
        return cls(
            title=str(d.get("title", "")).strip() or "Untitled finding",
            severity=Severity.from_str(d.get("severity")),
            source=str(d.get("source", "sast")),
            description=str(d.get("description", "")),
            recommendation=str(d.get("recommendation", "")),
            cwe=_norm_cwe(d.get("cwe", "")),
            file=str(d.get("file", "")),
            start_line=_int(d.get("start_line", 0)),
            end_line=_int(d.get("end_line", 0)),
            confidence=_float(d.get("confidence", 0.5)),
            references=list(d.get("references", []) or []),
            extra=dict(d.get("extra", {}) or {}),
        )

    # -- dedupe support ----------------------------------------------------
    def key(self) -> tuple:
        return (
            self.source,
            self.file,
            self.cwe,
            self.start_line,
            self.end_line,
            self.title.strip().lower(),
        )


def _int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _float(v: Any) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return 0.5
    return max(0.0, min(1.0, f))


def _norm_cwe(v: Any) -> str:
    s = str(v or "").strip()
    if not s:
        return ""
    if s.upper().startswith("CWE"):
        digits = "".join(ch for ch in s if ch.isdigit())
        return f"CWE-{digits}" if digits else s.upper()
    if s.isdigit():
        return f"CWE-{s}"
    return s


def _overlap(a: Finding, b: Finding) -> bool:
    """Do two findings refer to overlapping (or both-absent) line ranges?"""
    if not (a.start_line or a.end_line) and not (b.start_line or b.end_line):
        return True  # neither has a range -> treat as same location
    a0, a1 = a.start_line, a.end_line or a.start_line
    b0, b1 = b.start_line, b.end_line or b.start_line
    return a0 <= b1 and b0 <= a1


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    """Merge near-duplicates and return a stably sorted list.

    Two findings merge when they share source, file and cwe and have overlapping
    line ranges. The merged finding keeps the higher severity and confidence and
    unions their references.
    """
    buckets: list[Finding] = []
    for f in findings:
        merged = False
        for kept in buckets:
            if (
                kept.source == f.source
                and kept.file == f.file
                and kept.cwe == f.cwe
                and _overlap(kept, f)
            ):
                kept.severity = max(kept.severity, f.severity)
                kept.confidence = max(kept.confidence, f.confidence)
                for ref in f.references:
                    if ref not in kept.references:
                        kept.references.append(ref)
                # widen the range to cover both
                if f.start_line:
                    kept.start_line = min(kept.start_line or f.start_line, f.start_line)
                kept.end_line = max(kept.end_line, f.end_line)
                merged = True
                break
        if not merged:
            buckets.append(f)
    return sort_findings(buckets)


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Sort by severity DESC, then file, then start_line."""
    return sorted(
        findings,
        key=lambda f: (-int(f.severity), f.file, f.start_line, f.title.lower()),
    )


def max_severity(findings: Iterable[Finding]) -> Severity:
    sev = Severity.INFO
    for f in findings:
        if f.severity > sev:
            sev = f.severity
    return sev


def severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {s.label: 0 for s in Severity}
    for f in findings:
        counts[f.severity.label] += 1
    return counts
