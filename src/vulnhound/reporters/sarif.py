"""SARIF 2.1.0 report, suitable for GitHub code scanning upload."""

from __future__ import annotations

import json
from typing import Iterable

from vulnhound import __version__
from vulnhound.findings import Finding, Severity, sort_findings

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {
    Severity.INFO: "none",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def _level(sev: Severity) -> str:
    return _LEVEL.get(sev, "warning")


def _rule_id(f: Finding) -> str:
    return f.cwe or f.title or "vulnhound.finding"


def render(findings: Iterable[Finding], target: str = "") -> str:
    findings = sort_findings(findings)

    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        rid = _rule_id(f)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f.cwe or f.title or "Finding",
                "shortDescription": {"text": f.title or rid},
                "properties": {"security-severity": _security_severity(f.severity)},
            }

        result = {
            "ruleId": rid,
            "level": _level(f.severity),
            "message": {"text": _message(f)},
            "properties": {
                "source": f.source,
                "confidence": f.confidence,
                "severity": f.severity.label,
            },
        }
        location = _location(f)
        if location is not None:
            result["locations"] = [location]
        results.append(result)

    sarif = {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vulnhound",
                        "informationUri": "https://github.com/paul97ashish/open",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {"target": target},
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _message(f: Finding) -> str:
    parts = [f.description or f.title]
    if f.recommendation:
        parts.append(f"Recommendation: {f.recommendation}")
    return "\n".join(p for p in parts if p)


def _location(f: Finding):
    if not f.file:
        return None
    physical = {"artifactLocation": {"uri": f.file}}
    if f.start_line and f.start_line > 0:
        region = {"startLine": f.start_line}
        if f.end_line and f.end_line >= f.start_line:
            region["endLine"] = f.end_line
        physical["region"] = region
    return {"physicalLocation": physical}


def _security_severity(sev: Severity) -> str:
    # GitHub uses a 0.0-10.0 numeric scale for security-severity.
    return {
        Severity.INFO: "0.0",
        Severity.LOW: "3.0",
        Severity.MEDIUM: "5.5",
        Severity.HIGH: "8.0",
        Severity.CRITICAL: "9.5",
    }.get(sev, "5.5")
