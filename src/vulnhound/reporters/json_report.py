"""Machine-readable JSON report."""

from __future__ import annotations

import json
from typing import Iterable

from vulnhound.findings import Finding, severity_counts, sort_findings


def render(findings: Iterable[Finding], target: str = "") -> str:
    findings = sort_findings(findings)
    payload = {
        "tool": "vulnhound",
        "target": target,
        "summary": {
            "total": len(findings),
            "by_severity": severity_counts(findings),
        },
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)
