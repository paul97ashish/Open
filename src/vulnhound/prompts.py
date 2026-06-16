"""Prompt templates and robust response parsing shared by all scan modes."""

from __future__ import annotations

import json
from typing import Any

SECURITY_AUDITOR_SYSTEM = """\
You are a senior application-security auditor performing an authorized review.
Identify only REAL, high-signal security vulnerabilities — do not invent issues
and do not report stylistic nits.

For every finding, think about concrete exploitability (who is the attacker, what
do they control, what is the impact). Prefer precision over recall: it is better
to omit a doubtful issue than to flood the report with false positives.

You MUST respond with a STRICT JSON array and nothing else — no markdown, no prose,
no code fences. Each array element is an object with EXACTLY these keys:
  - "title": short human title of the vulnerability
  - "severity": one of "info", "low", "medium", "high", "critical"
  - "cwe": the most relevant CWE id like "CWE-89" (empty string if unknown)
  - "start_line": integer line number where the issue begins (0 if not applicable)
  - "end_line": integer line number where it ends (0 if not applicable)
  - "description": what the vulnerability is and why it is exploitable
  - "recommendation": concrete remediation guidance
  - "confidence": a number from 0 to 1

If there are no vulnerabilities, respond with an empty array: []
"""


def build_sast_user(path: str, numbered_code: str) -> str:
    return (
        f"Review the following source file for security vulnerabilities.\n"
        f"File: {path}\n"
        f"Each line is prefixed with its line number. Use those exact numbers in "
        f"start_line/end_line.\n\n"
        f"```\n{numbered_code}\n```\n\n"
        f"Return the JSON array of findings now."
    )


def build_deps_triage_user(package: str, version: str, osv_summaries: str) -> str:
    return (
        f"An authorized dependency audit found advisories for a package in use.\n"
        f"Package: {package}\nInstalled version: {version}\n\n"
        f"Advisories (from OSV.dev):\n{osv_summaries}\n\n"
        f"Triage these for this project: assess real-world severity and "
        f"exploitability and give concise upgrade/mitigation advice. "
        f"Set \"file\" handling aside; just return the JSON array of findings "
        f"(one per distinct advisory you consider relevant)."
    )


def build_dast_user(url: str, evidence: str) -> str:
    return (
        f"During an AUTHORIZED dynamic test of a web application, the following "
        f"evidence was collected.\nURL: {url}\n\n"
        f"Evidence:\n{evidence}\n\n"
        f"Identify security vulnerabilities supported by this evidence and return "
        f"the JSON array of findings. Use line 0 for all findings."
    )


def parse_findings_json(raw: str) -> list[dict]:
    """Best-effort extraction of a list of finding dicts from model output.

    Handles code fences, surrounding prose, a single object instead of an array,
    and trailing junk. Never raises — returns [] on total failure.
    """
    if not raw:
        return []
    text = raw.strip()

    # Strip ```json ... ``` or ``` ... ``` fences if present.
    if text.startswith("```"):
        text = text.strip("`")
        # drop a leading language tag like "json\n"
        newline = text.find("\n")
        if newline != -1 and " " not in text[:newline]:
            text = text[newline + 1 :]
        text = text.strip().rstrip("`").strip()

    # 1) Try the outermost JSON array.
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        candidate = text[start : end + 1]
        parsed = _try_load(candidate)
        if isinstance(parsed, list):
            return [d for d in parsed if isinstance(d, dict)]

    # 2) Fall back to a single object.
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        parsed = _try_load(text[start : end + 1])
        if isinstance(parsed, dict):
            return [parsed]

    # 3) Maybe the whole thing is already valid JSON of some shape.
    parsed = _try_load(text)
    if isinstance(parsed, list):
        return [d for d in parsed if isinstance(d, dict)]
    if isinstance(parsed, dict):
        return [parsed]
    return []


def _try_load(s: str) -> Any:
    try:
        return json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return None
