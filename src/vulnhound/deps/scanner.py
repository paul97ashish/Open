"""Dependency vulnerability scanner entry point.

``run(config, target)`` is the public API consumed by the CLI and web UI.
It discovers dependency manifests, queries OSV.dev for known vulnerabilities,
optionally triages with an LLM, and returns a de-duplicated list of Finding objects.
"""

from __future__ import annotations

import os
from typing import Optional

from vulnhound.config import Config
from vulnhound.deps.manifests import collect_dependencies
from vulnhound.deps.osv import OSV_MOCK_FIXTURE, query_batch, severity_from_osv
from vulnhound.findings import Finding, Severity, dedupe
from vulnhound.model_client import get_client
from vulnhound.prompts import build_deps_triage_user, parse_findings_json


def run(config: Config, target: str) -> list[Finding]:
    """Scan *target* for dependency vulnerabilities and return deduplicated findings.

    Parameters
    ----------
    config:
        Runtime configuration. ``config.mock`` triggers offline mode using mocked
        OSV responses. ``config.model`` and ``config.extra`` control optional
        LLM-based triage.
    target:
        Filesystem path to a directory or manifest file to scan.

    Returns
    -------
    list[Finding]:
        Deduplicated findings with source="deps", extra containing package/version/ecosystem/fixed_version.
    """
    target = os.path.abspath(target)

    # Discover and parse dependencies
    deps = collect_dependencies(target)
    if not deps:
        return []

    # Query OSV for vulnerabilities
    if config.mock:
        # Offline mode: use fixture from config.extra or default
        fixture = config.extra.get("osv_fixture") if config.extra else None
        if fixture is None:
            fixture = OSV_MOCK_FIXTURE
        # Simulate the OSV response structure
        vuln_results = _simulate_osv_from_fixture(deps, fixture)
    else:
        # Online mode: hit the real API
        vuln_results = query_batch(deps)

    # Build findings from vulnerabilities
    all_findings: list[Finding] = []
    client = None

    for dep_idx, dep in enumerate(deps):
        vulns = vuln_results.get(dep_idx, [])
        if not vulns:
            continue

        # Create a finding for each vulnerability
        for vuln in vulns:
            vuln_id = vuln.get("id", "unknown")
            summary = vuln.get("summary", "")
            details = vuln.get("details", "")

            # Determine fixed version (best-effort from affected ranges)
            fixed_version = _extract_fixed_version(vuln)

            # Build title
            title = f"{dep.name} {dep.version}: {vuln_id}"

            # Determine severity
            severity_str = severity_from_osv(vuln)
            severity = Severity.from_str(severity_str)

            # Extract references
            references = []
            for ref in vuln.get("references", []):
                if isinstance(ref, dict) and "url" in ref:
                    references.append(ref["url"])
                elif isinstance(ref, str):
                    references.append(ref)

            # Build the finding
            description = f"{summary}\n{details}".strip() if details else summary
            finding = Finding(
                title=title,
                severity=severity,
                source="deps",
                description=description,
                recommendation="",
                cwe="",
                file=dep.manifest,
                start_line=0,
                end_line=0,
                confidence=0.5,
                references=references,
                extra={
                    "package": dep.name,
                    "version": dep.version,
                    "ecosystem": dep.ecosystem,
                    "fixed_version": fixed_version,
                }
            )

            # Optional: LLM triage for richer description/recommendation
            if not config.mock and config.model:
                finding = _triage_with_llm(
                    client or get_client(config),
                    dep.name,
                    dep.version,
                    vuln,
                    finding
                )
                client = client or get_client(config)

            all_findings.append(finding)

    return dedupe(all_findings)


def _simulate_osv_from_fixture(deps: list, fixture: dict) -> dict:
    """Simulate OSV response from a fixture.

    For testing purposes, check if any dependency matches the fixture data.
    """
    vuln_results = {i: [] for i in range(len(deps))}

    # Simple matching: for each dep, check if there's a vuln in the fixture
    # that matches by package name
    fixture_results = fixture.get("results", [])

    for dep_idx, dep in enumerate(deps):
        for fixture_result in fixture_results:
            vulns = fixture_result.get("vulns", [])
            for vuln in vulns:
                # Check if vuln affects this package version
                affected_list = vuln.get("affected", [])
                is_affected = False

                # Simple heuristic: if no affected info, assume it matches
                if not affected_list:
                    is_affected = True
                else:
                    # Check if dep version falls within affected range
                    for affected in affected_list:
                        if isinstance(affected, dict):
                            ranges = affected.get("ranges", [])
                            for rng in ranges:
                                # Simple version checking
                                if isinstance(rng, dict):
                                    events = rng.get("events", [])
                                    is_affected = _version_in_range(dep.version, events)
                                    if is_affected:
                                        break
                        if is_affected:
                            break

                if is_affected:
                    vuln_results[dep_idx].append(vuln)

    return vuln_results


def _version_in_range(version: str, events: list) -> bool:
    """Simple version range check: does version fall in the affected range?

    Parameters
    ----------
    version:
        Semantic version string (e.g., "1.2.3").
    events:
        List of range events like [{"introduced": "0"}, {"fixed": "2.0.0"}].

    Returns
    -------
    bool:
        True if version is in the affected range, False otherwise.
    """
    if not events:
        return True  # No events means all versions affected

    introduced = "0"
    fixed = None

    for event in events:
        if isinstance(event, dict):
            if "introduced" in event:
                introduced = event["introduced"]
            if "fixed" in event:
                fixed = event["fixed"]

    # Simple string comparison (works for semver in most cases)
    try:
        v = _parse_version(version)
        intro = _parse_version(introduced)
        if v < intro:
            return False
        if fixed:
            fix = _parse_version(fixed)
            if v >= fix:
                return False
        return True
    except Exception:
        return True  # Fallback: assume affected


def _parse_version(version_str: str) -> tuple:
    """Parse version string into a sortable tuple."""
    # Simple approach: split on dots and convert to integers where possible
    parts = []
    for part in version_str.split("."):
        try:
            parts.append((0, int(part)))  # (0, int) sorts before strings
        except ValueError:
            parts.append((1, part))  # (1, str) sorts after ints
    return tuple(parts)


def _extract_fixed_version(vuln: dict) -> str:
    """Extract the fixed version from a vulnerability's affected ranges."""
    affected = vuln.get("affected", [])
    for item in affected:
        if isinstance(item, dict):
            ranges = item.get("ranges", [])
            for rng in ranges:
                if isinstance(rng, dict):
                    events = rng.get("events", [])
                    for event in events:
                        if isinstance(event, dict) and "fixed" in event:
                            return event["fixed"]
    return ""


def _triage_with_llm(
    client: object,
    package: str,
    version: str,
    vuln: dict,
    finding: Finding
) -> Finding:
    """Optionally enhance a finding with LLM triage.

    This is best-effort and guarded — absence of a model never breaks the scan.
    """
    try:
        # Build OSV summary for the LLM
        summary = vuln.get("summary", "")
        osv_summaries = f"- {vuln.get('id', 'unknown')}: {summary}"

        # Call LLM
        user_prompt = build_deps_triage_user(package, version, osv_summaries)
        raw = client.complete("", user_prompt)

        # Parse findings from response
        dicts = parse_findings_json(raw)
        if dicts:
            # Use the first finding to enrich ours
            triage_dict = dicts[0]
            if "description" in triage_dict:
                finding.description = triage_dict["description"]
            if "recommendation" in triage_dict:
                finding.recommendation = triage_dict["recommendation"]
            if "severity" in triage_dict:
                finding.severity = Severity.from_str(triage_dict["severity"])
    except Exception:
        # Best-effort: if triage fails, keep the original finding
        pass

    return finding
