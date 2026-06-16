"""Query OSV.dev for known vulnerabilities in dependencies."""

from __future__ import annotations

from typing import Optional

from vulnhound.deps.manifests import Dependency


# Mock fixture: a canned OSV querybatch response for testing offline.
# Structure matches OSV /v1/querybatch response.
OSV_MOCK_FIXTURE = {
    "results": [
        # Example: a vulnerable version of requests
        {
            "vulns": [
                {
                    "id": "GHSA-2p6m-p686-q6pc",
                    "summary": "Requests library before 2.20.0 does not validate SSL certificates",
                    "details": "The requests library in versions before 2.20.0 has improper certificate validation",
                    "severity": "HIGH",
                    "references": [
                        {"url": "https://github.com/psf/requests/security/advisories/GHSA-2p6m-p686-q6pc"}
                    ],
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "2.20.0"}
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    ]
}


def query_batch(
    deps: list[Dependency],
    client: Optional[object] = None,
    base_url: str = "https://api.osv.dev"
) -> dict:
    """Query OSV.dev /v1/querybatch for vulnerabilities in a batch of dependencies.

    Parameters
    ----------
    deps:
        List of Dependency objects to query.
    client:
        Optional HTTP client object with .post(url, json=...) method returning an
        object with .json() and .raise_for_status() methods. If None, uses httpx.
    base_url:
        Base URL for OSV API (default: https://api.osv.dev).

    Returns
    -------
    dict:
        Mapping from dependency index (int) to list of vulnerability dicts.
        Each vuln dict has keys: "id", "summary", "details", "severity", "fixed", "references".
    """
    if not deps:
        return {}

    # Build the querybatch request
    queries = []
    for dep in deps:
        queries.append({
            "package": {
                "name": dep.name,
                "ecosystem": dep.ecosystem
            },
            "version": dep.version
        })

    request_body = {"queries": queries}

    # If no client provided, create an httpx client
    if client is None:
        try:
            import httpx
            client = httpx.Client()
        except ImportError:
            # Graceful fallback: return empty results if httpx not available
            return {i: [] for i in range(len(deps))}

    # Make the request
    try:
        response = client.post(f"{base_url}/v1/querybatch", json=request_body)
        response.raise_for_status()
        data = response.json()
    except Exception:
        # Network failure or JSON decode error: return empty results
        return {i: [] for i in range(len(deps))}

    # Parse the response and map results to dependency indices
    results_map = {}
    results = data.get("results", [])
    for idx, result in enumerate(results):
        if idx < len(deps):
            vulns = result.get("vulns", [])
            results_map[idx] = vulns

    # Ensure all deps are in the map (even with empty vulns)
    for i in range(len(deps)):
        if i not in results_map:
            results_map[i] = []

    return results_map


def severity_from_osv(vuln: dict) -> str:
    """Map OSV severity / CVSS score to one of: info, low, medium, high, critical.

    Parameters
    ----------
    vuln:
        A vulnerability dict from OSV (with optional "severity" or database_specific fields).

    Returns
    -------
    str:
        One of "info", "low", "medium", "high", "critical". Defaults to "medium".
    """
    # Try OSV severity field first
    severity = vuln.get("severity", "").upper().strip()
    if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        return severity.lower()

    # Try CVSS score if available
    affected = vuln.get("affected", [])
    if affected and isinstance(affected, list):
        for item in affected:
            if isinstance(item, dict):
                # Some OSV responses have database_specific with CVSS
                db_specific = item.get("database_specific", {})
                if isinstance(db_specific, dict):
                    cvss = db_specific.get("cvss", "")
                    if cvss:
                        try:
                            score = float(str(cvss).split(":")[0])
                            if score >= 9.0:
                                return "critical"
                            elif score >= 7.0:
                                return "high"
                            elif score >= 4.0:
                                return "medium"
                            elif score > 0:
                                return "low"
                        except (ValueError, IndexError):
                            pass

    # Default to medium if we can't determine
    return "medium"
