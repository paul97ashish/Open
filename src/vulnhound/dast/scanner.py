"""DAST scanner entry point.

``run(config, target)`` is the public API consumed by the CLI and web UI.
It crawls a target URL from a safe origin, runs security checks on each page,
optionally passes evidence to an LLM for analysis, and returns a list of
deduplicated Finding objects.

Authorization gate: requires ``config.authorized == True`` to prevent
accidental testing of unauthorized targets.
"""

from __future__ import annotations

from vulnhound.config import Config
from vulnhound.dast.crawler import crawl, httpx_fetcher
from vulnhound.dast.checks import run_checks
from vulnhound.findings import Finding, dedupe
from vulnhound.model_client import get_client
from vulnhound.prompts import (
    SECURITY_AUDITOR_SYSTEM,
    build_dast_user,
    parse_findings_json,
)


def run(config: Config, target: str) -> list[Finding]:
    """Scan a web target for security vulnerabilities.

    Parameters
    ----------
    config:
        Runtime configuration. ``config.authorized`` must be True.
        ``config.mock`` triggers offline mode.
        ``config.extra`` may contain:
          - ``"fetcher"``: injected fake fetcher (tests only).
          - ``"max_pages"``: maximum pages to crawl (default 20).
          - ``"max_depth"``: maximum crawl depth (default 2).
    target:
        The URL to start crawling from.

    Returns
    -------
    A list of deduplicated Finding objects, all with source="dast" and file=url.

    Raises
    ------
    PermissionError:
        If config.authorized is not True. DAST requires explicit authorization.
    """
    # Authorization gate: DAST must only run on authorized targets.
    if not config.authorized:
        raise PermissionError(
            "DAST requires explicit authorization (--authorized). "
            "Only test systems you own or are permitted to assess."
        )

    extra = config.extra or {}

    # Get the fetcher: in mock mode, use the injected fake; otherwise build one over httpx.
    if config.mock and "fetcher" in extra:
        fetch = extra["fetcher"]
    else:
        fetch = httpx_fetcher()

    # Crawl with bounds from config.extra.
    max_pages = int(extra.get("max_pages", 20))
    max_depth = int(extra.get("max_depth", 2))

    pages = crawl(target, fetch, max_pages=max_pages, max_depth=max_depth)

    # Run passive checks on all pages.
    findings: list[Finding] = run_checks(pages)

    # Optionally pass pages to LLM for deeper analysis (best-effort, guarded).
    client = get_client(config)
    if not config.mock and config.model:
        # In production with a real model, analyze each page for additional findings.
        for page in pages:
            try:
                # Build evidence from the page headers and body summary.
                evidence = (
                    f"Status: {page.status}\n"
                    f"Headers: {page.headers}\n"
                    f"Body (first 1000 chars): {page.body[:1000]}"
                )
                raw = client.complete(SECURITY_AUDITOR_SYSTEM, build_dast_user(page.url, evidence))
                dicts = parse_findings_json(raw)
                for d in dicts:
                    try:
                        f = Finding.from_dict(d)
                    except Exception:  # noqa: BLE001
                        continue
                    # Force canonical metadata.
                    f.source = "dast"
                    f.file = page.url
                    findings.append(f)
            except Exception:  # noqa: BLE001 - never crash the whole scan
                pass

    return dedupe(findings)
