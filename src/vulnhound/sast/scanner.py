"""SAST scanner entry point.

``run(config, target)`` is the public API consumed by the CLI and web UI.
It walks *target*, asks the model to review each chunk of each source file,
parses the JSON findings, and returns a de-duplicated list of :class:`Finding`
objects.
"""

from __future__ import annotations

import concurrent.futures
import os
from typing import List

from vulnhound.config import Config
from vulnhound.findings import Finding, dedupe
from vulnhound.model_client import get_client
from vulnhound.prompts import (
    SECURITY_AUDITOR_SYSTEM,
    build_sast_user,
    parse_findings_json,
)
from vulnhound.sast.collector import changed_files, chunk_file, discover_files


def _scan_file(
    client,
    root: str,
    relpath: str,
) -> list[Finding]:
    """Scan a single file and return raw (not-yet-deduped) findings."""
    abs_path = os.path.join(root, relpath)
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []

    findings: list[Finding] = []
    for _start_line, chunk_text in chunk_file(abs_path, text):
        try:
            raw = client.complete(SECURITY_AUDITOR_SYSTEM, build_sast_user(relpath, chunk_text))
        except Exception:  # noqa: BLE001 - never crash the whole scan
            continue
        dicts = parse_findings_json(raw)
        for d in dicts:
            try:
                f = Finding.from_dict(d)
            except Exception:  # noqa: BLE001
                continue
            # Force canonical metadata regardless of what the model returned.
            f.source = "sast"
            f.file = relpath
            findings.append(f)

    return findings


def run(config: Config, target: str) -> list[Finding]:
    """Scan *target* for security vulnerabilities and return deduplicated findings.

    Parameters
    ----------
    config:
        Runtime configuration.  ``config.mock`` triggers offline mode.
        ``config.extra`` may contain:
          - ``"diff"`` (truthy): scan only files changed vs. ``"ref"`` (default HEAD).
          - ``"include"`` (list[str]): fnmatch globs to include.
          - ``"exclude"`` (list[str]): fnmatch globs to exclude.
    target:
        Filesystem path to a directory or a single file to scan.
    """
    target = os.path.abspath(target)
    extra = config.extra or {}

    # When target is a single file, the "root" for relative-path resolution
    # must be its parent directory (discover_files returns paths relative to
    # the parent when given a file, not to the file itself).
    if os.path.isfile(target):
        scan_root = os.path.dirname(target)
    else:
        scan_root = target

    # ------------------------------------------------------------------
    # Resolve the list of files to scan.
    # ------------------------------------------------------------------
    if extra.get("diff"):
        ref = extra.get("ref", "HEAD")
        rel_paths = changed_files(scan_root, ref=ref)
    else:
        rel_paths = discover_files(
            target,
            include=extra.get("include"),
            exclude=extra.get("exclude"),
        )

    if not rel_paths:
        return []

    client = get_client(config)

    # ------------------------------------------------------------------
    # Scan files, optionally in parallel.
    # ------------------------------------------------------------------
    all_findings: list[Finding] = []

    max_workers = max(1, getattr(config, "concurrency", 4))

    if max_workers == 1:
        # Single-threaded path — simpler, easier to debug.
        for relpath in rel_paths:
            all_findings.extend(_scan_file(client, scan_root, relpath))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_scan_file, client, scan_root, relpath): relpath
                for relpath in rel_paths
            }
            for future in concurrent.futures.as_completed(futures):
                try:
                    all_findings.extend(future.result())
                except Exception:  # noqa: BLE001 - log and continue
                    pass

    return dedupe(all_findings)
