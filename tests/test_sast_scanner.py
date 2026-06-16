"""Tests for vulnhound.sast.scanner — fully offline, no model/network."""

from __future__ import annotations

import os

import pytest

from vulnhound.config import Config
from vulnhound.findings import Severity
from vulnhound.sast import scanner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


SQL_INJECTION_RESPONSE = (
    '[{"title":"SQL Injection","severity":"high","cwe":"CWE-89",'
    '"start_line":3,"end_line":3,'
    '"description":"User input concatenated into SQL query.","recommendation":'
    '"Use parameterized queries.","confidence":0.9}]'
)


# ---------------------------------------------------------------------------
# Core scanner tests
# ---------------------------------------------------------------------------


class TestSastScannerRun:
    def test_finds_vulnerability_via_mock(self, tmp_path):
        """MockClient should match the filename substring and return findings."""
        vuln_file = str(tmp_path / "vulnerable_app.py")
        write(vuln_file, "import sqlite3\nconn = sqlite3.connect('db')\n"
              "conn.execute('SELECT * FROM users WHERE id = ' + user_id)\n")

        config = Config(
            mock=True,
            mock_responses={"vulnerable_app.py": SQL_INJECTION_RESPONSE},
            concurrency=1,
        )
        findings = scanner.run(config, str(tmp_path))

        assert len(findings) == 1
        f = findings[0]
        assert f.source == "sast"
        assert f.file == "vulnerable_app.py"
        assert f.severity == Severity.HIGH
        assert f.cwe == "CWE-89"
        assert f.title == "SQL Injection"

    def test_source_forced_to_sast(self, tmp_path):
        """Even if the model returns a different source, we override it to 'sast'."""
        write(str(tmp_path / "app.py"), "x = 1")

        # Response with wrong source
        response = (
            '[{"title":"XSS","severity":"medium","cwe":"CWE-79","source":"dast",'
            '"description":"cross-site scripting","recommendation":"escape output",'
            '"start_line":1,"end_line":1,"confidence":0.8}]'
        )
        config = Config(
            mock=True,
            mock_responses={"app.py": response},
            concurrency=1,
        )
        findings = scanner.run(config, str(tmp_path))
        assert all(f.source == "sast" for f in findings)

    def test_file_forced_to_relpath(self, tmp_path):
        """The file attribute must be the repo-relative path, not what the model says."""
        write(str(tmp_path / "myfile.py"), "x = eval(input())")

        response = (
            '[{"title":"Code Injection","severity":"critical","cwe":"CWE-95",'
            '"file":"/absolute/wrong/path.py",'
            '"description":"eval on user input","recommendation":"remove eval",'
            '"start_line":1,"end_line":1,"confidence":0.95}]'
        )
        config = Config(
            mock=True,
            mock_responses={"myfile.py": response},
            concurrency=1,
        )
        findings = scanner.run(config, str(tmp_path))
        assert len(findings) == 1
        assert findings[0].file == "myfile.py"

    def test_empty_response_yields_no_findings(self, tmp_path):
        """When the mock returns '[]' (default), there should be no findings."""
        write(str(tmp_path / "clean.py"), "x = 1 + 2")

        config = Config(mock=True, mock_responses={}, concurrency=1)
        findings = scanner.run(config, str(tmp_path))
        assert findings == []

    def test_empty_directory_yields_no_findings(self, tmp_path):
        config = Config(mock=True, concurrency=1)
        findings = scanner.run(config, str(tmp_path))
        assert findings == []

    def test_multiple_files_aggregated(self, tmp_path):
        """Findings from multiple files are aggregated."""
        write(str(tmp_path / "file_a.py"), "eval(input())")
        write(str(tmp_path / "file_b.py"), "subprocess.run(cmd, shell=True)")

        responses = {
            "file_a.py": (
                '[{"title":"Code Injection","severity":"critical","cwe":"CWE-95",'
                '"description":"eval","recommendation":"remove eval",'
                '"start_line":1,"end_line":1,"confidence":0.9}]'
            ),
            "file_b.py": (
                '[{"title":"Command Injection","severity":"high","cwe":"CWE-78",'
                '"description":"shell=True","recommendation":"avoid shell=True",'
                '"start_line":1,"end_line":1,"confidence":0.85}]'
            ),
        }
        config = Config(mock=True, mock_responses=responses, concurrency=1)
        findings = scanner.run(config, str(tmp_path))

        titles = {f.title for f in findings}
        assert "Code Injection" in titles
        assert "Command Injection" in titles

    def test_unreadable_file_does_not_crash(self, tmp_path):
        """An unreadable file should be silently skipped."""
        path = str(tmp_path / "unreadable.py")
        write(path, "x = 1")
        os.chmod(path, 0o000)

        config = Config(mock=True, concurrency=1)
        try:
            findings = scanner.run(config, str(tmp_path))
            # Should not raise; findings may be empty.
            assert isinstance(findings, list)
        finally:
            os.chmod(path, 0o644)  # restore so tmp_path cleanup works

    def test_findings_are_deduped(self, tmp_path):
        """Identical findings (same file, cwe, lines) are de-duplicated."""
        write(str(tmp_path / "dup.py"), "eval(x)")

        # Return the same finding twice (simulating chunked output overlap).
        response = (
            '[{"title":"Code Injection","severity":"high","cwe":"CWE-95",'
            '"description":"eval","recommendation":"remove eval",'
            '"start_line":1,"end_line":1,"confidence":0.9},'
            '{"title":"Code Injection","severity":"high","cwe":"CWE-95",'
            '"description":"eval","recommendation":"remove eval",'
            '"start_line":1,"end_line":1,"confidence":0.9}]'
        )
        config = Config(mock=True, mock_responses={"dup.py": response}, concurrency=1)
        findings = scanner.run(config, str(tmp_path))
        # After dedupe there should be exactly one finding.
        assert len(findings) == 1

    def test_severity_ordering(self, tmp_path):
        """Results must be sorted by severity descending."""
        write(str(tmp_path / "multi.py"), "x = 1")
        response = (
            '[{"title":"Low Issue","severity":"low","cwe":"CWE-1",'
            '"description":"d","recommendation":"r","start_line":1,"end_line":1,"confidence":0.5},'
            '{"title":"Critical Issue","severity":"critical","cwe":"CWE-2",'
            '"description":"d","recommendation":"r","start_line":2,"end_line":2,"confidence":0.9},'
            '{"title":"Medium Issue","severity":"medium","cwe":"CWE-3",'
            '"description":"d","recommendation":"r","start_line":3,"end_line":3,"confidence":0.7}]'
        )
        config = Config(mock=True, mock_responses={"multi.py": response}, concurrency=1)
        findings = scanner.run(config, str(tmp_path))

        severities = [f.severity for f in findings]
        assert severities == sorted(severities, reverse=True), (
            f"Expected DESC order, got {[s.label for s in severities]}"
        )

    def test_single_file_target(self, tmp_path):
        """Passing a single file as target works correctly."""
        path = str(tmp_path / "single.py")
        write(path, "eval(input())")

        response = (
            '[{"title":"Code Injection","severity":"critical","cwe":"CWE-95",'
            '"description":"eval on user input","recommendation":"remove eval",'
            '"start_line":1,"end_line":1,"confidence":0.95}]'
        )
        config = Config(
            mock=True,
            mock_responses={"single.py": response},
            concurrency=1,
        )
        findings = scanner.run(config, path)
        assert len(findings) == 1
        assert findings[0].cwe == "CWE-95"

    def test_concurrent_scan(self, tmp_path):
        """Concurrent mode (concurrency > 1) returns the same results."""
        for i in range(5):
            write(str(tmp_path / f"f{i}.py"), f"x = {i}")

        config = Config(mock=True, mock_responses={}, concurrency=4)
        findings = scanner.run(config, str(tmp_path))
        assert isinstance(findings, list)
        assert findings == []

    def test_include_extra_filter(self, tmp_path):
        """config.extra['include'] limits which files are scanned."""
        write(str(tmp_path / "app.py"), "eval(input())")
        write(str(tmp_path / "ignored.js"), "eval(input)")

        response = (
            '[{"title":"Code Injection","severity":"high","cwe":"CWE-95",'
            '"description":"eval","recommendation":"remove eval",'
            '"start_line":1,"end_line":1,"confidence":0.9}]'
        )
        config = Config(
            mock=True,
            mock_responses={"app.py": response},
            extra={"include": ["*.py"]},
            concurrency=1,
        )
        findings = scanner.run(config, str(tmp_path))
        # Only the .py file is scanned.
        files = {f.file for f in findings}
        assert "app.py" in files
        assert "ignored.js" not in files
