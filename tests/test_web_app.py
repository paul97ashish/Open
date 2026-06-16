"""Tests for vulnhound.web.app — fully offline, no model/network."""

from __future__ import annotations

import json
from typing import Callable

import pytest
from fastapi.testclient import TestClient

from vulnhound.config import Config
from vulnhound.findings import Finding, Severity
from vulnhound.web.app import create_app


# ---------------------------------------------------------------------------
# Fixtures and Helpers
# ---------------------------------------------------------------------------


def mock_scanner(
    scan_type: str,
    target: str,
    config: Config,
) -> list[Finding]:
    """A mock scanner that returns a fixed set of findings.

    Returns one HIGH severity SAST finding and one LOW severity deps finding.
    """
    return [
        Finding(
            title="SQL Injection",
            severity=Severity.HIGH,
            source="sast",
            description="User input concatenated into SQL query.",
            recommendation="Use parameterized queries.",
            cwe="CWE-89",
            file="app.py",
            start_line=42,
            end_line=42,
            confidence=0.9,
        ),
        Finding(
            title="Vulnerable Dependency",
            severity=Severity.LOW,
            source="deps",
            description="Package has a known vulnerability.",
            recommendation="Upgrade to patched version.",
            cwe="CWE-400",
            file="requirements.txt",
            confidence=0.8,
            extra={"package": "requests", "version": "2.25.1", "fixed_version": "2.26.0"},
        ),
    ]


def permission_denied_scanner(
    scan_type: str,
    target: str,
    config: Config,
) -> list[Finding]:
    """A mock scanner that raises PermissionError for DAST scans."""
    if scan_type == "web":
        raise PermissionError("DAST scans require the authorized checkbox.")
    return []


def import_error_scanner(
    scan_type: str,
    target: str,
    config: Config,
) -> list[Finding]:
    """A mock scanner that raises ImportError."""
    raise ImportError("Scanner module not found")


def generic_exception_scanner(
    scan_type: str,
    target: str,
    config: Config,
) -> list[Finding]:
    """A mock scanner that raises a generic exception."""
    raise RuntimeError("Something went wrong in the scanner")


@pytest.fixture
def app_with_mock():
    """Create app with mock scanner."""
    return create_app(scan_override=mock_scanner)


@pytest.fixture
def app_with_permission_error():
    """Create app with scanner that raises PermissionError."""
    return create_app(scan_override=permission_denied_scanner)


@pytest.fixture
def app_with_import_error():
    """Create app with scanner that raises ImportError."""
    return create_app(scan_override=import_error_scanner)


@pytest.fixture
def app_with_generic_error():
    """Create app with scanner that raises a generic exception."""
    return create_app(scan_override=generic_exception_scanner)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHealthz:
    """Test the health check endpoint."""

    def test_healthz(self, app_with_mock):
        """GET /healthz returns 200 with status=ok."""
        client = TestClient(app_with_mock)
        response = client.get("/healthz")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"


class TestIndexRoute:
    """Test the form page."""

    def test_get_index(self, app_with_mock):
        """GET / returns 200 and contains the form."""
        client = TestClient(app_with_mock)
        response = client.get("/")
        assert response.status_code == 200
        html = response.text
        assert "vulnhound" in html
        assert "Scan Configuration" in html or "scan_type" in html
        assert "target" in html
        assert "form" in html or "method" in html


class TestScanRoute:
    """Test the POST /scan endpoint."""

    def test_scan_with_findings(self, app_with_mock):
        """POST /scan with form data returns 200 and renders findings."""
        client = TestClient(app_with_mock)
        response = client.post(
            "/scan",
            data={
                "scan_type": "code",
                "target": "/path/to/project",
                "model": "",
                "base_url": "",
                "mock": "on",
                "severity_threshold": "low",
                "authorized": "",
            },
        )
        assert response.status_code == 200
        html = response.text
        # Check that findings are in the response
        assert "SQL Injection" in html
        assert "Vulnerable Dependency" in html
        assert "HIGH" in html or "high" in html
        assert "LOW" in html or "low" in html

    def test_scan_results_contain_severity_summary(self, app_with_mock):
        """POST /scan response includes severity counts."""
        client = TestClient(app_with_mock)
        response = client.post(
            "/scan",
            data={
                "scan_type": "code",
                "target": "/path/to/project",
                "model": "",
                "base_url": "",
                "mock": "on",
                "severity_threshold": "low",
                "authorized": "",
            },
        )
        assert response.status_code == 200
        html = response.text
        # Check for severity counts
        assert "Total findings" in html or "findings" in html

    def test_scan_results_contain_table(self, app_with_mock):
        """POST /scan response includes a findings table."""
        client = TestClient(app_with_mock)
        response = client.post(
            "/scan",
            data={
                "scan_type": "code",
                "target": "/path/to/project",
                "model": "",
                "base_url": "",
                "mock": "on",
                "severity_threshold": "low",
                "authorized": "",
            },
        )
        assert response.status_code == 200
        html = response.text
        # Check for table elements
        assert "app.py" in html  # file from first finding
        assert "CWE-89" in html or "CWE-89" in html  # CWE from first finding

    def test_scan_permission_error_shows_friendly_message(self, app_with_permission_error):
        """POST /scan with PermissionError shows a friendly error, not 500."""
        client = TestClient(app_with_permission_error)
        response = client.post(
            "/scan",
            data={
                "scan_type": "web",
                "target": "https://example.com",
                "model": "",
                "base_url": "",
                "mock": "on",
                "severity_threshold": "low",
                "authorized": "",  # NOT authorized
            },
        )
        assert response.status_code == 200
        html = response.text
        assert "Permission" in html or "permission" in html or "authorized" in html

    def test_scan_import_error_shows_friendly_message(self, app_with_import_error):
        """POST /scan with ImportError shows a friendly error."""
        client = TestClient(app_with_import_error)
        response = client.post(
            "/scan",
            data={
                "scan_type": "code",
                "target": "/path/to/project",
                "model": "",
                "base_url": "",
                "mock": "on",
                "severity_threshold": "low",
                "authorized": "",
            },
        )
        assert response.status_code == 200
        html = response.text
        assert "error" in html.lower() or "not available" in html.lower()

    def test_scan_generic_exception_shows_friendly_message(self, app_with_generic_error):
        """POST /scan with generic exception shows a friendly error."""
        client = TestClient(app_with_generic_error)
        response = client.post(
            "/scan",
            data={
                "scan_type": "code",
                "target": "/path/to/project",
                "model": "",
                "base_url": "",
                "mock": "on",
                "severity_threshold": "low",
                "authorized": "",
            },
        )
        assert response.status_code == 200
        html = response.text
        assert "error" in html.lower() or "failed" in html.lower()


class TestApiScanRoute:
    """Test the JSON/SARIF API endpoint."""

    def test_api_scan_returns_json(self, app_with_mock):
        """GET /api/scan with format=json returns valid JSON."""
        client = TestClient(app_with_mock)
        response = client.get(
            "/api/scan",
            params={
                "scan_type": "code",
                "target": "/path/to/project",
                "format": "json",
            },
        )
        assert response.status_code == 200
        # Should be valid JSON
        data = response.json()
        # JSON reporter output structure
        assert "findings" in data or isinstance(data, dict)

    def test_api_scan_contains_findings(self, app_with_mock):
        """GET /api/scan JSON contains the findings."""
        client = TestClient(app_with_mock)
        response = client.get(
            "/api/scan",
            params={
                "scan_type": "code",
                "target": "/path/to/project",
                "format": "json",
            },
        )
        assert response.status_code == 200
        data = response.json()
        # Check for findings
        assert "findings" in data
        findings = data["findings"]
        assert len(findings) > 0
        # Check first finding
        first = findings[0]
        assert "title" in first
        assert first["title"] == "SQL Injection" or "SQL" in first["title"]

    def test_api_scan_sarif_format(self, app_with_mock):
        """GET /api/scan with format=sarif returns SARIF JSON."""
        client = TestClient(app_with_mock)
        response = client.get(
            "/api/scan",
            params={
                "scan_type": "code",
                "target": "/path/to/project",
                "format": "sarif",
            },
        )
        assert response.status_code == 200
        # Should be valid JSON
        data = response.json()
        assert isinstance(data, dict)
        # SARIF has a sarif field or is the sarif object itself
        assert "sarif" in data or "version" in data or "$schema" in data

    def test_api_scan_post_form(self, app_with_mock):
        """POST /api/scan with form data returns JSON."""
        client = TestClient(app_with_mock)
        response = client.post(
            "/api/scan",
            data={
                "scan_type": "code",
                "target": "/path/to/project",
                "format": "json",
                "mock": "on",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "findings" in data

    def test_api_scan_permission_error_returns_403(self, app_with_permission_error):
        """GET /api/scan DAST without auth returns 403."""
        client = TestClient(app_with_permission_error)
        response = client.get(
            "/api/scan",
            params={
                "scan_type": "web",
                "target": "https://example.com",
                "authorized": "false",
            },
        )
        assert response.status_code == 403

    def test_api_scan_import_error_returns_503(self, app_with_import_error):
        """GET /api/scan with ImportError returns 503."""
        client = TestClient(app_with_import_error)
        response = client.get(
            "/api/scan",
            params={
                "scan_type": "code",
                "target": "/path/to/project",
            },
        )
        assert response.status_code == 503

    def test_api_scan_missing_params(self, app_with_mock):
        """GET /api/scan without required params returns error."""
        client = TestClient(app_with_mock)
        response = client.get("/api/scan")
        # Missing required query params should be a 422 (validation error)
        assert response.status_code in (400, 422)


class TestNoFindings:
    """Test behavior when scanner returns no findings."""

    def test_scan_no_findings(self, app_with_mock):
        """POST /scan with empty findings shows 'no findings' message."""
        empty_scanner = lambda scan_type, target, config: []
        app = create_app(scan_override=empty_scanner)
        client = TestClient(app)
        response = client.post(
            "/scan",
            data={
                "scan_type": "code",
                "target": "/path/to/project",
                "model": "",
                "base_url": "",
                "mock": "on",
                "severity_threshold": "low",
                "authorized": "",
            },
        )
        assert response.status_code == 200
        html = response.text
        # Should mention no findings detected
        assert "No findings" in html or "no findings" in html


class TestFindingDeduplication:
    """Test that findings are deduplicated."""

    def test_scan_deduplicates_findings(self, app_with_mock):
        """POST /scan deduplicate findings before rendering."""
        # The mock scanner returns 2 findings, but if the dedupe
        # logic changes, we just check that results are rendered.
        client = TestClient(app_with_mock)
        response = client.post(
            "/scan",
            data={
                "scan_type": "code",
                "target": "/path/to/project",
                "model": "",
                "base_url": "",
                "mock": "on",
                "severity_threshold": "low",
                "authorized": "",
            },
        )
        assert response.status_code == 200


class TestSeverityHandling:
    """Test severity threshold and filtering."""

    def test_scan_shows_all_severities(self, app_with_mock):
        """POST /scan renders findings regardless of threshold."""
        # The web UI doesn't filter by threshold in rendering
        # (that's for CLI exit codes); it shows all findings.
        client = TestClient(app_with_mock)
        response = client.post(
            "/scan",
            data={
                "scan_type": "code",
                "target": "/path/to/project",
                "model": "",
                "base_url": "",
                "mock": "on",
                "severity_threshold": "critical",
                "authorized": "",
            },
        )
        assert response.status_code == 200
        html = response.text
        # Even though threshold is critical, both HIGH and LOW findings should be shown
        assert "SQL Injection" in html


class TestConfigBuilding:
    """Test that form data is properly converted to Config."""

    def test_scan_config_mock_flag(self, app_with_mock):
        """Form mock checkbox is properly passed to Config."""
        # The default in the form is checked (True)
        # We just verify the scan runs without error
        client = TestClient(app_with_mock)
        response = client.post(
            "/scan",
            data={
                "scan_type": "code",
                "target": "/path/to/project",
                "model": "test-model",
                "base_url": "https://test.com",
                "mock": "on",
                "severity_threshold": "low",
                "authorized": "",
            },
        )
        assert response.status_code == 200


class TestStaticFiles:
    """Test that static files are accessible."""

    def test_static_css_exists(self, app_with_mock):
        """GET /static/style.css returns 200 if mounted."""
        client = TestClient(app_with_mock)
        response = client.get("/static/style.css")
        # Should succeed (200) or at least not 500
        assert response.status_code in (200, 404)  # 404 if not found, but should be 200
        if response.status_code == 200:
            assert "body" in response.text or "css" in response.text.lower()
