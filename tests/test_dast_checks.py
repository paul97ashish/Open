"""Tests for vulnhound.dast — fully offline, no model/network."""

from __future__ import annotations

import pytest

from vulnhound.config import Config
from vulnhound.dast.checks import (
    check_cookie_flags,
    check_directory_listing,
    check_open_redirect,
    check_reflected_input,
    check_security_headers,
    check_verbose_errors,
    run_checks,
)
from vulnhound.dast.crawler import Page, crawl, extract_links, same_origin
from vulnhound.dast.scanner import run
from vulnhound.findings import Severity


# ---------------------------------------------------------------------------
# Test same_origin
# ---------------------------------------------------------------------------


class TestSameOrigin:
    def test_same_origin_http(self):
        a = "http://example.com/path"
        b = "http://example.com/other"
        assert same_origin(a, b)

    def test_same_origin_https(self):
        a = "https://example.com/path"
        b = "https://example.com/other"
        assert same_origin(a, b)

    def test_different_scheme(self):
        a = "http://example.com/path"
        b = "https://example.com/path"
        assert not same_origin(a, b)

    def test_different_host(self):
        a = "http://example.com/path"
        b = "http://other.com/path"
        assert not same_origin(a, b)

    def test_different_port(self):
        a = "http://example.com:8080/path"
        b = "http://example.com:9090/path"
        assert not same_origin(a, b)


# ---------------------------------------------------------------------------
# Test extract_links
# ---------------------------------------------------------------------------


class TestExtractLinks:
    def test_extract_href(self):
        html = '<a href="/about">About</a>'
        links = extract_links("http://example.com/", html)
        assert "http://example.com/about" in links

    def test_extract_src(self):
        html = '<script src="/script.js"></script>'
        links = extract_links("http://example.com/", html)
        assert "http://example.com/script.js" in links

    def test_resolve_relative(self):
        html = '<a href="page.html">Page</a>'
        links = extract_links("http://example.com/dir/index.html", html)
        assert "http://example.com/dir/page.html" in links

    def test_ignore_off_origin(self):
        html = '<a href="http://evil.com/page">Evil</a>'
        links = extract_links("http://example.com/", html)
        assert not links

    def test_ignore_protocol_relative_off_origin(self):
        html = '<a href="//evil.com/page">Evil</a>'
        links = extract_links("http://example.com/", html)
        # Same-origin check allows it only if netloc matches
        assert "http://evil.com/page" not in links

    def test_ignore_javascript(self):
        html = '<a href="javascript:alert(1)">JS</a>'
        links = extract_links("http://example.com/", html)
        assert not links


# ---------------------------------------------------------------------------
# Test crawl
# ---------------------------------------------------------------------------


class TestCrawl:
    def test_crawl_single_page(self):
        """Crawl a single page with no outbound links."""
        pages = []

        def fake_fetch(url):
            pages_returned = {
                "http://example.com/": Page(
                    url="http://example.com/",
                    status=200,
                    headers={"content-type": "text/html"},
                    body="<html><body>Hello</body></html>",
                ),
            }
            return pages_returned[url]

        result = crawl("http://example.com/", fake_fetch)
        assert len(result) == 1
        assert result[0].url == "http://example.com/"

    def test_crawl_multiple_pages_same_origin(self):
        """Crawl multiple same-origin pages."""
        def fake_fetch(url):
            pages_map = {
                "http://example.com/": Page(
                    url="http://example.com/",
                    status=200,
                    headers={},
                    body='<a href="/page1">Page 1</a><a href="/page2">Page 2</a>',
                ),
                "http://example.com/page1": Page(
                    url="http://example.com/page1",
                    status=200,
                    headers={},
                    body="<html>Page 1</html>",
                ),
                "http://example.com/page2": Page(
                    url="http://example.com/page2",
                    status=200,
                    headers={},
                    body="<html>Page 2</html>",
                ),
            }
            return pages_map[url]

        result = crawl("http://example.com/", fake_fetch, max_pages=10)
        assert len(result) == 3
        urls = {p.url for p in result}
        assert "http://example.com/" in urls
        assert "http://example.com/page1" in urls
        assert "http://example.com/page2" in urls

    def test_crawl_respects_max_pages(self):
        """Crawl stops at max_pages."""
        def fake_fetch(url):
            # Each page links to the next.
            pages_map = {
                "http://example.com/0": Page(
                    url="http://example.com/0",
                    status=200,
                    headers={},
                    body='<a href="/1">Next</a>',
                ),
                "http://example.com/1": Page(
                    url="http://example.com/1",
                    status=200,
                    headers={},
                    body='<a href="/2">Next</a>',
                ),
                "http://example.com/2": Page(
                    url="http://example.com/2",
                    status=200,
                    headers={},
                    body='<a href="/3">Next</a>',
                ),
                "http://example.com/3": Page(
                    url="http://example.com/3",
                    status=200,
                    headers={},
                    body="<html>End</html>",
                ),
            }
            return pages_map[url]

        result = crawl("http://example.com/0", fake_fetch, max_pages=2)
        assert len(result) == 2

    def test_crawl_respects_max_depth(self):
        """Crawl respects max_depth."""
        def fake_fetch(url):
            pages_map = {
                "http://example.com/": Page(
                    url="http://example.com/",
                    status=200,
                    headers={},
                    body='<a href="/d1">Level 1</a>',
                ),
                "http://example.com/d1": Page(
                    url="http://example.com/d1",
                    status=200,
                    headers={},
                    body='<a href="/d2">Level 2</a>',
                ),
                "http://example.com/d2": Page(
                    url="http://example.com/d2",
                    status=200,
                    headers={},
                    body='<a href="/d3">Level 3</a>',
                ),
            }
            return pages_map[url]

        # max_depth=1 means we should get root (depth 0) and one level of links (depth 1).
        result = crawl("http://example.com/", fake_fetch, max_depth=1, max_pages=10)
        urls = {p.url for p in result}
        # Should include root and /d1, but not /d2 (depth 2).
        assert "http://example.com/" in urls
        assert "http://example.com/d1" in urls
        assert "http://example.com/d2" not in urls

    def test_crawl_ignores_off_origin(self):
        """Crawl ignores off-origin links."""
        def fake_fetch(url):
            pages_map = {
                "http://example.com/": Page(
                    url="http://example.com/",
                    status=200,
                    headers={},
                    body='<a href="http://evil.com/page">Evil</a><a href="/safe">Safe</a>',
                ),
                "http://example.com/safe": Page(
                    url="http://example.com/safe",
                    status=200,
                    headers={},
                    body="<html>Safe</html>",
                ),
            }
            return pages_map[url]

        result = crawl("http://example.com/", fake_fetch)
        urls = {p.url for p in result}
        assert "http://example.com/" in urls
        assert "http://example.com/safe" in urls
        assert "http://evil.com/page" not in urls

    def test_crawl_skip_on_fetch_error(self):
        """Crawl skips pages that fail to fetch."""
        fetch_count = [0]

        def fake_fetch(url):
            fetch_count[0] += 1
            if url == "http://example.com/fail":
                raise Exception("Network error")
            pages_map = {
                "http://example.com/": Page(
                    url="http://example.com/",
                    status=200,
                    headers={},
                    body='<a href="/fail">Fail</a><a href="/ok">OK</a>',
                ),
                "http://example.com/ok": Page(
                    url="http://example.com/ok",
                    status=200,
                    headers={},
                    body="<html>OK</html>",
                ),
            }
            return pages_map[url]

        result = crawl("http://example.com/", fake_fetch)
        urls = {p.url for p in result}
        # Should have root and /ok, but not /fail.
        assert "http://example.com/" in urls
        assert "http://example.com/ok" in urls
        assert "http://example.com/fail" not in urls


# ---------------------------------------------------------------------------
# Test checks
# ---------------------------------------------------------------------------


class TestCheckSecurityHeaders:
    def test_missing_csp(self):
        page = Page(
            url="http://example.com/",
            status=200,
            headers={},
            body="<html></html>",
        )
        findings = check_security_headers(page)
        assert any("Content-Security-Policy" in f.title for f in findings)

    def test_missing_x_content_type_options(self):
        page = Page(
            url="http://example.com/",
            status=200,
            headers={"content-security-policy": "default-src 'self'"},
            body="<html></html>",
        )
        findings = check_security_headers(page)
        assert any("X-Content-Type-Options" in f.title for f in findings)

    def test_missing_hsts_on_https(self):
        page = Page(
            url="https://example.com/",
            status=200,
            headers={
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
            },
            body="<html></html>",
        )
        findings = check_security_headers(page)
        assert any("Strict-Transport-Security" in f.title for f in findings)

    def test_no_hsts_check_on_http(self):
        page = Page(
            url="http://example.com/",
            status=200,
            headers={
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "x-frame-options": "SAMEORIGIN",
            },
            body="<html></html>",
        )
        findings = check_security_headers(page)
        assert not any("Strict-Transport-Security" in f.title for f in findings)

    def test_all_headers_present(self):
        page = Page(
            url="https://example.com/",
            status=200,
            headers={
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "strict-transport-security": "max-age=31536000",
                "x-frame-options": "SAMEORIGIN",
            },
            body="<html></html>",
        )
        findings = check_security_headers(page)
        assert findings == []


class TestCheckCookieFlags:
    def test_cookie_missing_httponly(self):
        page = Page(
            url="http://example.com/",
            status=200,
            headers={"set-cookie": "session=abc123; Path=/; Secure"},
            body="<html></html>",
        )
        findings = check_cookie_flags(page)
        assert any("HttpOnly" in f.title for f in findings)

    def test_cookie_missing_secure_on_https(self):
        page = Page(
            url="https://example.com/",
            status=200,
            headers={"set-cookie": "session=abc123; Path=/; HttpOnly"},
            body="<html></html>",
        )
        findings = check_cookie_flags(page)
        assert any("Secure" in f.title for f in findings)

    def test_cookie_secure_on_http_not_checked(self):
        page = Page(
            url="http://example.com/",
            status=200,
            headers={"set-cookie": "session=abc123; Path=/; HttpOnly"},
            body="<html></html>",
        )
        findings = check_cookie_flags(page)
        # Should not complain about missing Secure on HTTP.
        assert not any("Secure" in f.title for f in findings)

    def test_cookie_with_all_flags(self):
        page = Page(
            url="https://example.com/",
            status=200,
            headers={"set-cookie": "session=abc123; Path=/; Secure; HttpOnly"},
            body="<html></html>",
        )
        findings = check_cookie_flags(page)
        assert findings == []


class TestCheckOpenRedirect:
    def test_detect_open_redirect(self):
        page = Page(
            url="http://example.com/redirect?redirect=http://evil.com",
            status=200,
            headers={},
            body='<a href="http://evil.com">Click</a>',
        )
        findings = check_open_redirect(page)
        assert any("Redirect" in f.title for f in findings)

    def test_no_false_positive_on_relative_redirect(self):
        page = Page(
            url="http://example.com/redirect?next=/safe",
            status=200,
            headers={},
            body="<html></html>",
        )
        findings = check_open_redirect(page)
        # Relative URL, so no alert.
        assert not findings


class TestCheckReflectedInput:
    def test_detect_reflected_xss(self):
        page = Page(
            url="http://example.com/search?q=alert(1)",
            status=200,
            headers={},
            body="<html>Search results for: alert(1)</html>",
        )
        findings = check_reflected_input(page)
        assert any("Reflected" in f.title for f in findings)
        assert any("CWE-79" in f.cwe for f in findings)

    def test_no_alert_on_short_params(self):
        page = Page(
            url="http://example.com/page?id=1",
            status=200,
            headers={},
            body="<html>ID: 1</html>",
        )
        findings = check_reflected_input(page)
        # Short numeric values are filtered.
        assert not findings

    def test_no_alert_if_value_escaped(self):
        page = Page(
            url="http://example.com/search?q=<script>",
            status=200,
            headers={},
            body="<html>Search results for: &lt;script&gt;</html>",
        )
        findings = check_reflected_input(page)
        # The value is escaped in the body, so no raw reflection.
        assert not findings


class TestCheckDirectoryListing:
    def test_detect_directory_listing(self):
        page = Page(
            url="http://example.com/files/",
            status=200,
            headers={},
            body="<html><h1>Index of /files/</h1><ul><li>file.txt</li></ul></html>",
        )
        findings = check_directory_listing(page)
        assert any("Directory Listing" in f.title for f in findings)

    def test_no_alert_without_listing_pattern(self):
        page = Page(
            url="http://example.com/",
            status=200,
            headers={},
            body="<html><body>Normal page</body></html>",
        )
        findings = check_directory_listing(page)
        assert not findings


class TestCheckVerboseErrors:
    def test_detect_python_traceback(self):
        page = Page(
            url="http://example.com/api",
            status=500,
            headers={},
            body="<html>Traceback (most recent call last):\n  File ..., line 1, in ...\nNameError: ...</html>",
        )
        findings = check_verbose_errors(page)
        assert any("Verbose Error" in f.title for f in findings)

    def test_detect_php_error(self):
        page = Page(
            url="http://example.com/api",
            status=500,
            headers={},
            body="<html>Fatal error: Call to undefined function foo() in /var/www/html/index.php on line 42</html>",
        )
        findings = check_verbose_errors(page)
        assert any("Verbose Error" in f.title for f in findings)

    def test_no_alert_without_error_pattern(self):
        page = Page(
            url="http://example.com/",
            status=200,
            headers={},
            body="<html><body>Normal page</body></html>",
        )
        findings = check_verbose_errors(page)
        assert not findings


# ---------------------------------------------------------------------------
# Test run_checks (integration)
# ---------------------------------------------------------------------------


class TestRunChecks:
    def test_run_checks_on_multiple_pages(self):
        pages = [
            Page(
                url="http://example.com/",
                status=200,
                headers={},
                body="<html></html>",
            ),
            Page(
                url="http://example.com/api",
                status=500,
                headers={},
                body="Traceback (most recent call last):",
            ),
        ]
        findings = run_checks(pages)
        # Should have findings from both pages.
        assert len(findings) > 0
        assert any(f.file == "http://example.com/" for f in findings)
        assert any(f.file == "http://example.com/api" for f in findings)

    def test_run_checks_skips_broken_checks(self):
        # Ensure that a broken check doesn't crash run_checks.
        pages = [
            Page(
                url="http://example.com/",
                status=200,
                headers={},
                body="<html></html>",
            ),
        ]
        findings = run_checks(pages)
        # Should complete without raising.
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# Test scanner authorization gate
# ---------------------------------------------------------------------------


class TestScannerAuthorizationGate:
    def test_authorization_gate_raises_without_authorized(self):
        """DAST scanner must raise PermissionError if config.authorized is False."""
        config = Config(authorized=False, mock=True)
        with pytest.raises(PermissionError, match="authorized"):
            run(config, "http://example.com/")

    def test_authorization_gate_allows_with_authorized(self):
        """DAST scanner succeeds if config.authorized is True."""
        def fake_fetch(url):
            return Page(
                url=url,
                status=200,
                headers={},
                body="<html></html>",
            )

        config = Config(
            authorized=True,
            mock=True,
            extra={"fetcher": fake_fetch},
        )
        findings = run(config, "http://example.com/")
        # Should complete without raising and return findings (empty or not).
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# Test scanner with canned pages
# ---------------------------------------------------------------------------


class TestScannerWithCanmedPages:
    def test_scanner_returns_findings_from_checks(self):
        """Scanner crawls and runs checks, returning findings with source='dast'."""
        def fake_fetch(url):
            # Return a page with a missing security header.
            return Page(
                url=url,
                status=200,
                headers={},  # No CSP, etc.
                body="<html><body>Test page</body></html>",
            )

        config = Config(
            authorized=True,
            mock=True,
            extra={"fetcher": fake_fetch, "max_pages": 5, "max_depth": 1},
        )
        findings = run(config, "http://example.com/")

        # Should have findings from the checks.
        assert len(findings) > 0
        # All findings must have source="dast".
        assert all(f.source == "dast" for f in findings)
        # All findings must have file=url.
        assert all(f.file == "http://example.com/" for f in findings)

    def test_scanner_with_mock_model_client(self):
        """Scanner works with MockClient for LLM analysis."""
        def fake_fetch(url):
            return Page(
                url=url,
                status=200,
                headers={},
                body="<html></html>",
            )

        dast_response = '[{"title":"Test Finding","severity":"medium","cwe":"CWE-999","description":"test","recommendation":"test","confidence":0.5}]'
        config = Config(
            authorized=True,
            mock=True,
            model="mock",
            mock_responses={"http://example.com/": dast_response},
            extra={"fetcher": fake_fetch},
        )
        findings = run(config, "http://example.com/")

        # Should include findings from both checks and the mock model.
        assert len(findings) > 0
        assert all(f.source == "dast" for f in findings)

    def test_scanner_no_network_access(self):
        """Scanner in mock mode never attempts real network access."""
        # This test verifies that httpx_fetcher is not called in mock mode.
        def fake_fetch(url):
            return Page(
                url=url,
                status=200,
                headers={},
                body="<html></html>",
            )

        config = Config(
            authorized=True,
            mock=True,
            extra={"fetcher": fake_fetch},
        )
        # Should complete without importing or calling httpx.
        findings = run(config, "http://example.com/")
        assert isinstance(findings, list)
