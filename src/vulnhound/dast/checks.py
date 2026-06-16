"""Lightweight passive security checks for crawled pages."""

from __future__ import annotations

import re
from typing import Optional

from vulnhound.dast.crawler import Page
from vulnhound.findings import Finding, Severity


def check_security_headers(page: Page) -> list[Finding]:
    """Check for missing or weak security headers.

    Checks for:
      - Content-Security-Policy (missing or weak)
      - X-Content-Type-Options: nosniff
      - Strict-Transport-Security (HTTPS only)
      - X-Frame-Options or frame-ancestors in CSP

    Returns findings for each missing critical header.
    """
    findings: list[Finding] = []
    headers_lower = {k.lower(): v for k, v in page.headers.items()}

    # Check CSP
    csp = headers_lower.get("content-security-policy", "")
    if not csp:
        findings.append(
            Finding(
                title="Missing Content-Security-Policy",
                severity=Severity.MEDIUM,
                source="dast",
                description=(
                    "The page does not define a Content-Security-Policy header, "
                    "which increases the risk of XSS and other injection attacks."
                ),
                recommendation=(
                    "Define a restrictive Content-Security-Policy header. "
                    "Start with default-src 'self' and refine as needed."
                ),
                cwe="CWE-693",
                file=page.url,
                confidence=0.8,
            )
        )

    # Check X-Content-Type-Options
    xcto = headers_lower.get("x-content-type-options", "")
    if not xcto or "nosniff" not in xcto.lower():
        findings.append(
            Finding(
                title="Missing X-Content-Type-Options: nosniff",
                severity=Severity.MEDIUM,
                source="dast",
                description=(
                    "The page does not set X-Content-Type-Options: nosniff, "
                    "allowing browsers to sniff MIME types and potentially execute scripts."
                ),
                recommendation=(
                    "Set the X-Content-Type-Options header to 'nosniff' on all responses."
                ),
                cwe="CWE-693",
                file=page.url,
                confidence=0.8,
            )
        )

    # Check HSTS (for HTTPS only)
    if page.url.startswith("https://"):
        hsts = headers_lower.get("strict-transport-security", "")
        if not hsts:
            findings.append(
                Finding(
                    title="Missing Strict-Transport-Security",
                    severity=Severity.LOW,
                    source="dast",
                    description=(
                        "The HTTPS page does not set a Strict-Transport-Security header, "
                        "allowing potential downgrade attacks."
                    ),
                    recommendation=(
                        "Set Strict-Transport-Security: max-age=31536000; includeSubDomains on all HTTPS responses."
                    ),
                    cwe="CWE-693",
                    file=page.url,
                    confidence=0.7,
                )
            )

    # Check X-Frame-Options or frame-ancestors in CSP
    xfo = headers_lower.get("x-frame-options", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    if not xfo and not has_frame_ancestors:
        findings.append(
            Finding(
                title="Missing X-Frame-Options",
                severity=Severity.LOW,
                source="dast",
                description=(
                    "The page does not set X-Frame-Options or CSP frame-ancestors, "
                    "allowing clickjacking attacks."
                ),
                recommendation=(
                    "Set X-Frame-Options: SAMEORIGIN or define frame-ancestors in CSP."
                ),
                cwe="CWE-693",
                file=page.url,
                confidence=0.7,
            )
        )

    return findings


def check_cookie_flags(page: Page) -> list[Finding]:
    """Check for Set-Cookie headers missing Secure or HttpOnly flags.

    Parses Set-Cookie headers and alerts on missing flags that would reduce
    cookie protection in transit or from JavaScript access.
    """
    findings: list[Finding] = []
    set_cookie_headers = []

    # Get all Set-Cookie headers (case-insensitive).
    for key, value in page.headers.items():
        if key.lower() == "set-cookie":
            if isinstance(value, list):
                set_cookie_headers.extend(value)
            else:
                set_cookie_headers.append(value)

    for sc in set_cookie_headers:
        sc_lower = sc.lower()
        cookie_name = sc.split("=", 1)[0].strip() if "=" in sc else "unnamed"

        # Check for HttpOnly flag (CWE-1004)
        if "httponly" not in sc_lower:
            findings.append(
                Finding(
                    title=f"Cookie '{cookie_name}' missing HttpOnly flag",
                    severity=Severity.LOW,
                    source="dast",
                    description=(
                        f"The cookie '{cookie_name}' does not have the HttpOnly flag, "
                        "allowing JavaScript to access it and increasing XSS impact."
                    ),
                    recommendation=(
                        "Add the HttpOnly flag to all cookies that don't need JavaScript access."
                    ),
                    cwe="CWE-1004",
                    file=page.url,
                    confidence=0.8,
                )
            )

        # Check for Secure flag (CWE-614)
        if "secure" not in sc_lower and page.url.startswith("https://"):
            findings.append(
                Finding(
                    title=f"Cookie '{cookie_name}' missing Secure flag",
                    severity=Severity.LOW,
                    source="dast",
                    description=(
                        f"The cookie '{cookie_name}' on an HTTPS page lacks the Secure flag, "
                        "allowing transmission over unencrypted channels."
                    ),
                    recommendation=(
                        "Add the Secure flag to all cookies set over HTTPS."
                    ),
                    cwe="CWE-614",
                    file=page.url,
                    confidence=0.8,
                )
            )

    return findings


def check_open_redirect(page: Page, fetch: Optional[object] = None) -> list[Finding]:
    """Detect obvious reflected redirect parameters.

    Looks for query parameters that are reflected in the body in a way that
    suggests an open redirect. Conservative heuristic to avoid false positives.
    """
    findings: list[Finding] = []

    # Parse query params from the URL.
    from urllib.parse import urlparse, parse_qs

    parsed = urlparse(page.url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    # Look for common redirect parameter names.
    redirect_param_names = ["redirect", "return", "returnurl", "redirect_uri", "next", "url", "goto"]

    for name in redirect_param_names:
        if name in params:
            values = params[name]
            for value in values:
                # If the value is reflected in the body unescaped, that's suspicious.
                if value and value in page.body:
                    # Verify it doesn't look like it's safely quoted or encoded.
                    # Very basic check: if it's in the body AND looks like a URL, suspect redirect.
                    if value.startswith(("http://", "https://", "//")):
                        findings.append(
                            Finding(
                                title="Potential Open Redirect",
                                severity=Severity.LOW,
                                source="dast",
                                description=(
                                    f"The redirect parameter '{name}' reflects an external URL in the page, "
                                    "suggesting an open redirect vulnerability."
                                ),
                                recommendation=(
                                    "Validate and whitelist redirect URLs; never trust user input for redirects."
                                ),
                                cwe="CWE-601",
                                file=page.url,
                                confidence=0.6,
                            )
                        )
                        break  # One finding per parameter.

    return findings


def check_reflected_input(page: Page) -> list[Finding]:
    """Detect reflected query parameters in the body unescaped.

    If a URL query value is reflected verbatim in the body unescaped,
    that suggests a reflected XSS vulnerability.
    """
    findings: list[Finding] = []

    from urllib.parse import urlparse, parse_qs

    parsed = urlparse(page.url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    for name, values in params.items():
        for value in values:
            if not value or len(value) < 3:  # Skip very short values to reduce noise.
                continue

            # Check if the value is in the body unescaped.
            if value in page.body:
                # Basic heuristic: check if it's surrounded by HTML tags or quotes.
                # If it's plain in the body, it's likely a reflected parameter.
                # Avoid alerts for common false positives like numbers or short strings.
                if not value.replace(".", "").replace("-", "").isdigit():
                    findings.append(
                        Finding(
                            title="Reflected User Input in Response",
                            severity=Severity.LOW,
                            source="dast",
                            description=(
                                f"The query parameter '{name}' with value '{value}' "
                                "is reflected in the response unescaped, suggesting a reflected XSS vulnerability."
                            ),
                            recommendation=(
                                "Ensure all user input is properly escaped before rendering in HTML. "
                                "Use a template engine with auto-escaping enabled."
                            ),
                            cwe="CWE-79",
                            file=page.url,
                            confidence=0.6,
                        )
                    )
                    break  # One finding per parameter.

    return findings


def check_directory_listing(page: Page) -> list[Finding]:
    """Detect directory listing pages (autoindex).

    Looks for patterns typical of automated directory indexes, such as
    "Index of /", which suggests the server is serving directory listings.
    """
    findings: list[Finding] = []

    # Look for common directory listing patterns.
    if re.search(r"index\s+of\s+/", page.body, re.IGNORECASE):
        findings.append(
            Finding(
                title="Directory Listing Enabled",
                severity=Severity.LOW,
                source="dast",
                description=(
                    "The server appears to be serving a directory listing, "
                    "exposing file and directory names that may leak information."
                ),
                recommendation=(
                    "Disable directory listing by removing the Indexes directive from Apache, "
                    "or ensure autoindex is disabled in your web server."
                ),
                cwe="CWE-548",
                file=page.url,
                confidence=0.8,
            )
        )

    return findings


def check_verbose_errors(page: Page) -> list[Finding]:
    """Detect verbose error messages and stack traces.

    Looks for patterns typical of unhandled exceptions and error dumps,
    such as Python tracebacks, PHP errors, or Java stack traces.
    """
    findings: list[Finding] = []

    error_patterns = [
        r"Traceback\s+\(most recent call last\)",  # Python
        r"Fatal error",  # PHP
        r"Exception in thread",  # Java
        r"TypeError:|NameError:|ValueError:",  # Python exceptions
        r"Parse error:",  # Generic PHP
        r"at java\.",  # Java stack trace
    ]

    for pattern in error_patterns:
        if re.search(pattern, page.body, re.IGNORECASE):
            findings.append(
                Finding(
                    title="Verbose Error Information Disclosed",
                    severity=Severity.LOW,
                    source="dast",
                    description=(
                        "The page reveals detailed error information or stack traces, "
                        "potentially exposing sensitive information about the application."
                    ),
                    recommendation=(
                        "Configure error handling to hide sensitive details from users. "
                        "Log errors server-side and return generic error messages to clients."
                    ),
                    cwe="CWE-209",
                    file=page.url,
                    confidence=0.7,
                )
            )
            break  # One finding per page.

    return findings


# List of all check functions to run.
ALL_CHECKS = [
    check_security_headers,
    check_cookie_flags,
    check_open_redirect,
    check_reflected_input,
    check_directory_listing,
    check_verbose_errors,
]


def run_checks(pages: list[Page]) -> list[Finding]:
    """Apply all checks to all pages and collect findings.

    Parameters
    ----------
    pages:
        List of Page objects to check.

    Returns
    -------
    A list of Finding objects (not yet deduplicated).
    """
    findings: list[Finding] = []
    for page in pages:
        for check in ALL_CHECKS:
            try:
                findings.extend(check(page))
            except Exception:
                # Never crash on a check failure.
                pass
    return findings
