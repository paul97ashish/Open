"""FastAPI web dashboard for vulnhound.

Provides a local web UI to launch any scan type and browse/download findings.
Calls the same scanner `run` functions and the same reporters.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Optional

from fastapi import FastAPI, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse

from vulnhound.config import Config
from vulnhound.findings import Finding, dedupe, severity_counts, sort_findings
from vulnhound.reporters import get_reporter

# Dispatcher: scan_type -> module path for lazy import
_SCANNER_MODULES = {
    "code": "vulnhound.sast.scanner",
    "deps": "vulnhound.deps.scanner",
    "web": "vulnhound.dast.scanner",
}


def _get_scanner_run(scan_type: str) -> Callable:
    """Lazily import and return the run function for the given scan type.

    Raises ImportError if the scanner module doesn't exist yet.
    """
    module_path = _SCANNER_MODULES.get(scan_type)
    if not module_path:
        raise ValueError(f"unknown scan type: {scan_type}")

    parts = module_path.rsplit(".", 1)
    module_name, func_name = parts[0], parts[1]

    mod = __import__(module_name, fromlist=[func_name])
    return getattr(mod, "run")


def _run_scan(
    scan_type: str,
    target: str,
    config: Config,
    scan_override: Optional[Callable] = None,
) -> list[Finding]:
    """Run a scan and return findings. If scan_override is provided, use it."""
    if scan_override:
        return scan_override(scan_type, target, config)

    scanner_run = _get_scanner_run(scan_type)
    return scanner_run(config, target)


def create_app(scan_override: Optional[Callable] = None) -> FastAPI:
    """Create and configure the FastAPI app.

    Args:
        scan_override: Optional callable(scan_type, target, config) -> list[Finding]
                      Used by tests to bypass real scanners. When None, the app
                      lazily imports the real scanner modules.

    Returns:
        A configured FastAPI application.
    """
    app = FastAPI(title="vulnhound — Security Scanner")

    # Setup templates and static files
    templates_dir = Path(__file__).parent / "templates"
    static_dir = Path(__file__).parent / "static"

    # Create a fresh Jinja2 environment with cache disabled
    jinja_env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        cache_size=0,  # Disable caching to avoid test conflicts
        auto_reload=True,
    )

    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # ---------------------------------------------------------------------------
    # Routes
    # ---------------------------------------------------------------------------

    @app.get("/healthz", response_model=dict)
    async def healthz():
        """Health check endpoint."""
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        """Render the scan form."""
        template = jinja_env.get_template("index.html")
        html = template.render(request=request)
        return HTMLResponse(html)

    @app.post("/scan", response_class=HTMLResponse)
    async def scan(
        request: Request,
        scan_type: str = Form(...),
        target: str = Form(...),
        model: str = Form(""),
        base_url: str = Form(""),
        mock: bool = Form(True),  # default True for safety in the UI
        severity_threshold: str = Form("low"),
        authorized: bool = Form(False),
    ):
        """Run a scan and render the results page."""
        try:
            # Build the config from form fields
            from vulnhound.findings import Severity

            config = Config(
                model=model,
                base_url=base_url or None,
                mock=mock,
                severity_threshold=Severity.from_str(severity_threshold),
                authorized=authorized,
            )

            # Run the scan
            findings = []
            error = None
            try:
                findings = _run_scan(scan_type, target, config, scan_override)
            except PermissionError as e:
                # DAST without authorization
                error = f"Permission denied: {str(e) or 'DAST scans require the authorized checkbox.'}"
            except ImportError as e:
                # Scanner module not yet available
                error = f"Scanner not available: {str(e)}"
            except Exception as e:
                # Catch any scanner exceptions
                error = f"Scan failed: {str(e)}"

            if error:
                template = jinja_env.get_template("results.html")
                html = template.render(
                    request=request,
                    error=error,
                    findings=[],
                    severity_summary={"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
                    target=target,
                    scan_type=scan_type,
                )
                return HTMLResponse(html)

            # Dedupe and sort findings
            findings = dedupe(findings)

            # Get severity counts
            severity_summary = severity_counts(findings)

            template = jinja_env.get_template("results.html")
            html = template.render(
                request=request,
                findings=findings,
                severity_summary=severity_summary,
                target=target,
                scan_type=scan_type,
                error=None,
            )
            return HTMLResponse(html)

        except Exception as e:
            # Catch any unexpected errors
            template = jinja_env.get_template("results.html")
            html = template.render(
                request=request,
                error=f"Unexpected error: {str(e)}",
                findings=[],
                severity_summary={"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
                target=target,
                scan_type=scan_type,
            )
            return HTMLResponse(html)

    @app.get("/api/scan", response_class=JSONResponse)
    async def api_scan(
        scan_type: str,
        target: str,
        model: str = "",
        base_url: str = "",
        mock: bool = True,
        severity_threshold: str = "low",
        authorized: bool = False,
        format: str = "json",
    ):
        """API endpoint to run a scan and return JSON or SARIF."""
        try:
            from vulnhound.findings import Severity

            config = Config(
                model=model,
                base_url=base_url or None,
                mock=mock,
                severity_threshold=Severity.from_str(severity_threshold),
                authorized=authorized,
            )

            # Run the scan
            try:
                findings = _run_scan(scan_type, target, config, scan_override)
            except PermissionError:
                raise HTTPException(
                    status_code=403,
                    detail="DAST scans require authorization.",
                )
            except ImportError as e:
                raise HTTPException(
                    status_code=503,
                    detail=f"Scanner not available: {str(e)}",
                )

            # Dedupe findings
            findings = dedupe(findings)

            # Get the appropriate reporter and render
            fmt = format.lower() if format else "json"
            if fmt not in ("json", "sarif"):
                fmt = "json"

            reporter = get_reporter(fmt)
            output = reporter.render(findings, target=target)

            # For JSON, parse and return as dict; for SARIF, return as-is
            if fmt == "json":
                return json.loads(output)
            else:
                # SARIF as JSON string
                return JSONResponse({"sarif": output})

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Scan failed: {str(e)}",
            )

    @app.post("/api/scan", response_class=JSONResponse)
    async def api_scan_post(
        scan_type: str = Form(...),
        target: str = Form(...),
        model: str = Form(""),
        base_url: str = Form(""),
        mock: bool = Form(True),
        severity_threshold: str = Form("low"),
        authorized: bool = Form(False),
        format: str = Form("json"),
    ):
        """POST version of /api/scan for form submission."""
        return await api_scan(
            scan_type=scan_type,
            target=target,
            model=model,
            base_url=base_url,
            mock=mock,
            severity_threshold=severity_threshold,
            authorized=authorized,
            format=format,
        )

    return app


# Module-level app for direct uvicorn usage
app = create_app()
