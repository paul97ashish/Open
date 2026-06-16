"""vulnhound command-line interface.

Subcommands:
  vulnhound scan code <path>            # SAST: LLM static analysis
  vulnhound scan deps <path>            # dependency-CVE scan (OSV.dev)
  vulnhound scan web  <url> --authorized  # DAST: authorized dynamic probing
  vulnhound serve                       # launch the web dashboard

Works with any open-source model via an OpenAI-compatible API (Ollama, vLLM,
LM Studio, llama.cpp server, ...). Defensive / authorized-use tool.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from vulnhound import __version__
from vulnhound.config import Config
from vulnhound.findings import Severity
from vulnhound.reporters import get_reporter
from vulnhound.reporters.terminal import severity_exit_code

# scan-type -> dotted scanner module exposing run(config, target)
_SCANNERS = {
    "code": "vulnhound.sast.scanner",
    "deps": "vulnhound.deps.scanner",
    "web": "vulnhound.dast.scanner",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnhound",
        description="LLM-powered cybersecurity vulnerability harness "
        "(any open-source model via an OpenAI-compatible API).",
    )
    parser.add_argument("--version", action="version", version=f"vulnhound {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # --- scan ---------------------------------------------------------------
    scan = sub.add_parser("scan", help="run a vulnerability scan")
    scan_sub = scan.add_subparsers(dest="scan_type", required=True)

    for name, helptext, target_help in (
        ("code", "static analysis of source code (SAST)", "path to a file or directory"),
        ("deps", "dependency-CVE scan via OSV.dev", "path to a project directory"),
        ("web", "dynamic probing of an authorized web target (DAST)", "target URL"),
    ):
        p = scan_sub.add_parser(name, help=helptext)
        p.add_argument("target", help=target_help)
        _add_common_scan_args(p)
        if name == "code":
            p.add_argument("--diff", nargs="?", const="HEAD", default=None,
                           metavar="REF", help="only scan files changed vs REF (default HEAD)")
            p.add_argument("--include", action="append", help="glob to include (repeatable)")
            p.add_argument("--exclude", action="append", help="glob to exclude (repeatable)")
        if name == "web":
            p.add_argument("--authorized", action="store_true",
                           help="confirm you are authorized to test this target (required)")
            p.add_argument("--max-pages", type=int, default=20)
            p.add_argument("--max-depth", type=int, default=2)

    # --- serve --------------------------------------------------------------
    serve = sub.add_parser("serve", help="launch the web dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true", help="auto-reload (dev)")

    return parser


def _add_common_scan_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--model", default=None, help="model name (env VULNHOUND_MODEL)")
    p.add_argument("--base-url", default=None,
                   help="OpenAI-compatible base URL, e.g. http://localhost:11434/v1")
    p.add_argument("--api-key-env", default=None,
                   help="environment variable holding the API key")
    p.add_argument("--temperature", type=float, default=0.1)
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--format", choices=["terminal", "json", "sarif"], default="terminal")
    p.add_argument("--output", default=None, help="write the report to this file")
    p.add_argument("--severity-threshold", default="low",
                   choices=[s.label for s in Severity],
                   help="fail (exit 1) when a finding at/above this severity exists")
    p.add_argument("--mock", action="store_true",
                   help="offline mode: use the built-in mock model (no network)")


def _config_from_scan_args(args: argparse.Namespace) -> Config:
    import os

    api_key = None
    if getattr(args, "api_key_env", None):
        api_key = os.environ.get(args.api_key_env)

    extra: dict = {}
    if getattr(args, "diff", None) is not None:
        extra["diff"] = True
        extra["ref"] = args.diff
    if getattr(args, "include", None):
        extra["include"] = args.include
    if getattr(args, "exclude", None):
        extra["exclude"] = args.exclude
    if getattr(args, "max_pages", None) is not None:
        extra["max_pages"] = args.max_pages
    if getattr(args, "max_depth", None) is not None:
        extra["max_depth"] = args.max_depth

    return Config.from_args(
        {
            "model": args.model,
            "base_url": args.base_url,
            "api_key": api_key,
            "mock": getattr(args, "mock", False),
            "temperature": args.temperature,
            "severity_threshold": args.severity_threshold,
            "concurrency": args.concurrency,
            "format": args.format,
            "output": args.output,
            "authorized": getattr(args, "authorized", False),
            "extra": extra,
        }
    )


def _run_scan(args: argparse.Namespace) -> int:
    import importlib

    config = _config_from_scan_args(args)
    module = importlib.import_module(_SCANNERS[args.scan_type])

    try:
        findings = module.run(config, args.target)
    except PermissionError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    except Exception as err:  # noqa: BLE001 - surface a clean message
        print(f"error: scan failed: {err}", file=sys.stderr)
        return 2

    reporter = get_reporter(config.fmt)
    report = reporter.render(findings, target=args.target)

    if config.output:
        with open(config.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"wrote {len(findings)} finding(s) to {config.output}", file=sys.stderr)
    elif config.fmt != "terminal":
        # terminal reporter already printed; others need explicit output
        print(report)

    return severity_exit_code(findings, config.severity_threshold)


def _run_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(
        "vulnhound.web.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )
    return 0


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "serve":
        return _run_serve(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
