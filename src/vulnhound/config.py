"""Runtime configuration shared across the CLI, scanners and web UI."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional

from vulnhound.findings import Severity


@dataclass
class Config:
    """Everything a scanner / reporter needs to run."""

    model: str = ""
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    mock: bool = False
    temperature: float = 0.1
    severity_threshold: Severity = Severity.LOW
    concurrency: int = 4
    fmt: str = "terminal"
    output: Optional[str] = None
    authorized: bool = False  # required gate for DAST
    # scan-mode specific knobs (max_files, max_depth, include/exclude globs, ...)
    extra: dict = field(default_factory=dict)
    # offline testing helpers consumed by model_client.get_client
    mock_responses: Optional[dict] = None
    mock_default: str = "[]"

    @classmethod
    def from_args(cls, args: Any) -> "Config":
        """Build from an argparse.Namespace or a plain dict.

        Falls back to VULNHOUND_MODEL / VULNHOUND_BASE_URL / VULNHOUND_API_KEY.
        """
        get = _getter(args)
        threshold = get("severity_threshold", None)
        return cls(
            model=get("model", None) or os.environ.get("VULNHOUND_MODEL", ""),
            base_url=get("base_url", None) or os.environ.get("VULNHOUND_BASE_URL"),
            api_key=get("api_key", None) or os.environ.get("VULNHOUND_API_KEY"),
            mock=bool(get("mock", False)),
            temperature=float(get("temperature", 0.1) or 0.1),
            severity_threshold=Severity.from_str(threshold) if threshold is not None else Severity.LOW,
            concurrency=int(get("concurrency", 4) or 4),
            fmt=get("format", None) or get("fmt", None) or "terminal",
            output=get("output", None),
            authorized=bool(get("authorized", False)),
            extra=dict(get("extra", {}) or {}),
        )


def _getter(args: Any):
    if isinstance(args, dict):
        return lambda k, d=None: args.get(k, d)
    return lambda k, d=None: getattr(args, k, d)


def load_yaml(path: str) -> dict:
    """Load a YAML config file into a dict (empty dict if missing/blank)."""
    try:
        import yaml
    except ImportError:  # pragma: no cover - yaml is a declared dependency
        return {}
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return data or {}
