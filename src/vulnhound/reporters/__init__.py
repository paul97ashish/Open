"""Reporter dispatch.

Each reporter exposes ``render(findings, target="") -> str``. The terminal
reporter additionally prints a colourised table as a side effect.
"""

from __future__ import annotations

from vulnhound.reporters import json_report, sarif, terminal

_REPORTERS = {
    "terminal": terminal,
    "json": json_report,
    "sarif": sarif,
}


def get_reporter(fmt: str):
    """Return the reporter module for ``fmt`` (terminal|json|sarif)."""
    key = (fmt or "terminal").lower()
    if key not in _REPORTERS:
        raise ValueError(
            f"unknown format {fmt!r}; choose one of {', '.join(_REPORTERS)}"
        )
    return _REPORTERS[key]


__all__ = ["get_reporter", "terminal", "json_report", "sarif"]
