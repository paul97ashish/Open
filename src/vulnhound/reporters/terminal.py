"""Human-friendly terminal report using rich (with a plain-text fallback)."""

from __future__ import annotations

from typing import Iterable

from vulnhound.findings import Finding, Severity, severity_counts, sort_findings

_COLOR = {
    Severity.INFO: "dim",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold white on red",
}


def severity_exit_code(findings: Iterable[Finding], threshold: Severity) -> int:
    """Return 1 if any finding is at or above ``threshold``, else 0."""
    for f in findings:
        if f.severity >= threshold:
            return 1
    return 0


def render(findings: Iterable[Finding], target: str = "") -> str:
    """Print a colourised table and return a plain-text version of the report."""
    findings = sort_findings(findings)
    plain = _plain(findings, target)
    try:
        _rich_print(findings, target)
    except Exception:  # pragma: no cover - never let rendering crash a scan
        print(plain)
    return plain


def _location(f: Finding) -> str:
    if not f.file:
        return "-"
    if f.start_line:
        if f.end_line and f.end_line != f.start_line:
            return f"{f.file}:{f.start_line}-{f.end_line}"
        return f"{f.file}:{f.start_line}"
    return f.file


def _rich_print(findings, target: str) -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()
    counts = severity_counts(findings)
    header = f"vulnhound — {len(list(findings))} finding(s)"
    if target:
        header += f" in {target}"
    console.print(f"[bold]{header}[/bold]")

    if not findings:
        console.print("[green]No findings.[/green]")
        return

    table = Table(show_lines=False, header_style="bold")
    table.add_column("Severity")
    table.add_column("Source")
    table.add_column("CWE")
    table.add_column("Location")
    table.add_column("Title")
    for f in findings:
        style = _COLOR.get(f.severity, "")
        table.add_row(
            f"[{style}]{f.severity.label.upper()}[/{style}]",
            f.source,
            f.cwe or "-",
            _location(f),
            f.title,
        )
    console.print(table)
    summary = "  ".join(
        f"{name}={n}" for name, n in counts.items() if n
    ) or "none"
    console.print(f"[dim]Summary: {summary}[/dim]")


def _plain(findings, target: str) -> str:
    lines = []
    header = f"vulnhound — {len(findings)} finding(s)"
    if target:
        header += f" in {target}"
    lines.append(header)
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)
    for f in findings:
        lines.append(
            f"[{f.severity.label.upper()}] ({f.source}) {f.cwe or '-'} "
            f"{_location(f)} :: {f.title}"
        )
        if f.description:
            lines.append(f"    {f.description}")
    counts = severity_counts(findings)
    summary = "  ".join(f"{name}={n}" for name, n in counts.items() if n) or "none"
    lines.append(f"Summary: {summary}")
    return "\n".join(lines)
