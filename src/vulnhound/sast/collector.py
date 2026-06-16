"""File discovery and text utilities for the SAST scanner.

Responsibilities:
  - Walk a directory tree and collect source files that are worth scanning.
  - Number lines so the model can cite exact positions.
  - Chunk large files into overlapping windows that fit the model's context.
  - Identify files changed in git since a reference commit.
"""

from __future__ import annotations

import fnmatch
import os
import subprocess
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CODE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".java",
        ".go",
        ".rb",
        ".php",
        ".c",
        ".h",
        ".cpp",
        ".cc",
        ".cxx",
        ".hh",
        ".hpp",
        ".cs",
        ".rs",
        ".sh",
        ".bash",
        ".zsh",
        ".kt",
        ".kts",
        ".scala",
        ".sql",
        ".swift",
        ".m",
        ".mm",
        ".r",
        ".pl",
        ".pm",
        ".lua",
        ".ex",
        ".exs",
        ".erl",
        ".hrl",
        ".dart",
        ".groovy",
        ".tf",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".xml",
        ".html",
        ".htm",
        ".vue",
        ".svelte",
    }
)

IGNORE_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "venv",
        ".venv",
        "env",
        ".env",
        "__pycache__",
        "dist",
        "build",
        "out",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        "vendor",
        "third_party",
        "target",
        "coverage",
        ".coverage",
        "htmlcoverage",
        ".eggs",
        "*.egg-info",
        ".DS_Store",
        "tmp",
        "temp",
        ".idea",
        ".vscode",
        "__mocks__",
    }
)

# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def _is_binary(path: str, chunk_size: int = 8192) -> bool:
    """Heuristic: a file is binary if its first chunk contains a NUL byte."""
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(chunk_size)
    except OSError:
        return True


def _matches_any(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(name, pat) for pat in patterns)


def discover_files(
    root: str,
    include: Optional[list[str]] = None,
    exclude: Optional[list[str]] = None,
    max_file_bytes: int = 200_000,
) -> list[str]:
    """Return repo-relative POSIX paths for all scannable source files under *root*.

    Parameters
    ----------
    root:
        A directory to walk, or a single file path. The returned paths are
        relative to *root* (or to the parent directory when *root* is a file).
    include:
        If given, only files whose names match at least one fnmatch glob are kept.
    exclude:
        Files whose names match any of these globs are skipped.
    max_file_bytes:
        Files larger than this are skipped (default 200 kB).
    """
    root = os.path.abspath(root)

    # Single-file shortcut.
    if os.path.isfile(root):
        base = os.path.dirname(root)
        name = os.path.basename(root)
        ext = os.path.splitext(name)[1].lower()
        if ext not in CODE_EXTENSIONS:
            return []
        if include and not _matches_any(name, include):
            return []
        if exclude and _matches_any(name, exclude):
            return []
        if os.path.getsize(root) > max_file_bytes:
            return []
        if _is_binary(root):
            return []
        rel = os.path.relpath(root, base).replace(os.sep, "/")
        return [rel]

    results: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        # Prune ignored directories in-place so os.walk won't recurse into them.
        dirnames[:] = [
            d
            for d in dirnames
            if d not in IGNORE_DIRS
            and not any(fnmatch.fnmatch(d, pat) for pat in IGNORE_DIRS if "*" in pat)
        ]

        for name in sorted(filenames):
            ext = os.path.splitext(name)[1].lower()
            if ext not in CODE_EXTENSIONS:
                continue
            if include and not _matches_any(name, include):
                continue
            if exclude and _matches_any(name, exclude):
                continue

            abs_path = os.path.join(dirpath, name)

            try:
                size = os.path.getsize(abs_path)
            except OSError:
                continue
            if size > max_file_bytes:
                continue
            if _is_binary(abs_path):
                continue

            rel = os.path.relpath(abs_path, root).replace(os.sep, "/")
            results.append(rel)

    return sorted(results)


# ---------------------------------------------------------------------------
# Line numbering
# ---------------------------------------------------------------------------


def number_lines(text: str) -> str:
    """Prefix every line with its 1-based line number right-aligned to 6 chars.

    Example::

        "     1| first line\\n     2| second line"
    """
    lines = text.splitlines()
    parts = [f"{i:>6}| {line}" for i, line in enumerate(lines, start=1)]
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------


def chunk_file(
    path: str,
    text: str,
    max_chars: int = 12_000,
    overlap_lines: int = 20,
) -> list[tuple[int, str]]:
    """Split a file's text into overlapping chunks that fit within *max_chars*.

    Returns a list of ``(start_line, numbered_chunk_text)`` tuples where
    *start_line* is 1-based and the embedded line numbers in the chunk text
    use **absolute** line numbers so the model cites correct positions.

    Small files that fit in one chunk are returned as a single-element list.
    """
    lines = text.splitlines()
    if not lines:
        return [(1, "")]

    # Build the numbered representation for every line upfront.
    numbered: list[str] = [f"{i:>6}| {line}" for i, line in enumerate(lines, start=1)]

    chunks: list[tuple[int, str]] = []
    idx = 0  # index into *numbered* (0-based)

    while idx < len(numbered):
        # Accumulate lines until we'd exceed max_chars.
        chunk_lines: list[str] = []
        char_count = 0
        j = idx

        while j < len(numbered):
            entry = numbered[j]
            # +1 for the newline we'll join with
            if chunk_lines and char_count + len(entry) + 1 > max_chars:
                break
            chunk_lines.append(entry)
            char_count += len(entry) + 1
            j += 1

        # If we couldn't fit even a single line, force-include it to avoid
        # an infinite loop (pathological lines > max_chars).
        if not chunk_lines:
            chunk_lines.append(numbered[idx])
            j = idx + 1

        start_line = idx + 1  # 1-based
        chunks.append((start_line, "\n".join(chunk_lines)))

        if j >= len(numbered):
            break

        # Advance with overlap: step back *overlap_lines* from where we stopped.
        next_idx = max(idx + 1, j - overlap_lines)
        idx = next_idx

    return chunks


# ---------------------------------------------------------------------------
# Git diff helper
# ---------------------------------------------------------------------------


def changed_files(root: str, ref: str = "HEAD") -> list[str]:
    """Return repo-relative paths of files changed since *ref*.

    Runs ``git -C root diff --name-only ref``. Non-git directories or any
    subprocess error returns an empty list silently.
    """
    try:
        result = subprocess.run(
            ["git", "-C", root, "diff", "--name-only", ref],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return []
        paths: list[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            abs_path = os.path.join(root, line)
            if not os.path.isfile(abs_path):
                continue
            ext = os.path.splitext(line)[1].lower()
            if ext not in CODE_EXTENSIONS:
                continue
            # Return as POSIX relative path.
            paths.append(line.replace(os.sep, "/"))
        return sorted(paths)
    except Exception:  # noqa: BLE001 - tolerate anything
        return []
