"""Tests for vulnhound.sast.collector — fully offline, no model/network."""

from __future__ import annotations

import os

import pytest

from vulnhound.sast.collector import (
    IGNORE_DIRS,
    chunk_file,
    discover_files,
    number_lines,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def write_bytes(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


# ---------------------------------------------------------------------------
# discover_files
# ---------------------------------------------------------------------------


class TestDiscoverFiles:
    def test_returns_code_files(self, tmp_path):
        write(str(tmp_path / "app.py"), "print('hello')")
        write(str(tmp_path / "util.js"), "console.log('hi');")
        write(str(tmp_path / "README.md"), "# docs")  # not a code ext in default set

        files = discover_files(str(tmp_path))
        assert "app.py" in files
        assert "util.js" in files
        # .md is not in CODE_EXTENSIONS by default
        assert "README.md" not in files

    def test_ignores_ignored_dirs(self, tmp_path):
        for ignored_dir in ["node_modules", "__pycache__", ".git", "venv"]:
            write(str(tmp_path / ignored_dir / "secret.py"), "x = 1")
        write(str(tmp_path / "main.py"), "x = 1")

        files = discover_files(str(tmp_path))
        assert files == ["main.py"]

    def test_skips_oversized_files(self, tmp_path):
        # Write a file larger than max_file_bytes
        big = str(tmp_path / "big.py")
        write(big, "x = 1\n" * 50_000)  # well over 200 kB
        write(str(tmp_path / "small.py"), "x = 1")

        files = discover_files(str(tmp_path), max_file_bytes=200_000)
        assert "big.py" not in files
        assert "small.py" in files

    def test_skips_binary_files(self, tmp_path):
        # File with NUL bytes is considered binary.
        write_bytes(str(tmp_path / "binary.py"), b"x = 1\x00\xff\xfe binary content")
        write(str(tmp_path / "text.py"), "x = 1")

        files = discover_files(str(tmp_path))
        assert "binary.py" not in files
        assert "text.py" in files

    def test_include_glob(self, tmp_path):
        write(str(tmp_path / "app.py"), "x=1")
        write(str(tmp_path / "util.js"), "x=1")

        files = discover_files(str(tmp_path), include=["*.py"])
        assert "app.py" in files
        assert "util.js" not in files

    def test_exclude_glob(self, tmp_path):
        write(str(tmp_path / "app.py"), "x=1")
        write(str(tmp_path / "test_app.py"), "x=1")

        files = discover_files(str(tmp_path), exclude=["test_*.py"])
        assert "app.py" in files
        assert "test_app.py" not in files

    def test_nested_directories(self, tmp_path):
        write(str(tmp_path / "pkg" / "module.py"), "x = 1")
        write(str(tmp_path / "pkg" / "sub" / "deep.py"), "y = 2")

        files = discover_files(str(tmp_path))
        assert "pkg/module.py" in files
        assert "pkg/sub/deep.py" in files

    def test_single_file_input(self, tmp_path):
        path = str(tmp_path / "only.py")
        write(path, "x = 1")

        files = discover_files(path)
        assert files == ["only.py"]

    def test_single_file_wrong_extension(self, tmp_path):
        path = str(tmp_path / "data.csv")
        write(path, "a,b,c")

        files = discover_files(path)
        assert files == []

    def test_returns_sorted(self, tmp_path):
        for name in ["zebra.py", "alpha.py", "middle.py"]:
            write(str(tmp_path / name), "x=1")

        files = discover_files(str(tmp_path))
        assert files == sorted(files)

    def test_returns_posix_paths(self, tmp_path):
        write(str(tmp_path / "sub" / "file.py"), "x=1")
        files = discover_files(str(tmp_path))
        for f in files:
            assert "\\" not in f, f"Path should use POSIX separators: {f!r}"

    def test_empty_directory(self, tmp_path):
        files = discover_files(str(tmp_path))
        assert files == []

    def test_custom_max_file_bytes(self, tmp_path):
        # 10-byte limit — even a tiny file is too large if it exceeds it.
        path = str(tmp_path / "big.py")
        write(path, "x = 1\n" * 5)  # ~30 bytes

        files = discover_files(str(tmp_path), max_file_bytes=10)
        assert "big.py" not in files


# ---------------------------------------------------------------------------
# number_lines
# ---------------------------------------------------------------------------


class TestNumberLines:
    def test_single_line(self):
        result = number_lines("hello")
        assert result == "     1| hello"

    def test_multiple_lines(self):
        result = number_lines("a\nb\nc")
        lines = result.split("\n")
        assert lines[0] == "     1| a"
        assert lines[1] == "     2| b"
        assert lines[2] == "     3| c"

    def test_line_numbers_right_aligned_to_6(self):
        # Produce enough lines to get a two-digit number.
        text = "\n".join(f"line {i}" for i in range(1, 12))
        result = number_lines(text)
        output_lines = result.split("\n")
        # Line 10 should have its number right-justified within 6 chars.
        assert output_lines[9].startswith("    10| ")

    def test_empty_string(self):
        result = number_lines("")
        # single empty line (splitlines of "" is [])
        assert result == ""


# ---------------------------------------------------------------------------
# chunk_file
# ---------------------------------------------------------------------------


class TestChunkFile:
    def test_small_file_single_chunk(self):
        text = "line one\nline two\nline three"
        chunks = chunk_file("test.py", text, max_chars=10_000)
        assert len(chunks) == 1
        start_line, chunk_text = chunks[0]
        assert start_line == 1
        # Absolute line numbers must appear in the text.
        assert "     1|" in chunk_text
        assert "     2|" in chunk_text
        assert "     3|" in chunk_text

    def test_large_file_produces_multiple_chunks(self):
        # Generate a file that is definitely bigger than max_chars.
        num_lines = 300
        text = "\n".join(f"x = {i}  # some padding to make lines longer" for i in range(num_lines))
        chunks = chunk_file("big.py", text, max_chars=2000, overlap_lines=5)
        assert len(chunks) > 1

    def test_absolute_line_numbers_in_second_chunk(self):
        """The second chunk must contain absolute (not local) line numbers."""
        num_lines = 100
        text = "\n".join(f"line {i}" for i in range(1, num_lines + 1))
        # Force small chunks so we definitely get a second chunk.
        chunks = chunk_file("f.py", text, max_chars=500, overlap_lines=2)
        assert len(chunks) >= 2

        # The second chunk's start_line should be > 1.
        second_start, second_text = chunks[1]
        assert second_start > 1

        # The text in the second chunk should contain line numbers >= second_start.
        first_numbered_line = second_text.split("\n")[0]
        # Extract the number before the '|'
        num_str = first_numbered_line.split("|")[0].strip()
        assert int(num_str) == second_start

    def test_chunk_text_uses_absolute_numbers(self):
        """Every line in every chunk must carry its absolute (1-based) number."""
        num_lines = 60
        text = "\n".join(f"x = {i}" for i in range(1, num_lines + 1))
        chunks = chunk_file("f.py", text, max_chars=600, overlap_lines=3)

        for start_line, chunk_text in chunks:
            chunk_lines = chunk_text.split("\n")
            first_num_str = chunk_lines[0].split("|")[0].strip()
            assert int(first_num_str) == start_line, (
                f"Expected chunk to start at line {start_line}, "
                f"but first line number was {first_num_str}"
            )

    def test_overlap_coverage(self):
        """Overlap lines from the end of chunk N appear at the start of chunk N+1."""
        num_lines = 80
        text = "\n".join(f"line_{i}" for i in range(1, num_lines + 1))
        overlap = 5
        chunks = chunk_file("f.py", text, max_chars=500, overlap_lines=overlap)

        if len(chunks) >= 2:
            _, first_text = chunks[0]
            second_start, second_text = chunks[1]
            # second_start should overlap into the end of the first chunk
            _, first_start = chunks[0][0], chunks[0][0]
            # The second chunk's start line should be less than the end of the first.
            first_lines = first_text.split("\n")
            last_num_in_first = int(first_lines[-1].split("|")[0].strip())
            assert second_start <= last_num_in_first

    def test_empty_file(self):
        chunks = chunk_file("empty.py", "")
        assert len(chunks) == 1
        start_line, text = chunks[0]
        assert start_line == 1
        assert text == ""
