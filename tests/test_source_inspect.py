"""Tests for ZeroForge source inspection tools."""

import os
import tempfile
from pathlib import Path

from zero_forge.tools.source_inspect import (
    git_diff_inspect,
    read_source_files,
    search_code,
)


def test_read_source_files_single():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write("print('hello')\n")
        f.flush()
        path = f.name
    try:
        results = read_source_files(path)
        assert len(results) == 1
        assert "hello" in results[0]["content"]
        assert results[0]["language"] == "python"
    finally:
        os.unlink(path)


def test_read_source_files_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "a.py").write_text("x = 1\n")
        (Path(tmpdir) / "b.rb").write_text("puts 'hi'\n")
        results = read_source_files(tmpdir)
        assert len(results) == 2
        langs = {r["language"] for r in results}
        assert "python" in langs
        assert "ruby" in langs


def test_read_source_files_nonexistent():
    results = read_source_files("/nonexistent/path/xyz")
    assert results == []


def test_read_source_files_max_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        for i in range(10):
            (Path(tmpdir) / f"file_{i}.py").write_text(f"# file {i}\n")
        results = read_source_files(tmpdir, max_files=3)
        assert len(results) == 3


def test_search_code_match():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "test.py").write_text("vulnerable_function()\nsafe_code\n")
        results = search_code(tmpdir, "vulnerable_function")
        assert len(results) == 1
        assert "vulnerable_function" in results[0]["line"]


def test_search_code_no_match():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "test.py").write_text("print('safe')\n")
        results = search_code(tmpdir, "nonexistent_pattern_xyz")
        assert results == []


def test_search_code_empty_pattern():
    results = search_code("/tmp", "")
    assert results == []


def test_git_diff_inspect_basic():
    diff = """diff --git a/vuln.py b/vuln.py
index 123..456 100644
--- a/vuln.py
+++ b/vuln.py
@@ -1,3 +1,4 @@
 import os
-old_code()
+new_code()
+extra_line()
"""
    result = git_diff_inspect(diff_text=diff)
    assert "vuln.py" in result["files_changed"]
    assert result["additions"] == 2
    assert result["deletions"] == 1


def test_git_diff_inspect_empty():
    result = git_diff_inspect(diff_text="")
    assert result["files_changed"] == []
    assert result["additions"] == 0
    assert result["deletions"] == 0
