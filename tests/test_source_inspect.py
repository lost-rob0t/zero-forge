"""Tests for ZeroForge source inspection tools."""

import os
import tempfile
from pathlib import Path

from zero_forge.tools.source_inspect import (
    _categorize_file,
    _detect_language,
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
        assert results[0]["category"] == "code"
        assert results[0]["filename"] == os.path.basename(path)
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


def test_documentation_files_prioritized():
    """README.md should appear before .py files in results."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "README.md").write_text("# My Project\nVulnerable software X\n")
        (Path(tmpdir) / "exploit.py").write_text("print('exploit')\n")
        (Path(tmpdir) / "config.json").write_text('{"name": "test"}\n')
        results = read_source_files(tmpdir)
        assert len(results) == 3
        # Documentation should be first
        assert results[0]["category"] == "documentation"
        assert results[0]["filename"] == "README.md"
        # Config should be second
        assert results[1]["category"] == "config"
        # Code should be last
        assert results[2]["category"] == "code"


def test_non_code_files_read():
    """Non-code files (.md, .json, .txt) should be read and categorized."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "README.md").write_text("# Docs\n")
        (Path(tmpdir) / "requirements.txt").write_text("requests\n")
        (Path(tmpdir) / "settings.json").write_text('{}')
        results = read_source_files(tmpdir)
        assert len(results) == 3
        cats = {r["category"] for r in results}
        assert "documentation" in cats
        assert "config" in cats


def test_categorize_file():
    assert _categorize_file("README.md") == "documentation"
    assert _categorize_file("CHANGELOG.txt") == "documentation"
    assert _categorize_file("readme") == "documentation"
    assert _categorize_file("config.json") == "config"
    assert _categorize_file("settings.yaml") == "config"
    assert _categorize_file("data.csv") == "data"
    assert _categorize_file("exploit.py") == "code"
    assert _categorize_file("module.rb") == "code"


def test_detect_language_non_code():
    assert _detect_language("README.md") == "markdown"
    assert _detect_language("notes.txt") == "text"
    assert _detect_language("config.json") == "json"
    assert _detect_language("app.cfm") == "cfml"
    assert _detect_language("unknown.xyz") == "unknown"


def test_binary_files_skipped():
    """Binary files should be skipped, not included in results."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "README.md").write_text("docs")
        (Path(tmpdir) / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        results = read_source_files(tmpdir)
        assert len(results) == 1
        assert results[0]["filename"] == "README.md"


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


def test_git_diff_inspect_preserves_filename_beginning_with_b():
    diff = """diff --git a/bbb.py b/bbb.py
--- a/bbb.py
+++ b/bbb.py
+x
"""
    assert git_diff_inspect(diff)["files_changed"] == ["bbb.py"]


def test_git_diff_inspect_preserves_unquoted_path_with_spaces():
    diff = """diff --git a/file with spaces.py b/file with spaces.py
--- a/file with spaces.py
+++ b/file with spaces.py
+x
"""
    assert git_diff_inspect(diff)["files_changed"] == ["file with spaces.py"]


def test_git_diff_inspect_preserves_quoted_path_with_spaces():
    diff = """diff --git "a/file with spaces.py" "b/file with spaces.py"
--- "a/file with spaces.py"
+++ "b/file with spaces.py"
+x
"""
    assert git_diff_inspect(diff)["files_changed"] == ["file with spaces.py"]


def test_git_diff_inspect_rename_reports_destination():
    diff = """diff --git a/old.py b/better.py
similarity index 100%
rename from old.py
rename to better.py
"""
    assert git_diff_inspect(diff)["files_changed"] == ["better.py"]


def test_git_diff_inspect_new_file_ignores_dev_null():
    diff = """diff --git a/new.py b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
+x
"""
    result = git_diff_inspect(diff)
    assert result["files_changed"] == ["new.py"]
    assert result["additions"] == 1


def test_git_diff_inspect_deleted_file_ignores_dev_null():
    diff = """diff --git a/deleted.py b/deleted.py
deleted file mode 100644
--- a/deleted.py
+++ /dev/null
-x
"""
    result = git_diff_inspect(diff)
    assert result["files_changed"] == ["deleted.py"]
    assert result["deletions"] == 1

