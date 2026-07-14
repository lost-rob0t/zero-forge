"""Tests for ZeroForge source inspection tools."""

import os
import tempfile
from pathlib import Path

from zero_forge.tools.source_inspect import (
    _categorize_file,
    _detect_language,
    _is_secret_file,
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
        readable = [r for r in results if not r.get("skipped")]
        assert len(readable) == 1
        assert "hello" in readable[0]["content"]
        assert readable[0]["language"] == "python"
        assert readable[0]["category"] == "code"
        assert readable[0]["filename"] == os.path.basename(path)
    finally:
        os.unlink(path)


def test_read_source_files_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "a.py").write_text("x = 1\n")
        (Path(tmpdir) / "b.rb").write_text("puts 'hi'\n")
        results = read_source_files(tmpdir)
        readable = [r for r in results if not r.get("skipped")]
        assert len(readable) == 2
        langs = {r["language"] for r in readable}
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
        readable = [r for r in results if not r.get("skipped")]
        assert len(readable) == 3


def test_documentation_files_prioritized():
    """README.md should appear before .py files in results."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "README.md").write_text("# My Project\nVulnerable software X\n")
        (Path(tmpdir) / "exploit.py").write_text("print('exploit')\n")
        (Path(tmpdir) / "config.json").write_text('{"name": "test"}\n')
        results = read_source_files(tmpdir)
        readable = [r for r in results if not r.get("skipped")]
        assert len(readable) == 3
        # Documentation should be first
        assert readable[0]["category"] == "documentation"
        assert readable[0]["filename"] == "README.md"
        # Config should be second
        assert readable[1]["category"] == "config"
        # Code should be last
        assert readable[2]["category"] == "code"


def test_non_code_files_read():
    """Non-code files (.md, .json, .txt) should be read and categorized."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "README.md").write_text("# Docs\n")
        (Path(tmpdir) / "requirements.txt").write_text("requests\n")
        (Path(tmpdir) / "settings.json").write_text('{}')
        results = read_source_files(tmpdir)
        readable = [r for r in results if not r.get("skipped")]
        assert len(readable) == 3
        cats = {r["category"] for r in readable}
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
        readable = [r for r in results if not r.get("skipped")]
        assert len(readable) == 1
        assert readable[0]["filename"] == "README.md"


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


# --- Security tests (issue #5) ------------------------------------------

def test_symlink_not_followed():
    """Symlinks should be skipped in safe mode, not followed."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a file outside the source root
        outside = Path(tmpdir) / "_outside_secret.txt"
        outside.write_text("SECRET_DATA=exfiltrated\n")

        # Create source directory with a symlink pointing outside
        src = Path(tmpdir) / "src"
        src.mkdir()
        (src / "safe.py").write_text("x = 1\n")
        link = src / "leak.txt"
        os.symlink(outside, link)

        results = read_source_files(str(src))
        readable = [r for r in results if not r.get("skipped")]
        skipped = [r for r in results if r.get("skipped")]

        # The symlink should be skipped, not read
        assert len(readable) == 1
        assert readable[0]["filename"] == "safe.py"
        assert any(s["filename"] == "leak.txt" for s in skipped)
        assert any("symlink" in s["reason"] for s in skipped)

        # The secret content must not appear anywhere in results
        for r in results:
            assert "exfiltrated" not in r.get("content", "")


def test_env_file_excluded():
    """ .env files should be excluded in safe mode."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "safe.py").write_text("x = 1\n")
        (Path(tmpdir) / ".env").write_text("API_KEY=supersecret123\n")

        results = read_source_files(tmpdir)
        readable = [r for r in results if not r.get("skipped")]
        skipped = [r for r in results if r.get("skipped")]

        assert len(readable) == 1
        assert readable[0]["filename"] == "safe.py"
        assert any(s["filename"] == ".env" for s in skipped)
        assert any("secret" in s["reason"] for s in skipped)

        # Secret content must not appear in any result
        for r in results:
            assert "supersecret123" not in r.get("content", "")


def test_private_key_excluded():
    """Private key files should be excluded in safe mode."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "exploit.py").write_text("print('exploit')\n")
        (Path(tmpdir) / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nfakekey\n")
        (Path(tmpdir) / "server.pem").write_text("-----BEGIN CERTIFICATE-----\nfakecert\n")

        results = read_source_files(tmpdir)
        readable = [r for r in results if not r.get("skipped")]
        skipped = [r for r in results if r.get("skipped")]

        assert len(readable) == 1
        assert readable[0]["filename"] == "exploit.py"
        assert any(s["filename"] == "id_rsa" for s in skipped)
        assert any(s["filename"] == "server.pem" for s in skipped)

        for r in results:
            assert "fakekey" not in r.get("content", "")
            assert "fakecert" not in r.get("content", "")


def test_gitignored_file_excluded():
    """Files matching .gitignore patterns should be excluded in safe mode."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / ".gitignore").write_text("*.local\nsecrets/\n")
        (Path(tmpdir) / "app.py").write_text("print('app')\n")
        (Path(tmpdir) / "config.local").write_text("SECRET=hidden\n")
        secrets_dir = Path(tmpdir) / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "token.txt").write_text("token=hidden\n")

        results = read_source_files(tmpdir)
        readable = [r for r in results if not r.get("skipped")]
        skipped = [r for r in results if r.get("skipped")]

        filenames_read = {r["filename"] for r in readable}
        skipped_names = {r["filename"] for r in skipped}

        assert "app.py" in filenames_read
        assert "config.local" not in filenames_read
        assert "token.txt" not in filenames_read
        assert "config.local" in skipped_names


def test_unsafe_mode_reads_secrets_and_symlinks():
    """In unsafe mode, secret files and symlinks should be read."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a file outside the source root
        outside = Path(tmpdir) / "_outside.txt"
        outside.write_text("SECRET_DATA=exfiltrated\n")

        src = Path(tmpdir) / "src"
        src.mkdir()
        (src / "safe.py").write_text("x = 1\n")
        (src / ".env").write_text("API_KEY=supersecret123\n")
        link = src / "leak.txt"
        os.symlink(outside, link)

        results = read_source_files(str(src), unsafe=True)
        readable = [r for r in results if not r.get("skipped")]
        skipped = [r for r in results if r.get("skipped")]

        # In unsafe mode, everything should be read and nothing skipped
        assert len(skipped) == 0
        filenames = {r["filename"] for r in readable}
        assert ".env" in filenames
        assert "leak.txt" in filenames
        assert "safe.py" in filenames

        # Content should be present (unsafe mode)
        env_result = [r for r in readable if r["filename"] == ".env"][0]
        assert "supersecret123" in env_result["content"]


def test_skipped_files_have_no_content():
    """Skipped file entries must never contain file content."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / ".env").write_text("API_KEY=supersecret123\n")
        (Path(tmpdir) / "safe.py").write_text("x = 1\n")

        results = read_source_files(tmpdir)
        skipped = [r for r in results if r.get("skipped")]

        assert len(skipped) >= 1
        for s in skipped:
            assert "content" not in s
            assert "reason" in s
            assert s["skipped"] is True


def test_is_secret_file_detection():
    """The _is_secret_file helper should detect common secret files."""
    assert _is_secret_file(".env")
    assert _is_secret_file(".env.local")
    assert _is_secret_file(".env.production")
    assert _is_secret_file("id_rsa")
    assert _is_secret_file("id_ed25519")
    assert _is_secret_file("server.pem")
    assert _is_secret_file("private.key")
    assert _is_secret_file(".npmrc")
    assert _is_secret_file("credentials.json")
    assert _is_secret_file("my-api-key.txt")
    assert _is_secret_file("secret_token.yaml")

    # Non-secret files should not match
    assert not _is_secret_file("exploit.py")
    assert not _is_secret_file("README.md")
    assert not _is_secret_file("config.json")
    assert not _is_secret_file("payload.rb")


def test_env_example_excluded_safe_mode():
    """ .env.example should also be excluded in safe mode (templates may contain real secrets)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "app.py").write_text("x = 1\n")
        (Path(tmpdir) / ".env.example").write_text("API_KEY=example_key\n")

        results = read_source_files(tmpdir)
        readable = [r for r in results if not r.get("skipped")]

        assert len(readable) == 1
        assert readable[0]["filename"] == "app.py"


def test_symlink_escape_outside_root():
    """A symlink that resolves outside the source root must be skipped."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a secret file outside the source root
        outside_dir = Path(tmpdir) / "outside"
        outside_dir.mkdir()
        secret_file = outside_dir / "etc_shadow.txt"
        secret_file.write_text("root:$6$hashedpassword\n")

        # Create source directory with a symlink to the outside file
        src = Path(tmpdir) / "src"
        src.mkdir()
        (src / "safe.py").write_text("x = 1\n")
        link = src / "shadow_link"
        os.symlink(secret_file, link)

        results = read_source_files(str(src))
        readable = [r for r in results if not r.get("skipped")]

        assert len(readable) == 1
        assert readable[0]["filename"] == "safe.py"

        # The secret content must not be present
        for r in results:
            assert "hashedpassword" not in r.get("content", "")


def test_dotenv_with_extension_excluded():
    """Files like config.env, app.env should be excluded in safe mode."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "app.py").write_text("x = 1\n")
        (Path(tmpdir) / "config.env").write_text("SECRET=hidden\n")

        results = read_source_files(tmpdir)
        readable = [r for r in results if not r.get("skipped")]

        assert len(readable) == 1
        assert readable[0]["filename"] == "app.py"
