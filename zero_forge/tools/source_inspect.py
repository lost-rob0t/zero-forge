"""Source code, documentation, and Git inspection tools."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

# --- File classification ------------------------------------------------

_DOC_EXTS = {".md", ".txt", ".rst", ".adoc", ".org"}
_CONFIG_EXTS = {
    ".json", ".yaml", ".yml", ".ini", ".conf", ".properties",
    ".env", ".cfg", ".toml", ".xml", ".config",
}
_DATA_EXTS = {".csv", ".tsv", ".sql", ".sqlite"}
_SKIP_EXTS = {
    ".pyc", ".pyo", ".class", ".jar", ".war", ".zip", ".gz",
    ".tar", ".bz2", ".7z", ".rar", ".png", ".jpg", ".jpeg",
    ".gif", ".bmp", ".ico", ".pdf", ".exe", ".dll", ".so",
    ".dylib", ".bin", ".dat", ".db",
}
_DOC_FILENAMES = {
    "readme", "changelog", "changes", "authors", "license",
    "copying", "install", "hacking", "todo",
}
_CATEGORY_PRIORITY = {"documentation": 0, "config": 1, "data": 2, "code": 3}


def _detect_language(filepath: str) -> str:
    ext_map = {
        ".py": "python", ".rb": "ruby", ".js": "javascript", ".ts": "typescript",
        ".java": "java", ".c": "c", ".cpp": "cpp", ".h": "c",
        ".go": "go", ".rs": "rust", ".php": "php", ".sh": "bash",
        ".pl": "perl", ".xml": "xml", ".html": "html",
        ".yml": "yaml", ".yaml": "yaml",
        ".md": "markdown", ".txt": "text", ".rst": "rst",
        ".json": "json", ".ini": "ini", ".conf": "conf",
        ".properties": "properties", ".toml": "toml",
        ".cfg": "ini", ".env": "env", ".csv": "csv",
        ".cfm": "cfml", ".cfc": "cfml",
        ".asp": "asp", ".aspx": "asp", ".jsp": "jsp",
    }
    _, ext = os.path.splitext(filepath)
    return ext_map.get(ext.lower(), "unknown")


def _categorize_file(filepath: str) -> str:
    """Classify a file as documentation, config, data, or code."""
    ext = os.path.splitext(filepath)[1].lower()
    stem = os.path.splitext(os.path.basename(filepath))[0].lower()
    if ext in _DOC_EXTS or stem in _DOC_FILENAMES:
        return "documentation"
    if ext in _CONFIG_EXTS:
        return "config"
    if ext in _DATA_EXTS:
        return "data"
    return "code"


def _should_skip(filepath: str) -> bool:
    """Check if a file should be skipped (binary/archive/image)."""
    ext = os.path.splitext(filepath)[1].lower()
    return ext in _SKIP_EXTS


def read_source_files(
    source_path: str, max_files: int = 20, max_file_size: int = 51200
) -> list[dict[str, Any]]:
    """Read files from a directory or single file.

    Files are categorized (documentation/config/data/code) and sorted with
    documentation first so the LLM receives vulnerability context (README,
    write-ups, advisories) before source code.
    """
    base = Path(source_path)
    if not base.exists():
        return []

    if base.is_file():
        files = [base]
    else:
        files = []
        for root, dirs, filenames in os.walk(base):
            dirs[:] = [
    d for d in dirs
    if d not in {".git", "node_modules", "__pycache__", ".venv", "venv", "build", "dist"}
]
            for fname in sorted(filenames):
                files.append(Path(root) / fname)

    results: list[dict[str, Any]] = []

    for fpath in files:
        if _should_skip(str(fpath)):
            continue
        try:
            size = fpath.stat().st_size
            if size > max_file_size:
                continue
            raw = fpath.read_text(encoding="utf-8", errors="replace")
            if "\x00" in raw:
                continue
            category = _categorize_file(str(fpath))
            results.append({
                "path": str(fpath),
                "content": raw,
                "language": _detect_language(str(fpath)),
                "category": category,
                "filename": fpath.name,
            })
        except OSError:
            continue

    results.sort(key=lambda r: (_CATEGORY_PRIORITY.get(r["category"], 99), r["path"]))
    return results[:max_files]


def search_code(source_path: str, pattern: str, max_results: int = 10) -> list[dict[str, Any]]:
    """Search source code for a pattern (string or regex)."""
    base = Path(source_path)
    if not base.exists() or not pattern:
        return []

    results: list[dict[str, Any]] = []

    try:
        proc = subprocess.run(
            ["rg", "-n", "--no-heading", "-C", "2", pattern, str(base)],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines()[:max_results]:
                results.append({"match": line})
            return results
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    try:
        regex = re.compile(re.escape(pattern))
    except re.error:
        return results

    if base.is_file():
        files = [base]
    else:
        files = []
        for root, dirs, filenames in os.walk(base):
            dirs[:] = [
    d for d in dirs
    if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}
]
            for fname in sorted(filenames):
                files.append(Path(root) / fname)

    for fpath in sorted(files):
        if len(results) >= max_results:
            break
        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            if regex.search(line):
                start = max(0, i - 1)
                end = min(len(lines), i + 2)
                context = "\n".join(f"{start+j+1}: {lines[start+j]}" for j in range(end - start))
                results.append({
    "path": str(fpath), "line_number": i + 1,
    "line": line.strip(), "context": context,
})
                if len(results) >= max_results:
                    break

    return results


def git_diff_inspect(diff_text: str = "", repo_path: str = "") -> dict[str, Any]:
    """Inspect a git diff or patch."""
    result: dict[str, Any] = {
    "files_changed": [], "additions": 0,
    "deletions": 0, "diff_summary": "",
}

    diff = diff_text
    if not diff and repo_path:
        try:
            proc = subprocess.run(
    ["git", "diff", "HEAD"], cwd=repo_path,
    capture_output=True, text=True, timeout=10,
)
            diff = proc.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    if not diff:
        return result

    files: list[str] = []
    add = 0
    dele = 0

    for line in diff.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                files.append(parts[-1].lstrip("b/"))
        elif line.startswith("+++") or line.startswith("---"):
            continue
        elif line.startswith("+") and not line.startswith("+++"):
            add += 1
        elif line.startswith("-") and not line.startswith("---"):
            dele += 1

    result["files_changed"] = files
    result["additions"] = add
    result["deletions"] = dele
    result["diff_summary"] = f"{len(files)} file(s) changed, {add} insertion(s), {dele} deletion(s)"
    return result
