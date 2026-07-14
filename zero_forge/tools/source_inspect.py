"""Source code and Git inspection tools."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any


def _detect_language(filepath: str) -> str:
    ext_map = {
        ".py": "python", ".rb": "ruby", ".js": "javascript", ".ts": "typescript",
        ".java": "java", ".c": "c", ".cpp": "cpp", ".h": "c",
        ".go": "go", ".rs": "rust", ".php": "php", ".sh": "bash",
        ".pl": "perl", ".xml": "xml", ".html": "html", ".yml": "yaml", ".yaml": "yaml",
    }
    _, ext = os.path.splitext(filepath)
    return ext_map.get(ext.lower(), "unknown")


def read_source_files(source_path: str, max_files: int = 20, max_file_size: int = 51200) -> list[dict[str, Any]]:
    """Read source files from a directory or single file."""
    base = Path(source_path)
    if not base.exists():
        return []

    results: list[dict[str, Any]] = []

    if base.is_file():
        files = [base]
    else:
        files = []
        for root, dirs, filenames in os.walk(base):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv", "venv", "build", "dist"}]
            for fname in sorted(filenames):
                files.append(Path(root) / fname)
        files = sorted(files)

    for fpath in files[:max_files]:
        try:
            size = fpath.stat().st_size
            if size > max_file_size:
                continue
            raw = fpath.read_text(encoding="utf-8", errors="replace")
            if "\x00" in raw:
                continue
            results.append({"path": str(fpath), "content": raw, "language": _detect_language(str(fpath))})
        except OSError:
            continue

    return results


def search_code(source_path: str, pattern: str, max_results: int = 10) -> list[dict[str, Any]]:
    """Search source code for a pattern (string or regex)."""
    base = Path(source_path)
    if not base.exists() or not pattern:
        return []

    results: list[dict[str, Any]] = []

    # Try ripgrep first
    try:
        proc = subprocess.run(["rg", "-n", "--no-heading", "-C", "2", pattern, str(base)], capture_output=True, text=True, timeout=10)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines()[:max_results]:
                results.append({"match": line})
            return results
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: Python line scanner
    try:
        regex = re.compile(re.escape(pattern))
    except re.error:
        return results

    if base.is_file():
        files = [base]
    else:
        files = []
        for root, dirs, filenames in os.walk(base):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}]
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
                results.append({"path": str(fpath), "line_number": i + 1, "line": line.strip(), "context": context})
                if len(results) >= max_results:
                    break

    return results


def git_diff_inspect(diff_text: str = "", repo_path: str = "") -> dict[str, Any]:
    """Inspect a git diff or patch."""
    result: dict[str, Any] = {"files_changed": [], "additions": 0, "deletions": 0, "diff_summary": ""}

    diff = diff_text
    if not diff and repo_path:
        try:
            proc = subprocess.run(["git", "diff", "HEAD"], cwd=repo_path, capture_output=True, text=True, timeout=10)
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
