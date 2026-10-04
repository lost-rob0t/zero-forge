"""Source code, documentation, and Git inspection tools."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

# --- File classification ------------------------------------------------

_DOC_EXTS = {".md", ".txt", ".rst", ".adoc", ".org"}
_CONFIG_EXTS = {
    ".json",
    ".yaml",
    ".yml",
    ".ini",
    ".conf",
    ".properties",
    ".env",
    ".cfg",
    ".toml",
    ".xml",
    ".config",
}
_DATA_EXTS = {".csv", ".tsv", ".sql", ".sqlite"}
_SKIP_EXTS = {
    ".pyc",
    ".pyo",
    ".class",
    ".jar",
    ".war",
    ".zip",
    ".gz",
    ".tar",
    ".bz2",
    ".7z",
    ".rar",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".pdf",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".dat",
    ".db",
}
_DOC_FILENAMES = {
    "readme",
    "changelog",
    "changes",
    "authors",
    "license",
    "copying",
    "install",
    "hacking",
    "todo",
}
_CATEGORY_PRIORITY = {"documentation": 0, "config": 1, "data": 2, "code": 3}

# --- Secret / sensitive file detection ----------------------------------

# Filenames that are always secrets or credentials when matched
# case-insensitively against the basename (with optional extension).
_SECRET_FILENAMES: set[str] = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.development",
    ".env.test",
    ".env.example",  # .env.example is a template, but skip to be safe
    ".npmrc",
    ".pypirc",
    ".netrc",
    "credentials",
    "credentials.json",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "identity",
    "secret.key",
    "private.key",
    "private_key",
    "serviceaccount.json",
    "credentials.csv",
}

# Extensions associated with private keys and certificate secrets.
_SECRET_EXTS: set[str] = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".keystore",
    ".jks",
    ".ssh",
    ".gpg",
    ".asc",
}

# Regex patterns for filenames that look like secrets.
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\.(env|npmrc|pypirc|netrc)", re.IGNORECASE),
    re.compile(r"^id_(rsa|dsa|ecdsa|ed25519)", re.IGNORECASE),
    re.compile(r"(^|[-_.])(private|secret|api[_-]?key|token|credential)([-_.]|$)", re.IGNORECASE),
    re.compile(r"\.env($|\.)", re.IGNORECASE),
    re.compile(r"\.htpasswd$", re.IGNORECASE),
    re.compile(r"^shadow$", re.IGNORECASE),
    re.compile(r"^\.(gitconfig|git-credentials)$", re.IGNORECASE),
]


def _is_secret_file(filepath: str) -> bool:
    """Return True if the file looks like a secret or credential file."""
    basename = os.path.basename(filepath)
    stem = os.path.splitext(basename)[0].lower()
    ext = os.path.splitext(filepath)[1].lower()

    if basename.lower() in _SECRET_FILENAMES or stem in _SECRET_FILENAMES:
        return True
    if ext in _SECRET_EXTS:
        return True
    for pat in _SECRET_PATTERNS:
        if pat.search(basename):
            return True
    return False


# --- VCS ignore support -------------------------------------------------

_SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "build",
    "dist",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".tox",
    ".eggs",
    ".cache",
}


def _load_gitignore(root: Path) -> list[re.Pattern[str]]:
    """Load .gitignore patterns from *root* and compile them."""
    gitignore = root / ".gitignore"
    if not gitignore.is_file():
        return []
    patterns: list[re.Pattern[str]] = []
    try:
        text = gitignore.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Skip negation patterns (!...) — we don't support un-ignoring.
        if line.startswith("!"):
            continue
        # Convert glob to regex (simple: * → .*, ? → .)
        regex = re.escape(line).replace(r"\*", ".*").replace(r"\?", ".")
        patterns.append(re.compile(regex, re.IGNORECASE))
    return patterns


def _is_gitignored(rel_path: str, patterns: list[re.Pattern[str]]) -> bool:
    """Return True if *rel_path* matches any gitignore pattern."""
    for pat in patterns:
        if pat.search(rel_path):
            return True
    return False


# --- Language detection -------------------------------------------------


def _detect_language(filepath: str) -> str:
    ext_map = {
        ".py": "python",
        ".rb": "ruby",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".c": "c",
        ".cpp": "cpp",
        ".h": "c",
        ".go": "go",
        ".rs": "rust",
        ".php": "php",
        ".sh": "bash",
        ".pl": "perl",
        ".xml": "xml",
        ".html": "html",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".md": "markdown",
        ".txt": "text",
        ".rst": "rst",
        ".json": "json",
        ".ini": "ini",
        ".conf": "conf",
        ".properties": "properties",
        ".toml": "toml",
        ".cfg": "ini",
        ".env": "env",
        ".csv": "csv",
        ".cfm": "cfml",
        ".cfc": "cfml",
        ".asp": "asp",
        ".aspx": "asp",
        ".jsp": "jsp",
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


# --- Source file reading ------------------------------------------------

_MAX_TRAVERSAL_CANDIDATES = 500
_MAX_READ_BYTES = 1_048_576  # 1 MiB total across all files
_TRAVERSAL_TIMEOUT = 10.0  # seconds for directory walk
_READ_TIMEOUT = 10.0  # seconds for content reads


def read_source_files(
    source_path: str,
    max_files: int = 20,
    max_file_size: int = 51200,
    unsafe: bool = False,
) -> list[dict[str, Any]]:
    """Read files from a directory or single file.

    Files are categorized (documentation/config/data/code) and sorted with
    documentation first so the LLM receives vulnerability context (README,
    write-ups, advisories) before source code.

    Traversal and content reads are **bounded**: the directory walk stops
    after ``_MAX_TRAVERSAL_CANDIDATES`` candidates or ``_TRAVERSAL_TIMEOUT``
    seconds.  Content reads stop after ``max_files`` files or
    ``_MAX_READ_BYTES`` total bytes or ``_READ_TIMEOUT`` seconds.  If the
    budget is exhausted before all candidates are read, a truncation
    entry is appended to the results.

    When *unsafe* is False (default), the function:
      - Never follows symlinks.
      - Excludes known secret/credential files and patterns.
      - Respects .gitignore rules in the source root.
      - Verifies every resolved file stays under the source root.
      - Records skipped-file reasons (without secret content) as entries
        with ``"skipped": True`` and ``"reason"`` keys.

    When *unsafe* is True, all safety checks are bypassed and every
    eligible file is read (legacy behaviour, still bounded by the same
    budgets).
    """
    raw_source = Path(source_path)
    if not unsafe and raw_source.is_symlink():
        return [
            {
                "path": str(raw_source),
                "filename": raw_source.name,
                "skipped": True,
                "reason": "symlink: source_path is a symlink, not following",
            }
        ]
    base = raw_source.resolve()
    if not base.exists():
        return []

    if base.is_file():
        all_files: list[Path] = [base]
    else:
        all_files = []
        walk_start = time.monotonic()
        for root, dirs, filenames in os.walk(base):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for fname in sorted(filenames):
                all_files.append(Path(root) / fname)
                if len(all_files) >= _MAX_TRAVERSAL_CANDIDATES:
                    break
            if len(all_files) >= _MAX_TRAVERSAL_CANDIDATES:
                break
            if time.monotonic() - walk_start > _TRAVERSAL_TIMEOUT:
                break

    results: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    # Pre-load gitignore patterns for safe mode.
    gitignore_patterns: list[re.Pattern[str]] = []
    if not unsafe and base.is_dir():
        gitignore_patterns = _load_gitignore(base)

    # Phase 1: Collect candidate metadata without reading content.
    # Rank by category priority before reading to ensure the most relevant
    # files (documentation, config) are read first within the budget.
    candidates: list[dict[str, Any]] = []

    for fpath in all_files:
        # --- Safe-mode checks (skipped entirely in unsafe mode) ---
        if not unsafe:
            # 1. Never follow symlinks.
            if fpath.is_symlink():
                skipped.append(
                    {
                        "path": str(fpath),
                        "filename": fpath.name,
                        "skipped": True,
                        "reason": "symlink: not following file symlinks",
                    }
                )
                continue

            # 2. Verify resolved path stays under source root.
            try:
                resolved = fpath.resolve()
                if not str(resolved).startswith(str(base)):
                    skipped.append(
                        {
                            "path": str(fpath),
                            "filename": fpath.name,
                            "skipped": True,
                            "reason": "path escape: file resolves outside source root",
                        }
                    )
                    continue
            except OSError:
                skipped.append(
                    {
                        "path": str(fpath),
                        "filename": fpath.name,
                        "skipped": True,
                        "reason": "resolve error: unable to resolve path",
                    }
                )
                continue

            # 3. Exclude known secret/credential files.
            if _is_secret_file(str(fpath)):
                skipped.append(
                    {
                        "path": str(fpath),
                        "filename": fpath.name,
                        "skipped": True,
                        "reason": "secret file: credential or key material excluded",
                    }
                )
                continue

            # 4. Respect .gitignore rules.
            try:
                rel = str(fpath.relative_to(base))
            except ValueError:
                rel = str(fpath)
            if _is_gitignored(rel, gitignore_patterns):
                skipped.append(
                    {
                        "path": str(fpath),
                        "filename": fpath.name,
                        "skipped": True,
                        "reason": "gitignored: file matches .gitignore pattern",
                    }
                )
                continue

        # --- Common checks (both safe and unsafe modes) ---
        if _should_skip(str(fpath)):
            continue
        try:
            size = fpath.stat().st_size
            if size > max_file_size:
                continue
            category = _categorize_file(str(fpath))
            candidates.append(
                {
                    "path": str(fpath),
                    "filename": fpath.name,
                    "language": _detect_language(str(fpath)),
                    "category": category,
                    "size": size,
                    "_fpath": fpath,
                }
            )
        except OSError:
            continue

    # Rank candidates by category priority then path, before reading content.
    candidates.sort(key=lambda c: (_CATEGORY_PRIORITY.get(c["category"], 99), c["path"]))

    # Phase 2: Read content for only the top max_files candidates,
    # bounded by total bytes and time.
    total_bytes = 0
    read_start = time.monotonic()
    truncated = False

    for cand in candidates:
        if len(results) >= max_files:
            truncated = True
            break
        if total_bytes + cand["size"] > _MAX_READ_BYTES:
            truncated = True
            continue
        if time.monotonic() - read_start > _READ_TIMEOUT:
            truncated = True
            break
        try:
            raw = cand["_fpath"].read_text(encoding="utf-8", errors="replace")
            if "\x00" in raw:
                continue
            total_bytes += len(raw)
            results.append(
                {
                    "path": cand["path"],
                    "content": raw,
                    "language": cand["language"],
                    "category": cand["category"],
                    "filename": cand["filename"],
                }
            )
        except OSError:
            continue

    if truncated:
        results.append(
            {
                "path": "<budget>",
                "filename": "<budget>",
                "truncated": True,
                "reason": (
                    f"Source scanning budget exhausted: {len(results)} files read, "
                    f"{total_bytes} bytes, {len(candidates)} candidates found"
                ),
            }
        )

    return results + skipped


def search_code(
    source_path: str,
    pattern: str,
    max_results: int = 10,
    unsafe: bool = False,
    allowed_paths: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Search source code for a pattern (string or regex).

    When *unsafe* is False (default), only files admitted by the
    source-collection policy are searched.  When *allowed_paths* is
    provided, only those explicit paths are searched; otherwise the
    same policy as ``read_source_files()`` is applied internally.

    When *unsafe* is True, all safety checks are bypassed and every
    file under *source_path* is searched (legacy behaviour).
    """
    base = Path(source_path)
    if not base.exists() or not pattern:
        return []

    results: list[dict[str, Any]] = []

    # --- Determine the set of files to search -------------------------------
    if unsafe:
        # Unsafe: search everything (legacy behaviour).
        if base.is_file():
            search_files: list[str] = [str(base)]
            rg_targets: list[str] = [str(base)]
        else:
            search_files = []
            for root, dirs, filenames in os.walk(base):
                dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
                for fname in sorted(filenames):
                    search_files.append(str(Path(root) / fname))
            # Pass the directory itself to rg to avoid ARG_MAX overflow on large trees.
            rg_targets = [str(base)]
    elif allowed_paths is not None:
        # Safe with explicit allowlist: intersect with internally-generated
        # admitted set so the caller's list is never treated as authorization.
        admitted_raw = read_source_files(source_path, unsafe=False)
        admitted_set = {
            r["path"] for r in admitted_raw if not r.get("skipped") and not r.get("truncated")
        }
        search_files = [p for p in allowed_paths if p in admitted_set]
        rg_targets = search_files
    else:
        # Safe without allowlist: apply policy via read_source_files().
        admitted = read_source_files(source_path, unsafe=False)
        search_files = [
            r["path"] for r in admitted if not r.get("skipped") and not r.get("truncated")
        ]
        rg_targets = search_files

    if not search_files:
        return []

    # --- Ripgrep path -------------------------------------------------------
    rg_cmd = ["rg", "--json", "-n"]
    # When searching a directory directly (unsafe mode), add glob exclusions
    # for _SKIP_DIRS to match the old pruned-walk behaviour and avoid ARG_MAX.
    if unsafe and base.is_dir():
        rg_cmd.extend(["--no-ignore", "--hidden", "--follow"])
        for skip_dir in sorted(_SKIP_DIRS):
            rg_cmd.extend(["-g", f"!{skip_dir}", "-g", f"!{skip_dir}/**"])
    rg_cmd.append(pattern)
    rg_cmd.extend(rg_targets)
    try:
        proc = subprocess.run(
            rg_cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0:
            for raw_event in proc.stdout.splitlines():
                try:
                    event = json.loads(raw_event)
                except json.JSONDecodeError:
                    continue
                if event.get("type") != "match":
                    continue
                data = event.get("data", {})
                path = data.get("path", {}).get("text", "")
                line_number = data.get("line_number", 0)
                line = data.get("lines", {}).get("text", "").rstrip("\r\n")
                results.append(
                    {
                        "path": path,
                        "line_number": line_number,
                        "line": line.strip(),
                        "context": f"{line_number}: {line}",
                    }
                )
                if len(results) >= max_results:
                    break
            return results
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # --- Python fallback ----------------------------------------------------
    try:
        regex = re.compile(re.escape(pattern))
    except re.error:
        return results

    for fpath_str in sorted(search_files):
        fpath = Path(fpath_str)
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
                context = "\n".join(
                    f"{start + j + 1}: {lines[start + j]}" for j in range(end - start)
                )
                results.append(
                    {
                        "path": str(fpath),
                        "line_number": i + 1,
                        "line": line.strip(),
                        "context": context,
                    }
                )
                if len(results) >= max_results:
                    break

    return results


def _diff_destination_path(header: str) -> str | None:
    """Extract the destination path from a ``diff --git`` header."""
    payload = header.removeprefix("diff --git ")

    if payload.endswith('"'):
        try:
            parts = shlex.split(payload)
        except ValueError:
            return None
        if len(parts) >= 2:
            return parts[-1].removeprefix("b/")

    _, separator, destination = payload.rpartition(" b/")
    if separator:
        return destination

    return None


def git_diff_inspect(diff_text: str = "", repo_path: str = "") -> dict[str, Any]:
    """Inspect a git diff or patch."""
    result: dict[str, Any] = {
        "files_changed": [],
        "additions": 0,
        "deletions": 0,
        "diff_summary": "",
    }

    diff = diff_text
    if not diff and repo_path:
        try:
            proc = subprocess.run(
                ["git", "diff", "HEAD"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=10,
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
        if line.startswith("diff --git "):
            destination = _diff_destination_path(line)
            if destination is not None:
                files.append(destination)
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
