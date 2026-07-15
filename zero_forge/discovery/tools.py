"""Deterministic tools for the discovery workflow.

Tools registered with the Tool Agent for the discovery subgraph:
- ``generate_flag`` — create a randomized flag string.
- ``write_flag_to_path`` — write a flag to a file path (SWE agent uses this).
- ``execute_metasploit_rc`` — run ``msfconsole -q -r`` against a resource file.
- ``verify_flag_in_output`` — check whether a flag appears in captured output.
- ``read_file`` — read a file's contents within bounded limits.

All tools are plain functions registered through the existing ToolRegistry.
"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from ..logging_config import get_logger

logger = get_logger(__name__)

FLAG_PREFIX = "FLAG{"
FLAG_SUFFIX = "}"
FLAG_LENGTH = 32
MSFCONSOLE_TIMEOUT = 120.0
MAX_FILE_READ_BYTES = 50_000

# Allowed flag output roots (prevents writing to arbitrary paths).
# Any path under these roots is acceptable; configurable via
# ZERO_FORGE_FLAG_DIRS env var (colon-separated).
_DEFAULT_FLAG_DIRS = "/tmp/zeroforge-target:/tmp/zeroforge:/tmp/pytest-of-"
_ALLOWED_FLAG_DIRS = frozenset(
    os.environ.get("ZERO_FORGE_FLAG_DIRS", _DEFAULT_FLAG_DIRS).split(":")
)


class ToolPathError(Exception):
    """Raised when a tool path is invalid or escapes allowed boundaries."""


def _validate_flag_path(path: str) -> Path:
    """Validate that *path* is within an allowed directory and not a symlink.

    Raises ToolPathError for traversal, symlink, or out-of-bounds paths.
    """
    raw = Path(path)
    # Reject symlinks on the raw path before resolving
    if raw.is_symlink():
        raise ToolPathError(f"Flag path must not be a symlink: {path}")
    # Reject parent traversal
    if ".." in raw.parts:
        raise ToolPathError(f"Flag path contains parent traversal: {path}")
    p = raw.resolve()
    # Check that the resolved path is within an allowed directory
    allowed_roots = [Path(d).resolve() for d in _ALLOWED_FLAG_DIRS]
    if not any(
        str(p).startswith(str(root)) for root in allowed_roots
    ):
        raise ToolPathError(
            f"Flag path escapes allowed directories: {path}"
        )
    return p


def _validate_read_path(path: str) -> Path:
    """Validate that *path* is safe to read.

    Rejects symlinks, parent traversal beyond allowed roots, and
    known secret locations.
    """
    p = Path(path)
    # Reject symlinks
    if p.is_symlink():
        raise ToolPathError(f"Read path must not be a symlink: {path}")
    # Reject parent traversal
    if ".." in p.parts:
        raise ToolPathError(f"Read path contains parent traversal: {path}")
    # Reject known secret paths
    secret_patterns = (
        ".env", "secret", "credential", "/etc/shadow",
        "/etc/passwd", "id_rsa", ".ssh", "/proc/",
    )
    lower_path = str(p).lower()
    for pattern in secret_patterns:
        if pattern in lower_path:
            raise ToolPathError(
                f"Read path appears to reference secrets: {path}"
            )
    return p.resolve()


def generate_flag() -> str:
    """Generate a randomized flag string.

    The flag format is ``FLAG{<random_hex>}`` so it is easy to grep for
    in exploit output.  The random portion uses ``secrets.token_hex``
    for cryptographic randomness per the maintainer's requirement that
    the flag be randomized.
    """
    random_part = secrets.token_hex(FLAG_LENGTH)
    return f"{FLAG_PREFIX}{random_part}{FLAG_SUFFIX}"


def write_flag_to_path(flag: str, path: str) -> str:
    """Write *flag* to *path* and return the absolute path.

    The SWE agent calls this to place a randomized flag at a known location.
    The exploit phase agent receives the path so it can target the flag.

    Raises ToolPathError if the path is outside allowed directories or
    is a symlink.
    """
    validated = _validate_flag_path(path)
    validated.parent.mkdir(parents=True, exist_ok=True)
    validated.write_text(flag, encoding="utf-8")
    logger.info("Flag written to %s", validated)
    return str(validated)


def execute_metasploit_rc(
    rc_file: str,
    msfconsole_path: str = "msfconsole",
) -> dict[str, Any]:
    """Execute a Metasploit resource file with ``msfconsole -q -r``.

    Returns a dict with stdout, stderr, exit_code, and timing_ms.
    Falls back to returning the error if msfconsole is unavailable.
    """
    console = shutil.which(msfconsole_path)
    if console is None:
        return {
            "stdout": "",
            "stderr": "msfconsole not found on PATH",
            "exit_code": -1,
            "timing_ms": 0.0,
        }

    # Reject symlinks on the raw path before resolving
    raw_rc = Path(rc_file)
    if raw_rc.is_symlink():
        return {
            "stdout": "",
            "stderr": f"Resource file must not be a symlink: {rc_file}",
            "exit_code": -1,
            "timing_ms": 0.0,
        }

    rc_path = raw_rc.resolve()
    if not rc_path.is_file():
        return {
            "stdout": "",
            "stderr": f"Resource file not found: {rc_path}",
            "exit_code": -1,
            "timing_ms": 0.0,
        }

    start = time.monotonic()
    try:
        result = subprocess.run(
            [console, "-q", "-r", str(rc_path)],
            capture_output=True,
            text=True,
            timeout=MSFCONSOLE_TIMEOUT,
            shell=False,
        )
        elapsed = (time.monotonic() - start) * 1000.0
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode,
            "timing_ms": round(elapsed, 2),
        }
    except subprocess.TimeoutExpired:
        elapsed = (time.monotonic() - start) * 1000.0
        return {
            "stdout": "",
            "stderr": f"msfconsole timed out after {MSFCONSOLE_TIMEOUT}s",
            "exit_code": -1,
            "timing_ms": round(elapsed, 2),
        }
    except Exception as exc:
        elapsed = (time.monotonic() - start) * 1000.0
        return {
            "stdout": "",
            "stderr": f"msfconsole execution failed: {exc}",
            "exit_code": -1,
            "timing_ms": round(elapsed, 2),
        }


def verify_flag_in_output(flag: str, output: str) -> dict[str, Any]:
    """Check whether *flag* appears in *output*.

    The verification is a simple substring match — no LLM judgment involved.
    If the flag is found, the exploit is deemed successful.
    """
    found = flag in output
    return {
        "flag_found": found,
        "flag_value": flag if found else "",
    }


def generate_metasploit_rc(
    module_name: str,
    *,
    options: dict[str, str] | None = None,
    payload: str = "",
    lhost: str = "",
    lport: str = "",
    rhost: str = "",
    rport: str = "",
    additional_commands: list[str] | None = None,
    auto_run: bool = True,
) -> str:
    """Generate a Metasploit resource (.rc) file content.

    Per the maintainer's direction: generate a .rc file and execute it
    using ``msfconsole -q -r <file>``.

    Returns the .rc file content as a string.
    """
    lines: list[str] = []
    opts = options or {}

    # Merge structured fields into options dict
    if payload:
        opts["PAYLOAD"] = payload
    if lhost:
        opts["LHOST"] = lhost
    if lport:
        opts["LPORT"] = lport
    if rhost:
        opts["RHOST"] = rhost
    if rport:
        opts["RPORT"] = rport

    if module_name:
        lines.append(f"use {module_name}")

    for key, value in opts.items():
        lines.append(f"set {key} {value}")

    if additional_commands:
        lines.extend(additional_commands)

    if auto_run:
        lines.append("exploit -j")

    return "\n".join(lines) + "\n"


def write_metasploit_rc(
    content: str,
    output_path: str,
) -> str:
    """Write a Metasploit .rc file to disk.

    Returns the absolute path to the written file.
    """
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    logger.info("Metasploit .rc file written to %s", p.resolve())
    return str(p.resolve())


def read_file(path: str, max_bytes: int = MAX_FILE_READ_BYTES) -> dict[str, Any]:
    """Read a file's contents within bounded limits.

    Used by the research phase to inspect source files, configs, and logs.
    Rejects symlinks, parent traversal, and paths that appear to reference
    secrets.
    """
    try:
        validated = _validate_read_path(path)
    except ToolPathError as exc:
        return {"path": path, "content": "", "error": str(exc)}

    if not validated.is_file():
        return {"path": path, "content": "", "error": f"File not found: {path}"}
    try:
        content = validated.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"path": path, "content": "", "error": str(exc)}
    # Truncate by bytes: encode, slice, then decode back
    encoded = content.encode("utf-8")
    if len(encoded) > max_bytes:
        truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
        content = truncated + "\n... [truncated]"
    return {"path": path, "content": content, "error": ""}
