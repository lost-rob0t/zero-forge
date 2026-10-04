"""Metasploit Framework validation layered over Ruby structural checks."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .validator import (
    RubyRunner,
    ValidatorRuntimeUnavailable,
    validate_metasploit,
)

MSFCONSOLE_TIMEOUT = 60.0
MSFCONSOLE_UNAVAILABLE_ERROR = (
    "Metasploit Framework is required for module load validation but msfconsole "
    "was not found on PATH; install Metasploit Framework and retry"
)
_VALIDATION_MODULE = "exploit/zeroforge/generated_validation"
_FAILURE_PATTERNS = (
    re.compile(r"failed to load", re.IGNORECASE),
    re.compile(r"could not be loaded", re.IGNORECASE),
    re.compile(r"error loading module", re.IGNORECASE),
    re.compile(r"unable to find module", re.IGNORECASE),
    re.compile(r"no module selected", re.IGNORECASE),
    re.compile(r"invalid module", re.IGNORECASE),
    re.compile(r"(?mi)^\s*\[-\]\s+.*(?:failed|error|invalid|unable)"),
)
_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_SUCCESS_PATTERN = re.compile(rf"(?mi)^\s*Module:\s+{re.escape(_VALIDATION_MODULE)}\s*$")
_BASE64_TRANSPORT_PATTERN = re.compile(
    r"(?:\.pack\(\s*['\"]m0['\"]\s*\)|strict_encode64|encode_base64|Base64\.)"
)
_SHELL_CHECK_PATTERN = re.compile(
    r"(?m)^\s*(?:check_)?(?:cmd|code)\s*=\s*['\"](?:echo|id|whoami|uname|printf)\b"
)
_MODULE_CLASS_PATTERN = re.compile(r"(?m)^\s*class\s+MetasploitModule\b")


@runtime_checkable
class MetasploitRunner(Protocol):
    """Interface for loading one module through Metasploit Framework."""

    def load_module(self, content: str) -> tuple[int, str, str]:
        """Return ``(returncode, stdout, stderr)`` from a framework load attempt."""
        ...


class DefaultMetasploitRunner:
    """Load a temporary module with ``msfconsole`` and request its module info."""

    def __init__(
        self,
        executable: str = "msfconsole",
        timeout: float = MSFCONSOLE_TIMEOUT,
    ) -> None:
        self._executable = executable
        self._timeout = timeout

    def _resolve_executable(self) -> str:
        candidate = Path(self._executable).expanduser()
        if candidate.parent != Path("."):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
            raise ValidatorRuntimeUnavailable(MSFCONSOLE_UNAVAILABLE_ERROR)

        resolved = shutil.which(self._executable)
        if resolved is None:
            raise ValidatorRuntimeUnavailable(MSFCONSOLE_UNAVAILABLE_ERROR)
        return resolved

    def load_module(self, content: str) -> tuple[int, str, str]:
        executable = self._resolve_executable()
        with tempfile.TemporaryDirectory(prefix="zeroforge-msf-") as root_text:
            root = Path(root_text)
            module_path = root / "exploits" / "zeroforge" / "generated_validation.rb"
            module_path.parent.mkdir(parents=True)
            module_path.write_text(content, encoding="utf-8")

            resource_path = root / "validate.rc"
            resource_path.write_text(
                "\n".join(
                    (
                        f"loadpath {root}",
                        f"use {_VALIDATION_MODULE}",
                        "info",
                        "exit -y",
                        "",
                    )
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [executable, "-q", "-r", str(resource_path)],
                capture_output=True,
                text=True,
                timeout=self._timeout,
                shell=False,
                cwd=root,
            )
            return result.returncode, result.stdout, result.stderr


def _method_body(content: str, name: str) -> str:
    """Return a conventional two-space-indented Ruby method body."""
    match = re.search(
        rf"(?ms)^\s{{2}}def\s+{re.escape(name)}\b.*?(?=^\s{{2}}def\s+|^end\s*$|\Z)",
        content,
    )
    return match.group(0) if match else ""


def _semantic_errors(content: str) -> tuple[list[str], list[str]]:
    """Catch high-confidence module-contract failures before framework loading."""
    errors: list[str] = []
    warnings: list[str] = []
    check_body = _method_body(content, "check")

    module_count = len(_MODULE_CLASS_PATTERN.findall(content))
    if module_count != 1:
        errors.append(
            "module must contain exactly one MetasploitModule class declaration; "
            f"found {module_count}, which indicates concatenated artifacts"
        )

    if "Msf::Exploit::Remote::AutoCheck" in content and not check_body:
        errors.append("AutoCheck is prepended but the module does not define a check method")

    if (
        check_body
        and _SHELL_CHECK_PATTERN.search(check_body)
        and re.search(r"['\"]code['\"]\s*=>", content)
    ):
        errors.append(
            "check appears to submit shell syntax to a target-language code field; "
            "send valid source code for the target runtime"
        )

    if (
        "ARCH_CMD" in content
        and "payload.encoded" in content
        and "subprocess" in content
        and not _BASE64_TRANSPORT_PATTERN.search(content)
    ):
        errors.append(
            "ARCH_CMD payload is nested inside Python source without a binary-safe "
            "Base64 transport; quoting can corrupt common command payloads"
        )

    if check_body and "CheckCode::Detected" in check_body:
        warnings.append(
            "check can return CheckCode::Detected; AutoCheck permits exploitation for "
            "Detected results, so this path must represent intentional fingerprint-only evidence"
        )

    return errors, warnings


def _base_result(
    *,
    is_valid: bool,
    errors: list[str],
    warnings: list[str],
    runtime_error: bool = False,
    stages: dict[str, str] | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "is_valid": is_valid,
        "errors": errors,
        "warnings": warnings,
        "runtime_error": runtime_error,
        "stages": stages or {},
        "evidence": evidence or {},
    }


def validate_metasploit_with_runners(
    content: str,
    *,
    ruby_runner: RubyRunner | None = None,
    metasploit_runner: MetasploitRunner | None = None,
) -> dict[str, Any]:
    """Validate syntax, module semantics, and actual Metasploit Framework loading."""
    structural = validate_metasploit(content, ruby_runner=ruby_runner)
    warnings = list(structural.get("warnings", []))
    stages = {
        "ruby_structure": "passed" if structural.get("is_valid") else "failed",
        "metasploit_semantics": "not_run",
        "metasploit_load": "not_run",
    }
    if not structural.get("is_valid"):
        return _base_result(
            is_valid=False,
            errors=list(structural.get("errors", [])),
            warnings=warnings,
            runtime_error=bool(structural.get("runtime_error", False)),
            stages=stages,
        )

    semantic_errors, semantic_warnings = _semantic_errors(content)
    warnings.extend(semantic_warnings)
    stages["metasploit_semantics"] = "failed" if semantic_errors else "passed"
    if semantic_errors:
        return _base_result(
            is_valid=False,
            errors=semantic_errors,
            warnings=warnings,
            stages=stages,
        )

    runner = metasploit_runner or DefaultMetasploitRunner()
    try:
        returncode, stdout, stderr = runner.load_module(content)
    except ValidatorRuntimeUnavailable as exc:
        stages["metasploit_load"] = "unavailable"
        return _base_result(
            is_valid=False,
            errors=[str(exc)],
            warnings=warnings,
            runtime_error=True,
            stages=stages,
        )
    except FileNotFoundError:
        stages["metasploit_load"] = "unavailable"
        return _base_result(
            is_valid=False,
            errors=[MSFCONSOLE_UNAVAILABLE_ERROR],
            warnings=warnings,
            runtime_error=True,
            stages=stages,
        )
    except subprocess.TimeoutExpired:
        stages["metasploit_load"] = "timed_out"
        return _base_result(
            is_valid=False,
            errors=["Metasploit module load validation timed out"],
            warnings=warnings,
            runtime_error=True,
            stages=stages,
        )
    except Exception as exc:
        stages["metasploit_load"] = "error"
        return _base_result(
            is_valid=False,
            errors=[f"Metasploit module load validation failed: {exc}"],
            warnings=warnings,
            runtime_error=True,
            stages=stages,
        )

    combined = "\n".join(part for part in (stdout, stderr) if part).strip()
    normalized_output = _ANSI_ESCAPE_PATTERN.sub("", combined)
    evidence = {"metasploit_output": normalized_output[-4000:]}
    if returncode != 0:
        stages["metasploit_load"] = "failed"
        detail = combined or f"msfconsole exited with status {returncode}"
        return _base_result(
            is_valid=False,
            errors=[f"Metasploit rejected the module: {detail[-1000:]}"],
            warnings=warnings,
            stages=stages,
            evidence=evidence,
        )

    failure = next(
        (pattern.pattern for pattern in _FAILURE_PATTERNS if pattern.search(normalized_output)),
        None,
    )
    if failure is not None or not _SUCCESS_PATTERN.search(normalized_output):
        stages["metasploit_load"] = "failed"
        detail = combined or "msfconsole did not emit module information"
        return _base_result(
            is_valid=False,
            errors=[f"Metasploit did not load and select the generated module: {detail[-1000:]}"],
            warnings=warnings,
            stages=stages,
            evidence=evidence,
        )

    stages["metasploit_load"] = "passed"
    return _base_result(
        is_valid=True,
        errors=[],
        warnings=warnings,
        stages=stages,
        evidence=evidence,
    )


def validate_metasploit_loadable(content: str) -> dict[str, Any]:
    """Registry-safe entry point requiring only module content."""
    return validate_metasploit_with_runners(content)
