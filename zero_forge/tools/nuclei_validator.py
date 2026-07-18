"""Nuclei YAML template validation."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import yaml

NUCLEI_TIMEOUT = 15.0
_NUCLEI_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_NUCLEI_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
_NUCLEI_PROTOCOL_KEYS = frozenset(
    {
        "code",
        "dns",
        "file",
        "headless",
        "http",
        "javascript",
        "network",
        "ssl",
        "tcp",
        "websocket",
        "whois",
    }
)


@runtime_checkable
class NucleiRunner(Protocol):
    """Interface for validating one template with the Nuclei CLI."""

    def validate(self, content: str) -> tuple[int, str, str]:
        """Return ``(returncode, stdout, stderr)`` for one template."""
        ...


class DefaultNucleiRunner:
    """Run bounded, offline-oriented Nuclei template validation."""

    def __init__(self, executable: str, timeout: float = NUCLEI_TIMEOUT) -> None:
        self._executable = executable
        self._timeout = timeout

    def validate(self, content: str) -> tuple[int, str, str]:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".yaml",
            delete=False,
            encoding="utf-8",
        ) as stream:
            stream.write(content)
            path = Path(stream.name)
        try:
            result = subprocess.run(
                [
                    self._executable,
                    "-validate",
                    "-t",
                    str(path),
                    "-duc",
                ],
                capture_output=True,
                text=True,
                timeout=self._timeout,
                shell=False,
            )
            return result.returncode, result.stdout, result.stderr
        finally:
            path.unlink(missing_ok=True)


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_author(value: object) -> bool:
    if _nonempty_string(value):
        return True
    return isinstance(value, list) and bool(value) and all(_nonempty_string(item) for item in value)


def _contains_detection_logic(value: object) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in {"matchers", "extractors"} and isinstance(nested, list) and nested:
                return True
            if _contains_detection_logic(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_detection_logic(item) for item in value)
    return False


def _validate_schema(template: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    template_id = template.get("id")
    if not _nonempty_string(template_id):
        errors.append("Nuclei template 'id' must be a non-empty string")
    elif not _NUCLEI_ID_RE.fullmatch(str(template_id)):
        errors.append("Nuclei template 'id' contains unsupported characters")

    info = template.get("info")
    if not isinstance(info, dict):
        errors.append("Nuclei template must define an 'info' mapping")
    else:
        if not _nonempty_string(info.get("name")):
            errors.append("Nuclei template info.name must be a non-empty string")
        if not _valid_author(info.get("author")):
            errors.append("Nuclei template info.author must be a name or non-empty name list")
        severity = str(info.get("severity", "")).lower()
        if severity not in _NUCLEI_SEVERITIES:
            errors.append(
                "Nuclei template info.severity must be info, low, medium, high, critical, or unknown"
            )
        if not _nonempty_string(info.get("description")):
            warnings.append("Add info.description to explain the detection evidence")
        references = info.get("reference")
        if references is None:
            warnings.append("Add info.reference with authoritative vulnerability sources")
        elif not (
            _nonempty_string(references)
            or (
                isinstance(references, list)
                and bool(references)
                and all(_nonempty_string(item) for item in references)
            )
        ):
            errors.append("Nuclei template info.reference must be a string or non-empty string list")

    protocols = sorted(key for key in _NUCLEI_PROTOCOL_KEYS if key in template)
    if not protocols:
        errors.append("Nuclei template must define at least one supported protocol request")
    for protocol in protocols:
        requests = template.get(protocol)
        if not isinstance(requests, list) or not requests:
            errors.append(f"Nuclei protocol '{protocol}' must contain a non-empty request list")
        elif any(not isinstance(request, dict) for request in requests):
            errors.append(f"Nuclei protocol '{protocol}' requests must be mappings")

    if protocols and not _contains_detection_logic(
        {protocol: template.get(protocol) for protocol in protocols}
    ):
        errors.append("Nuclei template must define at least one matcher or extractor")

    return errors, warnings, protocols


def validate_nuclei(
    content: str,
    nuclei_runner: NucleiRunner | None = None,
) -> dict[str, Any]:
    """Validate one Nuclei YAML template and use ``nuclei -validate`` when available."""
    stages: dict[str, str] = {}
    evidence: dict[str, Any] = {}
    if not content or not content.strip():
        return {
            "is_valid": False,
            "errors": ["Empty Nuclei template content"],
            "warnings": [],
            "stages": {"yaml": "failed"},
            "evidence": {},
        }

    try:
        documents = [document for document in yaml.safe_load_all(content) if document is not None]
    except yaml.YAMLError as exc:
        return {
            "is_valid": False,
            "errors": [f"Invalid Nuclei YAML: {exc}"],
            "warnings": [],
            "stages": {"yaml": "failed"},
            "evidence": {},
        }

    if len(documents) != 1:
        return {
            "is_valid": False,
            "errors": ["Nuclei artifact must contain exactly one YAML document"],
            "warnings": [],
            "stages": {"yaml": "failed"},
            "evidence": {"document_count": len(documents)},
        }
    template = documents[0]
    if not isinstance(template, dict):
        return {
            "is_valid": False,
            "errors": ["Nuclei YAML document must define a mapping"],
            "warnings": [],
            "stages": {"yaml": "failed"},
            "evidence": {},
        }

    stages["yaml"] = "passed"
    errors, warnings, protocols = _validate_schema(template)
    evidence.update(
        {
            "template_id": str(template.get("id", "")),
            "protocols": protocols,
            "document_count": 1,
        }
    )
    if errors:
        stages["schema"] = "failed"
        stages["nuclei_cli"] = "not_run"
        return {
            "is_valid": False,
            "errors": errors,
            "warnings": warnings,
            "stages": stages,
            "evidence": evidence,
        }
    stages["schema"] = "passed"

    runner = nuclei_runner
    if runner is None:
        executable = shutil.which("nuclei")
        if executable is None:
            warnings.append("Nuclei binary not found; skipped nuclei -validate")
            stages["nuclei_cli"] = "skipped"
            evidence["nuclei_cli_available"] = False
            return {
                "is_valid": True,
                "errors": [],
                "warnings": warnings,
                "stages": stages,
                "evidence": evidence,
            }
        runner = DefaultNucleiRunner(executable)

    evidence["nuclei_cli_available"] = True
    try:
        returncode, stdout, stderr = runner.validate(content)
    except subprocess.TimeoutExpired:
        stages["nuclei_cli"] = "failed"
        return {
            "is_valid": False,
            "errors": ["Nuclei template validation timed out"],
            "warnings": warnings,
            "runtime_error": True,
            "stages": stages,
            "evidence": evidence,
        }
    except Exception as exc:
        stages["nuclei_cli"] = "failed"
        return {
            "is_valid": False,
            "errors": [f"Nuclei template validation failed to run: {exc}"],
            "warnings": warnings,
            "runtime_error": True,
            "stages": stages,
            "evidence": evidence,
        }

    if returncode != 0:
        detail = (stderr.strip() or stdout.strip() or "unknown validation error")[:1000]
        stages["nuclei_cli"] = "failed"
        return {
            "is_valid": False,
            "errors": [f"Nuclei template validation failed: {detail}"],
            "warnings": warnings,
            "stages": stages,
            "evidence": evidence,
        }

    stages["nuclei_cli"] = "passed"
    return {
        "is_valid": True,
        "errors": [],
        "warnings": warnings,
        "stages": stages,
        "evidence": evidence,
    }
