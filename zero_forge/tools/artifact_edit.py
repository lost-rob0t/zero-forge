"""Deterministic exact-match artifact editing and unified diff generation."""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from typing import Any

_MAX_EDITS = 32


class ArtifactEditError(ValueError):
    """Raised when an edit plan is stale, ambiguous, or structurally unsafe."""


def artifact_sha256(content: str) -> str:
    """Return the SHA-256 digest for UTF-8 artifact content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _strip_json_fence(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def parse_artifact_edit_plan(text: str) -> dict[str, Any]:
    """Parse one strict model edit response."""
    try:
        payload = json.loads(_strip_json_fence(text))
    except json.JSONDecodeError as exc:
        raise ArtifactEditError(f"Artifact edit response is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != {"base_sha256", "edits"}:
        raise ArtifactEditError(
            "Artifact edit response must contain exactly base_sha256 and edits"
        )
    base_sha256 = payload.get("base_sha256")
    edits = payload.get("edits")
    if not isinstance(base_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", base_sha256
    ):
        raise ArtifactEditError("base_sha256 must be a lowercase SHA-256 digest")
    if not isinstance(edits, list) or not edits or len(edits) > _MAX_EDITS:
        raise ArtifactEditError(f"edits must contain between 1 and {_MAX_EDITS} entries")
    normalized: list[dict[str, str]] = []
    for index, edit in enumerate(edits, start=1):
        if not isinstance(edit, dict) or set(edit) != {"old", "new"}:
            raise ArtifactEditError(f"edit {index} must contain exactly old and new")
        old = edit.get("old")
        new = edit.get("new")
        if not isinstance(old, str) or not isinstance(new, str):
            raise ArtifactEditError(f"edit {index} old and new must be strings")
        if not old:
            raise ArtifactEditError(f"edit {index} old text must be non-empty")
        if old == new:
            raise ArtifactEditError(f"edit {index} does not change the artifact")
        normalized.append({"old": old, "new": new})
    return {"base_sha256": base_sha256, "edits": normalized}


def artifact_root_counts(content: str, artifact_type: str) -> dict[str, int]:
    """Count required top-level roots for one supported artifact."""
    normalized = artifact_type.strip().lower()
    if normalized == "metasploit":
        return {
            "MetasploitModule": len(
                re.findall(r"(?m)^\s*class\s+MetasploitModule\b", content)
            )
        }
    if normalized in {"zap_active_scan", "zap_active"}:
        return {
            "getMetadata": len(
                re.findall(r"\bfunction\s+getMetadata\s*\(", content)
            ),
            "scan": len(
                re.findall(
                    r"\bfunction\s+scan\s*\(\s*as\s*,\s*msg\s*,\s*param\s*,\s*value\s*\)",
                    content,
                )
            ),
        }
    if normalized in {"zap_passive_scan", "zap_passive"}:
        return {
            "getMetadata": len(
                re.findall(r"\bfunction\s+getMetadata\s*\(", content)
            ),
            "scan": len(
                re.findall(
                    r"\bfunction\s+scan\s*\(\s*ps\s*,\s*msg\s*,\s*src\s*\)",
                    content,
                )
            ),
        }
    return {}


def require_single_artifact(content: str, artifact_type: str) -> dict[str, int]:
    """Require exactly one complete root for Metasploit and ZAP artifacts."""
    counts = artifact_root_counts(content, artifact_type)
    if counts.get("MetasploitModule", 0) > 1:
        raise ArtifactEditError(
            "edit would concatenate multiple MetasploitModule roots; "
            f"found {counts['MetasploitModule']}"
        )
    duplicate_zap = [name for name, count in counts.items() if count > 1]
    if duplicate_zap:
        raise ArtifactEditError(
            "edit would concatenate multiple ZAP rule roots: "
            + ", ".join(duplicate_zap)
        )
    invalid = {name: count for name, count in counts.items() if count != 1}
    if invalid:
        details = ", ".join(f"{name}={count}" for name, count in invalid.items())
        raise ArtifactEditError(
            "artifact must contain exactly one complete root; " + details
        )
    return counts


def apply_artifact_edits(
    content: str,
    base_sha256: str,
    edits: list[dict[str, str]],
    artifact_type: str = "",
    max_bytes: int = 1_000_000,
) -> dict[str, Any]:
    """Apply exact replacements against one immutable artifact revision.

    Every ``old`` span must occur exactly once in the evolving artifact. Empty
    ``old`` spans are rejected, so an edit cannot append a second artifact.
    """
    if not isinstance(content, str) or not content:
        raise ArtifactEditError("Artifact content must be a non-empty string")
    if not 1 <= max_bytes <= 1_000_000:
        raise ArtifactEditError("max_bytes must be between 1 and 1000000")
    actual_sha256 = artifact_sha256(content)
    if base_sha256 != actual_sha256:
        raise ArtifactEditError(
            f"Artifact edit base is stale: expected {actual_sha256}, received {base_sha256}"
        )

    plan = parse_artifact_edit_plan(
        json.dumps({"base_sha256": base_sha256, "edits": edits})
    )
    normalized_edits = plan["edits"]
    if not isinstance(normalized_edits, list):
        raise ArtifactEditError("normalized edit plan is invalid")

    updated = content
    for index, edit in enumerate(normalized_edits, start=1):
        if not isinstance(edit, dict):
            raise ArtifactEditError(f"edit {index} is invalid")
        old = edit.get("old")
        new = edit.get("new")
        if not isinstance(old, str) or not isinstance(new, str):
            raise ArtifactEditError(f"edit {index} old and new must be strings")
        occurrences = updated.count(old)
        if occurrences != 1:
            raise ArtifactEditError(
                f"edit {index} old text must occur exactly once; found {occurrences}"
            )
        updated = updated.replace(old, new, 1)

    if updated == content:
        raise ArtifactEditError("Artifact edit plan produced no change")
    if len(updated.encode("utf-8")) > max_bytes:
        raise ArtifactEditError("Edited artifact exceeded max_bytes")
    roots = require_single_artifact(updated, artifact_type)

    diff = "".join(
        difflib.unified_diff(
            content.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile="artifact.before",
            tofile="artifact.after",
        )
    )
    return {
        "content": updated,
        "base_sha256": actual_sha256,
        "sha256": artifact_sha256(updated),
        "diff": diff,
        "applied_edits": len(normalized_edits),
        "artifact_roots": roots,
    }


def diff_artifact_edits(
    content: str,
    base_sha256: str,
    edits: list[dict[str, str]],
    artifact_type: str = "",
    max_bytes: int = 1_000_000,
) -> dict[str, Any]:
    """Preview the same exact-match edit contract without filesystem mutation."""
    return apply_artifact_edits(
        content,
        base_sha256,
        edits,
        artifact_type=artifact_type,
        max_bytes=max_bytes,
    )
