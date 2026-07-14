"""Filesystem output for generated artifacts."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from .config import get_settings
from .schemas import Artifact

# CVE ID pattern: CVE-YYYY-NNNN+
_CVE_ID_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


class ArtifactPathError(Exception):
    """Raised when an artifact path is invalid or escapes the output directory."""


def _validate_cve_id(artifact: Artifact) -> None:
    """Validate CVE ID format if present in artifact metadata."""
    cve_id = artifact.metadata.get("cve_id")
    if cve_id is not None and not _CVE_ID_RE.match(str(cve_id)):
        raise ArtifactPathError(f"Invalid CVE ID: {cve_id!r}")


def _validate_filename(filename: str) -> str:
    """Validate that *filename* is a safe basename only.

    Returns the validated basename.
    """
    if not filename:
        raise ArtifactPathError("Artifact filename must not be empty")

    # Reject path separators (both Unix and Windows)
    if "/" in filename or "\\" in filename:
        raise ArtifactPathError(
            f"Artifact filename must not contain path separators: {filename!r}"
        )

    # Reject parent directory references
    if ".." in filename:
        raise ArtifactPathError(
            f"Artifact filename must not contain parent directory references: {filename!r}"
        )

    # Reject absolute paths (Unix and Windows drive letters)
    if Path(filename).is_absolute() or re.match(r"^[A-Za-z]:", filename):
        raise ArtifactPathError(
            f"Artifact filename must not be an absolute path: {filename!r}"
        )

    # Final safety: extract basename
    basename = Path(filename).name
    if not basename or basename in (".", ".."):
        raise ArtifactPathError(
            f"Artifact filename resolves to an unsafe basename: {filename!r}"
        )

    return basename


def _safe_resolve(output_root: Path, filename: str) -> Path:
    """Safely resolve *filename* within *output_root*.

    Validates the filename, resolves both root and destination, and ensures
    the destination stays inside the output root.

    Raises:
        ArtifactPathError: If the path is invalid, escapes the output root,
            is a symlink, or is an existing non-regular file.
    """
    basename = _validate_filename(filename)
    resolved_root = output_root.resolve()
    candidate = resolved_root / basename

    # Reject symlinks before resolving so the link target cannot escape
    if candidate.is_symlink():
        raise ArtifactPathError(
            f"Artifact destination must not be a symlink: {candidate}"
        )

    destination = candidate.resolve()

    try:
        destination.relative_to(resolved_root)
    except ValueError as exc:
        raise ArtifactPathError(
            f"Artifact destination escapes output directory: {destination}"
        ) from exc

    if destination.exists() and not destination.is_file():
        raise ArtifactPathError(
            f"Artifact destination exists but is not a regular file: {destination}"
        )

    return destination


def save_artifact(artifact: Artifact, output_dir: Path | str | None = None) -> str:
    """Save an artifact to the filesystem.

    Creates the output directory if it doesn't exist.
    Returns the absolute path to the saved file.

    Raises:
        ArtifactPathError: If the artifact path is invalid, escapes the
            output directory, points to a symlink, or an existing
            non-regular file.
    """
    _validate_cve_id(artifact)

    if output_dir is None:
        out_path = Path(get_settings().output.dir)
    else:
        out_path = Path(output_dir)

    out_path.mkdir(parents=True, exist_ok=True)

    filename = artifact.filename or f"artifact_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    filepath = _safe_resolve(out_path, filename)

    filepath.write_text(artifact.content, encoding="utf-8")

    # Metadata sidecar: derive name from validated filepath and apply same protection
    meta_name = filepath.name + ".meta.json"
    meta_path = _safe_resolve(out_path, meta_name)

    meta = {
        "artifact_type": artifact.artifact_type.value,
        "filename": filepath.name,
        "saved_at": datetime.now().isoformat(),
        **artifact.metadata,
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    return str(filepath.resolve())
