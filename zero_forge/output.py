"""Filesystem output for generated artifacts."""

from __future__ import annotations

import json
import os
import re
import secrets
from datetime import datetime
from pathlib import Path

from .config import get_settings
from .logging_config import get_logger
from .schemas import Artifact

logger = get_logger(__name__)

# CVE ID pattern: CVE-YYYY-NNNN+
_CVE_ID_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")

# Reserved sidecar fields that must never be overwritten by free-form metadata
_RESERVED_META_KEYS = frozenset({"artifact_type", "filename", "saved_at"})


class ArtifactPathError(Exception):
    """Raised when an artifact path is invalid or escapes the output directory."""


_EXCLUSIVE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)


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


def _reserve_destination(path: Path) -> None:
    """Atomically reserve *path* without following links or replacing files."""
    try:
        descriptor = os.open(path, _EXCLUSIVE_FLAGS, 0o600)
    except FileExistsError as exc:
        raise ArtifactPathError(
            f"Artifact output already exists; refusing to overwrite: {path}"
        ) from exc
    except OSError as exc:
        raise ArtifactPathError(f"Could not reserve artifact output {path}: {exc}") from exc
    os.close(descriptor)


def _write_temporary(output_root: Path, content: str) -> Path:
    """Write and fsync *content* to a secure temporary file in *output_root*."""
    for _ in range(10):
        path = output_root / f".zeroforge-{secrets.token_hex(16)}.tmp"
        try:
            descriptor = os.open(path, _EXCLUSIVE_FLAGS, 0o600)
        except FileExistsError:
            continue
        except OSError as exc:
            raise ArtifactPathError(f"Could not create temporary output file: {exc}") from exc

        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return path
    raise ArtifactPathError("Could not allocate a unique temporary output file")


def _fsync_directory(path: Path) -> None:
    """Persist directory entry changes on platforms that support directory fsync."""
    if not hasattr(os, "O_DIRECTORY"):
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_paths(paths: list[Path]) -> None:
    """Best-effort cleanup for transaction-owned paths."""
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


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
    logger.debug("Saving artifact %s to %s", filename, out_path)
    filepath = _safe_resolve(out_path, filename)

    # Metadata sidecar: derive name from validated filepath and apply same protection
    meta_name = filepath.name + ".meta.json"
    meta_path = _safe_resolve(out_path, meta_name)

    # Filter reserved keys from user metadata to prevent sidecar spoofing
    user_meta = {
        k: v for k, v in artifact.metadata.items() if k not in _RESERVED_META_KEYS
    }
    meta = {
        "artifact_type": artifact.artifact_type.value,
        "filename": filepath.name,
        "saved_at": datetime.now().isoformat(),
        **user_meta,
    }
    metadata_content = json.dumps(meta, indent=2)

    reserved: list[Path] = []
    temporary: list[Path] = []
    published: list[Path] = []
    try:
        for destination in (filepath, meta_path):
            _reserve_destination(destination)
            reserved.append(destination)

        artifact_temp = _write_temporary(filepath.parent, artifact.content)
        temporary.append(artifact_temp)
        metadata_temp = _write_temporary(filepath.parent, metadata_content)
        temporary.append(metadata_temp)

        # Publish metadata first. The artifact becomes visible only after its
        # matching sidecar is already in place.
        os.replace(metadata_temp, meta_path)
        temporary.remove(metadata_temp)
        reserved.remove(meta_path)
        published.append(meta_path)

        os.replace(artifact_temp, filepath)
        temporary.remove(artifact_temp)
        reserved.remove(filepath)
        published.append(filepath)
        _fsync_directory(filepath.parent)
    except Exception as exc:
        _remove_paths(temporary + published + reserved)
        if isinstance(exc, ArtifactPathError):
            raise
        raise ArtifactPathError(f"Atomic artifact publication failed: {exc}") from exc

    return str(filepath.resolve())
