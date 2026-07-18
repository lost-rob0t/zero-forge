"""Atomic promotion of reviewed native lab artifacts."""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import cast

from ..schemas import ArtifactType
from .types import LabError
from .util import (
    atomic_write_json,
    ensure_under,
    normalize_optional_cve,
    resolve_lab_root,
    sanitize_name,
)

DEFAULT_MSF_LAYOUT = "modules/exploits/multi/http"


def read_manifest(run_dir: Path) -> dict[str, object]:
    try:
        payload = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LabError(f"Invalid or missing run manifest: {run_dir}") from exc
    if not isinstance(payload, dict):
        raise LabError("Run manifest must be a JSON object")
    return cast(dict[str, object], payload)


def strip_poc_prefix(filename: str) -> str:
    path = Path(filename)
    stem = re.sub(r"^poc(?:[-_. ]+)?", "", path.stem, flags=re.IGNORECASE)
    return f"{stem or 'exploit'}{path.suffix}"


def _layout(value: str) -> PurePosixPath:
    path = PurePosixPath(value.strip().lstrip("/"))
    if not path.parts or path.parts[0] != "modules" or ".." in path.parts:
        raise LabError("Metasploit layout must be contained beneath modules/")
    return path


def _destinations(
    run_dir: Path, artifact_type: ArtifactType, msf_layout: PurePosixPath
) -> list[tuple[Path, PurePosixPath]]:
    root = run_dir / "zeroforge"
    suffix = ".rb" if artifact_type == ArtifactType.METASPLOIT else ".js"
    artifacts = sorted(path for path in root.rglob(f"*{suffix}") if path.is_file())
    mapped: list[tuple[Path, PurePosixPath]] = []
    seen: set[PurePosixPath] = set()
    for artifact in artifacts:
        if artifact_type == ArtifactType.METASPLOIT:
            rel = PurePosixPath("metasploit") / msf_layout / strip_poc_prefix(artifact.name)
        elif artifact_type == ArtifactType.ZAP_ACTIVE:
            rel = PurePosixPath("zap/active") / strip_poc_prefix(artifact.name)
        else:
            rel = PurePosixPath("zap/passive") / strip_poc_prefix(artifact.name)
        if rel in seen:
            raise LabError(f"Multiple artifacts map to the same promoted path: {rel}")
        seen.add(rel)
        mapped.append((artifact, rel))
    return mapped


def _install(stage: Path, destination: Path, *, force: bool) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not force:
        raise LabError(f"Already promoted: {destination} (use --force to replace it)")
    backup: Path | None = None
    if destination.exists():
        backup = destination.parent / f".{destination.name}.backup-{secrets.token_hex(8)}"
        os.replace(destination, backup)
    try:
        os.replace(stage, destination)
    except Exception:
        if backup and backup.exists() and not destination.exists():
            os.replace(backup, destination)
        raise
    if backup:
        shutil.rmtree(backup)


def promote_lab_run(
    *,
    run_dir: Path,
    lab_root: Path,
    msf_layout: str = DEFAULT_MSF_LAYOUT,
    force: bool = False,
    dry_run: bool = False,
) -> Path:
    """Promote a completed run and reject empty artifact bundles."""
    root = resolve_lab_root(lab_root)
    run_root = ensure_under(run_dir, root / "output")
    manifest = read_manifest(run_root)
    if manifest.get("status") != "completed":
        raise LabError("Only completed lab runs can be promoted")
    try:
        artifact_type = ArtifactType(str(manifest.get("artifact_type", "")))
    except ValueError as exc:
        raise LabError("Unsupported artifact type in run manifest") from exc
    destinations = _destinations(run_root, artifact_type, _layout(msf_layout))
    if not destinations:
        raise LabError(f"No promotable {artifact_type.value} artifact found")
    cve = normalize_optional_cve(str(manifest.get("cve_id", "")))
    name = sanitize_name(str(manifest.get("repo_name", "")))
    run_id = sanitize_name(str(manifest.get("run_id", run_root.name)))
    destination = (
        root / "vuln-db" / "artifacts" / cve
        if cve
        else root / "vuln-db" / "artifacts" / "unassigned" / name / run_id
    )
    ensure_under(destination, root / "vuln-db" / "artifacts")
    if destination.exists() and not force:
        raise LabError(f"Already promoted: {destination} (use --force to replace it)")
    if dry_run:
        return destination
    stage_parent = root / "vuln-db"
    stage_parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".promote-", dir=stage_parent))
    try:
        if (run_root / "poc").is_dir():
            shutil.copytree(run_root / "poc", stage / "poc")
        for artifact, relative in destinations:
            target = stage.joinpath(*relative.parts)
            ensure_under(target, stage)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(artifact, target)
            sidecar = artifact.with_name(artifact.name + ".meta.json")
            if sidecar.is_file():
                shutil.copy2(sidecar, target.with_name(target.name + ".meta.json"))
        shutil.copy2(run_root / "run.json", stage / "run.json")
        atomic_write_json(
            stage / "promotion.json",
            {
                "schema_version": 1,
                "promoted_at": datetime.now(UTC).isoformat(),
                "source_run": str(run_root),
                "artifact_type": artifact_type.value,
                "artifact_count": len(destinations),
            },
        )
        _install(stage, destination, force=force)
    except Exception:
        if stage.exists():
            shutil.rmtree(stage)
        raise
    return destination
