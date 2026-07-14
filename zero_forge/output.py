"""Filesystem output for generated artifacts."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .config import get_settings
from .schemas import Artifact


def save_artifact(artifact: Artifact, output_dir: Path | str | None = None) -> str:
    """Save an artifact to the filesystem.

    Creates the output directory if it doesn't exist.
    Returns the absolute path to the saved file.
    """
    if output_dir is None:
        out_path = Path(get_settings().output.dir)
    else:
        out_path = Path(output_dir)

    out_path.mkdir(parents=True, exist_ok=True)

    filename = artifact.filename or f"artifact_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    filepath = out_path / filename

    filepath.write_text(artifact.content, encoding="utf-8")

    meta_path = filepath.with_suffix(filepath.suffix + ".meta.json")
    meta = {
        "artifact_type": artifact.artifact_type.value,
        "filename": filename,
        "saved_at": datetime.now().isoformat(),
        **artifact.metadata,
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    return str(filepath.resolve())
