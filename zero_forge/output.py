"""Filesystem output for generated artifacts."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from .schemas import Artifact


DEFAULT_OUTPUT_DIR = Path(os.environ.get("ZERO_FORGE_OUTPUT_DIR", "./output"))


def save_artifact(artifact: Artifact, output_dir: Path | str | None = None) -> str:
    """Save an artifact to the filesystem.

    Creates the output directory if it doesn't exist.
    Returns the absolute path to the saved file.
    """
    if output_dir is None:
        out_path = DEFAULT_OUTPUT_DIR
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
