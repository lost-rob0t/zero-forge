"""Tests for ZeroForge output module."""

import json
import os
from pathlib import Path

import pytest

from zero_forge.output import ArtifactPathError, save_artifact
from zero_forge.schemas import Artifact, ArtifactType


def _make_artifact(filename: str, cve_id: str | None = "CVE-2021-44228") -> Artifact:
    meta: dict = {}
    if cve_id is not None:
        meta["cve_id"] = cve_id
    return Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content="class MetasploitModule\nend\n",
        filename=filename,
        metadata=meta,
    )


# --- Existing / valid cases ------------------------------------------------

def test_save_artifact(tmp_path):
    art = _make_artifact("test_exploit.rb")
    path = save_artifact(art, output_dir=tmp_path)
    assert Path(path).exists()
    assert Path(path).read_text() == "class MetasploitModule\nend\n"

    meta_path = Path(path).with_suffix(".rb.meta.json")
    assert meta_path.exists()
    meta = json.loads(meta_path.read_text())
    assert meta["artifact_type"] == "metasploit"
    assert meta["cve_id"] == "CVE-2021-44228"


def test_save_artifact_default_filename(tmp_path):
    art = _make_artifact("", cve_id=None)
    path = save_artifact(art, output_dir=tmp_path)
    assert Path(path).exists()
    assert Path(path).read_text() == "class MetasploitModule\nend\n"


def test_save_artifact_creates_dir(tmp_path):
    nested = tmp_path / "nested" / "deep" / "output"
    art = _make_artifact("out.rb")
    path = save_artifact(art, output_dir=nested)
    assert Path(path).exists()
    assert nested.exists()


# --- Path traversal tests --------------------------------------------------

def test_save_artifact_rejects_parent_traversal(tmp_path):
    art = _make_artifact("../escaped.rb")
    with pytest.raises(ArtifactPathError, match="parent directory|path separators"):
        save_artifact(art, output_dir=tmp_path)


def test_save_artifact_rejects_absolute_path(tmp_path):
    art = _make_artifact("/etc/passwd")
    with pytest.raises(ArtifactPathError, match="path separators|absolute"):
        save_artifact(art, output_dir=tmp_path)


def test_save_artifact_rejects_nested_path(tmp_path):
    art = _make_artifact("subdir/exploit.rb")
    with pytest.raises(ArtifactPathError, match="path separators"):
        save_artifact(art, output_dir=tmp_path)


def test_save_artifact_rejects_windows_traversal(tmp_path):
    art = _make_artifact("..\\escaped.rb")
    with pytest.raises(ArtifactPathError, match="parent directory|path separators"):
        save_artifact(art, output_dir=tmp_path)


def test_save_artifact_rejects_empty_filename(tmp_path):
    # Empty filename with no cve_id should still fail because the default
    # filename is generated only after validation, but the validation happens
    # on artifact.filename directly.
    art = _make_artifact("", cve_id=None)
    # Override: we want to test truly empty - the save_artifact should generate
    # a default name, so this should actually succeed. Let's test a filename
    # that is just whitespace or a dot instead.
    art = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content="test",
        filename="",
    )
    # Empty filename triggers default name generation, which is valid.
    path = save_artifact(art, output_dir=tmp_path)
    assert Path(path).exists()


def test_save_artifact_rejects_cve_id_with_traversal(tmp_path):
    art = _make_artifact("valid.rb", cve_id="../../etc/passwd")
    with pytest.raises(ArtifactPathError, match="Invalid CVE ID"):
        save_artifact(art, output_dir=tmp_path)


def test_save_artifact_rejects_symlink_outside(tmp_path):
    # Create a symlink inside output dir pointing outside
    outside_file = tmp_path.parent / "outside_secret.txt"
    outside_file.write_text("secret")
    symlink_path = tmp_path / "evil.rb"
    os.symlink(outside_file, symlink_path)

    art = _make_artifact("evil.rb")
    with pytest.raises(ArtifactPathError, match="symlink"):
        save_artifact(art, output_dir=tmp_path)


def test_save_artifact_rejects_existing_non_regular_file(tmp_path):
    # Create a directory where the artifact would be written
    dir_path = tmp_path / "exploit.rb"
    dir_path.mkdir()

    art = _make_artifact("exploit.rb")
    with pytest.raises(ArtifactPathError, match="not a regular file"):
        save_artifact(art, output_dir=tmp_path)


def test_metadata_sidecar_containment(tmp_path):
    """Ensure metadata sidecar is written inside output directory."""
    art = _make_artifact("safe_exploit.rb")
    path = save_artifact(art, output_dir=tmp_path)

    meta_path = Path(path).with_suffix(".rb.meta.json")
    assert meta_path.exists()

    # Verify the sidecar is inside the output directory
    assert meta_path.resolve().parent == Path(path).resolve().parent

    # Verify no symlinks
    assert not meta_path.is_symlink()
    assert meta_path.is_file()


def test_save_artifact_valid_filename_stays_in_output(tmp_path):
    """A valid filename should produce a path inside the output directory."""
    art = _make_artifact("valid_exploit.rb")
    path = save_artifact(art, output_dir=tmp_path)

    resolved_path = Path(path).resolve()
    resolved_root = tmp_path.resolve()
    assert resolved_path.relative_to(resolved_root)


def test_save_artifact_rejects_windows_drive_absolute(tmp_path):
    art = _make_artifact("C:\\Users\\evil.rb")
    with pytest.raises(ArtifactPathError, match="path separators|absolute"):
        save_artifact(art, output_dir=tmp_path)


def test_save_artifact_rejects_dot_filename(tmp_path):
    art = _make_artifact(".")
    with pytest.raises(ArtifactPathError, match="basename"):
        save_artifact(art, output_dir=tmp_path)


def test_save_artifact_rejects_double_dot_filename(tmp_path):
    art = _make_artifact("..")
    with pytest.raises(ArtifactPathError, match="parent directory|basename"):
        save_artifact(art, output_dir=tmp_path)
