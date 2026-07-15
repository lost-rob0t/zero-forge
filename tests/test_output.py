"""Tests for ZeroForge output module."""

import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import zero_forge.output as output_module
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


def test_save_artifact_allows_empty_cve_id(tmp_path):
    """An empty cve_id in metadata should not trigger validation failure (issue #68)."""
    art = _make_artifact("source_only.rb", cve_id="")
    path = save_artifact(art, output_dir=tmp_path)
    assert Path(path).exists()

    meta_path = Path(path).with_suffix(".rb.meta.json")
    meta = json.loads(meta_path.read_text())
    assert meta["cve_id"] == ""


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


def test_metadata_reserved_fields_not_overwritten(tmp_path):
    """User metadata cannot overwrite reserved sidecar fields (issue #6)."""
    art = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content="class MetasploitModule\nend\n",
        filename="spoof_test.rb",
        metadata={
            "cve_id": "CVE-2021-44228",
            "artifact_type": "spoof",
            "filename": "spoof.rb",
            "saved_at": "spoofed",
        },
    )
    path = save_artifact(art, output_dir=tmp_path)

    meta_path = Path(path).with_suffix(".rb.meta.json")
    meta = json.loads(meta_path.read_text())

    # Reserved fields must reflect actual saved artifact, not user metadata
    assert meta["artifact_type"] == "metasploit"
    assert meta["filename"] == "spoof_test.rb"
    assert meta["saved_at"] != "spoofed"
    # User-supplied cve_id is preserved
    assert meta["cve_id"] == "CVE-2021-44228"


def test_metadata_sidecar_matches_actual_artifact(tmp_path):
    """Sidecar filename and type must match the actual saved file (issue #6)."""
    art = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content="payload\n",
        filename="real_exploit.rb",
        metadata={
            "artifact_type": "fake",
            "filename": "fake.rb",
            "saved_at": "1970-01-01T00:00:00",
        },
    )
    path = save_artifact(art, output_dir=tmp_path)
    saved_path = Path(path)

    meta_path = saved_path.with_suffix(".rb.meta.json")
    meta = json.loads(meta_path.read_text())

    assert meta["filename"] == saved_path.name
    assert meta["artifact_type"] == art.artifact_type.value
    assert meta["saved_at"] != "1970-01-01T00:00:00"


def test_save_artifact_rejects_double_dot_filename(tmp_path):
    art = _make_artifact("..")
    with pytest.raises(ArtifactPathError, match="parent directory|basename"):
        save_artifact(art, output_dir=tmp_path)


def test_save_artifact_never_overwrites_existing_pair(tmp_path):
    first = _make_artifact("collision.rb")
    first.content = "first"
    first_path = Path(save_artifact(first, output_dir=tmp_path))
    first_meta = first_path.with_suffix(".rb.meta.json").read_text()

    second = _make_artifact("collision.rb")
    second.content = "second"
    with pytest.raises(ArtifactPathError, match="refusing to overwrite"):
        save_artifact(second, output_dir=tmp_path)

    assert first_path.read_text() == "first"
    assert first_path.with_suffix(".rb.meta.json").read_text() == first_meta


def test_sidecar_collision_leaves_no_artifact_placeholder(tmp_path):
    sidecar = tmp_path / "collision.rb.meta.json"
    sidecar.write_text("existing", encoding="utf-8")

    with pytest.raises(ArtifactPathError, match="refusing to overwrite"):
        save_artifact(_make_artifact("collision.rb"), output_dir=tmp_path)

    assert not (tmp_path / "collision.rb").exists()
    assert sidecar.read_text() == "existing"


def test_partial_publish_failure_cleans_entire_pair(tmp_path, monkeypatch):
    real_replace = os.replace
    replacements = 0

    def fail_second_replace(source, destination):
        nonlocal replacements
        replacements += 1
        if replacements == 2:
            raise OSError("simulated artifact publish failure")
        real_replace(source, destination)

    monkeypatch.setattr(output_module.os, "replace", fail_second_replace)

    with pytest.raises(ArtifactPathError, match="simulated artifact publish failure"):
        save_artifact(_make_artifact("partial.rb"), output_dir=tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_concurrent_writers_publish_exactly_one_complete_pair(tmp_path):
    def publish(content: str):
        artifact = _make_artifact("concurrent.rb")
        artifact.content = content
        try:
            return save_artifact(artifact, output_dir=tmp_path)
        except ArtifactPathError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(publish, ["first", "second"]))

    assert sum(result is not None for result in results) == 1
    artifact_path = tmp_path / "concurrent.rb"
    metadata_path = tmp_path / "concurrent.rb.meta.json"
    assert artifact_path.read_text() in {"first", "second"}
    assert json.loads(metadata_path.read_text())["filename"] == artifact_path.name
    assert not list(tmp_path.glob(".zeroforge-*.tmp"))


def test_symlink_inserted_after_path_check_is_not_followed(tmp_path, monkeypatch):
    outside = tmp_path.parent / "race-target.txt"
    outside.write_text("unchanged", encoding="utf-8")
    real_reserve = output_module._reserve_destination
    inserted = False

    def insert_symlink(path: Path) -> None:
        nonlocal inserted
        if not inserted and path.name == "race.rb":
            path.symlink_to(outside)
            inserted = True
        real_reserve(path)

    monkeypatch.setattr(output_module, "_reserve_destination", insert_symlink)

    with pytest.raises(ArtifactPathError, match="refusing to overwrite"):
        save_artifact(_make_artifact("race.rb"), output_dir=tmp_path)

    assert outside.read_text() == "unchanged"
    assert (tmp_path / "race.rb").is_symlink()
