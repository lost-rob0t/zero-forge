"""Tests for ZeroForge output module."""

import json
from pathlib import Path

from zero_forge.output import save_artifact
from zero_forge.schemas import Artifact, ArtifactType


def test_save_artifact(tmp_path):
    art = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content="class MetasploitModule\nend\n",
        filename="test_exploit.rb",
        metadata={"cve_id": "CVE-2021-44228"},
    )
    path = save_artifact(art, output_dir=tmp_path)
    assert Path(path).exists()
    assert Path(path).read_text() == "class MetasploitModule\nend\n"

    meta_path = Path(path).with_suffix(".rb.meta.json")
    assert meta_path.exists()
    meta = json.loads(meta_path.read_text())
    assert meta["artifact_type"] == "metasploit"
    assert meta["cve_id"] == "CVE-2021-44228"


def test_save_artifact_default_filename(tmp_path):
    art = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content="puts 'hello'",
        filename="",
    )
    path = save_artifact(art, output_dir=tmp_path)
    assert Path(path).exists()
    assert Path(path).read_text() == "puts 'hello'"


def test_save_artifact_creates_dir(tmp_path):
    nested = tmp_path / "nested" / "deep" / "output"
    art = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content="test",
        filename="out.rb",
    )
    path = save_artifact(art, output_dir=nested)
    assert Path(path).exists()
    assert nested.exists()
