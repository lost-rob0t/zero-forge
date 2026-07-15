"""Tests for bounded artifact example loading."""

from pathlib import Path

import pytest

from zero_forge.examples import load_artifact_examples
from zero_forge.schemas import ArtifactType


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_examples_are_sorted_filtered_and_bounded(tmp_path):
    _write(tmp_path / "zap" / "active" / "b.js", "b")
    _write(tmp_path / "zap" / "active" / "a.js", "aa")
    _write(tmp_path / "zap" / "active" / "ignored.rb", "ruby")
    _write(tmp_path / "zap" / "passive" / "passive.js", "passive")

    examples = load_artifact_examples(
        ArtifactType.ZAP_ACTIVE,
        root=tmp_path,
        max_examples=1,
        max_chars=10,
    )

    assert [example.name for example in examples] == ["a.js"]
    assert examples[0].content == "aa"


def test_examples_skip_files_that_would_be_truncated(tmp_path):
    _write(tmp_path / "metasploit" / "a.rb", "a" * 20)
    _write(tmp_path / "metasploit" / "b.rb", "valid")

    examples = load_artifact_examples(
        ArtifactType.METASPLOIT,
        root=tmp_path,
        max_chars=10,
    )

    assert [example.name for example in examples] == ["b.rb"]


def test_missing_example_directory_returns_empty(tmp_path):
    assert load_artifact_examples(ArtifactType.ZAP_PASSIVE, root=tmp_path) == []


def test_negative_example_limit_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="non-negative"):
        load_artifact_examples(
            ArtifactType.METASPLOIT,
            root=tmp_path,
            max_examples=-1,
        )
