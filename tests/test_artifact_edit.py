from __future__ import annotations

import json

import pytest

from zero_forge.tools.artifact_edit import (
    ArtifactEditError,
    apply_artifact_edits,
    artifact_sha256,
    parse_artifact_edit_plan,
)

MODULE = """class MetasploitModule < Msf::Exploit::Remote
  def exploit
    print_status('old')
  end
end
"""


def test_exact_edit_returns_updated_content_and_diff():
    result = apply_artifact_edits(
        MODULE,
        artifact_sha256(MODULE),
        [{"old": "print_status('old')", "new": "print_status('new')"}],
        artifact_type="metasploit",
    )

    assert "print_status('new')" in result["content"]
    assert "-    print_status('old')" in result["diff"]
    assert "+    print_status('new')" in result["diff"]
    assert result["applied_edits"] == 1


def test_stale_sha_is_rejected():
    with pytest.raises(ArtifactEditError, match="stale"):
        apply_artifact_edits(
            MODULE,
            "0" * 64,
            [{"old": "old", "new": "new"}],
            artifact_type="metasploit",
        )


def test_ambiguous_old_span_is_rejected():
    content = "class MetasploitModule\nold\nold\nend\n"
    with pytest.raises(ArtifactEditError, match="exactly once"):
        apply_artifact_edits(
            content,
            artifact_sha256(content),
            [{"old": "old", "new": "new"}],
            artifact_type="metasploit",
        )


def test_empty_old_span_cannot_append_content():
    raw = json.dumps(
        {
            "base_sha256": artifact_sha256(MODULE),
            "edits": [{"old": "", "new": "class MetasploitModule\nend\n"}],
        }
    )
    with pytest.raises(ArtifactEditError, match="non-empty"):
        parse_artifact_edit_plan(raw)


def test_edit_cannot_concatenate_second_metasploit_module():
    second = "\nclass MetasploitModule < Msf::Exploit::Remote\nend\n"
    with pytest.raises(ArtifactEditError, match="concatenate"):
        apply_artifact_edits(
            MODULE,
            artifact_sha256(MODULE),
            [{"old": MODULE, "new": MODULE + second}],
            artifact_type="metasploit",
        )


def test_edit_plan_rejects_extra_fields():
    raw = json.dumps(
        {
            "base_sha256": artifact_sha256(MODULE),
            "edits": [{"old": "old", "new": "new"}],
            "content": MODULE,
        }
    )
    with pytest.raises(ArtifactEditError, match="exactly"):
        parse_artifact_edit_plan(raw)
