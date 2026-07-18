from __future__ import annotations

import pytest

from zero_forge.tools.artifact_edit import (
    ArtifactEditError,
    apply_artifact_edits,
    artifact_sha256,
    diff_artifact_edits,
    parse_artifact_edit_plan,
    require_single_artifact,
)

MODULE = """class MetasploitModule < Msf::Exploit::Remote
  def exploit
  end
end
"""


def test_apply_exact_edit_returns_unified_diff():
    result = apply_artifact_edits(
        content=MODULE,
        base_sha256=artifact_sha256(MODULE),
        edits=[
            {
                "old": "  def exploit\n",
                "new": "  def check\n  end\n\n  def exploit\n",
            }
        ],
        artifact_type="metasploit",
    )

    assert result["applied_edits"] == 1
    assert "def check" in result["content"]
    assert result["base_sha256"] == artifact_sha256(MODULE)
    assert result["sha256"] == artifact_sha256(result["content"])
    assert result["artifact_roots"] == {"MetasploitModule": 1}
    assert "+++ artifact.after" in result["diff"]


def test_diff_tool_uses_same_guarded_edit_contract():
    result = diff_artifact_edits(
        content=MODULE,
        base_sha256=artifact_sha256(MODULE),
        edits=[{"old": "def exploit", "new": "def check"}],
        artifact_type="metasploit",
    )

    assert "def check" in result["content"]
    assert result["applied_edits"] == 1


def test_stale_hash_is_rejected():
    with pytest.raises(ArtifactEditError, match="stale"):
        apply_artifact_edits(
            content=MODULE,
            base_sha256="0" * 64,
            edits=[{"old": "exploit", "new": "check"}],
            artifact_type="metasploit",
        )


def test_ambiguous_old_text_is_rejected():
    with pytest.raises(ArtifactEditError, match="exactly once"):
        apply_artifact_edits(
            content=MODULE,
            base_sha256=artifact_sha256(MODULE),
            edits=[{"old": "end", "new": "finish"}],
            artifact_type="metasploit",
        )


def test_concatenated_module_result_is_rejected():
    with pytest.raises(ArtifactEditError, match="multiple MetasploitModule"):
        apply_artifact_edits(
            content=MODULE,
            base_sha256=artifact_sha256(MODULE),
            edits=[{"old": MODULE, "new": MODULE + "\n" + MODULE}],
            artifact_type="metasploit",
        )


def test_missing_required_zap_root_is_rejected():
    with pytest.raises(ArtifactEditError, match="getMetadata=0"):
        require_single_artifact(
            "function scan(as, msg, param, value) {}",
            "zap_active_scan",
        )


def test_edit_plan_parser_rejects_undeclared_fields():
    payload = (
        '{"base_sha256":"'
        + artifact_sha256(MODULE)
        + '","edits":[{"old":"exploit","new":"check","reason":"extra"}]}'
    )
    with pytest.raises(ArtifactEditError, match="exactly old and new"):
        parse_artifact_edit_plan(payload)
