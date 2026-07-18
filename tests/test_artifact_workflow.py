from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from zero_forge.agents import artifact_workflow
from zero_forge.schemas import (
    Artifact,
    ArtifactType,
    CollectedContext,
    SourceFile,
    ValidationResult,
    VulnerabilityInput,
)
from zero_forge.tools.artifact_edit import apply_artifact_edits, artifact_sha256

FIXTURE = (Path(__file__).parent / "fixtures" / "langflow_poc_bundle.txt").read_text(
    encoding="utf-8"
)
VALID_MODULE = """class MetasploitModule < Msf::Exploit::Remote
  def exploit
  end
end
"""


class ApplyingToolAgent:
    def run(self, request):
        output = apply_artifact_edits(**request.arguments)
        return SimpleNamespace(output=output, error="")


def test_generation_normalizes_poc_and_records_decisions(monkeypatch):
    captured = {}

    def generate(vuln_input, context):
        captured["context"] = context
        return Artifact(
            artifact_type=ArtifactType.METASPLOIT,
            content=VALID_MODULE,
            filename="test.rb",
            metadata={"stub": False},
        )

    monkeypatch.setattr(artifact_workflow.legacy, "generate_artifact", generate)
    context = CollectedContext(
        cve_id="",
        poc_text=FIXTURE,
        source_files=[
            SourceFile(
                path="pyproject.toml",
                filename="pyproject.toml",
                language="toml",
                content='project = "langflow"\nversion = "1.2.0"',
            )
        ],
    )

    artifact = artifact_workflow.generate_artifact(
        VulnerabilityInput(cve_id=""),
        context,
    )

    normalized = captured["context"].poc_text
    assert "exploitdb:52364" in normalized
    assert "exploitdb:52262" not in normalized
    assert "CVE-2026-0770" not in normalized
    assert artifact.metadata["poc_selection"]
    assert artifact.metadata["artifact_root_count"] == 1


def test_generation_rejects_concatenated_artifact(monkeypatch):
    monkeypatch.setattr(
        artifact_workflow.legacy,
        "generate_artifact",
        lambda *_args: Artifact(
            artifact_type=ArtifactType.METASPLOIT,
            content=VALID_MODULE + "\n" + VALID_MODULE,
            filename="test.rb",
            metadata={"stub": False},
        ),
    )

    artifact = artifact_workflow.generate_artifact(
        VulnerabilityInput(cve_id=""),
        CollectedContext(cve_id=""),
    )

    assert artifact.metadata["generation_rejected"] is True
    assert "exactly one complete root" in artifact.metadata["generation_error"]
    assert "class MetasploitModule" not in artifact.content


def test_repair_applies_sha_pinned_edit_plan(monkeypatch):
    original = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content=VALID_MODULE,
        filename="test.rb",
        metadata={"stub": False},
    )
    raw = (
        '{"base_sha256":"'
        + artifact_sha256(VALID_MODULE)
        + '","edits":[{"old":"  def exploit\\n",'
        + '"new":"  def check\\n  end\\n\\n  def exploit\\n"}]}'
    )
    monkeypatch.setattr(artifact_workflow.legacy, "_call_llm", lambda *_args: raw)
    monkeypatch.setattr(artifact_workflow, "ToolAgent", ApplyingToolAgent)

    repaired = artifact_workflow.repair_artifact(
        original,
        ValidationResult(is_valid=False, errors=["missing check"]),
        CollectedContext(cve_id=""),
    )

    assert "def check" in repaired.content
    assert repaired.metadata["edit_count"] == 1
    assert repaired.metadata["legacy_full_replacement"] is False
    assert "+++ artifact.after" in repaired.metadata["edit_diff"]


def test_repair_rejects_concatenated_legacy_full_response(monkeypatch):
    original = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content=VALID_MODULE,
        filename="test.rb",
        metadata={"stub": False},
    )
    monkeypatch.setattr(
        artifact_workflow.legacy,
        "_call_llm",
        lambda *_args: f"```ruby\n{VALID_MODULE}\n{VALID_MODULE}\n```",
    )
    monkeypatch.setattr(artifact_workflow, "ToolAgent", ApplyingToolAgent)

    repaired = artifact_workflow.repair_artifact(
        original,
        ValidationResult(is_valid=False, errors=["test"]),
        CollectedContext(cve_id=""),
    )

    assert repaired is original
