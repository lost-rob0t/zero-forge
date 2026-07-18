from __future__ import annotations

import json
from pathlib import Path

import pytest

import zero_forge.agents.smart_agent as smart_agent
from zero_forge.agents.smart_agent import _build_context_prompt, repair_artifact
from zero_forge.agents.llm import LLMResponseError
from zero_forge.schemas import (
    Artifact,
    ArtifactType,
    CollectedContext,
    ValidationResult,
    VulnerabilityInput,
)
from zero_forge.tools.artifact_edit import artifact_sha256


FIXTURE = (Path(__file__).parent / "fixtures" / "langflow_poc_bundle.txt").read_text(
    encoding="utf-8"
)


def test_repair_applies_sha_bound_exact_edit(monkeypatch):
    original_content = "class Foo\nend"
    response = json.dumps(
        {
            "base_sha256": artifact_sha256(original_content),
            "edits": [
                {
                    "old": "class Foo",
                    "new": "class MetasploitModule < Msf::Exploit::Remote",
                }
            ],
        }
    )
    monkeypatch.setattr(smart_agent, "_call_llm", lambda *_args: response)
    artifact = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content=original_content,
        filename="test.rb",
    )

    repaired = repair_artifact(
        artifact,
        ValidationResult(is_valid=False, errors=["wrong class"]),
        CollectedContext(cve_id=""),
    )

    assert repaired.content.startswith("class MetasploitModule")
    assert repaired.metadata["repair_base_sha256"] == artifact_sha256(original_content)
    assert "-class Foo" in repaired.metadata["repair_diff"]
    assert repaired.metadata["repair_edits"] == 1


def test_repair_rejects_concatenated_full_artifact(monkeypatch):
    original = "class MetasploitModule < Msf::Exploit::Remote\nend"
    concatenated = original + "\nclass MetasploitModule < Msf::Exploit::Remote\nend"
    monkeypatch.setattr(
        smart_agent,
        "_call_llm",
        lambda *_args: f"```ruby\n{concatenated}\n```",
    )
    artifact = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content=original,
        filename="test.rb",
    )

    with pytest.raises(LLMResponseError, match="concatenate"):
        repair_artifact(
            artifact,
            ValidationResult(is_valid=False, errors=["duplicate module"]),
            CollectedContext(cve_id=""),
        )


def test_context_prompt_uses_selected_poc_sections_only():
    context = CollectedContext(
        cve_id="",
        poc_text=FIXTURE,
        source_files=[],
        writeup_text="Langflow 1.2.0 validates Python at /api/v1/validate/code",
    )
    prompt = _build_context_prompt(VulnerabilityInput(cve_id=""), context)

    assert "exploitdb:52364: selected" in prompt
    assert "exploitdb:52262: excluded" in prompt
    assert "exploitdb:52597: excluded" in prompt
    assert "/webapps/52364.py" in prompt
    assert "/remote/52262.txt" not in prompt
    assert "/webapps/52597.py" not in prompt
