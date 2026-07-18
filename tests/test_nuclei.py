"""Regression tests for Nuclei artifact generation, validation, and promotion."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import zero_forge.cli as cli
from zero_forge.agents import smart_agent
from zero_forge.agents.tool_agent import ToolAgent
from zero_forge.config import reset_settings
from zero_forge.examples import load_artifact_examples
from zero_forge.lab import promote_lab_run
from zero_forge.schemas import (
    ArtifactType,
    CollectedContext,
    ValidationResult,
    VulnerabilityInput,
    WorkflowState,
)
from zero_forge.tools.artifact_edit import (
    ArtifactEditError,
    apply_artifact_edits,
    artifact_sha256,
)
from zero_forge.tools.nuclei_validator import validate_nuclei

VALID_TEMPLATE = """id: zeroforge-http-header-detection

info:
  name: HTTP Header Detection Example
  author:
    - zeroforge
  severity: info
  description: Demonstrates a bounded HTTP response-header matcher.
  reference:
    - https://docs.projectdiscovery.io/templates/protocols/http/basic-http
  tags: http,example,zeroforge

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        part: header
        words:
          - "Content-Type"
"""


class FakeNucleiRunner:
    def __init__(self, result: tuple[int, str, str] = (0, "validated", "")) -> None:
        self.result = result
        self.seen = ""

    def validate(self, content: str) -> tuple[int, str, str]:
        self.seen = content
        return self.result


def test_nuclei_is_a_supported_artifact_type() -> None:
    value = VulnerabilityInput(
        cve_id="CVE-2021-44228",
        artifact_type="nuclei",
    )
    assert value.artifact_type == ArtifactType.NUCLEI
    assert ArtifactType.NUCLEI in list(ArtifactType)


def test_nuclei_profile_and_packaged_example_are_registered() -> None:
    profile = smart_agent._PROFILES[ArtifactType.NUCLEI]
    examples = load_artifact_examples(ArtifactType.NUCLEI)

    assert profile.language == "yaml"
    assert profile.filename_suffix == "_nuclei.yaml"
    assert "matchers or extractors" in profile.contract
    assert [example.name for example in examples] == ["http_header_detection.yaml"]


def test_nuclei_generation_uses_yaml_profile_and_filename(monkeypatch) -> None:
    monkeypatch.setenv("ZERO_FORGE_STUB_MODE", "true")
    reset_settings()

    artifact = smart_agent.generate_artifact(
        VulnerabilityInput(
            cve_id="CVE-2021-44228",
            artifact_type=ArtifactType.NUCLEI,
        ),
        CollectedContext(cve_id="CVE-2021-44228"),
    )

    assert artifact.artifact_type == ArtifactType.NUCLEI
    assert artifact.filename == "cve_2021_44228_nuclei.yaml"
    assert artifact.content.startswith("id: zeroforge-http-header-detection")
    assert artifact.metadata["stub"] is True


def test_validate_nuclei_runs_cli_after_yaml_and_schema_pass() -> None:
    runner = FakeNucleiRunner()

    result = validate_nuclei(VALID_TEMPLATE, nuclei_runner=runner)

    assert result["is_valid"] is True
    assert result["errors"] == []
    assert result["stages"] == {
        "yaml": "passed",
        "schema": "passed",
        "nuclei_cli": "passed",
    }
    assert result["evidence"]["template_id"] == "zeroforge-http-header-detection"
    assert result["evidence"]["protocols"] == ["http"]
    assert runner.seen == VALID_TEMPLATE


def test_validate_nuclei_skips_optional_binary_when_unavailable(monkeypatch) -> None:
    monkeypatch.setattr("zero_forge.tools.nuclei_validator.shutil.which", lambda _name: None)

    result = validate_nuclei(VALID_TEMPLATE)

    assert result["is_valid"] is True
    assert result["stages"]["nuclei_cli"] == "skipped"
    assert any("binary not found" in warning for warning in result["warnings"])


def test_validate_nuclei_rejects_invalid_yaml_and_multiple_documents() -> None:
    invalid = validate_nuclei("id: [unterminated")
    multiple = validate_nuclei(VALID_TEMPLATE + "\n---\n" + VALID_TEMPLATE)

    assert invalid["is_valid"] is False
    assert any("Invalid Nuclei YAML" in error for error in invalid["errors"])
    assert multiple["is_valid"] is False
    assert multiple["errors"] == ["Nuclei artifact must contain exactly one YAML document"]


def test_validate_nuclei_requires_detection_schema() -> None:
    result = validate_nuclei(
        """id: incomplete
info:
  name: Incomplete
  author: tester
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
""",
        nuclei_runner=FakeNucleiRunner(),
    )

    assert result["is_valid"] is False
    assert any("matcher or extractor" in error for error in result["errors"])
    assert result["stages"]["nuclei_cli"] == "not_run"


def test_validate_nuclei_surfaces_cli_rejection() -> None:
    result = validate_nuclei(
        VALID_TEMPLATE,
        nuclei_runner=FakeNucleiRunner((1, "", "template syntax rejected")),
    )

    assert result["is_valid"] is False
    assert result["stages"]["nuclei_cli"] == "failed"
    assert any("template syntax rejected" in error for error in result["errors"])


def test_tool_agent_registers_and_dispatches_nuclei_validator(monkeypatch) -> None:
    monkeypatch.setattr("zero_forge.tools.nuclei_validator.shutil.which", lambda _name: None)

    agent = ToolAgent()
    result = agent.validate_artifact(VALID_TEMPLATE, "nuclei")

    assert "validate_nuclei" in agent.list_available_tools()
    assert result.is_valid is True
    assert result.stages["schema"] == "passed"


def test_nuclei_repair_cannot_concatenate_a_second_yaml_document() -> None:
    with pytest.raises(ArtifactEditError, match="multiple Nuclei YAML documents"):
        apply_artifact_edits(
            VALID_TEMPLATE,
            artifact_sha256(VALID_TEMPLATE),
            [{"old": VALID_TEMPLATE, "new": VALID_TEMPLATE + "\n---\n" + VALID_TEMPLATE}],
            artifact_type="nuclei",
        )


def test_nuclei_workflow_does_not_require_node(monkeypatch, tmp_path) -> None:
    def unexpected_node() -> str:
        pytest.fail("Nuclei generation must not require Node.js")

    monkeypatch.setattr("zero_forge.workflow.require_node_runtime", unexpected_node)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ZERO_FORGE_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setattr(
        "zero_forge.workflow.ToolAgent.collect_context",
        lambda _self, vuln_input: CollectedContext(cve_id=vuln_input.cve_id),
    )

    from zero_forge.workflow import run_workflow

    result = run_workflow(
        VulnerabilityInput(
            cve_id="CVE-2021-44228",
            artifact_type=ArtifactType.NUCLEI,
        )
    )

    assert result.status == "failed"
    assert result.failure is not None
    assert result.failure.code == "llm_configuration_error"


def test_generate_all_includes_nuclei(monkeypatch, tmp_path) -> None:
    seen: list[ArtifactType] = []

    def completed(vuln_input: VulnerabilityInput) -> WorkflowState:
        seen.append(vuln_input.artifact_type)
        return WorkflowState(
            vuln_input=vuln_input,
            validation=ValidationResult(is_valid=True),
            status="completed",
        )

    monkeypatch.setattr(cli, "_ensure_config", lambda _path: None)
    monkeypatch.setattr(cli, "_apply_env_overrides", lambda **_kwargs: None)
    monkeypatch.setattr(cli, "setup_logging_from_settings", lambda: None)
    monkeypatch.setattr(cli, "run_workflow", completed)

    result = CliRunner().invoke(
        cli.app,
        ["generate", "--cve", "CVE-2021-44228", "--all", "--output", str(tmp_path)],
    )

    assert result.exit_code == 0
    assert seen == list(ArtifactType)
    assert ArtifactType.NUCLEI in seen


def test_lab_promotion_routes_nuclei_yaml(tmp_path: Path) -> None:
    lab_root = tmp_path / "lab"
    run_dir = lab_root / "output" / "CVE-2021-44228" / "run-1"
    artifact_dir = run_dir / "zeroforge"
    artifact_dir.mkdir(parents=True)
    (artifact_dir / "cve_2021_44228_nuclei.yaml").write_text(
        VALID_TEMPLATE,
        encoding="utf-8",
    )
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "status": "completed",
                "artifact_type": "nuclei",
                "cve_id": "CVE-2021-44228",
                "repo_name": "example",
                "run_id": "run-1",
            }
        ),
        encoding="utf-8",
    )

    destination = promote_lab_run(run_dir=run_dir, lab_root=lab_root)

    assert destination == lab_root / "vuln-db" / "artifacts" / "CVE-2021-44228"
    assert (destination / "nuclei" / "cve_2021_44228_nuclei.yaml").is_file()
    assert not (destination / "zap" / "passive").exists()
