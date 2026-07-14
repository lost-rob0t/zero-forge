"""Tests for ZF-002: invalid artifacts must not be saved as completed."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from zero_forge.schemas import (
    Artifact,
    ArtifactType,
    CollectedContext,
    ValidationResult,
    VulnerabilityInput,
)
from zero_forge.workflow import (
    build_workflow,
    fail_node,
    save_artifact_node,
    should_repair_after_fix,
    should_repair_or_finish,
)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_VALID_CONTENT = """\
class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Test',
      'Description' => %q{Test},
      'Author' => ['Test'],
      'References' => [['CVE', '2021-44228']],
      'License' => MSF_LICENSE,
    ))
    register_options([])
  end

  def exploit
  end
end
"""

_INVALID_CONTENT = "this is not a valid metasploit module"


def _make_vuln_input() -> VulnerabilityInput:
    return VulnerabilityInput(
        cve_id="CVE-2021-44228",
        poc_text="print('pwned')",
        writeup_text="RCE via JNDI lookup",
    )


def _make_context() -> CollectedContext:
    return CollectedContext(
        cve_id="CVE-2021-44228",
        poc_text="print('pwned')",
        writeup_text="RCE via JNDI lookup",
    )


def _make_artifact(content: str = _VALID_CONTENT) -> Artifact:
    return Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content=content,
        filename="cve_2021_44228_exploit.rb",
        metadata={"cve_id": "CVE-2021-44228"},
    )


def _make_state(**overrides):
    from zero_forge.schemas import WorkflowState

    defaults = {
        "vuln_input": _make_vuln_input(),
        "context": _make_context(),
        "artifact": _make_artifact(),
        "validation": ValidationResult(is_valid=True),
        "repair_attempts": 0,
        "max_repair_attempts": 3,
    }
    defaults.update(overrides)
    return WorkflowState(**defaults)


def _run_workflow_with_mocks(
    *,
    artifact_content: str = _VALID_CONTENT,
    validation_errors: list[str] | None = None,
    max_repair_attempts: int = 3,
    tmp_path: Path,
) -> dict:
    """Run the full workflow with mocked agents and controlled validation."""
    is_valid = validation_errors is None
    validation = ValidationResult(
        is_valid=is_valid,
        errors=validation_errors or [],
    )

    mock_tool_agent = MagicMock()
    mock_tool_agent.collect_context.return_value = _make_context()
    mock_tool_agent.validate_artifact.return_value = validation

    with (
        patch("zero_forge.workflow.ToolAgent", return_value=mock_tool_agent),
        patch("zero_forge.workflow.generate_artifact", return_value=_make_artifact(artifact_content)),
        patch("zero_forge.workflow.repair_artifact", return_value=_make_artifact(artifact_content)),
        patch.dict("os.environ", {"ZERO_FORGE_OUTPUT_DIR": str(tmp_path)}),
    ):
        from zero_forge.config import reset_settings
        from zero_forge.schemas import WorkflowState

        reset_settings()
        app = build_workflow()
        initial = WorkflowState(
            vuln_input=_make_vuln_input(),
            max_repair_attempts=max_repair_attempts,
        )
        return app.invoke(initial)


# --------------------------------------------------------------------------- #
# 1. Valid artifact is saved and marked completed
# --------------------------------------------------------------------------- #


def test_valid_artifact_saved_and_completed(tmp_path):
    result = _run_workflow_with_mocks(
        artifact_content=_VALID_CONTENT,
        validation_errors=None,
        tmp_path=tmp_path,
    )
    assert result["status"] == "completed"
    assert result.get("output_path") is not None
    assert Path(result["output_path"]).exists()


# --------------------------------------------------------------------------- #
# 2. Invalid artifact with no retries remaining is marked failed
# --------------------------------------------------------------------------- #


def test_invalid_artifact_no_retries_is_failed(tmp_path):
    result = _run_workflow_with_mocks(
        artifact_content=_INVALID_CONTENT,
        validation_errors=["Missing class definition", "Missing metadata key: 'Name'"],
        max_repair_attempts=0,
        tmp_path=tmp_path,
    )
    assert result["status"] == "failed"


# --------------------------------------------------------------------------- #
# 3. Invalid artifact is not written to the normal output path
# --------------------------------------------------------------------------- #


def test_invalid_artifact_not_written(tmp_path):
    result = _run_workflow_with_mocks(
        artifact_content=_INVALID_CONTENT,
        validation_errors=["Missing class definition"],
        max_repair_attempts=0,
        tmp_path=tmp_path,
    )
    assert result["status"] == "failed"
    assert result.get("output_path") is None
    # No files should be written to the output directory
    written_files = list(tmp_path.iterdir())
    assert written_files == [], f"Unexpected files written: {written_files}"


# --------------------------------------------------------------------------- #
# 4. Exhausted repair attempts terminate the graph
# --------------------------------------------------------------------------- #


def test_exhausted_repairs_terminate_graph(tmp_path):
    """After max repairs, the graph terminates via fail, not save."""
    result = _run_workflow_with_mocks(
        artifact_content=_INVALID_CONTENT,
        validation_errors=["Missing class definition"],
        max_repair_attempts=2,
        tmp_path=tmp_path,
    )
    assert result["status"] == "failed"
    # repair_attempts should equal max
    assert result["repair_attempts"] == 2
    assert result.get("output_path") is None


# --------------------------------------------------------------------------- #
# 5. Missing validation produces failed status
# --------------------------------------------------------------------------- #


def test_missing_validation_produces_failed():
    """should_repair_or_finish routes to 'fail' when validation is None."""
    state = _make_state(validation=None)
    assert should_repair_or_finish(state) == "fail"


def test_save_node_rejects_missing_validation():
    """save_artifact_node returns failed when validation is None."""
    state = _make_state(validation=None)
    result = save_artifact_node(state)
    assert result["status"] == "failed"
    assert "Missing validation" in result["error"]


def test_fail_node_handles_missing_validation():
    """fail_node sets a descriptive error when validation is missing."""
    state = _make_state(validation=None)
    result = fail_node(state)
    assert result["status"] == "failed"
    assert "Missing validation" in result["error"]


# --------------------------------------------------------------------------- #
# 6. Validation errors remain available in the final state
# --------------------------------------------------------------------------- #


def test_validation_errors_preserved_in_final_state(tmp_path):
    errors = ["Missing class definition", "Missing metadata key: 'Name'"]
    result = _run_workflow_with_mocks(
        artifact_content=_INVALID_CONTENT,
        validation_errors=errors,
        max_repair_attempts=0,
        tmp_path=tmp_path,
    )
    assert result["status"] == "failed"
    # Validation errors must be preserved
    validation = result.get("validation")
    assert validation is not None
    assert not validation.is_valid
    assert validation.errors == errors
    # Error field should also contain the validation errors
    for err in errors:
        assert err in result["error"]


# --------------------------------------------------------------------------- #
# 7. Existing successful workflow behavior still works
# --------------------------------------------------------------------------- #


def test_existing_successful_workflow_still_works(tmp_path, monkeypatch):
    """A real, validated artifact still completes."""
    result = _run_workflow_with_mocks(
        artifact_content=_VALID_CONTENT,
        validation_errors=None,
        tmp_path=tmp_path,
    )
    assert result["status"] == "completed"
    assert result["artifact"] is not None
    assert result["output_path"] is not None
    assert Path(result["output_path"]).exists()


# --------------------------------------------------------------------------- #
# 8. should_repair_after_fix always validates (never saves directly)
# --------------------------------------------------------------------------- #


def test_should_repair_after_fix_always_validates():
    state = _make_state(repair_attempts=5, max_repair_attempts=3)
    assert should_repair_after_fix(state) == "validate"


def test_should_repair_after_fix_validates_at_limit():
    state = _make_state(repair_attempts=3, max_repair_attempts=3)
    assert should_repair_after_fix(state) == "validate"


# --------------------------------------------------------------------------- #
# 9. fail_node preserves validation errors
# --------------------------------------------------------------------------- #


def test_fail_node_preserves_validation_errors():
    errors = ["Error A", "Error B"]
    state = _make_state(validation=ValidationResult(is_valid=False, errors=errors))
    result = fail_node(state)
    assert result["status"] == "failed"
    assert "Error A" in result["error"]
    assert "Error B" in result["error"]


def test_fail_node_with_no_errors():
    state = _make_state(validation=ValidationResult(is_valid=False, errors=[]))
    result = fail_node(state)
    assert result["status"] == "failed"
    assert "failed validation" in result["error"].lower()
