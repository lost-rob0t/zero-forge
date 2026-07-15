"""Tests for ZeroForge schemas."""

import pytest
from pydantic import ValidationError

from zero_forge.schemas import (
    Artifact,
    ArtifactType,
    CollectedContext,
    ToolCall,
    ToolRequest,
    ValidationResult,
    VulnerabilityInput,
    WorkflowError,
    WorkflowState,
)


def test_vulnerability_input_minimal():
    vi = VulnerabilityInput(cve_id="CVE-2021-44228")
    assert vi.cve_id == "CVE-2021-44228"
    assert vi.poc_text == ""
    assert vi.source_path is None
    assert vi.artifact_type == ArtifactType.METASPLOIT


def test_vulnerability_input_accepts_zap_artifact_type():
    vi = VulnerabilityInput(
        cve_id="CVE-2021-44228",
        artifact_type="zap_passive_scan",
    )
    assert vi.artifact_type == ArtifactType.ZAP_PASSIVE


def test_vulnerability_input_full():
    vi = VulnerabilityInput(
        cve_id="CVE-2021-44228",
        poc_text="print('pwned')",
        writeup_text="RCE via JNDI",
        source_path="/tmp/src",
        patch_diff="diff --git a/file b/file\n-old\n+new",
    )
    assert vi.poc_text == "print('pwned')"
    assert vi.source_path == "/tmp/src"


def test_vulnerability_input_without_cve():
    vi = VulnerabilityInput()
    assert vi.cve_id == ""
    assert vi.poc_text == ""
    assert vi.source_path is None


def test_vulnerability_input_source_only():
    vi = VulnerabilityInput(source_path="/tmp/dvwa")
    assert vi.cve_id == ""
    assert vi.source_path == "/tmp/dvwa"


def test_artifact_creation():
    art = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content="class MetasploitModule",
        filename="exploit.rb",
    )
    assert art.artifact_type == ArtifactType.METASPLOIT
    assert art.filename == "exploit.rb"


def test_validation_result():
    vr = ValidationResult(is_valid=True)
    assert vr.is_valid is True
    assert vr.errors == []
    assert vr.warnings == []


def test_workflow_state():
    vi = VulnerabilityInput(cve_id="CVE-2021-44228")
    state = WorkflowState(vuln_input=vi)
    assert state.status == "pending"
    assert state.repair_attempts == 0
    assert state.max_repair_attempts == 3
    assert state.context is None
    assert state.artifact is None
    assert state.failure is None


def test_workflow_error_context():
    failure = WorkflowError(
        code="llm_provider_error",
        message="request failed",
        provider="openai",
        model="gpt-4o",
        retryable=True,
    )
    assert failure.code == "llm_provider_error"
    assert failure.retryable is True


def test_collected_context_defaults():
    ctx = CollectedContext(cve_id="CVE-2021-44228")
    assert ctx.cve_description == ""
    assert ctx.source_files == []
    assert ctx.references == []


def test_tool_schemas_reject_unknown_fields():
    request = ToolRequest(
        objective="Inspect a file",
        allowed_tools=["read_source_files"],
    )
    assert request.allowed_tools == ["read_source_files"]

    with pytest.raises(ValidationError, match="artifact_content"):
        ToolCall.model_validate(
            {
                "name": "read_source_files",
                "arguments": {},
                "artifact_content": "not allowed",
            }
        )
