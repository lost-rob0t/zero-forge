"""Tests for ZeroForge LangGraph LLM failure handling."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from zero_forge.agents.smart_agent import LLMProviderError
from zero_forge.schemas import CollectedContext, VulnerabilityInput, WorkflowState
from zero_forge.tools.validator import ValidatorRuntimeUnavailable
from zero_forge.workflow import build_workflow, generate_artifact_node, run_workflow


def _input() -> VulnerabilityInput:
    return VulnerabilityInput(cve_id="CVE-2021-44228")


def _disable_provider_keys(monkeypatch) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def test_workflow_builds():
    assert build_workflow() is not None


def test_workflow_rejects_malformed_cve_before_context_collection(monkeypatch):
    def collect_context(*_args):
        pytest.fail("context collection must not run")

    monkeypatch.setattr("zero_forge.workflow.ToolAgent.collect_context", collect_context)

    with pytest.raises(ValidationError, match="CVE ID must match"):
        run_workflow({"cve_id": "not-a-cve"})


def test_workflow_fails_without_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr("zero_forge.workflow.require_ruby_runtime", lambda: "ruby")
    _disable_provider_keys(monkeypatch)
    monkeypatch.setenv("ZERO_FORGE_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setattr(
        "zero_forge.workflow.ToolAgent.collect_context",
        lambda _self, vuln_input: CollectedContext(cve_id=vuln_input.cve_id),
    )

    result = run_workflow(_input())

    assert result.status == "failed"
    assert result.output_path is None
    assert result.failure is not None
    assert result.failure.code == "llm_configuration_error"
    assert list(tmp_path.iterdir()) == []


def test_explicit_stub_never_completes_or_saves(tmp_path, monkeypatch):
    monkeypatch.setattr("zero_forge.workflow.require_ruby_runtime", lambda: "ruby")
    _disable_provider_keys(monkeypatch)
    monkeypatch.setenv("ZERO_FORGE_STUB_MODE", "true")
    monkeypatch.setenv("ZERO_FORGE_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setattr(
        "zero_forge.workflow.ToolAgent.collect_context",
        lambda _self, vuln_input: CollectedContext(cve_id=vuln_input.cve_id),
    )

    result = run_workflow(_input())

    assert result.status == "failed"
    assert result.artifact is not None
    assert result.artifact.metadata["stub"] is True
    assert result.output_path is None
    assert result.failure is not None
    assert result.failure.code == "stub_artifact"
    assert list(tmp_path.iterdir()) == []


def test_missing_ruby_fails_before_context_or_generation(monkeypatch):
    message = "Ruby 3.3.8 is required for Metasploit validation but was not found"

    def unavailable():
        raise ValidatorRuntimeUnavailable(message)

    monkeypatch.setattr("zero_forge.workflow.require_ruby_runtime", unavailable)
    monkeypatch.setattr(
        "zero_forge.workflow.ToolAgent.collect_context",
        lambda *_args: pytest.fail("context collection must not run"),
    )
    monkeypatch.setattr(
        "zero_forge.workflow.generate_artifact",
        lambda *_args: pytest.fail("generation must not run"),
    )

    result = run_workflow(_input())

    assert result.status == "failed"
    assert result.error == message
    assert result.failure is not None
    assert result.failure.code == "validator_runtime_unavailable"
    assert result.repair_attempts == 0
    assert result.context is None
    assert result.artifact is None


def test_provider_failure_becomes_structured_workflow_error(monkeypatch):
    failure = LLMProviderError(
        "LLM request failed with TimeoutError",
        provider="openai",
        model="gpt-4o",
        retryable=True,
    )
    monkeypatch.setattr(
        "zero_forge.workflow.generate_artifact",
        lambda *_args: (_ for _ in ()).throw(failure),
    )
    state = WorkflowState(
        vuln_input=_input(),
        context=CollectedContext(cve_id="CVE-2021-44228"),
    )

    patch = generate_artifact_node(state)

    assert patch["status"] == "failed"
    assert patch["failure"].code == "llm_provider_error"
    assert patch["failure"].provider == "openai"
    assert patch["failure"].model == "gpt-4o"
    assert patch["failure"].retryable is True
