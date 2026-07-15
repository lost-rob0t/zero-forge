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
    _build_context_prompt,
    _build_repair_prompt,
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


def test_extract_javascript_code_block():
    text = "before\n```javascript\nfunction scan() {}\n```\nafter"
    result = _extract_code_block(text, ArtifactType.ZAP_ACTIVE)
    assert result == "function scan() {}"


def test_active_prompt_includes_only_active_examples():
    prompt = _build_context_prompt(
        VulnerabilityInput(
            cve_id="CVE-2021-44228",
            artifact_type=ArtifactType.ZAP_ACTIVE,
        ),
        _context(),
    )

    assert "function scan(as, msg, param, value)" in prompt
    assert "as.sendAndReceive" in prompt
    assert "MetasploitModule" not in prompt
    assert "function scan(ps, msg, src)" not in prompt


def test_passive_repair_prompt_reinforces_no_network_rule():
    artifact = Artifact(
        artifact_type=ArtifactType.ZAP_PASSIVE,
        content="function scan(ps, msg, src) {}",
        filename="passive.js",
    )
    validation = ValidationResult(
        is_valid=False,
        errors=["Passive rules must not send requests"],
    )

    prompt = _build_repair_prompt(artifact, validation)

    assert "Never call sendAndReceive" in prompt
    assert "function scan(ps, msg, src)" in prompt
    assert "Passive rules must not send requests" in prompt


def test_missing_credentials_fail_closed(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    with pytest.raises(LLMConfigurationError) as caught:
        _call_llm("system", "user")

    assert caught.value.code == "llm_configuration_error"
    assert caught.value.provider == "none"
    assert caught.value.retryable is False


def test_system_prompt_contains_authorization_framing():
    """SYSTEM_PROMPT must include authorization and defensive terminology (issue #74)."""
    from zero_forge.agents.smart_agent import SYSTEM_PROMPT

    assert "authorized" in SYSTEM_PROMPT.lower()
    assert "bug bounty" in SYSTEM_PROMPT.lower()
    assert "remediation" in SYSTEM_PROMPT.lower()
    assert "proof-of-concept" in SYSTEM_PROMPT.lower()


def test_system_prompt_avoids_exploit_as_noun():
    """SYSTEM_PROMPT must not use 'exploit' as a noun/descriptor (issue #74).

    Metasploit Framework API names (Msf::Exploit, exploit()) are allowed.
    """
    from zero_forge.agents.smart_agent import SYSTEM_PROMPT

    lines = SYSTEM_PROMPT.strip().splitlines()
    for line in lines:
        lower = line.lower().strip()
        # Allow framework API references
        if "msf::exploit" in lower:
            continue
        if "exploit()" in lower:
            continue
        # Flag standalone 'exploit' used as a noun
        assert "exploit" not in lower, f"'exploit' used as noun in prompt line: {line}"


def test_build_context_prompt_has_multi_step_chain():
    """Context prompt must decompose generation into multi-step reasoning (issue #74)."""
    from zero_forge.agents.smart_agent import _build_context_prompt

    ctx = CollectedContext(cve_id="CVE-2021-44228", cve_description="Log4Shell")
    prompt = _build_context_prompt(VulnerabilityInput(cve_id="CVE-2021-44228"), ctx)
    assert "## Assessment Task" in prompt
    assert "1." in prompt
    assert "2." in prompt
    assert "3." in prompt
    assert "4." in prompt
    assert "5." in prompt
    assert "defensive proof-of-concept" in prompt.lower()


def test_build_repair_prompt_uses_reframed_language():
    """Repair prompt must use reframed terminology, not bare 'fix the exploit' (issue #74)."""
    from zero_forge.agents.smart_agent import _build_repair_prompt

    artifact = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content="class MetasploitModule\nend",
        filename="test.rb",
    )
    validation = ValidationResult(
        is_valid=False,
        errors=["Missing required method: 'exploit'"],
    )
    prompt = _build_repair_prompt(artifact, validation)
    assert "remediation validation module" in prompt.lower()
    assert "validation issues" in prompt.lower()
    assert "fix the exploit" not in prompt.lower()


def test_build_repair_prompt_includes_format_reminder():
    """Repair prompt must include a format-only-code reminder (issue #72)."""
    from zero_forge.agents.smart_agent import _build_repair_prompt

    artifact = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content="class MetasploitModule\nend",
        filename="test.rb",
    )
    validation = ValidationResult(is_valid=False, errors=["syntax error"])
    prompt = _build_repair_prompt(artifact, validation)
    assert "## Output Format" in prompt
    assert "only" in prompt.lower()
    assert "explanatory text" in prompt.lower()


def test_build_repair_prompt_includes_attempt_tracking():
    """Repair prompt must include attempt number and remaining count (issue #72)."""
    from zero_forge.agents.smart_agent import _build_repair_prompt

    artifact = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content="class MetasploitModule\nend",
        filename="test.rb",
    )
    validation = ValidationResult(is_valid=False, errors=["syntax error"])
    prompt = _build_repair_prompt(
        artifact, validation, attempt=1, max_attempts=3
    )
    assert "repair attempt 1 of 3" in prompt.lower()
    assert "3 attempt(s) remain" in prompt.lower()


def test_build_repair_prompt_includes_recurring_error_guidance():
    """On attempt 2+, repair prompt must include recurring-error strategy guidance (issue #72)."""
    from zero_forge.agents.smart_agent import _build_repair_prompt

    artifact = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content="class MetasploitModule\nend",
        filename="test.rb",
    )
    validation = ValidationResult(is_valid=False, errors=["syntax error"])
    prompt = _build_repair_prompt(
        artifact, validation, attempt=2, max_attempts=3
    )
    assert "different approach" in prompt.lower()
    assert "non-ruby text" in prompt.lower()


def test_build_repair_prompt_omits_attempt_info_when_default():
    """Repair prompt should not include attempt tracking when defaults are used (backward compat)."""
    from zero_forge.agents.smart_agent import _build_repair_prompt

    artifact = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content="class MetasploitModule\nend",
        filename="test.rb",
    )
    validation = ValidationResult(is_valid=False, errors=["syntax error"])
    prompt = _build_repair_prompt(artifact, validation)
    assert "repair attempt" not in prompt.lower()
    assert "different approach" not in prompt.lower()


def test_generate_artifact_logs_refusal_on_empty_code(monkeypatch, capsys):
    """Empty code extraction triggers refusal warning, not silent stub (issue #74)."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    _install_litellm(monkeypatch, lambda **_kw: SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="I cannot help with that."))]
    ))

    artifact = generate_artifact(
        VulnerabilityInput(cve_id="CVE-2021-44228"),
        _context(),
    )

    assert "ZeroForge WARNING" in artifact.content
    assert "refusal" in artifact.content.lower()
    captured = capsys.readouterr()
    assert "ZeroForge WARNING" in captured.out


def test_repair_artifact_logs_refusal_on_empty_code(monkeypatch, capsys):
    """Empty repair code triggers refusal warning and returns original artifact (issue #74)."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    _install_litellm(monkeypatch, lambda **_kw: SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="I cannot help with that."))]
    ))

    original = Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content="class MetasploitModule\nend",
        filename="test.rb",
    )
    validation = ValidationResult(is_valid=False, errors=["Missing method"])

    repaired = repair_artifact(original, validation, _context())

    assert repaired is original
    captured = capsys.readouterr()
    assert "ZeroForge WARNING" in captured.out
    assert "repair" in captured.out.lower()


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


@pytest.mark.parametrize(
    ("artifact_type", "suffix", "signature"),
    [
        (ArtifactType.ZAP_ACTIVE, "_zap_active.js", "function scan(as, msg, param, value)"),
        (ArtifactType.ZAP_PASSIVE, "_zap_passive.js", "function scan(ps, msg, src)"),
    ],
)
def test_stub_generation_preserves_zap_artifact_type(
    monkeypatch, artifact_type, suffix, signature
):
    monkeypatch.setenv("ZERO_FORGE_STUB_MODE", "true")

    artifact = generate_artifact(
        VulnerabilityInput(
            cve_id="CVE-2021-44228",
            artifact_type=artifact_type,
        ),
        _context(),
    )

    assert artifact.artifact_type == artifact_type
    assert artifact.filename.endswith(suffix)
    assert signature in artifact.content


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


def test_build_context_prompt_omits_cve_when_empty():
    """When cve_id is empty, the prompt uses a source-only header (issue #68)."""
    from zero_forge.agents.smart_agent import _build_context_prompt

    ctx = CollectedContext(cve_id="", poc_text="print('pwned')")
    prompt = _build_context_prompt(VulnerabilityInput(cve_id=""), ctx)
    assert "## Source-Only Analysis" in prompt
    assert "## CVE:" not in prompt
    assert "print('pwned')" in prompt


def test_build_context_prompt_includes_cve_when_present():
    """When cve_id is present, the prompt includes the CVE header (issue #68)."""
    from zero_forge.agents.smart_agent import _build_context_prompt

    ctx = CollectedContext(cve_id="CVE-2021-44228", cve_description="Log4Shell")
    prompt = _build_context_prompt(VulnerabilityInput(cve_id="CVE-2021-44228"), ctx)
    assert "## CVE: CVE-2021-44228" in prompt
    assert "## Source-Only Analysis" not in prompt


def test_generate_artifact_uses_timestamp_filename_when_no_cve(monkeypatch):
    """When cve_id is empty, the artifact filename uses a timestamp (issue #68)."""
    monkeypatch.setenv("ZERO_FORGE_STUB_MODE", "true")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    ctx = CollectedContext(cve_id="")
    artifact = generate_artifact(VulnerabilityInput(cve_id=""), ctx)

    assert artifact.filename.startswith("poc_")
    assert artifact.filename.endswith(".rb")
    assert "CVE" not in artifact.filename
    assert artifact.metadata["cve_id"] == ""


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
