"""Smart Agent: analyzes vulnerabilities and writes security artifacts using an LLM."""

from __future__ import annotations

from dataclasses import dataclass

from ..config import get_settings
from ..examples import ArtifactExample, load_artifact_examples
from ..schemas import (
    Artifact,
    ArtifactType,
    CollectedContext,
    ValidationResult,
    VulnerabilityInput,
)
from .llm import (
    LLMCallError,
    LLMConfigurationError,
    LLMProviderError,
    LLMResponseError,
    call_model,
    resolve_model,
)

__all__ = [
    "LLMCallError",
    "LLMConfigurationError",
    "LLMProviderError",
    "LLMResponseError",
]


@dataclass(frozen=True, slots=True)
class ArtifactProfile:
    """Prompt and output contract for one artifact type."""

    label: str
    language: str
    fence_aliases: tuple[str, ...]
    filename_suffix: str
    system_instructions: str
    contract: str


_BASE_SYSTEM_PROMPT = """\
You are a security research expert producing security artifacts for authorized testing.
Use only the supplied vulnerability evidence. Identify the actual software, vendor, CVE,
vulnerability type, endpoints, parameters, and affected versions. Never substitute a
generic target. Emit one complete artifact and no prose outside its code fence.
"""

_PROFILES = {
    ArtifactType.METASPLOIT: ArtifactProfile(
        label="Metasploit exploit module",
        language="ruby",
        fence_aliases=("ruby", "rb"),
        filename_suffix="_exploit.rb",
        system_instructions="""\
Write Ruby compatible with current Metasploit Framework conventions. The module must
be a class named MetasploitModule under Msf::Exploit::Remote, include real initialize
and exploit methods, register required options, validate responses, and include
vulnerability-specific metadata and references.
""",
        contract="""\
- Define class MetasploitModule < Msf::Exploit::Remote.
- Include Name, Description, Author, References, License, Targets, and DefaultTarget.
- Define initialize(info = {}), register target-specific options, and define exploit.
- Use the correct remote mixins, payload pattern, endpoint, parameters, and protocol.
- Check every network response and fail with an appropriate Failure reason.
- Add a non-destructive check method when the evidence supports one.
- Output one complete Ruby module in a ruby code fence.
""",
    ),
    ArtifactType.ZAP_ACTIVE: ArtifactProfile(
        label="ZAP active scan detection rule",
        language="javascript",
        fence_aliases=("javascript", "js"),
        filename_suffix="_zap_active.js",
        system_instructions="""\
Write a GraalVM JavaScript Active Rule for the ZAP Script Console. Use non-destructive
detection probes. The script must mutate only a cloned request, send the probe through
the active helper, compare response evidence, and raise a fully populated alert.
""",
        contract="""\
- Import ScanRuleMetadata and return ScanRuleMetadata.fromYaml(...) from getMetadata().
- Metadata must include numeric id, name, description, solution, references, category,
  risk, confidence, cweId, wascId, and status.
- Define function scan(as, msg, param, value).
- Clone msg before mutation, call as.setParam(), then as.sendAndReceive().
- Inspect the probe response for vulnerability-specific evidence.
- Raise with as.newAlert().setParam().setAttack().setEvidence().setMessage().raise().
- Use a harmless, deterministic probe and stop promptly when as.isStop() is true.
- Output one complete JavaScript rule in a javascript code fence.
""",
    ),
    ArtifactType.ZAP_PASSIVE: ArtifactProfile(
        label="ZAP passive scan detection rule",
        language="javascript",
        fence_aliases=("javascript", "js"),
        filename_suffix="_zap_passive.js",
        system_instructions="""\
Write a GraalVM JavaScript Passive Rule for the ZAP Script Console. Passive rules
inspect an existing HTTP message only. They must never send a request, alter a request,
or perform any other network operation.
""",
        contract="""\
- Import ScanRuleMetadata and return ScanRuleMetadata.fromYaml(...) from getMetadata().
- Metadata must include numeric id, name, description, solution, references, risk,
  confidence, cweId, wascId, and status.
- Define function scan(ps, msg, src).
- Inspect only msg request/response headers or bodies already supplied by ZAP.
- Exclude irrelevant content types where appropriate and capture precise evidence.
- Raise with ps.newAlert().setEvidence().setMessage(msg).raise().
- Never call sendAndReceive, setParam, fetch, HttpSender, or any network API.
- Output one complete JavaScript rule in a javascript code fence.
""",
    ),
}

SYSTEM_PROMPT = _BASE_SYSTEM_PROMPT + _PROFILES[ArtifactType.METASPLOIT].system_instructions


def _profile(artifact_type: ArtifactType) -> ArtifactProfile:
    return _PROFILES[artifact_type]


def _system_prompt(artifact_type: ArtifactType) -> str:
    return _BASE_SYSTEM_PROMPT + _profile(artifact_type).system_instructions


def _format_examples(artifact_type: ArtifactType) -> str:
    examples = load_artifact_examples(artifact_type)
    if not examples:
        return "No local reference examples are available; follow the contract exactly."

    profile = _profile(artifact_type)
    parts = [
        "Use these as structural references only. Adapt every target-specific detail "
        "to the supplied vulnerability context."
    ]
    for example in examples:
        parts.append(f"### {example.name}")
        parts.append(f"```{profile.language}\n{example.content}\n```")
    return "\n\n".join(parts)


def _build_context_prompt(vuln: VulnerabilityInput, ctx: CollectedContext) -> str:
    profile = _profile(vuln.artifact_type)
    parts: list[str] = [
        f"## Requested Artifact\n{profile.label} ({vuln.artifact_type.value})",
        f"## Artifact Contract\n{profile.contract.strip()}",
        f"## CVE: {ctx.cve_id}",
    ]
    if ctx.cve_description:
        parts.append(f"### Description\n{ctx.cve_description}")
    if ctx.affected_versions:
        parts.append(f"### Affected Versions\n{ctx.affected_versions}")
    if ctx.references:
        parts.append("### References")
        parts.extend(f"- {ref}" for ref in ctx.references[:10])
    if ctx.poc_text:
        parts.append(f"### Proof of Concept\n```\n{ctx.poc_text[:4000]}\n```")
    if ctx.writeup_text:
        parts.append(f"### Write-up\n{ctx.writeup_text[:4000]}")
    if ctx.patch_diff:
        parts.append(f"### Patch / Diff\n```diff\n{ctx.patch_diff[:4000]}\n```")
    if ctx.source_files:
        parts.append("### Relevant Files from Source")
        for source_file in ctx.source_files[:8]:
            budget = 6000 if source_file.category == "documentation" else 4000
            label = source_file.category.upper() if source_file.category != "code" else "CODE"
            parts.append(
                f"**[{label}] File: {source_file.filename}** "
                f"(language: {source_file.language})"
            )
            parts.append(f"```\n{source_file.content[:budget]}\n```")
    if ctx.extra_notes:
        parts.append(f"### Notes\n{ctx.extra_notes}")
    parts.extend(
        [
            f"## Reference {profile.label} Examples\n{_format_examples(vuln.artifact_type)}",
            (
                f"## Task\nWrite one complete, target-specific {profile.label}. "
                f"Follow the artifact contract exactly. Output only a single "
                f"```{profile.language} code block."
            ),
        ]
    )
    return "\n\n".join(parts)


def _build_repair_prompt(artifact: Artifact, validation: ValidationResult) -> str:
    profile = _profile(artifact.artifact_type)
    parts = [
        f"## Artifact Contract\n{profile.contract.strip()}",
        "## Validation Errors",
        *(f"- {error}" for error in validation.errors),
    ]
    if validation.warnings:
        parts.extend(["## Warnings", *(f"- {warning}" for warning in validation.warnings)])
    parts.extend(
        [
            f"## Reference {profile.label} Examples\n{_format_examples(artifact.artifact_type)}",
            f"## Current Artifact\n```{profile.language}\n{artifact.content}\n```",
            (
                f"## Task\nFix every validation error without changing the artifact type. "
                f"Return the complete corrected artifact in one "
                f"```{profile.language} code block."
            ),
        ]
    )
    return "\n\n".join(parts)


def _extract_code_block(text: str, artifact_type: ArtifactType = ArtifactType.METASPLOIT) -> str:
    profile = _profile(artifact_type)
    fences = [f"```{alias}" for alias in profile.fence_aliases]
    fences.append("```")
    for fence in fences:
        if fence not in text:
            continue
        remaining = text[text.index(fence) + len(fence) :]
        if "```" in remaining:
            return remaining[: remaining.index("```")].strip()
        return remaining.strip()
    return text.strip()


def _resolve_provider() -> tuple[str | None, str, dict[str, str]]:
    cfg = get_settings()
    resolved = resolve_model("smart", cfg.models.smart)
    return resolved.api_key, resolved.model, resolved.extra_kwargs


def _provider_name() -> str:
    cfg = get_settings()
    return resolve_model("smart", cfg.models.smart).provider


def _call_llm(
    system_prompt: str,
    user_prompt: str,
    artifact_type: ArtifactType = ArtifactType.METASPLOIT,
) -> str:
    cfg = get_settings()
    if cfg.llm.stub_mode:
        return _stub_artifact(artifact_type)
    return call_model("smart", cfg.models.smart, system_prompt, user_prompt)


def _stub_artifact(artifact_type: ArtifactType) -> str:
    profile = _profile(artifact_type)
    examples: list[ArtifactExample] = load_artifact_examples(artifact_type, max_examples=1)
    if examples:
        return f"```{profile.language}\n{examples[0].content}\n```"
    if artifact_type == ArtifactType.METASPLOIT:
        content = """class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'ZeroForge Stub',
      'Description' => 'Explicit placeholder mode',
      'Author' => ['ZeroForge'],
      'References' => [],
      'License' => MSF_LICENSE
    ))
  end

  def exploit
    fail_with(Failure::BadConfig, 'Stub mode cannot exploit a target')
  end
end"""
    else:
        helper = "as" if artifact_type == ArtifactType.ZAP_ACTIVE else "ps"
        signature = (
            "as, msg, param, value"
            if artifact_type == ArtifactType.ZAP_ACTIVE
            else "ps, msg, src"
        )
        content = (
            "function getMetadata() { return null; }\n"
            f"function scan({signature}) {{ {helper}.newAlert; }}"
        )
    return f"```{profile.language}\n{content}\n```"


def _artifact_filename(cve_id: str, artifact_type: ArtifactType) -> str:
    stem = cve_id.lower().replace("-", "_")
    return f"{stem}{_profile(artifact_type).filename_suffix}"


def generate_artifact(vuln_input: VulnerabilityInput, context: CollectedContext) -> Artifact:
    artifact_type = vuln_input.artifact_type
    prompt = _build_context_prompt(vuln_input, context)
    raw = _call_llm(_system_prompt(artifact_type), prompt, artifact_type)
    code = _extract_code_block(raw, artifact_type)
    cfg = get_settings()
    return Artifact(
        artifact_type=artifact_type,
        content=code,
        filename=_artifact_filename(context.cve_id, artifact_type),
        metadata={
            "model": cfg.models.smart.model,
            "model_role": "smart",
            "cve_id": context.cve_id,
            "artifact_type": artifact_type.value,
            "stub": cfg.llm.stub_mode,
        },
    )


def repair_artifact(
    artifact: Artifact, validation: ValidationResult, context: CollectedContext
) -> Artifact:
    prompt = _build_repair_prompt(artifact, validation)
    raw = _call_llm(_system_prompt(artifact.artifact_type), prompt, artifact.artifact_type)
    code = _extract_code_block(raw, artifact.artifact_type)
    if not code.strip():
        return artifact
    return Artifact(
        artifact_type=artifact.artifact_type,
        content=code,
        filename=artifact.filename,
        metadata={**artifact.metadata, "repaired": True},
    )
