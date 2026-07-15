"""Smart Agent: analyzes vulnerability and writes security artifacts using LLM."""

from __future__ import annotations

from ..config import get_settings
from ..logging_config import get_logger
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

logger = get_logger(__name__)

__all__ = [
    "LLMCallError",
    "LLMConfigurationError",
    "LLMProviderError",
    "LLMResponseError",
]

SYSTEM_PROMPT = """\
You are a security research expert specializing in exploit development.
You analyze vulnerabilities and generate security artifacts for authorized testing.
You write clean, functional Metasploit exploit modules following Metasploit Framework conventions.

CRITICAL: You MUST identify the specific target software, vendor,
and vulnerability type from the provided context.
- Name the actual software (e.g., "Adobe ColdFusion", "Apache Log4j", "WordPress Plugin X")
- Reference the actual CVE ID provided in the context
- Describe the actual vulnerability type (e.g., path traversal, RCE, SQL injection, SSRF)
- Target the actual endpoints, parameters, and file paths mentioned in the PoC or write-up
- Never generate a generic module — always be specific to the target software

When writing a Metasploit module:
- Use the class-based module format (class MetasploitModule < Msf::Exploit)
- Include all required metadata: Name, Description, Author, References, License
- Define initialize() and exploit() methods
- Include register_options() for configurable parameters
- Use Rex::Text and Metasploit::Payload patterns
- Add comments explaining the vulnerability and exploitation strategy
- Write Ruby code compatible with Metasploit Framework

Always output the complete module code in a single code block.
"""


def _build_context_prompt(vuln: VulnerabilityInput, ctx: CollectedContext) -> str:
    parts: list[str] = []
    parts.append(f"## CVE: {ctx.cve_id}")
    if ctx.cve_description:
        parts.append(f"### Description\n{ctx.cve_description}")
    if ctx.affected_versions:
        parts.append(f"### Affected Versions\n{ctx.affected_versions}")
    if ctx.references:
        parts.append("### References")
        for ref in ctx.references[:10]:
            parts.append(f"- {ref}")
    if ctx.poc_text:
        parts.append(f"### Proof of Concept\n```\n{ctx.poc_text[:4000]}\n```")
    if ctx.writeup_text:
        parts.append(f"### Write-up\n{ctx.writeup_text[:4000]}")
    if ctx.patch_diff:
        parts.append(f"### Patch / Diff\n```diff\n{ctx.patch_diff[:4000]}\n```")
    if ctx.source_files:
        parts.append("### Relevant Files from Source")
        for sf in ctx.source_files[:8]:
            budget = 6000 if sf.category == "documentation" else 4000
            label = sf.category.upper() if sf.category != "code" else "CODE"
            parts.append(f"**[{label}] File: {sf.filename}** (language: {sf.language})")
            parts.append(f"```\n{sf.content[:budget]}\n```")
    if ctx.extra_notes:
        parts.append(f"### Notes\n{ctx.extra_notes}")
    parts.append("""
## Task
Based on the vulnerability context above, write a complete Metasploit exploit module.
Follow Metasploit Framework conventions strictly.
Output only the Ruby module code in a single ```ruby code block.
""")
    return "\n\n".join(parts)


def _build_repair_prompt(artifact: Artifact, validation: ValidationResult) -> str:
    parts: list[str] = []
    parts.append("## Validation Errors")
    for err in validation.errors:
        parts.append(f"- {err}")
    if validation.warnings:
        parts.append("\n## Warnings")
        for warn in validation.warnings:
            parts.append(f"- {warn}")
    parts.append("\n## Current Module")
    parts.append(f"```ruby\n{artifact.content}\n```")
    parts.append("""
## Task
Fix all validation errors in the Metasploit module above.
Output the complete corrected module in a single ```ruby code block.
""")
    return "\n\n".join(parts)


def _extract_code_block(text: str) -> str:
    for fence in ("```ruby", "```rb", "```"):
        if fence in text:
            start = text.index(fence) + len(fence)
            remaining = text[start:]
            if "```" in remaining:
                end = remaining.index("```")
                return remaining[:end].strip()
            return remaining.strip()
    return text.strip()


def _resolve_provider() -> tuple[str | None, str, dict[str, str]]:
    cfg = get_settings()
    resolved = resolve_model("smart", cfg.models.smart)
    return resolved.api_key, resolved.model, resolved.extra_kwargs


def _provider_name() -> str:
    cfg = get_settings()
    return resolve_model("smart", cfg.models.smart).provider


def _call_llm(system_prompt: str, user_prompt: str) -> str:
    cfg = get_settings()
    if cfg.llm.stub_mode:
        return _stub_metasploit_module()
    return call_model("smart", cfg.models.smart, system_prompt, user_prompt)


def _stub_metasploit_module() -> str:
    return """```ruby
#
# Metasploit module generated by ZeroForge (stub mode)
#

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'ZeroForge Generated Exploit',
      'Description' => %q{
        This module was generated by ZeroForge for authorized security testing.
        Replace this description with vulnerability-specific details.
      },
      'Author' => ['ZeroForge'],
      'References' => [
        ['CVE', ''],
      ],
      'License' => MSF_LICENSE,
      'Platform' => ['unix', 'linux'],
      'Arch' => [ARCH_X86, ARCH_X64],
      'Targets' => [
        ['Automatic', {}]
      ],
      'DefaultTarget' => 0,
      'DefaultOptions' => {
        'RPORT' => 8080
      }
    ))

    register_options([
      Opt::RPORT(8080),
      OptString.new('TARGETURI', [true, 'Base path', '/'])
    ])
  end

  def exploit
    # TODO: implement exploitation logic
    connect
    sock.puts("exploit payload\n")
    disconnect
  end

  def check
    # TODO: implement check logic
    CheckCode::Detected
  end
end
```"""


def generate_artifact(vuln_input: VulnerabilityInput, context: CollectedContext) -> Artifact:
    logger.info("Generating artifact for CVE %s", context.cve_id)
    logger.debug("Building context prompt for CVE %s", context.cve_id)
    prompt = _build_context_prompt(vuln_input, context)
    raw = _call_llm(SYSTEM_PROMPT, prompt)
    code = _extract_code_block(raw)
    logger.debug("Extracted code block: %d chars", len(code))
    cfg = get_settings()
    return Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content=code,
        filename=f"{context.cve_id.lower().replace('-', '_')}_exploit.rb",
        metadata={
            "model": cfg.models.smart.model,
            "model_role": "smart",
            "cve_id": context.cve_id,
            "stub": cfg.llm.stub_mode,
        },
    )


def repair_artifact(
    artifact: Artifact, validation: ValidationResult, context: CollectedContext
) -> Artifact:
    logger.info(
        "Repairing artifact (%d validation errors)",
        len(validation.errors),
    )
    prompt = _build_repair_prompt(artifact, validation)
    raw = _call_llm(SYSTEM_PROMPT, prompt)
    code = _extract_code_block(raw)
    if not code.strip():
        logger.warning("Repair produced empty code block; returning original artifact")
        return artifact
    return Artifact(
        artifact_type=artifact.artifact_type,
        content=code,
        filename=artifact.filename,
        metadata={**artifact.metadata, "repaired": True},
    )
