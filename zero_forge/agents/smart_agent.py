"""Smart Agent: analyzes vulnerability and writes security artifacts using LLM."""

from __future__ import annotations

from ..config import get_settings
from ..schemas import (
    Artifact,
    ArtifactType,
    CollectedContext,
    ValidationResult,
    VulnerabilityInput,
)

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
    """Resolve which LLM provider to use and return (api_key, model, extra_kwargs).

    Provider priority: OPENROUTER > OPENAI > ANTHROPIC > stub.
    """
    cfg = get_settings()
    or_key = cfg.openrouter_api_key
    openai_key = cfg.openai_api_key
    anthropic_key = cfg.anthropic_api_key
    model = cfg.llm.model
    extra_kwargs: dict[str, str] = {}

    if or_key:
        # Ensure model has openrouter/ prefix for LiteLLM routing
        if not model.startswith("openrouter/"):
            model = f"openrouter/{model}"
        # Optional custom base URL (e.g. self-hosted OpenRouter-compatible endpoint)
        if cfg.llm.openrouter_base_url:
            extra_kwargs["api_base"] = cfg.llm.openrouter_base_url
        return or_key, model, extra_kwargs

    if openai_key:
        return openai_key, model, extra_kwargs

    if anthropic_key:
        if not model.startswith("anthropic/"):
            model = f"anthropic/{model}"
        return anthropic_key, model, extra_kwargs

    return None, model, extra_kwargs


def _call_llm(system_prompt: str, user_prompt: str) -> str:
    api_key, model, extra_kwargs = _resolve_provider()
    if not api_key:
        return _stub_metasploit_module()
    try:
        import litellm
        cfg = get_settings()
        response = litellm.completion(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=cfg.llm.temperature,
            max_tokens=cfg.llm.max_tokens,
            **extra_kwargs,
        )
        return response.choices[0].message.content or ""
    except Exception:
        return _stub_metasploit_module()


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
    prompt = _build_context_prompt(vuln_input, context)
    raw = _call_llm(SYSTEM_PROMPT, prompt)
    code = _extract_code_block(raw)
    return Artifact(
        artifact_type=ArtifactType.METASPLOIT,
        content=code,
        filename=f"{context.cve_id.lower().replace('-', '_')}_exploit.rb",
        metadata={"model": get_settings().llm.model, "cve_id": context.cve_id},
    )


def repair_artifact(
    artifact: Artifact, validation: ValidationResult, context: CollectedContext
) -> Artifact:
    prompt = _build_repair_prompt(artifact, validation)
    raw = _call_llm(SYSTEM_PROMPT, prompt)
    code = _extract_code_block(raw)
    if not code.strip():
        return artifact
    return Artifact(
        artifact_type=artifact.artifact_type,
        content=code,
        filename=artifact.filename,
        metadata={**artifact.metadata, "repaired": True},
    )
