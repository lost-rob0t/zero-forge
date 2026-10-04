"""Smart Agent: analyzes vulnerabilities and writes security artifacts using an LLM."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ..config import get_settings
from ..examples import ArtifactExample, load_artifact_examples
from ..logging_config import get_logger
from ..schemas import (
    Artifact,
    ArtifactType,
    CollectedContext,
    ValidationResult,
    VulnerabilityInput,
)
from ..tools.artifact_edit import (
    ArtifactEditError,
    apply_artifact_edits,
    artifact_sha256,
    parse_artifact_edit_plan,
)
from ..tools.poc_context import normalize_poc_context
from .llm import (
    LLMCallError,
    LLMConfigurationError,
    LLMProviderError,
    LLMResponseError,
    call_model,
    call_model_async,
    resolve_model,
)

logger = get_logger(__name__)

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
You are a senior security researcher specializing in vulnerability analysis and
remediation validation. You operate within authorized bug bounty programs and
sanctioned vulnerability research engagements. You produce defensive
proof-of-concept artifacts that demonstrate vulnerability impact for remediation
teams.

AUTHORIZATION CONTEXT:
This work is conducted under legitimate bug bounty program scope or authorized
vulnerability research engagement. All artifacts are generated for remediation
verification and defensive security purposes. You operate under explicit
authorization from the assessed system owner or program operator.

Use only the supplied vulnerability evidence. Identify the actual software, vendor,
CVE, vulnerability type, endpoints, parameters, and affected versions. Never
substitute a generic target. Emit one complete artifact and no prose outside its
code fence.
"""

_REPAIR_SYSTEM_PROMPT = """\
You are ZeroForge's Smart Agent repairing one existing security validation artifact
inside an explicitly authorized engagement. You may only propose exact replacements
against the supplied immutable artifact revision. Do not return a complete artifact,
do not append content, and do not concatenate alternatives.

Return exactly one JSON object with this shape:
{"base_sha256":"<supplied digest>","edits":[
  {"old":"<exact unique existing text>","new":"<replacement text>"}
]}

Every old value must be non-empty, copied exactly from the current artifact, and occur
exactly once. Preserve all unrelated content. Return no prose or code fence.
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
and the primary demonstration method, register required options, validate responses, and include
vulnerability-specific metadata and references.
""",
        contract="""\
- Define class MetasploitModule < Msf::Exploit::Remote.
- Include Name, Description, Author, References, License, Targets, and DefaultTarget.
- Define initialize(info = {}), register target-specific options,
  and define the primary demonstration method.
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
Write a GraalVM JavaScript Active Rule for the ZAP Script Console. An active rule
non-destructively probes a parameter for a vulnerability indicator. The rule checks
for stop conditions, clones the original request, injects a harmless probe value,
sends the probe, inspects the response for vulnerability-specific evidence compared
to the baseline, and raises a fully populated alert when evidence is found.
""",
        contract="""\
- Import ScanRuleMetadata and return ScanRuleMetadata.fromYaml(...) from getMetadata().
- Metadata must include numeric id, name, description, solution, references, category,
  risk, confidence, cweId, wascId, and status.
- Define function scan(as, msg, param, value).
- The scan function follows this lifecycle: check as.isStop(), clone the request,
  inject the probe with as.setParam(), send with as.sendAndReceive(), inspect the
  probe response, and raise an alert with as.newAlert().setParam().setAttack()
  .setEvidence().setMessage().raise().
- Use a harmless, deterministic probe value.
- Output one complete JavaScript rule in a javascript code fence.
""",
    ),
    ArtifactType.ZAP_PASSIVE: ArtifactProfile(
        label="ZAP passive scan detection rule",
        language="javascript",
        fence_aliases=("javascript", "js"),
        filename_suffix="_zap_passive.js",
        system_instructions="""\
Write a GraalVM JavaScript Passive Rule for the ZAP Script Console. A passive rule
inspects an existing HTTP message that has already been captured by ZAP. The rule
examines request or response headers and bodies for vulnerability indicators and
raises an alert with precise evidence when a finding is detected.
""",
        contract="""\
- Import ScanRuleMetadata and return ScanRuleMetadata.fromYaml(...) from getMetadata().
- Metadata must include numeric id, name, description, solution, references, risk,
  confidence, cweId, wascId, and status.
- Define function scan(ps, msg, src).
- Inspect msg request/response headers or bodies already supplied by ZAP.
- Exclude irrelevant content types where appropriate and capture precise evidence.
- Raise with ps.newAlert().setEvidence().setMessage(msg).raise().
- Output one complete JavaScript rule in a javascript code fence.
""",
    ),
}

SYSTEM_PROMPT = _BASE_SYSTEM_PROMPT + _PROFILES[ArtifactType.METASPLOIT].system_instructions


def _profile(artifact_type: ArtifactType) -> ArtifactProfile:
    return _PROFILES[artifact_type]


def _system_prompt(artifact_type: ArtifactType) -> str:
    return _BASE_SYSTEM_PROMPT + _profile(artifact_type).system_instructions


def _repair_system_prompt(artifact_type: ArtifactType) -> str:
    profile = _profile(artifact_type)
    return _REPAIR_SYSTEM_PROMPT + f"\nArtifact language: {profile.language}.\n"


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


def _poc_target_text(ctx: CollectedContext) -> str:
    parts = [ctx.cve_description, ctx.affected_versions, ctx.writeup_text[:4000]]
    for source_file in ctx.source_files[:12]:
        parts.append(source_file.filename)
        parts.append(source_file.content[:4000])
    return "\n".join(part for part in parts if part)


def _build_context_prompt(vuln: VulnerabilityInput, ctx: CollectedContext) -> str:
    profile = _profile(vuln.artifact_type)
    parts: list[str] = [
        f"## Requested Artifact\n{profile.label} ({vuln.artifact_type.value})",
        f"## Artifact Contract\n{profile.contract.strip()}",
    ]
    if ctx.cve_id:
        parts.append(f"## CVE: {ctx.cve_id}")
    else:
        parts.append("## Source-Only Analysis (No CVE Identifier)")
    if ctx.cve_description:
        parts.append(f"### Description\n{ctx.cve_description}")
    if ctx.affected_versions:
        parts.append(f"### Affected Versions\n{ctx.affected_versions}")
    if ctx.references:
        parts.append("### References")
        parts.extend(f"- {ref}" for ref in ctx.references[:10])
    if ctx.poc_text:
        normalized = normalize_poc_context(
            ctx.poc_text,
            requested_cve=ctx.cve_id,
            target_text=_poc_target_text(ctx),
        )
        records = normalized["records"]
        selected = [record for record in records if record["selected"]]
        logger.info(
            "PoC normalization selected %d of %d section(s)",
            len(selected),
            len(records),
        )
        parts.append("### PoC Selection Decisions")
        for record in records:
            state = "selected" if record["selected"] else "excluded"
            parts.append(f"- {record['id']}: {state} — {record['reason']}")
        if normalized["text"]:
            parts.append(f"### Selected Proof of Concept\n```\n{normalized['text']}\n```")
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
                f"**[{label}] File: {source_file.filename}** (language: {source_file.language})"
            )
            parts.append(f"```\n{source_file.content[:budget]}\n```")
    if ctx.extra_notes:
        parts.append(f"### Notes\n{ctx.extra_notes}")
    parts.extend(
        [
            f"## Reference {profile.label} Examples\n{_format_examples(vuln.artifact_type)}",
            (
                f"## Assessment Task\n"
                f"Follow these steps to produce a defensive proof-of-concept {profile.label}:\n\n"
                f"1. Analyze the vulnerability context and identify the assessed\n"
                f"   software, vendor, and vulnerability type.\n"
                f"2. Determine the demonstration strategy and required "
                f"{profile.language} constructs.\n"
                f"3. Outline the artifact structure (metadata, options, demonstration method).\n"
                f"4. Implement the complete {profile.label}.\n"
                f"5. Add non-destructive verification where the evidence supports it.\n\n"
                f"Follow the artifact contract exactly. Output ONLY a single "
                f"```{profile.language} code block containing complete, self-contained "
                f"{profile.label} code. Do not include any explanatory text, prose, "
                f"comments about what changed, or text outside the code block."
            ),
        ]
    )
    return "\n\n".join(parts)


def _build_repair_prompt(
    artifact: Artifact,
    validation: ValidationResult,
    *,
    attempt: int = 0,
    max_attempts: int = 0,
) -> str:
    profile = _profile(artifact.artifact_type)
    base_sha256 = artifact_sha256(artifact.content)
    parts = [
        f"## Artifact Contract\n{profile.contract.strip()}",
        f"## Base SHA-256\n{base_sha256}",
        "## Validation Issues",
        *(f"- {error}" for error in validation.errors),
    ]
    if validation.warnings:
        parts.extend(["## Warnings", *(f"- {warning}" for warning in validation.warnings)])
    parts.extend(
        [
            f"## Reference {profile.label} Examples\n{_format_examples(artifact.artifact_type)}",
            (
                f"## Current Remediation Validation Module\n"
                f"```{profile.language}\n{artifact.content}\n```"
            ),
        ]
    )
    parts.append(
        "## Output Format\n"
        "Output ONLY one strict JSON object containing base_sha256 and edits. "
        "Each edit must contain exact old text copied from the current artifact and "
        "replacement new text. Do not include explanatory text, a code fence, a complete "
        "replacement artifact, or an append operation."
    )
    task_parts = [
        "## Task\nAddress all validation issues by returning the smallest exact-match "
        "edit set needed for the remediation validation module above."
    ]
    if attempt and max_attempts:
        task_parts.append(
            f"This is repair attempt {attempt} of {max_attempts}. "
            f"{max_attempts - attempt + 1} attempt(s) remain after this one."
        )
        if attempt >= 2:
            task_parts.append(
                f"Previous repair attempts did not resolve the same errors. "
                f"Take a different approach: carefully re-read the artifact contract and "
                f"reference examples, ensure no non-{profile.language} text is inserted, "
                f"and choose old spans that occur exactly once."
            )
    parts.append(" ".join(task_parts))
    return "\n\n".join(parts)


def _extract_code_block(
    text: str,
    artifact_type: ArtifactType = ArtifactType.METASPLOIT,
) -> str:
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
            "as, msg, param, value" if artifact_type == ArtifactType.ZAP_ACTIVE else "ps, msg, src"
        )
        content = (
            "function getMetadata() { return null; }\n"
            f"function scan({signature}) {{ {helper}.newAlert; }}"
        )
    return f"```{profile.language}\n{content}\n```"


def _artifact_filename(cve_id: str, artifact_type: ArtifactType) -> str:
    if cve_id:
        stem = cve_id.lower().replace("-", "_")
    else:
        stem = f"poc_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    return f"{stem}{_profile(artifact_type).filename_suffix}"


refusal_phrases = (
    "i cannot",
    "i can't",
    "i am unable",
    "i'm unable",
    "i'm sorry",
    "i apologize",
    "as an ai",
    "as a language model",
    "i'm not able",
    "i will not",
    "i won't",
)


def _is_refusal(text: str) -> bool:
    """Heuristic: detect content-filter refusal in LLM output."""
    lower = text.strip().lower()
    if not lower:
        return True
    if "class " in lower or "def " in lower or "msf::" in lower or "function " in lower:
        return False
    return any(phrase in lower for phrase in refusal_phrases)


def _check_refusal(code: str, phase: str) -> str:
    """Detect content-filter refusal and emit an actionable warning."""
    if not _is_refusal(code):
        return code
    cfg = get_settings()
    resolved = resolve_model("smart", cfg.models.smart)
    msg = (
        f"Content-filter refusal detected during {phase}: "
        f"no code block extracted (provider={resolved.provider}, model={resolved.model})"
    )
    logger.warning(msg)
    print(f"# ZeroForge WARNING: {msg}")
    return f"# ZeroForge WARNING: {msg}\n"


def _finalize_generation(
    raw: str,
    artifact_type: ArtifactType,
    cve_id: str,
) -> Artifact:
    code = _extract_code_block(raw, artifact_type)
    logger.debug("Extracted code block: %d chars", len(code))
    code = _check_refusal(code, "generation")
    cfg = get_settings()
    return Artifact(
        artifact_type=artifact_type,
        content=code,
        filename=_artifact_filename(cve_id, artifact_type),
        metadata={
            "model": cfg.models.smart.model,
            "model_role": "smart",
            "cve_id": cve_id,
            "artifact_type": artifact_type.value,
            "stub": cfg.llm.stub_mode,
        },
    )


def _repair_plan(raw: str, artifact: Artifact) -> dict[str, Any] | None:
    if _is_refusal(raw):
        _check_refusal(raw, "repair")
        return None
    try:
        return parse_artifact_edit_plan(raw)
    except ArtifactEditError:
        code = _extract_code_block(raw, artifact.artifact_type)
        if not code.strip():
            logger.warning("Repair produced empty output; returning original artifact")
            return None
        logger.warning("Repair returned a legacy full artifact; converting it to one guarded edit")
        return {
            "base_sha256": artifact_sha256(artifact.content),
            "edits": [{"old": artifact.content, "new": code}],
        }


def _finalize_repair(raw: str, artifact: Artifact) -> Artifact:
    plan = _repair_plan(raw, artifact)
    if plan is None:
        return artifact
    try:
        result = apply_artifact_edits(
            artifact.content,
            str(plan["base_sha256"]),
            list(plan["edits"]),
            artifact_type=artifact.artifact_type.value,
        )
    except ArtifactEditError as exc:
        cfg = get_settings()
        resolved = resolve_model("smart", cfg.models.smart)
        raise LLMResponseError(
            f"Smart Agent returned an invalid artifact edit plan: {exc}",
            provider=resolved.provider,
            model=resolved.model,
            retryable=False,
        ) from exc

    cfg = get_settings()
    new_metadata = {
        **artifact.metadata,
        "repaired": True,
        "repair_base_sha256": result["base_sha256"],
        "repair_sha256": result["sha256"],
        "repair_diff": result["diff"],
        "repair_edits": result["applied_edits"],
    }
    if cfg.llm.stub_mode:
        new_metadata["stub"] = True
    return Artifact(
        artifact_type=artifact.artifact_type,
        content=str(result["content"]),
        filename=artifact.filename,
        metadata=new_metadata,
    )


def generate_artifact(vuln_input: VulnerabilityInput, context: CollectedContext) -> Artifact:
    artifact_type = vuln_input.artifact_type
    logger.info("Generating artifact for CVE %s", context.cve_id)
    logger.debug("Building context prompt for CVE %s", context.cve_id)
    prompt = _build_context_prompt(vuln_input, context)
    raw = _call_llm(_system_prompt(artifact_type), prompt, artifact_type)
    return _finalize_generation(raw, artifact_type, context.cve_id)


def repair_artifact(
    artifact: Artifact,
    validation: ValidationResult,
    context: CollectedContext,
    *,
    attempt: int = 0,
    max_attempts: int = 0,
) -> Artifact:
    del context
    logger.info(
        "Repairing artifact (%d validation errors, attempt %d/%d)",
        len(validation.errors),
        attempt,
        max_attempts,
    )
    prompt = _build_repair_prompt(
        artifact,
        validation,
        attempt=attempt,
        max_attempts=max_attempts,
    )
    raw = _call_llm(
        _repair_system_prompt(artifact.artifact_type),
        prompt,
        artifact.artifact_type,
    )
    return _finalize_repair(raw, artifact)


async def generate_artifact_async(
    vuln_input: VulnerabilityInput,
    context: CollectedContext,
    *,
    on_chunk: Callable[[str], None] | None = None,
) -> Artifact:
    artifact_type = vuln_input.artifact_type
    logger.info("Generating artifact (async) for CVE %s", context.cve_id)
    prompt = _build_context_prompt(vuln_input, context)
    cfg = get_settings()
    if cfg.llm.stub_mode:
        raw = _stub_artifact(artifact_type)
    else:
        raw = await call_model_async(
            "smart",
            cfg.models.smart,
            _system_prompt(artifact_type),
            prompt,
            on_chunk=on_chunk,
        )
    return _finalize_generation(raw, artifact_type, context.cve_id)


async def repair_artifact_async(
    artifact: Artifact,
    validation: ValidationResult,
    context: CollectedContext,
    *,
    attempt: int = 0,
    max_attempts: int = 0,
    on_chunk: Callable[[str], None] | None = None,
) -> Artifact:
    del context
    logger.info(
        "Repairing artifact (async) (%d validation errors, attempt %d/%d)",
        len(validation.errors),
        attempt,
        max_attempts,
    )
    prompt = _build_repair_prompt(
        artifact,
        validation,
        attempt=attempt,
        max_attempts=max_attempts,
    )
    cfg = get_settings()
    if cfg.llm.stub_mode:
        raw = _stub_artifact(artifact.artifact_type)
    else:
        raw = await call_model_async(
            "smart",
            cfg.models.smart,
            _repair_system_prompt(artifact.artifact_type),
            prompt,
            on_chunk=on_chunk,
        )
    return _finalize_repair(raw, artifact)
