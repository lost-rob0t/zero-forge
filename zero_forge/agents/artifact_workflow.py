"""Generation wrapper with PoC selection and edit-only artifact repair."""

from __future__ import annotations

import json
import re
from typing import Any

from ..logging_config import get_logger
from ..schemas import (
    Artifact,
    ArtifactType,
    CollectedContext,
    ToolRequest,
    ValidationResult,
    VulnerabilityInput,
)
from ..tools.artifact_edit import (
    ArtifactEditError,
    artifact_sha256,
    parse_artifact_edit_plan,
)
from ..tools.poc_context import normalize_poc_context
from . import smart_agent as legacy
from .tool_agent import ToolAgent

logger = get_logger(__name__)

LLMCallError = legacy.LLMCallError
LLMConfigurationError = legacy.LLMConfigurationError
LLMProviderError = legacy.LLMProviderError
LLMResponseError = legacy.LLMResponseError

_EDIT_SYSTEM_PROMPT = """\
You are ZeroForge's Smart artifact repair agent operating in an authorized
vulnerability-research workflow. Repair only the current artifact supplied by the
workflow. Return one strict JSON object containing a base_sha256 and an edits array.
Each edit must use exact text copied from the current artifact as old and the intended
replacement as new. Do not return a complete artifact, code fence, prose, or multiple
artifacts. The deterministic edit tool applies and validates the plan.
"""


def _source_text(context: CollectedContext) -> str:
    parts: list[str] = []
    used = 0
    for source_file in context.source_files:
        remaining = 80_000 - used
        if remaining <= 0:
            break
        fragment = source_file.content[:remaining]
        parts.append(f"## {source_file.path}\n{fragment}")
        used += len(fragment)
    return "\n\n".join(parts)


def _normalize_context(
    context: CollectedContext,
) -> tuple[CollectedContext, list[dict[str, Any]]]:
    if not context.poc_text.strip():
        return context, []

    result = normalize_poc_context(
        context.poc_text,
        requested_cve=context.cve_id,
        target_text=_source_text(context),
        max_chars=3900,
        max_sections=2,
    )
    records = list(result.get("records", []))
    selected = [record.get("id") for record in records if record.get("selected")]
    excluded = [record for record in records if not record.get("selected")]
    logger.info("PoC context selected=%s excluded=%d", selected, len(excluded))
    for record in records:
        logger.info(
            "PoC context decision source=%s selected=%s reason=%s",
            record.get("id", "unknown"),
            record.get("selected", False),
            record.get("reason", ""),
        )

    notes = context.extra_notes
    if records:
        notes = (
            f"{notes}\nPoC selection decisions: "
            f"{json.dumps(records, sort_keys=True)}"
        ).strip()
    return (
        context.model_copy(
            update={
                "poc_text": str(result.get("text", "")),
                "extra_notes": notes,
            }
        ),
        records,
    )


def _artifact_root_count(content: str, artifact_type: ArtifactType) -> int:
    if artifact_type == ArtifactType.METASPLOIT:
        return len(re.findall(r"(?m)^\s*class\s+MetasploitModule\b", content))
    if artifact_type == ArtifactType.ZAP_ACTIVE:
        metadata_count = len(re.findall(r"\bfunction\s+getMetadata\s*\(", content))
        scan_count = len(
            re.findall(
                r"\bfunction\s+scan\s*\(\s*as\s*,\s*msg\s*,\s*param\s*,\s*value\s*\)",
                content,
            )
        )
        return 1 if metadata_count == 1 and scan_count == 1 else max(metadata_count, scan_count)
    metadata_count = len(re.findall(r"\bfunction\s+getMetadata\s*\(", content))
    scan_count = len(
        re.findall(
            r"\bfunction\s+scan\s*\(\s*ps\s*,\s*msg\s*,\s*src\s*\)",
            content,
        )
    )
    return 1 if metadata_count == 1 and scan_count == 1 else max(metadata_count, scan_count)


def _rejection_comment(artifact_type: ArtifactType, message: str) -> str:
    prefix = "#" if artifact_type == ArtifactType.METASPLOIT else "//"
    return f"{prefix} ZeroForge rejected generated artifact: {message}\n"


def generate_artifact(
    vuln_input: VulnerabilityInput,
    context: CollectedContext,
) -> Artifact:
    """Generate from normalized PoC evidence and reject concatenated roots."""

    normalized_context, records = _normalize_context(context)
    artifact = legacy.generate_artifact(vuln_input, normalized_context)
    metadata = {**artifact.metadata, "poc_selection": records}
    root_count = _artifact_root_count(artifact.content, artifact.artifact_type)
    if root_count != 1:
        message = f"artifact must contain exactly one complete root; found {root_count}"
        logger.warning("Generated artifact rejected before validation: %s", message)
        metadata.update(
            {
                "generation_rejected": True,
                "generation_error": message,
                "rejected_content_sha256": artifact_sha256(artifact.content),
            }
        )
        return artifact.model_copy(
            update={
                "content": _rejection_comment(artifact.artifact_type, message),
                "metadata": metadata,
            }
        )

    metadata["artifact_root_count"] = root_count
    return artifact.model_copy(update={"metadata": metadata})


def _build_edit_prompt(
    artifact: Artifact,
    validation: ValidationResult,
    context: CollectedContext,
    *,
    attempt: int,
    max_attempts: int,
) -> str:
    profile = legacy._profile(artifact.artifact_type)
    base_sha = artifact_sha256(artifact.content)
    parts = [
        f"## Artifact Contract\n{profile.contract.strip()}",
        "## Validation Issues",
        *(f"- {error}" for error in validation.errors),
    ]
    if validation.warnings:
        parts.extend(["## Warnings", *(f"- {warning}" for warning in validation.warnings)])
    if context.extra_notes:
        parts.append(f"## Context Notes\n{context.extra_notes}")
    parts.extend(
        [
            f"## Current Artifact SHA-256\n{base_sha}",
            (
                f"## Current Remediation Validation Module\n"
                f"```{profile.language}\n{artifact.content}\n```"
            ),
            (
                "## Edit Tool Contract\n"
                "Return ONLY one strict JSON object with this shape:\n"
                '{"base_sha256":"64 lowercase hex characters","edits":['
                '{"old":"exact unique text from the current artifact",'
                '"new":"replacement text"}]}\n'
                "The base_sha256 must exactly match the value above. Each old value must "
                "occur exactly once. Prefer the smallest edits that resolve every issue. "
                "Do not include a complete artifact, a code fence, explanatory text, or "
                "text outside the JSON object. The edit tool rejects stale hashes, ambiguous "
                "matches, excessive size, no-op plans, and output containing multiple "
                "artifact roots."
            ),
        ]
    )
    task = (
        "## Task\nAddress all validation issues by editing the current remediation "
        "validation module through the edit tool contract."
    )
    if attempt and max_attempts:
        task += (
            f" This is repair attempt {attempt} of {max_attempts}. "
            f"{max_attempts - attempt + 1} attempt(s) remain after this one."
        )
        if attempt >= 2:
            task += (
                " Previous attempts did not resolve the same errors. Take a different "
                f"approach, use smaller exact edits, and do not include non-{profile.language} "
                "text in replacement values unless required by the artifact syntax."
            )
    parts.append(task)
    return "\n\n".join(parts)


def _legacy_full_replacement_plan(raw: str, artifact: Artifact) -> dict[str, Any]:
    code = legacy._extract_code_block(raw, artifact.artifact_type)
    if not code.strip():
        raise ArtifactEditError("repair output did not contain an edit plan or artifact content")
    return {
        "base_sha256": artifact_sha256(artifact.content),
        "edits": [{"old": artifact.content, "new": code}],
    }


def _apply_model_edits(raw: str, artifact: Artifact) -> Artifact:
    if legacy._is_refusal(raw):
        legacy._check_refusal(raw, "repair")
        return artifact
    if not raw.strip():
        logger.warning("Repair produced empty edit output; returning original artifact")
        return artifact

    legacy_full_replacement = False
    try:
        try:
            plan = parse_artifact_edit_plan(raw)
        except ArtifactEditError:
            plan = _legacy_full_replacement_plan(raw, artifact)
            legacy_full_replacement = True

        arguments = {
            "content": artifact.content,
            "base_sha256": plan["base_sha256"],
            "edits": plan["edits"],
            "artifact_type": artifact.artifact_type.value,
        }
        result = ToolAgent().run(
            ToolRequest(
                objective="Apply the Smart Agent's bounded artifact edit plan",
                allowed_tools=["apply_artifact_edits"],
                arguments=arguments,
                locked_arguments=arguments,
            )
        )
        if result.error:
            raise ArtifactEditError(result.error)
        output = result.output
        if not isinstance(output, dict) or not isinstance(output.get("content"), str):
            raise ArtifactEditError("artifact edit tool returned an invalid result")
    except Exception as exc:
        logger.warning("Artifact edit plan rejected: %s", exc)
        return artifact

    cfg = legacy.get_settings()
    metadata = {
        **artifact.metadata,
        "repaired": True,
        "edit_count": output.get("applied_edits", len(plan["edits"])),
        "edit_diff": output.get("diff", "")[-12_000:],
        "edit_base_sha256": output.get("base_sha256", plan["base_sha256"]),
        "edit_result_sha256": output.get("sha256", ""),
        "legacy_full_replacement": legacy_full_replacement,
    }
    if cfg.llm.stub_mode:
        metadata["stub"] = True
    return artifact.model_copy(
        update={
            "content": output["content"],
            "metadata": metadata,
        }
    )


def repair_artifact(
    artifact: Artifact,
    validation: ValidationResult,
    context: CollectedContext,
    *,
    attempt: int = 0,
    max_attempts: int = 0,
) -> Artifact:
    """Repair one artifact through a SHA-pinned deterministic edit tool."""

    logger.info(
        "Repairing artifact with edits (%d validation errors, attempt %d/%d)",
        len(validation.errors),
        attempt,
        max_attempts,
    )
    prompt = _build_edit_prompt(
        artifact,
        validation,
        context,
        attempt=attempt,
        max_attempts=max_attempts,
    )
    raw = legacy._call_llm(_EDIT_SYSTEM_PROMPT, prompt, artifact.artifact_type)
    return _apply_model_edits(raw, artifact)
