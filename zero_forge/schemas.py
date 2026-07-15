"""Pydantic schemas for ZeroForge input, state, and artifacts."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StrictSchema(BaseModel):
    """Base schema that rejects undeclared fields."""

    model_config = ConfigDict(extra="forbid")


class ArtifactType(StrEnum):
    """Supported security artifact types."""

    METASPLOIT = "metasploit"
    ZAP_ACTIVE = "zap_active_scan"
    ZAP_PASSIVE = "zap_passive_scan"


class VulnerabilityInput(BaseModel):
    """User-supplied vulnerability context for the harness."""

    cve_id: str = Field(..., description="CVE identifier, e.g. CVE-2021-44228")
    poc_text: str = Field(default="", description="Public proof-of-concept text or code")
    writeup_text: str = Field(default="", description="Vulnerability write-up or analysis")
    source_path: str | None = Field(default=None, description="Path to vulnerable source code")
    patch_diff: str = Field(default="", description="Patch or git diff as text")

class SourceFile(BaseModel):
    """A single source file inspected by the harness."""

    path: str
    content: str
    language: str = "unknown"
    category: str = "code"
    filename: str = ""


class CollectedContext(BaseModel):
    """Aggregated vulnerability context after research and collection."""

    cve_id: str
    cve_description: str = ""
    affected_versions: str = ""
    references: list[str] = Field(default_factory=list)
    source_files: list[SourceFile] = Field(default_factory=list)
    skipped_files: list[dict[str, Any]] = Field(default_factory=list)
    patch_diff: str = ""
    poc_text: str = ""
    writeup_text: str = ""
    extra_notes: str = ""


class Artifact(BaseModel):
    """A generated security artifact."""

    artifact_type: ArtifactType
    content: str
    filename: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ValidationResult(BaseModel):
    """Result of validating a generated artifact."""

    is_valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ToolRequest(StrictSchema):
    """Bounded request for the Tool Agent model."""

    objective: str = Field(min_length=1)
    allowed_tools: list[str] = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    locked_arguments: dict[str, Any] = Field(default_factory=dict)


class ToolCall(StrictSchema):
    """Strict tool selection returned by the Tool Agent model."""

    name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolResult(StrictSchema):
    """Normalized result from deterministic tool execution."""

    name: str
    output: Any = None
    error: str = ""
    role: str = "tool"
    provider: str = ""
    model: str = ""


class WorkflowError(BaseModel):
    """Structured failure context retained in workflow state."""

    code: str
    message: str
    role: str = ""
    provider: str = ""
    model: str = ""
    retryable: bool = False
    attempt: int = 1
    max_attempts: int = 1


class WorkflowState(BaseModel):
    """State flowing through the LangGraph workflow."""

    vuln_input: VulnerabilityInput
    context: CollectedContext | None = None
    artifact: Artifact | None = None
    validation: ValidationResult | None = None
    repair_attempts: int = 0
    max_repair_attempts: int = 3
    output_path: str | None = None
    status: str = "pending"
    error: str = ""
    failure: WorkflowError | None = None

    model_config = {"arbitrary_types_allowed": True}
