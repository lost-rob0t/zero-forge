"""Pydantic schemas for ZeroForge input, state, and artifacts."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field


class ArtifactType(str, Enum):
    """Supported security artifact types."""

    METASPLOIT = "metasploit"
    ZAP_ACTIVE = "zap_active_scan"
    ZAP_PASSIVE = "zap_passive_scan"


class VulnerabilityInput(BaseModel):
    """User-supplied vulnerability context for the harness."""

    cve_id: str = Field(..., description="CVE identifier, e.g. CVE-2021-44228")
    poc_text: str = Field(default="", description="Public proof-of-concept text or code")
    writeup_text: str = Field(default="", description="Vulnerability write-up or analysis")
    source_path: Optional[str] = Field(default=None, description="Path to vulnerable source code")
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


class WorkflowState(BaseModel):
    """State flowing through the LangGraph workflow."""

    vuln_input: VulnerabilityInput
    context: Optional[CollectedContext] = None
    artifact: Optional[Artifact] = None
    validation: Optional[ValidationResult] = None
    repair_attempts: int = 0
    max_repair_attempts: int = 3
    output_path: Optional[str] = None
    status: str = "pending"
    error: str = ""

    model_config = {"arbitrary_types_allowed": True}
