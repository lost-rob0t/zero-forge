"""Typed schemas for the vulnerability discovery investigation graph.

Implements the minimum investigation entities and relationships from
issue #28: Target, Component, Observation, Hypothesis, Experiment, Evidence,
Finding, and Artifact.  Each hypothesis carries explicit success and refutation
conditions.  Negative and inconclusive results are retained so the system does
not repeat disproven theories.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def _utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(UTC).isoformat()


def _gen_id() -> str:
    """Generate a short unique identifier for an investigation entity."""
    return uuid4().hex[:12]


# --- Enums ------------------------------------------------------------------


class AccessMode(StrEnum):
    """Required access mode for a hypothesis or experiment."""

    INFORMATIONAL = "informational"
    REMOTE = "remote"
    LOCAL = "local"


class OperationalPhase(StrEnum):
    """Four-phase operational mode for discovery and exploit generation."""

    RESEARCH = "research"
    PLAN = "plan"
    EXPLOIT = "exploit"
    VERIFY = "verify"


class EvidenceClass(StrEnum):
    """Classification of an experiment result."""

    SUPPORTING = "supporting"
    REFUTING = "refuting"
    INCONCLUSIVE = "inconclusive"


class ExperimentStatus(StrEnum):
    """Lifecycle status of an experiment."""

    PENDING = "pending"
    AUTHORIZED = "authorized"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class FindingStatus(StrEnum):
    """Lifecycle status of a confirmed finding."""

    CONFIRMED = "confirmed"
    PROMOTED = "promoted"
    ARCHIVED = "archived"


class RelationshipType(StrEnum):
    """Minimum investigation graph relationships."""

    DERIVED_FROM = "derived_from"
    TARGETS = "targets"
    TESTS = "tests"
    SUPPORTS = "supports"
    REFUTES = "refutes"
    REQUIRES_ACCESS = "requires_access"
    REPRODUCES = "reproduces"
    AFFECTS = "affects"
    DUPLICATES = "duplicates"
    MITIGATED_BY = "mitigated_by"


# --- Investigation entities --------------------------------------------------


class Target(BaseModel):
    """A software or system under investigation."""

    id: str = Field(default_factory=_gen_id)
    name: str
    version: str = ""
    build_id: str = ""
    source_path: str | None = None
    docker_image: str = ""
    authorized: bool = False

    model_config = ConfigDict(extra="forbid")


class Component(BaseModel):
    """A logical or physical component within a target."""

    id: str = Field(default_factory=_gen_id)
    target_id: str
    name: str
    entry_point: str = ""
    suspected_sink: str = ""
    trust_boundary: str = ""

    model_config = ConfigDict(extra="forbid")


class Observation(BaseModel):
    """A raw observation from source inspection, scanning, or runtime."""

    id: str = Field(default_factory=_gen_id)
    target_id: str
    source: str = ""  # tool or method that produced the observation
    description: str
    raw_data: str = ""
    timestamp: str = Field(default_factory=_utc_now)

    model_config = ConfigDict(extra="forbid")


class Hypothesis(BaseModel):
    """A testable vulnerability hypothesis.

    Every hypothesis must include explicit success and refutation conditions
    so the system can classify evidence deterministically.
    """

    id: str = Field(default_factory=_gen_id)
    target_id: str
    component_id: str = ""

    # Required schema fields from issue #28
    claimed_weakness: str
    affected_component: str
    entry_point: str
    suspected_sink: str
    preconditions: list[str] = Field(default_factory=list)
    required_access: AccessMode = AccessMode.INFORMATIONAL
    attacker_controlled_input: str = ""
    expected_vulnerable_behavior: str
    expected_safe_behavior: str
    experiment_strategy: str
    success_condition: str
    failure_condition: str
    possible_side_effects: list[str] = Field(default_factory=list)

    # Evidence tracking
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence_basis: str = ""
    supporting_evidence: list[str] = Field(default_factory=list)
    counterevidence: list[str] = Field(default_factory=list)

    # Lifecycle
    created_at: str = Field(default_factory=_utc_now)
    status: str = "open"  # open, testing, supported, refuted, inconclusive

    model_config = ConfigDict(extra="forbid")


class Experiment(BaseModel):
    """A typed experiment derived from a hypothesis.

    The experiment is a bounded Tool Agent request—not a general instruction
    to "find a vulnerability".
    """

    id: str = Field(default_factory=_gen_id)
    hypothesis_id: str
    objective: str
    allowed_tools: list[str] = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    locked_arguments: dict[str, Any] = Field(default_factory=dict)

    # Authorization and safety
    required_access: AccessMode = AccessMode.INFORMATIONAL
    authorized: bool = False
    is_destructive: bool = False
    is_intrusive: bool = False

    # Budget tracking
    attempt: int = 0
    max_attempts: int = 1

    # Lifecycle
    status: ExperimentStatus = ExperimentStatus.PENDING
    created_at: str = Field(default_factory=_utc_now)

    model_config = ConfigDict(extra="forbid")


class EvidenceRecord(BaseModel):
    """Structured evidence captured from experiment execution.

    Immutable once persisted.  Linked to tool/version/environment provenance.
    """

    id: str = Field(default_factory=_gen_id)
    experiment_id: str
    run_id: str = Field(default_factory=_gen_id)

    # Captured output
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    files_read: dict[str, str | None] = Field(default_factory=dict)
    files_modified: list[str] = Field(default_factory=list)
    network_captures: list[dict[str, Any]] = Field(default_factory=list)
    timing_ms: float = 0.0

    # Provenance
    tool_name: str = ""
    tool_version: str = ""
    environment: str = ""  # docker image, host, etc.
    timestamp: str = Field(default_factory=_utc_now)

    # Classification
    classification: EvidenceClass = EvidenceClass.INCONCLUSIVE

    # Flag-based verification (simplified per maintainer direction)
    flag_found: bool = False
    flag_value: str = ""
    flag_path: str = ""

    model_config = ConfigDict(extra="forbid")


class VerificationResult(BaseModel):
    """Result of the reproduction gate.

    A Finding cannot be created without successful reproduction.
    """

    verified: bool = False
    flag_retrieved: bool = False
    flag_value: str = ""
    repeatability: int = 0  # N/N successful reruns
    repeatability_required: int = 1
    control_case_passed: bool = False  # fails against patched version
    evidence_ids: list[str] = Field(default_factory=list)
    failure_reason: str = ""

    model_config = ConfigDict(extra="forbid")


class Finding(BaseModel):
    """A confirmed vulnerability finding promoted from a verified hypothesis.

    Requires exact target/build identity, exact input and environment, captured
    output, a control case, evidence of a violated security property, and
    stable reproduction.
    """

    id: str = Field(default_factory=_gen_id)
    target_id: str
    hypothesis_id: str
    experiment_id: str = ""
    evidence_ids: list[str] = Field(default_factory=list)

    # Reproduction gate
    verification: VerificationResult | None = None

    # Finding details
    cve_id: str = ""
    weakness: str = ""
    component: str = ""
    entry_point: str = ""
    sink: str = ""
    description: str = ""

    # Reproducer
    reproducer_path: str = ""
    reproducer_type: str = ""  # metasploit_rc, shell_command, etc.
    reproducer_content: str = ""

    # Control case
    control_case: str = ""  # description of patched-version negative test

    # Status
    status: FindingStatus = FindingStatus.CONFIRMED
    created_at: str = Field(default_factory=_utc_now)

    model_config = ConfigDict(extra="forbid")


class InvestigationGraph(BaseModel):
    """Persistent, typed investigation/evidence graph.

    Separate from the LangGraph execution graph.  Stores all investigation
    entities and their relationships so negative and inconclusive results
    are preserved.
    """

    targets: dict[str, Target] = Field(default_factory=dict)
    components: dict[str, Component] = Field(default_factory=dict)
    observations: dict[str, Observation] = Field(default_factory=dict)
    hypotheses: dict[str, Hypothesis] = Field(default_factory=dict)
    experiments: dict[str, Experiment] = Field(default_factory=dict)
    evidence: dict[str, EvidenceRecord] = Field(default_factory=dict)
    findings: dict[str, Finding] = Field(default_factory=dict)

    # Typed relationships: list of (source_id, relationship_type, target_id, reason)
    relationships: list[dict[str, str]] = Field(default_factory=list)

    def add_relationship(
        self,
        source_id: str,
        rel: RelationshipType,
        target_id: str,
        reason: str = "",
    ) -> None:
        """Add a typed relationship to the investigation graph."""
        self.relationships.append(
            {
                "source": source_id,
                "type": rel.value,
                "target": target_id,
                "reason": reason,
            }
        )

    model_config = ConfigDict(extra="forbid")


class SWESetupResult(BaseModel):
    """Result of the SWE agent configuring Docker services.

    The SWE agent sets up the target environment and places a randomized flag
    at a known path.  The exploit phase agent receives this path.
    """

    docker_compose_path: str = ""
    service_names: list[str] = Field(default_factory=list)
    flag_path: str = ""
    flag_value: str = ""
    target_id: str = ""
    ready: bool = False
    error: str = ""

    model_config = ConfigDict(extra="forbid")


class DiscoveryState(BaseModel):
    """State flowing through the discovery LangGraph subgraph.

    This is the integration boundary for the discovery workflow, analogous
    to WorkflowState for the artifact generation workflow.
    """

    # Input
    target: Target
    authorized: bool = False

    # Investigation graph
    investigation: InvestigationGraph = Field(default_factory=InvestigationGraph)

    # Current phase state
    phase: OperationalPhase = OperationalPhase.RESEARCH
    current_hypothesis_id: str = ""
    current_experiment_id: str = ""
    current_evidence_id: str = ""

    # SWE setup
    swe_setup: SWESetupResult | None = None

    # Research artifacts
    research_summary: str = ""
    attack_surface: list[str] = Field(default_factory=list)
    research_iterations: int = 0
    max_research_iterations: int = 20

    # Budgets
    experiments_run: int = 0
    max_experiments: int = 10
    requests_made: int = 0
    max_requests: int = 100
    hypothesis_depth: int = 0
    max_hypothesis_depth: int = 3
    repair_attempts: int = 0
    max_repair_attempts: int = 3
    runtime_seconds: float = 0.0
    max_runtime_seconds: float = 3600.0

    # Findings
    findings: list[Finding] = Field(default_factory=list)

    # Terminal state
    # pending, researching, planning, exploiting, verifying, completed, failed
    status: str = "pending"
    error: str = ""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)
