"""Typed schemas for seeded vulnerability variant analysis."""

from __future__ import annotations

from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


def _new_id() -> str:
    return uuid4().hex[:12]


class StrictModel(BaseModel):
    """Base model that rejects undeclared fields."""

    model_config = ConfigDict(extra="forbid")


class FrozenStrictModel(BaseModel):
    """Immutable evidence model."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class DiscoveryPhase(StrEnum):
    """Phases in the seeded variant-analysis workflow."""

    SCOPE = "scope"
    COLLECT = "collect"
    HYPOTHESIZE = "hypothesize"
    INVESTIGATE = "investigate"
    COMPLETE = "complete"
    FAILED = "failed"


class HypothesisStatus(StrEnum):
    """Lifecycle status for one security hypothesis."""

    PROPOSED = "proposed"
    INCONCLUSIVE = "inconclusive"
    AWAITING_VERIFICATION = "awaiting_verification"
    REFUTED = "refuted"


class CandidateStatus(StrEnum):
    """Lifecycle status for a candidate finding."""

    AWAITING_VERIFICATION = "awaiting_verification"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class VariantAnalysisRequest(StrictModel):
    """Authorized request for source-assisted, seeded variant analysis."""

    source_path: str = Field(min_length=1)
    authorized: bool = False
    seed_summary: str = ""
    seed_diff: str = ""
    seed_terms: list[str] = Field(default_factory=list)
    seed_cve_ids: list[str] = Field(default_factory=list)
    seed_ghsa_ids: list[str] = Field(default_factory=list)
    seed_package_name: str = ""
    seed_package_ecosystem: str = ""
    seed_package_version: str = ""
    collect_known_bugs: bool = True
    max_known_bugs: int = Field(default=10, ge=1, le=50)
    web_timeout: int = Field(default=15, ge=1, le=60)
    max_hypotheses: int = Field(default=3, ge=1, le=10)
    max_searches: int = Field(default=8, ge=1, le=50)
    unsafe_source: bool = False

    @model_validator(mode="after")
    def require_seed(self) -> VariantAnalysisRequest:
        package_fields = (
            self.seed_package_name.strip(),
            self.seed_package_ecosystem.strip(),
        )
        if any(package_fields) and not all(package_fields):
            raise ValueError(
                "seed_package_name and seed_package_ecosystem must be supplied together"
            )
        has_seed = any(
            (
                self.seed_summary.strip(),
                self.seed_diff.strip(),
                self.seed_cve_ids,
                self.seed_ghsa_ids,
                all(package_fields),
            )
        )
        if not has_seed:
            raise ValueError(
                "seed_summary, seed_diff, advisory IDs, or a package seed is required"
            )
        return self


class SourceSnapshot(StrictModel):
    """Bounded source material admitted by the Tool Agent."""

    path: str
    filename: str = ""
    language: str = "unknown"
    category: str = "code"
    content: str = ""


class KnownBugRecord(FrozenStrictModel):
    """Normalized advisory context fetched from an official public source."""

    source: str = Field(min_length=1)
    advisory_id: str = Field(min_length=1)
    aliases: list[str] = Field(default_factory=list)
    summary: str = ""
    details: str = ""
    severity: str = ""
    cwes: list[str] = Field(default_factory=list)
    affected_packages: list[dict[str, Any]] = Field(default_factory=list)
    vulnerable_functions: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    published: str = ""
    modified: str = ""
    source_url: str = ""
    exploited_in_wild: bool | None = None
    kev_details: dict[str, Any] = Field(default_factory=dict)


class ThreatModel(StrictModel):
    """Explicit security boundary and properties for one audit."""

    attacker_control: list[str] = Field(min_length=1)
    trust_boundaries: list[str] = Field(min_length=1)
    protected_assets: list[str] = Field(min_length=1)
    security_properties: list[str] = Field(min_length=1)
    in_scope: list[str] = Field(min_length=1)
    out_of_scope: list[str] = Field(default_factory=list)


class SecurityInvariant(StrictModel):
    """Falsifiable local security specification."""

    statement: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    anchor_paths: list[str] = Field(default_factory=list)
    falsification_strategy: str = Field(min_length=1)


class SecurityHypothesis(StrictModel):
    """Seed-derived theory about a possible vulnerability variant."""

    id: str = Field(default_factory=_new_id)
    title: str = Field(min_length=1)
    root_cause_pattern: str = Field(min_length=1)
    candidate_location: str = Field(min_length=1)
    invariant: SecurityInvariant
    attacker_controlled_input: str = Field(min_length=1)
    preconditions: list[str] = Field(default_factory=list)
    expected_violation: str = Field(min_length=1)
    expected_safe_behavior: str = Field(min_length=1)
    search_terms: list[str] = Field(min_length=1)
    confidence_basis: str = Field(min_length=1)
    status: HypothesisStatus = HypothesisStatus.PROPOSED


class StaticEvidence(FrozenStrictModel):
    """Immutable source evidence returned by a bounded tool call."""

    id: str = Field(default_factory=_new_id)
    hypothesis_id: str
    tool_name: str
    query: str
    matches: list[dict[str, Any]] = Field(default_factory=list)
    error: str = ""
    supports_candidate: bool = False


class VerificationPlan(StrictModel):
    """Independent runtime proof required before finding promotion."""

    positive_case: str = Field(min_length=1)
    control_case: str = Field(min_length=1)
    success_condition: str = Field(min_length=1)
    required_runs: int = Field(default=2, ge=2, le=20)


class CandidateFinding(StrictModel):
    """A statically supported lead that is not yet a confirmed finding."""

    id: str = Field(default_factory=_new_id)
    hypothesis_id: str
    evidence_ids: list[str] = Field(min_length=1)
    verification_plan: VerificationPlan
    status: CandidateStatus = CandidateStatus.AWAITING_VERIFICATION


class VerificationResult(StrictModel):
    """Runtime evidence used to accept or reject a candidate."""

    positive_runs: int = Field(ge=0)
    control_runs: int = Field(ge=0)
    required_runs: int = Field(ge=2)
    control_case_passed: bool = False
    security_property_violated: bool = False
    reproduced: bool = False
    evidence_ids: list[str] = Field(default_factory=list)


class ConfirmedFinding(StrictModel):
    """Finding promoted only after an independent positive and control case."""

    id: str = Field(default_factory=_new_id)
    candidate_id: str
    hypothesis_id: str
    evidence_ids: list[str] = Field(min_length=1)
    status: CandidateStatus = CandidateStatus.CONFIRMED


class DiscoveryEvent(FrozenStrictModel):
    """Immutable phase transition or decision record."""

    phase: DiscoveryPhase
    event: str = Field(min_length=1)
    detail: str = ""


class DiscoveryState(StrictModel):
    """State flowing through the LangGraph variant-analysis subgraph."""

    request: VariantAnalysisRequest
    phase: DiscoveryPhase = DiscoveryPhase.SCOPE
    source_files: list[SourceSnapshot] = Field(default_factory=list)
    diff_summary: str = ""
    known_bugs: list[KnownBugRecord] = Field(default_factory=list)
    research_errors: list[str] = Field(default_factory=list)
    threat_model: ThreatModel | None = None
    hypotheses: list[SecurityHypothesis] = Field(default_factory=list)
    evidence: list[StaticEvidence] = Field(default_factory=list)
    candidates: list[CandidateFinding] = Field(default_factory=list)
    searches_run: int = 0
    events: list[DiscoveryEvent] = Field(default_factory=list)
    status: str = "pending"
    error: str = ""
