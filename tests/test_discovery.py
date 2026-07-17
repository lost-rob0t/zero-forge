# ruff: noqa: I001
"""Tests for the seeded, specification-first discovery workflow."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from zero_forge.agents.tool_agent import ToolAgent
from zero_forge.schemas import ToolRequest, ToolResult
from zero_forge.tools.registry import ToolRegistry
from zero_forge.tools.source_inspect import (
    git_diff_inspect,
    read_source_files,
    search_code,
)

from zero_forge.discovery.schemas import (
    CandidateFinding,
    CandidateStatus,
    DiscoveryPhase,
    HypothesisStatus,
    SecurityHypothesis,
    SecurityInvariant,
    StaticEvidence,
    ThreatModel,
    VariantAnalysisRequest,
    VerificationPlan,
    VerificationResult,
)
from zero_forge.discovery.workflow import (
    _parse_analysis,
    promote_candidate,
    run_variant_analysis,
)


def _registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register("read_source_files", read_source_files)
    registry.register("search_code", search_code)
    registry.register("git_diff_inspect", git_diff_inspect)
    return registry


def _analysis_generator(
    request: VariantAnalysisRequest,
    source_files,
    diff_summary: str,
    known_bugs,
):
    del request, source_files, diff_summary, known_bugs
    threat_model = ThreatModel(
        attacker_control=["index value supplied by an untrusted caller"],
        trust_boundaries=["public parser input to internal list access"],
        protected_assets=["process memory integrity"],
        security_properties=["normalized indexes remain within list bounds"],
        in_scope=["index normalization and list access"],
    )
    hypothesis = SecurityHypothesis(
        title="Sentinel index bypass reaches unchecked access",
        root_cause_pattern="a sentinel value bypasses normalization before indexing",
        candidate_location="normalize_index and use_index",
        invariant=SecurityInvariant(
            statement="Every index used for list access is between zero and len(values)-1",
            rationale="Negative or oversized indexes violate the caller-visible bounds contract",
            anchor_paths=["target.py"],
            falsification_strategy="Search for sentinel branches and unchecked indexed access",
        ),
        attacker_controlled_input="index",
        preconditions=["the caller can provide a negative index"],
        expected_violation="an out-of-contract element is read",
        expected_safe_behavior="invalid indexes are rejected before access",
        search_terms=["index == -1", "values[index]"],
        confidence_basis="the seed bug involved inconsistent sentinel handling",
    )
    return threat_model, [hypothesis]


class RecordingRunner:
    def __init__(self, delegate: ToolAgent) -> None:
        self.delegate = delegate
        self.requests: list[ToolRequest] = []

    def run(self, request: ToolRequest) -> ToolResult:
        self.requests.append(request)
        return self.delegate.run(request)


class AdvisoryRunner(RecordingRunner):
    def run(self, request: ToolRequest) -> ToolResult:
        self.requests.append(request)
        name = request.allowed_tools[0]
        if name == "github_advisory_search":
            return ToolResult(
                name=name,
                output=[
                    {
                        "source": "github_advisory",
                        "advisory_id": "GHSA-test-1234-5678",
                        "aliases": ["CVE-2026-12345"],
                        "summary": "Sentinel handling can bypass validation",
                        "vulnerable_functions": ["normalize_index"],
                        "source_url": (
                            "https://github.com/advisories/GHSA-test-1234-5678"
                        ),
                    }
                ],
            )
        if name == "cisa_kev_lookup":
            return ToolResult(
                name=name,
                output=[
                    {
                        "cve_id": "CVE-2026-12345",
                        "vendor_project": "Example",
                        "product": "Parser",
                        "vulnerability_name": "Sentinel Validation Bypass",
                        "short_description": "A crafted index bypasses validation.",
                    }
                ],
            )
        return self.delegate.run(request)


class FailingAdvisoryRunner(RecordingRunner):
    def run(self, request: ToolRequest) -> ToolResult:
        self.requests.append(request)
        name = request.allowed_tools[0]
        if name in {"github_advisory_search", "cisa_kev_lookup", "osv_query"}:
            return ToolResult(name=name, error="network unavailable")
        return self.delegate.run(request)


class NeverRunner:
    def run(self, request: ToolRequest) -> ToolResult:
        raise AssertionError(f"unexpected tool request: {request}")


def _write_candidate_source(tmp_path) -> None:
    (tmp_path / "target.py").write_text(
        "def normalize_index(index, length):\n"
        "    if index == -1:\n"
        "        return length - 1\n"
        "    return index\n\n"
        "def use_index(index, values):\n"
        "    return values[index]\n",
        encoding="utf-8",
    )


def test_variant_analysis_requires_authorization(tmp_path):
    request = VariantAnalysisRequest(
        source_path=str(tmp_path),
        authorized=False,
        seed_summary="A previous sentinel-index bug skipped bounds validation.",
    )

    result = run_variant_analysis(
        request,
        tool_runner=NeverRunner(),
        analysis_generator=_analysis_generator,
    )

    assert result.status == "failed"
    assert result.phase == DiscoveryPhase.FAILED
    assert "authorized" in result.error.lower()


def test_variant_analysis_creates_only_awaiting_verification_candidate(tmp_path):
    _write_candidate_source(tmp_path)
    runner = RecordingRunner(ToolAgent(_registry()))
    request = VariantAnalysisRequest(
        source_path=str(tmp_path),
        authorized=True,
        seed_summary="A sentinel index bypassed validation in a related component.",
        seed_terms=["sentinel", "bounds"],
    )

    result = run_variant_analysis(
        request,
        tool_runner=runner,
        analysis_generator=_analysis_generator,
    )

    assert result.status == "completed"
    assert result.phase == DiscoveryPhase.COMPLETE
    assert result.threat_model is not None
    assert len(result.hypotheses) == 1
    assert result.hypotheses[0].status == HypothesisStatus.AWAITING_VERIFICATION
    assert result.evidence
    assert any(item.supports_candidate for item in result.evidence)
    assert len(result.candidates) == 1
    assert result.candidates[0].status == CandidateStatus.AWAITING_VERIFICATION
    assert result.candidates[0].verification_plan.control_case
    assert [event.event for event in result.events] == [
        "authorization_accepted",
        "context_collected",
        "hypotheses_generated",
        "static_investigation_completed",
    ]
    assert all(len(request.allowed_tools) == 1 for request in runner.requests)
    assert all(
        request.arguments == request.locked_arguments for request in runner.requests
    )


def test_advisory_seed_is_enriched_and_passed_to_smart_agent(tmp_path):
    _write_candidate_source(tmp_path)
    runner = AdvisoryRunner(ToolAgent(_registry()))
    captured = {}

    def generator(request, source_files, diff_summary, known_bugs):
        captured["known_bugs"] = known_bugs
        return _analysis_generator(request, source_files, diff_summary, known_bugs)

    result = run_variant_analysis(
        VariantAnalysisRequest(
            source_path=str(tmp_path),
            authorized=True,
            seed_cve_ids=["CVE-2026-12345"],
        ),
        tool_runner=runner,
        analysis_generator=generator,
    )

    assert result.status == "completed"
    assert result.research_errors == []
    assert len(result.known_bugs) == 1
    assert result.known_bugs[0].advisory_id == "GHSA-test-1234-5678"
    assert result.known_bugs[0].exploited_in_wild is True
    assert result.known_bugs[0].kev_details["product"] == "Parser"
    assert captured["known_bugs"] == result.known_bugs
    tool_names = [request.allowed_tools[0] for request in runner.requests]
    assert "github_advisory_search" in tool_names
    assert "cisa_kev_lookup" in tool_names


def test_advisory_failure_degrades_to_local_seed_context(tmp_path):
    _write_candidate_source(tmp_path)
    runner = FailingAdvisoryRunner(ToolAgent(_registry()))

    result = run_variant_analysis(
        VariantAnalysisRequest(
            source_path=str(tmp_path),
            authorized=True,
            seed_cve_ids=["CVE-2026-12345"],
        ),
        tool_runner=runner,
        analysis_generator=_analysis_generator,
    )

    assert result.status == "completed"
    assert result.known_bugs == []
    assert len(result.research_errors) == 2
    assert all("network unavailable" in error for error in result.research_errors)


def test_static_search_without_matches_stays_inconclusive(tmp_path):
    (tmp_path / "target.py").write_text(
        "def safe_lookup(index, values):\n"
        "    if index < 0 or index >= len(values):\n"
        "        raise IndexError(index)\n"
        "    return values.__getitem__(index)\n",
        encoding="utf-8",
    )

    result = run_variant_analysis(
        VariantAnalysisRequest(
            source_path=str(tmp_path),
            authorized=True,
            seed_summary="A previous sentinel-index bug skipped bounds validation.",
        ),
        tool_runner=ToolAgent(_registry()),
        analysis_generator=_analysis_generator,
    )

    assert result.status == "completed"
    assert result.hypotheses[0].status == HypothesisStatus.INCONCLUSIVE
    assert result.candidates == []


def test_parse_analysis_accepts_json_fence():
    raw = """```json
{
  "threat_model": {
    "attacker_control": ["request bytes"],
    "trust_boundaries": ["parser to internal state"],
    "protected_assets": ["memory safety"],
    "security_properties": ["lengths remain consistent"],
    "in_scope": ["parser"],
    "out_of_scope": []
  },
  "hypotheses": [{
    "title": "Length mismatch",
    "root_cause_pattern": "two representations disagree on length",
    "candidate_location": "parse_record",
    "invariant": {
      "statement": "declared length equals available bytes",
      "rationale": "downstream reads trust the declared length",
      "anchor_paths": ["parser.c"],
      "falsification_strategy": "search for unchecked length propagation"
    },
    "attacker_controlled_input": "declared length",
    "preconditions": ["record reaches parser"],
    "expected_violation": "out-of-bounds read",
    "expected_safe_behavior": "record is rejected",
    "search_terms": ["declared_len", "payload_len"],
    "confidence_basis": "the seed patch added one missing equality check"
  }]
}
```"""

    threat_model, hypotheses = _parse_analysis(raw)

    assert threat_model.security_properties == ["lengths remain consistent"]
    assert hypotheses[0].invariant.statement == "declared length equals available bytes"


def test_static_evidence_is_immutable():
    evidence = StaticEvidence(
        hypothesis_id="hypothesis",
        tool_name="search_code",
        query="sentinel",
    )

    with pytest.raises(ValidationError):
        evidence.query = "changed"


def _candidate() -> CandidateFinding:
    return CandidateFinding(
        hypothesis_id="hypothesis",
        evidence_ids=["static-evidence"],
        verification_plan=VerificationPlan(
            positive_case="trigger the invariant violation",
            control_case="run against a patched build",
            success_condition="the security property is violated",
            required_runs=2,
        ),
    )


@pytest.mark.parametrize(
    "verification",
    [
        VerificationResult(
            positive_runs=2,
            control_runs=2,
            required_runs=2,
            control_case_passed=False,
            security_property_violated=True,
            reproduced=True,
        ),
        VerificationResult(
            positive_runs=1,
            control_runs=2,
            required_runs=2,
            control_case_passed=True,
            security_property_violated=True,
            reproduced=True,
        ),
        VerificationResult(
            positive_runs=2,
            control_runs=2,
            required_runs=2,
            control_case_passed=True,
            security_property_violated=False,
            reproduced=True,
        ),
    ],
)
def test_promotion_rejects_incomplete_runtime_proof(verification):
    with pytest.raises(ValueError):
        promote_candidate(_candidate(), verification)


def test_promotion_requires_positive_and_control_reproduction():
    finding = promote_candidate(
        _candidate(),
        VerificationResult(
            positive_runs=2,
            control_runs=2,
            required_runs=2,
            control_case_passed=True,
            security_property_violated=True,
            reproduced=True,
            evidence_ids=["runtime-positive", "runtime-control"],
        ),
    )

    assert finding.status == CandidateStatus.CONFIRMED
    assert finding.evidence_ids == [
        "static-evidence",
        "runtime-positive",
        "runtime-control",
    ]


def test_variant_request_accepts_advisory_or_package_seed(tmp_path):
    cve_request = VariantAnalysisRequest(
        source_path=str(tmp_path),
        authorized=True,
        seed_cve_ids=["CVE-2026-12345"],
    )
    package_request = VariantAnalysisRequest(
        source_path=str(tmp_path),
        authorized=True,
        seed_package_name="demo-parser",
        seed_package_ecosystem="PyPI",
    )

    assert cve_request.seed_cve_ids == ["CVE-2026-12345"]
    assert package_request.seed_package_name == "demo-parser"


def test_variant_request_rejects_partial_package_seed(tmp_path):
    with pytest.raises(ValidationError, match="supplied together"):
        VariantAnalysisRequest(
            source_path=str(tmp_path),
            authorized=True,
            seed_package_name="demo-parser",
        )


def test_variant_request_requires_a_concrete_seed(tmp_path):
    with pytest.raises(ValidationError):
        VariantAnalysisRequest(
            source_path=str(tmp_path),
            authorized=True,
        )
