"""Seeded, specification-first vulnerability variant analysis."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, Protocol

from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph

from ..agents.llm import LLMCallError, call_model
from ..agents.tool_agent import ToolAgent, ToolAgentError
from ..config import get_settings
from ..logging_config import get_logger
from ..schemas import ToolRequest, ToolResult
from .schemas import (
    CandidateFinding,
    CandidateStatus,
    ConfirmedFinding,
    DiscoveryEvent,
    DiscoveryPhase,
    DiscoveryState,
    HypothesisStatus,
    SecurityHypothesis,
    SourceSnapshot,
    StaticEvidence,
    ThreatModel,
    VariantAnalysisRequest,
    VerificationPlan,
    VerificationResult,
)

logger = get_logger(__name__)

_ANALYSIS_SYSTEM_PROMPT = """\
You are ZeroForge's Smart Agent operating in seeded vulnerability variant-analysis mode.

Start from the supplied historical bug, patch, or root-cause description. Do not perform
open-ended guessing and do not claim that a vulnerability is confirmed. Produce:

1. An explicit threat model that identifies attacker control, trust boundaries, protected
   assets, security properties, and scope.
2. A small ranked set of falsifiable security hypotheses for related variants.
3. For every hypothesis, an explicit invariant, candidate source location, concrete source
   search terms, expected violation, expected safe behavior, and confidence basis.

The Tool Agent, not you, executes source searches. Runtime verification and a control case
are required before any candidate may become a confirmed finding.

Return only one strict JSON object with this shape:
{
  "threat_model": {
    "attacker_control": ["..."],
    "trust_boundaries": ["..."],
    "protected_assets": ["..."],
    "security_properties": ["..."],
    "in_scope": ["..."],
    "out_of_scope": ["..."]
  },
  "hypotheses": [
    {
      "title": "...",
      "root_cause_pattern": "...",
      "candidate_location": "...",
      "invariant": {
        "statement": "...",
        "rationale": "...",
        "anchor_paths": ["..."],
        "falsification_strategy": "..."
      },
      "attacker_controlled_input": "...",
      "preconditions": ["..."],
      "expected_violation": "...",
      "expected_safe_behavior": "...",
      "search_terms": ["..."],
      "confidence_basis": "..."
    }
  ]
}
"""


class ToolRunner(Protocol):
    """Minimal Tool Agent execution boundary used by this subgraph."""

    def run(self, request: ToolRequest) -> ToolResult: ...


AnalysisGenerator = Callable[
    [VariantAnalysisRequest, list[SourceSnapshot], str],
    tuple[ThreatModel, list[SecurityHypothesis]],
]


def _strip_json_fence(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start < 0 or end < start:
        raise ValueError("Smart Agent response did not contain a JSON object")
    return stripped[start : end + 1]


def _parse_analysis(text: str) -> tuple[ThreatModel, list[SecurityHypothesis]]:
    payload = json.loads(_strip_json_fence(text))
    if not isinstance(payload, dict):
        raise ValueError("Smart Agent analysis must be a JSON object")
    threat_model = ThreatModel.model_validate(payload.get("threat_model"))
    hypotheses_raw = payload.get("hypotheses")
    if not isinstance(hypotheses_raw, list):
        raise ValueError("Smart Agent analysis must contain a hypotheses list")
    hypotheses = [SecurityHypothesis.model_validate(item) for item in hypotheses_raw]
    return threat_model, hypotheses


def _source_prompt(
    request: VariantAnalysisRequest,
    source_files: list[SourceSnapshot],
    diff_summary: str,
) -> str:
    source_sections: list[str] = []
    for source in source_files[:12]:
        source_sections.append(
            f"### {source.path}\n```{source.language}\n{source.content[:6000]}\n```"
        )
    terms = ", ".join(request.seed_terms) if request.seed_terms else "(none supplied)"
    return "\n\n".join(
        [
            "## Seed vulnerability or patch",
            request.seed_summary or "(see supplied diff)",
            "## Seed diff",
            request.seed_diff[:12000] or "(none)",
            f"## Diff summary\n{diff_summary or '(none)'}",
            f"## Maintainer-provided seed terms\n{terms}",
            "## Admitted source context",
            "\n\n".join(source_sections) or "(no source files admitted)",
        ]
    )


def _generate_analysis_with_smart_agent(
    request: VariantAnalysisRequest,
    source_files: list[SourceSnapshot],
    diff_summary: str,
) -> tuple[ThreatModel, list[SecurityHypothesis]]:
    settings = get_settings()
    raw = call_model(
        "smart",
        settings.models.smart,
        _ANALYSIS_SYSTEM_PROMPT,
        _source_prompt(request, source_files, diff_summary),
    )
    return _parse_analysis(raw)


def _event(
    state: DiscoveryState,
    phase: DiscoveryPhase,
    event: str,
    detail: str = "",
) -> list[DiscoveryEvent]:
    return [
        *state.events,
        DiscoveryEvent(phase=phase, event=event, detail=detail),
    ]


def scope_node(state: DiscoveryState) -> dict[str, Any]:
    """Require explicit authorization and a concrete seed before source access."""

    if not state.request.authorized:
        return {
            "phase": DiscoveryPhase.FAILED,
            "status": "failed",
            "error": "Variant analysis requires an explicitly authorized target",
            "events": _event(
                state,
                DiscoveryPhase.SCOPE,
                "authorization_rejected",
            ),
        }
    return {
        "phase": DiscoveryPhase.COLLECT,
        "status": "scoped",
        "events": _event(state, DiscoveryPhase.SCOPE, "authorization_accepted"),
    }


def _tool_failure(result: ToolResult) -> str:
    return result.error.strip()


def collect_node(state: DiscoveryState, tool_runner: ToolRunner) -> dict[str, Any]:
    """Collect bounded source and patch context exclusively through the Tool Agent."""

    request = state.request
    read_arguments = {
        "source_path": request.source_path,
        "max_files": 20,
        "max_file_size": 51200,
        "unsafe": request.unsafe_source,
    }
    try:
        source_result = tool_runner.run(
            ToolRequest(
                objective="Collect bounded source context for seeded variant analysis",
                allowed_tools=["read_source_files"],
                arguments=read_arguments,
                locked_arguments=read_arguments,
            )
        )
        if _tool_failure(source_result):
            return {
                "phase": DiscoveryPhase.FAILED,
                "status": "failed",
                "error": f"Source collection failed: {source_result.error}",
            }

        snapshots: list[SourceSnapshot] = []
        raw_sources = source_result.output if isinstance(source_result.output, list) else []
        for item in raw_sources:
            if not isinstance(item, dict):
                continue
            if item.get("skipped") or item.get("truncated"):
                continue
            snapshots.append(
                SourceSnapshot(
                    path=str(item.get("path", "")),
                    filename=str(item.get("filename", "")),
                    language=str(item.get("language", "unknown")),
                    category=str(item.get("category", "code")),
                    content=str(item.get("content", "")),
                )
            )

        diff_summary = ""
        if request.seed_diff:
            diff_arguments = {"diff_text": request.seed_diff, "repo_path": ""}
            diff_result = tool_runner.run(
                ToolRequest(
                    objective="Summarize the supplied seed patch",
                    allowed_tools=["git_diff_inspect"],
                    arguments=diff_arguments,
                    locked_arguments=diff_arguments,
                )
            )
            if _tool_failure(diff_result):
                return {
                    "phase": DiscoveryPhase.FAILED,
                    "status": "failed",
                    "error": f"Seed diff inspection failed: {diff_result.error}",
                }
            if isinstance(diff_result.output, dict):
                diff_summary = str(diff_result.output.get("diff_summary", ""))

    except (LLMCallError, ToolAgentError) as exc:
        return {
            "phase": DiscoveryPhase.FAILED,
            "status": "failed",
            "error": f"Tool Agent rejected source collection: {exc}",
        }

    if not snapshots and not request.seed_diff:
        return {
            "phase": DiscoveryPhase.FAILED,
            "status": "failed",
            "error": "No admissible source context or seed diff was available",
        }

    return {
        "source_files": snapshots,
        "diff_summary": diff_summary,
        "phase": DiscoveryPhase.HYPOTHESIZE,
        "status": "context_collected",
        "events": _event(
            state,
            DiscoveryPhase.COLLECT,
            "context_collected",
            f"{len(snapshots)} source file(s) admitted",
        ),
    }


def hypothesize_node(
    state: DiscoveryState,
    analysis_generator: AnalysisGenerator,
) -> dict[str, Any]:
    """Use the Smart Agent to emit an explicit threat model and invariants."""

    try:
        threat_model, hypotheses = analysis_generator(
            state.request,
            state.source_files,
            state.diff_summary,
        )
    except (LLMCallError, ValueError, TypeError) as exc:
        return {
            "phase": DiscoveryPhase.FAILED,
            "status": "failed",
            "error": f"Smart Agent analysis failed: {exc}",
        }

    bounded = hypotheses[: state.request.max_hypotheses]
    if not bounded:
        return {
            "phase": DiscoveryPhase.FAILED,
            "status": "failed",
            "error": "Smart Agent produced no valid security hypotheses",
        }

    return {
        "threat_model": threat_model,
        "hypotheses": bounded,
        "phase": DiscoveryPhase.INVESTIGATE,
        "status": "hypotheses_ready",
        "events": _event(
            state,
            DiscoveryPhase.HYPOTHESIZE,
            "hypotheses_generated",
            f"{len(bounded)} hypothesis/hypotheses",
        ),
    }


def _verification_plan(hypothesis: SecurityHypothesis) -> VerificationPlan:
    return VerificationPlan(
        positive_case=(
            "Construct the smallest authorized runtime input that can falsify: "
            f"{hypothesis.invariant.statement}"
        ),
        control_case=(
            "Run the same input against a patched or invariant-enforcing build and "
            "require the security property to hold"
        ),
        success_condition=hypothesis.expected_violation,
        required_runs=2,
    )


def investigate_node(state: DiscoveryState, tool_runner: ToolRunner) -> dict[str, Any]:
    """Gather static support for each hypothesis through bounded source searches."""

    admitted_paths = [source.path for source in state.source_files]
    evidence: list[StaticEvidence] = list(state.evidence)
    candidates: list[CandidateFinding] = list(state.candidates)
    updated_hypotheses: list[SecurityHypothesis] = []
    searches_run = state.searches_run

    try:
        for hypothesis in state.hypotheses:
            hypothesis_evidence: list[StaticEvidence] = []
            for term in hypothesis.search_terms:
                if searches_run >= state.request.max_searches:
                    break
                arguments = {
                    "source_path": state.request.source_path,
                    "pattern": term,
                    "max_results": 10,
                    "unsafe": state.request.unsafe_source,
                    "allowed_paths": admitted_paths,
                }
                result = tool_runner.run(
                    ToolRequest(
                        objective=(
                            "Search admitted source files for evidence relevant to "
                            f"hypothesis {hypothesis.id}"
                        ),
                        allowed_tools=["search_code"],
                        arguments=arguments,
                        locked_arguments=arguments,
                    )
                )
                searches_run += 1
                matches = result.output if isinstance(result.output, list) else []
                static_evidence = StaticEvidence(
                    hypothesis_id=hypothesis.id,
                    tool_name="search_code",
                    query=term,
                    matches=[item for item in matches if isinstance(item, dict)],
                    error=result.error,
                    supports_candidate=bool(matches) and not result.error,
                )
                evidence.append(static_evidence)
                hypothesis_evidence.append(static_evidence)

            supporting = [item for item in hypothesis_evidence if item.supports_candidate]
            if supporting:
                updated = hypothesis.model_copy(
                    update={"status": HypothesisStatus.AWAITING_VERIFICATION}
                )
                candidates.append(
                    CandidateFinding(
                        hypothesis_id=hypothesis.id,
                        evidence_ids=[item.id for item in supporting],
                        verification_plan=_verification_plan(hypothesis),
                    )
                )
            else:
                updated = hypothesis.model_copy(
                    update={"status": HypothesisStatus.INCONCLUSIVE}
                )
            updated_hypotheses.append(updated)

    except (LLMCallError, ToolAgentError) as exc:
        return {
            "phase": DiscoveryPhase.FAILED,
            "status": "failed",
            "error": f"Tool Agent rejected hypothesis investigation: {exc}",
            "searches_run": searches_run,
            "evidence": evidence,
        }

    return {
        "hypotheses": updated_hypotheses,
        "evidence": evidence,
        "candidates": candidates,
        "searches_run": searches_run,
        "phase": DiscoveryPhase.COMPLETE,
        "status": "completed",
        "events": _event(
            state,
            DiscoveryPhase.INVESTIGATE,
            "static_investigation_completed",
            f"{len(candidates)} candidate(s), {searches_run} search(es)",
        ),
    }


def promote_candidate(
    candidate: CandidateFinding,
    verification: VerificationResult,
) -> ConfirmedFinding:
    """Promote only independently reproduced candidates with a passing control case."""

    plan = candidate.verification_plan
    if candidate.status != CandidateStatus.AWAITING_VERIFICATION:
        raise ValueError("Only awaiting-verification candidates can be promoted")
    if verification.required_runs != plan.required_runs:
        raise ValueError("Verification run requirement does not match the candidate plan")
    if verification.positive_runs < plan.required_runs:
        raise ValueError("Candidate did not reproduce for the required positive runs")
    if verification.control_runs < plan.required_runs:
        raise ValueError("Control case did not run the required number of times")
    if not verification.control_case_passed:
        raise ValueError("Control case did not pass")
    if not verification.security_property_violated or not verification.reproduced:
        raise ValueError("Runtime evidence did not prove a reproducible property violation")
    evidence_ids = [*candidate.evidence_ids, *verification.evidence_ids]
    if not evidence_ids:
        raise ValueError("Confirmed findings require linked evidence")
    return ConfirmedFinding(
        candidate_id=candidate.id,
        hypothesis_id=candidate.hypothesis_id,
        evidence_ids=list(dict.fromkeys(evidence_ids)),
    )


def _route_after_scope(state: DiscoveryState) -> str:
    return "fail" if state.status == "failed" else "collect"


def _route_after_collect(state: DiscoveryState) -> str:
    return "fail" if state.status == "failed" else "hypothesize"


def _route_after_hypothesize(state: DiscoveryState) -> str:
    return "fail" if state.status == "failed" else "investigate"


def fail_node(state: DiscoveryState) -> dict[str, Any]:
    """Normalize terminal failures."""

    return {
        "phase": DiscoveryPhase.FAILED,
        "status": "failed",
        "error": state.error or "Variant analysis failed",
        "events": _event(
            state,
            DiscoveryPhase.FAILED,
            "workflow_failed",
            state.error or "Variant analysis failed",
        ),
    }


def build_variant_analysis_workflow(
    *,
    tool_runner: ToolRunner | None = None,
    analysis_generator: AnalysisGenerator | None = None,
) -> CompiledStateGraph[DiscoveryState, None, DiscoveryState, DiscoveryState]:
    """Build the seeded variant-analysis LangGraph subgraph."""

    runner = tool_runner or ToolAgent()
    generator = analysis_generator or _generate_analysis_with_smart_agent

    graph = StateGraph(DiscoveryState)
    graph.add_node("scope", scope_node)
    graph.add_node("collect", lambda state: collect_node(state, runner))
    graph.add_node(
        "hypothesize",
        lambda state: hypothesize_node(state, generator),
    )
    graph.add_node("investigate", lambda state: investigate_node(state, runner))
    graph.add_node("fail", fail_node)
    graph.set_entry_point("scope")
    graph.add_conditional_edges(
        "scope",
        _route_after_scope,
        {"collect": "collect", "fail": "fail"},
    )
    graph.add_conditional_edges(
        "collect",
        _route_after_collect,
        {"hypothesize": "hypothesize", "fail": "fail"},
    )
    graph.add_conditional_edges(
        "hypothesize",
        _route_after_hypothesize,
        {"investigate": "investigate", "fail": "fail"},
    )
    graph.add_edge("investigate", END)
    graph.add_edge("fail", END)
    return graph.compile()


def run_variant_analysis(
    request: VariantAnalysisRequest | dict[str, Any],
    *,
    tool_runner: ToolRunner | None = None,
    analysis_generator: AnalysisGenerator | None = None,
) -> DiscoveryState:
    """Run one authorized, seeded variant-analysis workflow."""

    if isinstance(request, dict):
        request = VariantAnalysisRequest.model_validate(request)
    initial_state = DiscoveryState(request=request)
    graph = build_variant_analysis_workflow(
        tool_runner=tool_runner,
        analysis_generator=analysis_generator,
    )
    result = graph.invoke(initial_state)
    if isinstance(result, DiscoveryState):
        return result
    if isinstance(result, dict):
        return DiscoveryState.model_validate(result)
    raise TypeError(
        f"LangGraph invoke() returned unexpected type {type(result).__name__}"
    )
