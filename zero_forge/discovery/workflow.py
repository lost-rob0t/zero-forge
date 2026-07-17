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
    KnownBugRecord,
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

Start from the supplied historical bug, patch, package advisory, or root-cause description.
Do not perform open-ended guessing and do not claim that a vulnerability is confirmed.
Produce:

1. An explicit threat model that identifies attacker control, trust boundaries, protected
   assets, security properties, and scope.
2. A small ranked set of falsifiable security hypotheses for related variants.
3. For every hypothesis, an explicit invariant, candidate source location, concrete source
   search terms, expected violation, expected safe behavior, and confidence basis.

Official advisory records are seed context, not proof that the target contains the bug.
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
    [VariantAnalysisRequest, list[SourceSnapshot], str, list[KnownBugRecord]],
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


def _seed_descriptor(request: VariantAnalysisRequest) -> dict[str, Any]:
    package: dict[str, str] | None = None
    if request.seed_package_name:
        package = {
            "name": request.seed_package_name,
            "ecosystem": request.seed_package_ecosystem,
            "version": request.seed_package_version,
        }
    return {
        "cve_ids": request.seed_cve_ids,
        "ghsa_ids": request.seed_ghsa_ids,
        "package": package,
        "seed_terms": request.seed_terms,
    }


def _source_prompt(
    request: VariantAnalysisRequest,
    source_files: list[SourceSnapshot],
    diff_summary: str,
    known_bugs: list[KnownBugRecord],
) -> str:
    source_sections: list[str] = []
    for source in source_files[:12]:
        source_sections.append(
            f"### {source.path}\n```{source.language}\n{source.content[:6000]}\n```"
        )
    advisory_payload = [record.model_dump(mode="json") for record in known_bugs[:20]]
    return "\n\n".join(
        [
            "## Requested seed",
            json.dumps(_seed_descriptor(request), sort_keys=True),
            "## Seed vulnerability or patch",
            request.seed_summary or "(derived from advisory identifiers or package metadata)",
            "## Seed diff",
            request.seed_diff[:12000] or "(none)",
            f"## Diff summary\n{diff_summary or '(none)'}",
            "## Official advisory context",
            json.dumps(advisory_payload, sort_keys=True) if advisory_payload else "(none)",
            "## Admitted source context",
            "\n\n".join(source_sections) or "(no source files admitted)",
        ]
    )


def _generate_analysis_with_smart_agent(
    request: VariantAnalysisRequest,
    source_files: list[SourceSnapshot],
    diff_summary: str,
    known_bugs: list[KnownBugRecord],
) -> tuple[ThreatModel, list[SecurityHypothesis]]:
    settings = get_settings()
    raw = call_model(
        "smart",
        settings.models.smart,
        _ANALYSIS_SYSTEM_PROMPT,
        _source_prompt(request, source_files, diff_summary, known_bugs),
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


def _run_locked_tool(
    tool_runner: ToolRunner,
    *,
    objective: str,
    name: str,
    arguments: dict[str, Any],
) -> ToolResult:
    return tool_runner.run(
        ToolRequest(
            objective=objective,
            allowed_tools=[name],
            arguments=arguments,
            locked_arguments=arguments,
        )
    )


def _advisory_records(
    result: ToolResult,
    *,
    source_name: str,
    errors: list[str],
) -> list[KnownBugRecord]:
    if result.error:
        errors.append(f"{source_name}: {result.error}")
        return []
    if not isinstance(result.output, list):
        errors.append(f"{source_name}: tool returned a non-list response")
        return []

    records: list[KnownBugRecord] = []
    for item in result.output:
        if not isinstance(item, dict):
            continue
        try:
            records.append(KnownBugRecord.model_validate(item))
        except (TypeError, ValueError) as exc:
            errors.append(f"{source_name}: rejected malformed advisory record: {exc}")
    return records


def _dedupe_known_bugs(
    records: list[KnownBugRecord],
    *,
    max_results: int,
) -> list[KnownBugRecord]:
    output: list[KnownBugRecord] = []
    seen: set[str] = set()
    for record in records:
        identity_values = [record.advisory_id, *record.aliases]
        key = next((value.upper() for value in identity_values if value), "")
        if not key or key in seen:
            continue
        seen.add(key)
        output.append(record)
        if len(output) >= max_results:
            break
    return output


def _known_cve_ids(
    request: VariantAnalysisRequest,
    records: list[KnownBugRecord],
) -> list[str]:
    cve_ids = {value.strip().upper() for value in request.seed_cve_ids if value.strip()}
    for record in records:
        for value in [record.advisory_id, *record.aliases]:
            normalized = value.strip().upper()
            if normalized.startswith("CVE-"):
                cve_ids.add(normalized)
    return sorted(cve_ids)


def _apply_kev_context(
    records: list[KnownBugRecord],
    kev_entries: list[dict[str, Any]],
    *,
    max_results: int,
) -> list[KnownBugRecord]:
    kev_by_cve = {
        str(entry.get("cve_id", "")).upper(): entry
        for entry in kev_entries
        if isinstance(entry, dict) and entry.get("cve_id")
    }
    enriched: list[KnownBugRecord] = []
    matched_cves: set[str] = set()
    for record in records:
        record_ids = {
            value.upper() for value in [record.advisory_id, *record.aliases] if value
        }
        matching = next((kev_by_cve[cve] for cve in record_ids if cve in kev_by_cve), None)
        if matching is None:
            enriched.append(record)
            continue
        matched_cves.add(str(matching["cve_id"]).upper())
        enriched.append(
            record.model_copy(
                update={
                    "exploited_in_wild": True,
                    "kev_details": matching,
                }
            )
        )

    for cve_id, entry in kev_by_cve.items():
        if cve_id in matched_cves:
            continue
        enriched.append(
            KnownBugRecord(
                source="cisa_kev",
                advisory_id=cve_id,
                summary=str(entry.get("vulnerability_name", "")),
                details=str(entry.get("short_description", "")),
                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                exploited_in_wild=True,
                kev_details=entry,
            )
        )
        if len(enriched) >= max_results:
            break
    return enriched[:max_results]


def _collect_known_bugs(
    request: VariantAnalysisRequest,
    tool_runner: ToolRunner,
) -> tuple[list[KnownBugRecord], list[str]]:
    if not request.collect_known_bugs:
        return [], []

    records: list[KnownBugRecord] = []
    errors: list[str] = []
    package_name = request.seed_package_name.strip()
    ecosystem = request.seed_package_ecosystem.strip()
    version = request.seed_package_version.strip()

    try:
        if package_name:
            osv_arguments = {
                "package_name": package_name,
                "ecosystem": ecosystem,
                "version": version,
                "max_results": request.max_known_bugs,
                "timeout": request.web_timeout,
            }
            result = _run_locked_tool(
                tool_runner,
                objective="Query OSV for known vulnerabilities affecting the seed package",
                name="osv_query",
                arguments=osv_arguments,
            )
            records.extend(
                _advisory_records(result, source_name="osv_query", errors=errors)
            )

        if request.seed_cve_ids or request.seed_ghsa_ids or package_name:
            github_arguments = {
                "cve_ids": request.seed_cve_ids,
                "ghsa_ids": request.seed_ghsa_ids,
                "package_name": package_name,
                "ecosystem": ecosystem,
                "version": version,
                "max_results": request.max_known_bugs,
                "timeout": request.web_timeout,
            }
            result = _run_locked_tool(
                tool_runner,
                objective="Query GitHub's public advisory database for seed context",
                name="github_advisory_search",
                arguments=github_arguments,
            )
            records.extend(
                _advisory_records(
                    result,
                    source_name="github_advisory_search",
                    errors=errors,
                )
            )

        records = _dedupe_known_bugs(records, max_results=request.max_known_bugs)
        cve_ids = _known_cve_ids(request, records)
        if cve_ids:
            kev_arguments = {
                "cve_ids": cve_ids,
                "max_results": request.max_known_bugs,
                "timeout": request.web_timeout,
            }
            result = _run_locked_tool(
                tool_runner,
                objective="Check whether seed CVEs appear in CISA KEV",
                name="cisa_kev_lookup",
                arguments=kev_arguments,
            )
            if result.error:
                errors.append(f"cisa_kev_lookup: {result.error}")
            elif isinstance(result.output, list):
                records = _apply_kev_context(
                    records,
                    [item for item in result.output if isinstance(item, dict)],
                    max_results=request.max_known_bugs,
                )
            else:
                errors.append("cisa_kev_lookup: tool returned a non-list response")
    except (LLMCallError, ToolAgentError) as exc:
        errors.append(f"advisory tool boundary rejected the request: {exc}")

    return records[: request.max_known_bugs], errors


def collect_node(state: DiscoveryState, tool_runner: ToolRunner) -> dict[str, Any]:
    """Collect bounded source, patch, and official advisory seed context."""

    request = state.request
    read_arguments = {
        "source_path": request.source_path,
        "max_files": 20,
        "max_file_size": 51200,
        "unsafe": request.unsafe_source,
    }
    try:
        source_result = _run_locked_tool(
            tool_runner,
            objective="Collect bounded source context for seeded variant analysis",
            name="read_source_files",
            arguments=read_arguments,
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
            diff_result = _run_locked_tool(
                tool_runner,
                objective="Summarize the supplied seed patch",
                name="git_diff_inspect",
                arguments=diff_arguments,
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

    known_bugs, research_errors = _collect_known_bugs(request, tool_runner)
    detail = (
        f"{len(snapshots)} source file(s), {len(known_bugs)} advisory record(s), "
        f"{len(research_errors)} advisory error(s)"
    )
    return {
        "source_files": snapshots,
        "diff_summary": diff_summary,
        "known_bugs": known_bugs,
        "research_errors": research_errors,
        "phase": DiscoveryPhase.HYPOTHESIZE,
        "status": "context_collected",
        "events": _event(
            state,
            DiscoveryPhase.COLLECT,
            "context_collected",
            detail,
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
            state.known_bugs,
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
                result = _run_locked_tool(
                    tool_runner,
                    objective=(
                        "Search admitted source files for evidence relevant to "
                        f"hypothesis {hypothesis.id}"
                    ),
                    name="search_code",
                    arguments=arguments,
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
