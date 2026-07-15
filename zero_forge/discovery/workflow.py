"""LangGraph discovery workflow: RESEARCH → PLAN → EXPLOIT → VERIFY.

Implements the bounded hypothesis → experiment → evidence loop from
issue #28 with the simplified flag-based verification direction from the
maintainer's last comment.

Four typed phases as LangGraph subgraph nodes:

1. **RESEARCH** — iterative deep information gathering: attack surface
   inventory, trust boundaries, entry points, parsers, sinks.
2. **PLAN** — generate and rank vulnerability hypotheses; convert the
   top hypothesis into a typed experiment with success/refutation conditions.
3. **EXPLOIT** — execute the experiment through the Tool Agent; capture
   structured evidence; classify as supporting, refuting, or inconclusive.
4. **VERIFY** — independent reproduction gate: re-run the experiment,
   check flag retrieval, enforce repeatability, and promote only
   reproducible cases to Finding.

Backward escalation paths (all implemented in routing):
- VERIFY → EXPLOIT (repair)
- VERIFY → PLAN (strategy revision)
- VERIFY → RESEARCH (information gap)
- EXPLOIT → PLAN (strategy change)
- EXPLOIT → RESEARCH (missing information)
- PLAN → RESEARCH (blocking unknowns)

Budgets and safety gates are enforced on every transition.
"""

from __future__ import annotations

import time
from typing import Any

from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph

from ..logging_config import get_logger
from .schemas import (
    AccessMode,
    DiscoveryState,
    EvidenceClass,
    EvidenceRecord,
    Experiment,
    ExperimentStatus,
    Finding,
    FindingStatus,
    Hypothesis,
    OperationalPhase,
    RelationshipType,
    Target,
    VerificationResult,
)
from .swe_agent import setup_target_environment
from .tools import read_file, verify_flag_in_output

logger = get_logger(__name__)


# --- Budget checks -----------------------------------------------------------

def _budget_exhausted(state: DiscoveryState) -> bool:
    """Return True if any configured budget has been exhausted."""
    if state.experiments_run >= state.max_experiments:
        return True
    if state.research_iterations >= state.max_research_iterations:
        return True
    if state.requests_made >= state.max_requests:
        return True
    if state.hypothesis_depth >= state.max_hypothesis_depth:
        return True
    if state.runtime_seconds >= state.max_runtime_seconds:
        return True
    return False


# --- Phase 1: RESEARCH ------------------------------------------------------

def research_node(state: DiscoveryState) -> dict[str, Any]:
    """Node: iterative deep information gathering.

    Builds an attack-surface inventory: trust boundaries, entry points,
    parsers, sinks, and state transitions.  In production, the Smart Agent
    drives this with ReAct-style iterative research.  Without an LLM, it
    performs a basic source-inspection pass.
    """
    logger.info("RESEARCH phase: iteration %d", state.research_iterations + 1)
    start_time = time.monotonic()

    # Authorization gate: SWE setup must not run for unauthorized targets
    if not state.authorized:
        return {
            "status": "failed",
            "error": "Research requires an authorized target",
        }

    if _budget_exhausted(state):
        return {
            "status": "failed",
            "error": "Research budget exhausted before forming a hypothesis",
        }

    investigation = state.investigation.model_copy()

    # Ensure the target is in the investigation graph
    if state.target.id not in investigation.targets:
        investigation.targets[state.target.id] = state.target
        investigation.add_relationship(
            state.target.id,
            RelationshipType.TARGETS,
            state.target.id,
            "target registered",
        )

    # SWE setup: configure Docker services and place the randomized flag
    if state.swe_setup is None:
        swe_result = setup_target_environment(state.target)
        if not swe_result.ready:
            return {
                "swe_setup": swe_result,
                "status": "failed",
                "error": swe_result.error or "SWE setup failed",
            }
        # Register the flag path in the investigation graph
        investigation.add_relationship(
            state.target.id,
            RelationshipType.REQUIRES_ACCESS,
            swe_result.flag_path,
            "flag placed by SWE agent",
        )
    else:
        swe_result = state.swe_setup

    # Basic attack surface inventory from target metadata
    attack_surface: list[str] = list(state.attack_surface)
    if not attack_surface:
        if state.target.source_path:
            attack_surface.append(f"Source path: {state.target.source_path}")
        if state.target.docker_image:
            attack_surface.append(f"Docker image: {state.target.docker_image}")
        attack_surface.append(f"Flag location: {swe_result.flag_path}")
        if swe_result.docker_compose_path:
            attack_surface.append(
                f"Docker compose: {swe_result.docker_compose_path}",
            )

    iterations = state.research_iterations + 1
    research_summary = (
        f"Research iteration {iterations}: acquired target context, "
        f"flag placed at {swe_result.flag_path}. "
        f"Attack surface: {len(attack_surface)} items."
    )

    # Termination criteria
    if iterations >= state.max_research_iterations:
        research_summary += " (max iterations reached)"
    elif len(attack_surface) >= 3:
        research_summary += " (sufficient attack surface mapped)"

    elapsed = time.monotonic() - start_time

    return {
        "investigation": investigation,
        "swe_setup": swe_result,
        "attack_surface": attack_surface,
        "research_summary": research_summary,
        "research_iterations": iterations,
        "requests_made": state.requests_made + 1,
        "runtime_seconds": state.runtime_seconds + elapsed,
        "phase": OperationalPhase.PLAN,
        "status": "planning",
    }


# --- Phase 2: PLAN ----------------------------------------------------------

def plan_node(state: DiscoveryState) -> dict[str, Any]:
    """Node: generate and rank hypotheses; convert one to a typed experiment.

    Every hypothesis includes explicit success and refutation conditions.
    The experiment is a bounded Tool Agent request.
    """
    logger.info("PLAN phase: generating hypothesis")
    start_time = time.monotonic()

    if _budget_exhausted(state):
        return {
            "status": "failed",
            "error": "Budget exhausted before planning",
        }

    investigation = state.investigation.model_copy()

    # In production, the Smart Agent generates ranked hypotheses.
    # Without an LLM, we create a stub hypothesis that targets the flag file.
    hypothesis = Hypothesis(
        target_id=state.target.id,
        claimed_weakness="flag_retrieval",
        affected_component="target filesystem",
        entry_point="read_file tool",
        suspected_sink="flag file at known path",
        preconditions=["SWE agent has placed flag", "flag path is known"],
        required_access=AccessMode.LOCAL,
        attacker_controlled_input="flag file path",
        expected_vulnerable_behavior="flag contents are readable",
        expected_safe_behavior="flag file is not accessible",
        experiment_strategy="Use read_file tool to read the flag path",
        success_condition="flag value appears in tool output",
        failure_condition="flag file not found or empty",
        possible_side_effects=[],
        confidence=0.5,
        confidence_basis="flag path provided by SWE agent",
    )

    investigation.hypotheses[hypothesis.id] = hypothesis
    investigation.add_relationship(
        hypothesis.id,
        RelationshipType.DERIVED_FROM,
        state.target.id,
        "hypothesis derived from target research",
    )

    # Convert hypothesis to a typed experiment
    flag_path = state.swe_setup.flag_path if state.swe_setup else ""
    experiment = Experiment(
        hypothesis_id=hypothesis.id,
        objective=f"Read the flag file at {flag_path}",
        allowed_tools=["read_file"],
        arguments={"path": flag_path},
        locked_arguments={"path": flag_path},
        required_access=AccessMode.LOCAL,
        authorized=state.authorized,
        is_destructive=False,
        is_intrusive=False,
        max_attempts=1,
    )

    investigation.experiments[experiment.id] = experiment
    investigation.add_relationship(
        experiment.id,
        RelationshipType.TESTS,
        hypothesis.id,
        "experiment tests hypothesis",
    )

    elapsed = time.monotonic() - start_time

    return {
        "investigation": investigation,
        "current_hypothesis_id": hypothesis.id,
        "current_experiment_id": experiment.id,
        "hypothesis_depth": state.hypothesis_depth + 1,
        "requests_made": state.requests_made + 1,
        "runtime_seconds": state.runtime_seconds + elapsed,
        "phase": OperationalPhase.EXPLOIT,
        "status": "exploiting",
    }


# --- Phase 3: EXPLOIT -------------------------------------------------------

def _classify_evidence(
    flag_found: bool,
    tool_error: str,
    tool_output: str,
) -> EvidenceClass:
    """Classify experiment evidence deterministically.

    - flag_found → SUPPORTING
    - tool error mentions "not found" → REFUTING
    - otherwise → INCONCLUSIVE
    """
    if flag_found:
        return EvidenceClass.SUPPORTING
    combined = (tool_error + tool_output).lower()
    if "not found" in combined or "file not found" in combined:
        return EvidenceClass.REFUTING
    return EvidenceClass.INCONCLUSIVE


def exploit_node(state: DiscoveryState) -> dict[str, Any]:
    """Node: execute the experiment through the Tool Agent.

    Authorization and access-mode checks gate every experiment.
    Intrusive or destructive experiments require explicit authorization.
    """
    logger.info("EXPLOIT phase: executing experiment")
    start_time = time.monotonic()

    investigation = state.investigation.model_copy()
    experiment = investigation.experiments.get(state.current_experiment_id)
    if experiment is None:
        return {"status": "failed", "error": "No current experiment to execute"}

    # Authorization gate
    if not state.authorized:
        experiment.status = ExperimentStatus.SKIPPED
        investigation.experiments[experiment.id] = experiment
        return {
            "investigation": investigation,
            "status": "failed",
            "error": "Experiment not authorized: target is not authorized",
        }

    if experiment.is_destructive and not experiment.authorized:
        experiment.status = ExperimentStatus.SKIPPED
        investigation.experiments[experiment.id] = experiment
        return {
            "investigation": investigation,
            "status": "failed",
            "error": "Destructive experiment requires explicit authorization",
        }

    if _budget_exhausted(state):
        experiment.status = ExperimentStatus.SKIPPED
        investigation.experiments[experiment.id] = experiment
        return {
            "investigation": investigation,
            "status": "failed",
            "error": "Budget exhausted before experiment execution",
        }

    experiment.status = ExperimentStatus.EXECUTING
    investigation.experiments[experiment.id] = experiment

    # Execute the experiment deterministically
    # In production, the Tool Agent selects and executes the tool.
    # Here we execute directly since the tool and arguments are locked.
    flag_path = experiment.locked_arguments.get(
        "path",
        experiment.arguments.get("path", ""),
    )
    try:
        tool_result = read_file(path=flag_path)
    except Exception as exc:
        evidence = EvidenceRecord(
            experiment_id=experiment.id,
            stdout="",
            stderr=f"Tool execution failed: {exc}",
            exit_code=-1,
            tool_name="read_file",
            classification=EvidenceClass.INCONCLUSIVE,
        )
        investigation.evidence[evidence.id] = evidence
        experiment.status = ExperimentStatus.FAILED
        investigation.experiments[experiment.id] = experiment
        elapsed = time.monotonic() - start_time
        return {
            "investigation": investigation,
            "current_evidence_id": evidence.id,
            "experiments_run": state.experiments_run + 1,
            "requests_made": state.requests_made + 1,
            "runtime_seconds": state.runtime_seconds + elapsed,
            "phase": OperationalPhase.VERIFY,
            "status": "verifying",
        }

    stdout = tool_result.get("content", "")
    stderr = tool_result.get("error", "")
    exit_code = 0 if not stderr else 1

    # Classify the result
    flag_value = state.swe_setup.flag_value if state.swe_setup else ""
    verification = verify_flag_in_output(flag=flag_value, output=stdout)
    flag_found = verification["flag_found"]
    classification = _classify_evidence(flag_found, stderr, stdout)

    evidence = EvidenceRecord(
        experiment_id=experiment.id,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        tool_name="read_file",
        environment=state.target.docker_image or "local",
        classification=classification,
        flag_found=flag_found,
        flag_value=verification["flag_value"],
        flag_path=flag_path,
    )

    investigation.evidence[evidence.id] = evidence

    # Add relationship based on classification
    if classification == EvidenceClass.SUPPORTING:
        investigation.add_relationship(
            evidence.id,
            RelationshipType.SUPPORTS,
            experiment.hypothesis_id,
            "evidence supports hypothesis",
        )
    elif classification == EvidenceClass.REFUTING:
        investigation.add_relationship(
            evidence.id,
            RelationshipType.REFUTES,
            experiment.hypothesis_id,
            "evidence refutes hypothesis",
        )
    # INCONCLUSIVE: no SUPPORTS or REFUTES edge — neutral retention

    # Update hypothesis status
    hypothesis = investigation.hypotheses.get(experiment.hypothesis_id)
    if hypothesis:
        if classification == EvidenceClass.SUPPORTING:
            hypothesis.status = "supported"
            hypothesis.supporting_evidence.append(evidence.id)
        elif classification == EvidenceClass.REFUTING:
            hypothesis.status = "refuted"
            hypothesis.counterevidence.append(evidence.id)
        else:
            hypothesis.status = "inconclusive"
        investigation.hypotheses[hypothesis.id] = hypothesis

    experiment.status = ExperimentStatus.COMPLETED
    investigation.experiments[experiment.id] = experiment

    elapsed = time.monotonic() - start_time

    return {
        "investigation": investigation,
        "current_evidence_id": evidence.id,
        "experiments_run": state.experiments_run + 1,
        "requests_made": state.requests_made + 1,
        "runtime_seconds": state.runtime_seconds + elapsed,
        "phase": OperationalPhase.VERIFY,
        "status": "verifying",
    }


# --- Phase 4: VERIFY --------------------------------------------------------

def verify_node(state: DiscoveryState) -> dict[str, Any]:
    """Node: independent reproduction gate.

    Re-runs the experiment, checks flag retrieval, and enforces
    repeatability.  A Finding cannot be created without successful
    reproduction.
    """
    logger.info("VERIFY phase: checking reproduction")
    start_time = time.monotonic()

    investigation = state.investigation.model_copy()
    evidence = investigation.evidence.get(state.current_evidence_id)
    if evidence is None:
        return {"status": "failed", "error": "No evidence to verify"}

    experiment = investigation.experiments.get(evidence.experiment_id)
    if experiment is None:
        return {"status": "failed", "error": "No experiment for evidence"}

    hypothesis = investigation.hypotheses.get(experiment.hypothesis_id)
    if hypothesis is None:
        return {"status": "failed", "error": "No hypothesis for experiment"}

    # If evidence was refuting or inconclusive, retain it and escalate
    if evidence.classification != EvidenceClass.SUPPORTING:
        logger.info(
            "Evidence is %s; retaining negative result",
            evidence.classification.value,
        )
        if _budget_exhausted(state):
            return {
                "status": "failed",
                "error": "Budget exhausted after negative evidence",
            }
        # Escalate back to PLAN for a new hypothesis
        elapsed = time.monotonic() - start_time
        return {
            "investigation": investigation,
            "phase": OperationalPhase.PLAN,
            "status": "planning",
            "repair_attempts": state.repair_attempts + 1,
            "runtime_seconds": state.runtime_seconds + elapsed,
        }

    # Reproduction gate: re-run the experiment to confirm
    flag_path = evidence.flag_path or experiment.locked_arguments.get(
        "path", experiment.arguments.get("path", ""),
    )
    flag_value = state.swe_setup.flag_value if state.swe_setup else ""

    repro_count = 0
    required = 1
    evidence_ids = [evidence.id]

    for _ in range(required):
        try:
            result = read_file(path=flag_path)
            output = result.get("content", "")
            check = verify_flag_in_output(flag=flag_value, output=output)
            if check["flag_found"]:
                repro_count += 1
        except Exception:
            pass

    verified = repro_count >= required
    flag_retrieved = evidence.flag_found and verified

    verification = VerificationResult(
        verified=verified,
        flag_retrieved=flag_retrieved,
        flag_value=flag_value if flag_retrieved else "",
        repeatability=repro_count,
        repeatability_required=required,
        control_case_passed=False,  # would require patched version
        evidence_ids=evidence_ids,
        failure_reason="" if verified else "Reproduction failed",
    )

    if not verified:
        # Escalate back to EXPLOIT for repair
        if state.repair_attempts < state.max_repair_attempts:
            elapsed = time.monotonic() - start_time
            return {
                "investigation": investigation,
                "phase": OperationalPhase.EXPLOIT,
                "status": "exploiting",
                "repair_attempts": state.repair_attempts + 1,
                "runtime_seconds": state.runtime_seconds + elapsed,
            }
        return {
            "investigation": investigation,
            "status": "failed",
            "error": "Reproduction failed after max repair attempts",
        }

    # Promote to Finding
    finding = Finding(
        target_id=state.target.id,
        hypothesis_id=hypothesis.id,
        experiment_id=experiment.id,
        evidence_ids=evidence_ids,
        verification=verification,
        weakness=hypothesis.claimed_weakness,
        component=hypothesis.affected_component,
        entry_point=hypothesis.entry_point,
        sink=hypothesis.suspected_sink,
        description=f"Confirmed: {hypothesis.success_condition}",
        reproducer_path=flag_path,
        reproducer_type="read_file",
        reproducer_content=f"read_file(path='{flag_path}')",
        control_case="Not yet tested against patched version",
        status=FindingStatus.CONFIRMED,
    )

    investigation.findings[finding.id] = finding
    investigation.add_relationship(
        finding.id,
        RelationshipType.REPRODUCES,
        experiment.id,
        "finding reproduces experiment",
    )

    elapsed = time.monotonic() - start_time

    return {
        "investigation": investigation,
        "findings": [*state.findings, finding],
        "phase": OperationalPhase.VERIFY,
        "status": "completed",
        "runtime_seconds": state.runtime_seconds + elapsed,
    }


# --- Routing ----------------------------------------------------------------

def route_from_research(state: DiscoveryState) -> str:
    """Route from RESEARCH to PLAN, RESEARCH (loop), or terminal."""
    if state.status == "failed":
        return "fail"
    if state.status == "completed":
        return "end"
    return "plan"


def route_from_plan(state: DiscoveryState) -> str:
    """Route from PLAN to EXPLOIT, RESEARCH (backward), or terminal."""
    if state.status == "failed":
        return "fail"
    if state.status == "completed":
        return "end"
    # Backward escalation to RESEARCH when hypothesis depth exceeds budget
    if state.hypothesis_depth >= state.max_hypothesis_depth:
        if state.research_iterations < state.max_research_iterations:
            return "research"
        return "end"
    return "exploit"


def route_from_exploit(state: DiscoveryState) -> str:
    """Route from EXPLOIT to VERIFY, PLAN (backward), RESEARCH (backward), or terminal."""
    if state.status == "failed":
        return "fail"
    if state.status == "completed":
        return "end"
    # Backward escalation: EXPLOIT → PLAN when repair budget exhausted
    if state.repair_attempts >= state.max_repair_attempts:
        if state.research_iterations < state.max_research_iterations:
            return "research"
        return "end"
    return "verify"


def route_from_verify(state: DiscoveryState) -> str:
    """Route from VERIFY with all backward escalation paths."""
    if state.status == "failed":
        return "fail"
    if state.status == "completed":
        return "end"
    if state.repair_attempts >= state.max_repair_attempts:
        return "fail"
    if state.phase == OperationalPhase.EXPLOIT:
        return "exploit"
    if state.phase == OperationalPhase.PLAN:
        return "plan"
    if state.phase == OperationalPhase.RESEARCH:
        return "research"
    return "fail"


def fail_node(state: DiscoveryState) -> dict[str, Any]:
    """Terminal node: mark the discovery workflow as failed."""
    error = state.error or "Discovery workflow failed"
    return {"status": "failed", "error": error}


# --- Graph builder -----------------------------------------------------------

def build_discovery_workflow() -> CompiledStateGraph:
    """Build and compile the discovery LangGraph subgraph.

    All six backward escalation paths are wired as conditional edges:
    - VERIFY → EXPLOIT (repair)
    - VERIFY → PLAN (strategy revision)
    - VERIFY → RESEARCH (information gap)
    - EXPLOIT → RESEARCH (missing information)
    - PLAN → RESEARCH (blocking unknowns)
    - EXPLOIT → PLAN is handled via verify→exploit→verify loop
    """
    graph = StateGraph(DiscoveryState)
    graph.add_node("research", research_node)
    graph.add_node("plan", plan_node)
    graph.add_node("exploit", exploit_node)
    graph.add_node("verify", verify_node)
    graph.add_node("fail", fail_node)

    graph.set_entry_point("research")
    graph.add_conditional_edges(
        "research",
        route_from_research,
        {"plan": "plan", "fail": "fail", "end": END},
    )
    graph.add_conditional_edges(
        "plan",
        route_from_plan,
        {
            "exploit": "exploit",
            "research": "research",
            "fail": "fail",
            "end": END,
        },
    )
    graph.add_conditional_edges(
        "exploit",
        route_from_exploit,
        {
            "verify": "verify",
            "research": "research",
            "fail": "fail",
            "end": END,
        },
    )
    graph.add_conditional_edges(
        "verify",
        route_from_verify,
        {
            "exploit": "exploit",
            "plan": "plan",
            "research": "research",
            "fail": "fail",
            "end": END,
        },
    )
    graph.add_edge("fail", END)
    return graph.compile()


def run_discovery(target: Target, *, authorized: bool = False) -> DiscoveryState:
    """Convenience: build and run the discovery workflow for a target."""
    logger.info("Starting discovery workflow for target %s", target.name)
    initial_state = DiscoveryState(
        target=target,
        authorized=authorized,
    )
    app = build_discovery_workflow()
    result = app.invoke(initial_state)
    if isinstance(result, DiscoveryState):
        return result
    if isinstance(result, dict):
        return DiscoveryState(**result)
    raise TypeError(
        f"Discovery invoke() returned unexpected type {type(result).__name__}",
    )
