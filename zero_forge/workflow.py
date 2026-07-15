"""LangGraph workflow for the ZeroForge harness."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph

from .agents.smart_agent import LLMCallError, generate_artifact, repair_artifact
from .agents.tool_agent import ToolAgent
from .schemas import WorkflowError, WorkflowState
from .tools.validator import ValidatorRuntimeUnavailable, require_ruby_runtime


def collect_context_node(state: WorkflowState) -> dict[str, Any]:
    """Node: collect vulnerability context using the Tool Agent."""
    agent = ToolAgent()
    ctx = agent.collect_context(state.vuln_input)
    return {"context": ctx, "status": "context_collected"}


def generate_artifact_node(state: WorkflowState) -> dict[str, Any]:
    """Node: Smart Agent generates the initial artifact."""
    if state.context is None:
        return {"error": "No context available for generation", "status": "error"}
    try:
        artifact = generate_artifact(state.vuln_input, state.context)
    except LLMCallError as exc:
        return {
            "error": str(exc),
            "failure": exc.as_workflow_error(),
            "status": "failed",
        }
    if artifact.metadata.get("stub"):
        message = "Stub mode generated a placeholder; no exploit artifact was produced"
        return {
            "artifact": artifact,
            "error": message,
            "failure": WorkflowError(
                code="stub_artifact",
                message=message,
                provider="stub",
                model=str(artifact.metadata.get("model", "")),
            ),
            "status": "stub_generated",
        }
    return {"artifact": artifact, "status": "artifact_generated"}


def validate_artifact_node(state: WorkflowState) -> dict[str, Any]:
    """Node: Tool Agent validates the generated artifact."""
    if state.artifact is None:
        return {"error": "No artifact to validate", "status": "error"}
    agent = ToolAgent()
    validation = agent.validate_artifact(state.artifact.content, state.artifact.artifact_type.value)
    return {"validation": validation, "status": "validated"}


def repair_artifact_node(state: WorkflowState) -> dict[str, Any]:
    """Node: Smart Agent repairs the artifact based on validation errors."""
    if state.artifact is None or state.validation is None or state.context is None:
        return {"error": "Missing data for repair", "status": "error"}
    repair_context = state.context.model_copy()
    repair_context.extra_notes += f"\nRepair attempt #{state.repair_attempts + 1}"
    try:
        repaired = repair_artifact(state.artifact, state.validation, repair_context)
    except LLMCallError as exc:
        return {
            "error": str(exc),
            "failure": exc.as_workflow_error(),
            "repair_attempts": state.repair_attempts + 1,
            "status": "failed",
        }
    return {
    "artifact": repaired,
    "repair_attempts": state.repair_attempts + 1,
    "status": "repaired",
}


def save_artifact_node(state: WorkflowState) -> dict[str, Any]:
    """Node: save the validated artifact to the filesystem.

    Only runs when validation exists and is valid. If validation is missing
    or invalid, this node should not have been reached; we guard defensively
    by returning a failed status instead of saving.
    """
    if state.validation is None:
        return {"error": "Missing validation result", "status": "failed"}
    if not state.validation.is_valid:
        errors = (
    "; ".join(state.validation.errors)
    if state.validation.errors
    else "Artifact failed validation"
)
        return {"error": errors, "status": "failed"}
    if state.artifact is None:
        return {"error": "No artifact to save", "status": "failed"}
    if state.artifact.metadata.get("stub"):
        return {"error": "Refusing to save a stub artifact as completed", "status": "failed"}
    from .output import save_artifact
    output_path = save_artifact(state.artifact)
    return {"output_path": output_path, "status": "completed"}


def fail_node(state: WorkflowState) -> dict[str, Any]:
    """Terminal node: mark the workflow as failed and preserve validation errors."""
    if state.error:
        errors = state.error
    elif state.validation is not None and state.validation.errors:
        errors = "; ".join(state.validation.errors)
    elif state.validation is None:
        errors = "Missing validation result"
    else:
        errors = "Artifact failed validation"
    return {"error": errors, "status": "failed"}


def should_validate_or_fail(state: WorkflowState) -> str:
    """Route generation to validation only when a real artifact exists."""
    if state.failure is not None or state.status != "artifact_generated":
        return "fail"
    return "validate"


def should_repair_or_finish(state: WorkflowState) -> str:
    """Conditional edge: decide whether to repair, save, or fail."""
    if state.validation is None:
        return "fail"
    if state.validation.is_valid:
        return "save"
    if state.validation.runtime_error:
        return "fail"
    if state.repair_attempts >= state.max_repair_attempts:
        return "fail"
    return "repair"


def should_repair_after_fix(state: WorkflowState) -> str:
    """Conditional edge: after repair, always re-validate.

    The max-repair-attempts check is handled by ``should_repair_or_finish``
    after validation runs, so a repaired artifact is never saved without
    being re-validated.
    """
    if state.failure is not None or state.status == "failed":
        return "fail"
    return "validate"


def build_workflow() -> CompiledStateGraph[WorkflowState, None, WorkflowState, WorkflowState]:
    """Build and compile the LangGraph workflow."""
    graph = StateGraph(WorkflowState)
    graph.add_node("collect_context", collect_context_node)
    graph.add_node("generate_artifact", generate_artifact_node)
    graph.add_node("validate_artifact", validate_artifact_node)
    graph.add_node("repair_artifact", repair_artifact_node)
    graph.add_node("save_artifact", save_artifact_node)
    graph.add_node("fail", fail_node)
    graph.set_entry_point("collect_context")
    graph.add_edge("collect_context", "generate_artifact")
    graph.add_conditional_edges(
        "generate_artifact",
        should_validate_or_fail,
        {"validate": "validate_artifact", "fail": "fail"},
    )
    graph.add_conditional_edges(
        "validate_artifact",
        should_repair_or_finish,
        {"repair": "repair_artifact", "save": "save_artifact", "fail": "fail"},
    )
    graph.add_conditional_edges(
        "repair_artifact",
        should_repair_after_fix,
        {"validate": "validate_artifact", "fail": "fail"},
    )
    graph.add_edge("save_artifact", END)
    graph.add_edge("fail", END)
    return graph.compile()


def run_workflow(vuln_input) -> WorkflowState:
    """Convenience: build and run the workflow with given input."""
    from .config import get_settings
    from .schemas import VulnerabilityInput
    if isinstance(vuln_input, dict):
        vuln_input = VulnerabilityInput(**vuln_input)
    initial_state = WorkflowState(
        vuln_input=vuln_input,
        max_repair_attempts=get_settings().workflow.max_repair_attempts,
    )
    try:
        require_ruby_runtime()
    except ValidatorRuntimeUnavailable as exc:
        message = str(exc)
        return initial_state.model_copy(
            update={
                "error": message,
                "failure": WorkflowError(
                    code="validator_runtime_unavailable",
                    message=message,
                ),
                "status": "failed",
            }
        )
    app = build_workflow()
    result = app.invoke(initial_state)
    if isinstance(result, WorkflowState):
        return result
    if isinstance(result, dict):
        return WorkflowState(**result)
    raise TypeError(f"LangGraph invoke() returned unexpected type {type(result).__name__}")
