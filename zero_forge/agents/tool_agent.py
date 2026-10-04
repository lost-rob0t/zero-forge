"""Tool Agent model selection and deterministic tool execution."""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from typing import Any, cast, get_type_hints

from pydantic import ConfigDict, ValidationError, create_model

from ..config import get_settings
from ..logging_config import get_logger
from ..schemas import (
    CollectedContext,
    SourceFile,
    ToolCall,
    ToolRequest,
    ToolResult,
    ValidationResult,
    VulnerabilityInput,
)
from ..tools.registry import ToolRegistry, create_default_registry
from .llm import LLMCallError, LLMResponseError, call_model, resolve_model

logger = get_logger(__name__)

TOOL_SYSTEM_PROMPT = """\
You are ZeroForge's Tool Agent. You only select one allowed registered tool and
construct its arguments. Never reason about exploit strategy, write or edit an
artifact, declare success, or add undeclared fields. Return only one JSON object:
{"name": "registered_tool_name", "arguments": {}}
Preserve every locked argument exactly as supplied.
"""


class ToolAgentError(RuntimeError):
    """Base error for a fail-closed Tool Agent boundary violation."""


class ToolSelectionError(ToolAgentError):
    """Raised when a Tool Agent call violates its request boundary."""


class ToolCallValidationError(ToolAgentError):
    """Raised before execution when tool arguments do not match the callable."""


_REPAIRABLE_SELECTION_ERRORS = (
    LLMResponseError,
    ToolSelectionError,
    ToolCallValidationError,
)


def _extract_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    parsed = json.loads(stripped)
    if not isinstance(parsed, dict):
        raise ValueError("Tool Agent response must be a JSON object")
    return parsed


def _argument_model(name: str, func: Callable[..., Any]):
    signature = inspect.signature(func)
    hints = get_type_hints(func)
    fields: dict[str, Any] = {}
    for parameter in signature.parameters.values():
        if parameter.kind in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD):
            raise ToolCallValidationError(
                f"Registered tool '{name}' cannot expose variadic arguments"
            )
        annotation = hints.get(parameter.name, Any)
        default = ... if parameter.default is inspect.Parameter.empty else parameter.default
        fields[parameter.name] = (annotation, default)
    return create_model(
        f"{name.title().replace('_', '')}Arguments",
        __config__=ConfigDict(extra="forbid", arbitrary_types_allowed=True),
        **fields,
    )


class ToolAgent:
    """Small model that selects allowlisted calls for deterministic execution."""

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self.registry = registry or create_default_registry()

    def _validate_request_allowlist(self, request: ToolRequest) -> list[str]:
        """Return the normalized allowlist after checking registered tools."""
        available = set(self.registry.names())
        allowed = sorted(set(request.allowed_tools))
        if not allowed or any(name not in available for name in allowed):
            raise ToolSelectionError("Tool request contains an unregistered tool")
        return allowed

    def _select_once(
        self,
        request: ToolRequest,
        allowed: list[str],
        corrective_messages: list[dict[str, str]],
        *,
        attempt: int,
        max_attempts: int,
    ) -> str | None:
        """Make one bounded Tool-model selection attempt."""
        settings = get_settings()
        if settings.llm.stub_mode:
            return None

        user_prompt = json.dumps(
            {
                "objective": request.objective,
                "allowed_tools": allowed,
                "arguments": request.arguments,
                "locked_arguments": request.locked_arguments,
            },
            sort_keys=True,
        )
        return call_model(
            "tool",
            settings.models.tool,
            TOOL_SYSTEM_PROMPT,
            user_prompt,
            additional_messages=corrective_messages,
            attempt=attempt,
            max_attempts=max_attempts,
        )

    @staticmethod
    def _parse_tool_call(
        raw: str,
        allowed: list[str],
        *,
        attempt: int,
        max_attempts: int,
    ) -> ToolCall:
        settings = get_settings()
        resolved = resolve_model("tool", settings.models.tool)
        try:
            call = ToolCall.model_validate(_extract_json_object(raw))
        except (json.JSONDecodeError, ValidationError, ValueError) as exc:
            raise LLMResponseError(
                f"Tool Agent response was not a strict ToolCall: {exc}",
                role="tool",
                provider=resolved.provider,
                model=resolved.model,
                retryable=False,
                attempt=attempt,
                max_attempts=max_attempts,
            ) from exc
        if call.name not in allowed:
            raise ToolSelectionError(f"Tool Agent selected disallowed tool '{call.name}'")
        return call

    @staticmethod
    def _corrective_message(exc: Exception) -> str:
        return (
            f"Your previous ToolCall was rejected: {exc}. Correct the error and return "
            "only one strict JSON object with an allowed registered tool name and "
            "arguments that match that tool's callable signature."
        )

    @staticmethod
    def _is_fully_locked(request: ToolRequest, allowed: list[str]) -> bool:
        """True when one tool is allowed and every argument is locked.

        In that case the model has nothing to decide: the tool name is fixed and
        every argument value is workflow-owned.  We skip the LLM call entirely
        and execute deterministically, which prevents model-dependent failures
        where the tool model alters or truncates locked argument values (issue
        #70) and eliminates malformed-JSON errors for fully-locked tools (issue
        #75).
        """
        if len(allowed) != 1:
            return False
        if not request.arguments:
            return False
        return set(request.arguments.keys()) <= set(request.locked_arguments.keys())

    def _select_with_repairs(
        self,
        request: ToolRequest,
        *,
        execute: bool,
    ) -> ToolCall | ToolResult:
        """Select, optionally validate/execute, and repair boundary failures."""
        settings = get_settings()
        allowed = self._validate_request_allowlist(request)

        # Deterministic shortcut: when every argument is locked and only one
        # tool is allowed, skip the LLM call entirely (issue #70).
        if self._is_fully_locked(request, allowed):
            call = ToolCall(name=allowed[0], arguments=request.arguments)
            self._validate_locked_arguments(call, request)
            if not execute:
                self._validated_arguments(call, allowed_tools=allowed)
                return call
            return self.execute_tool_call(call, allowed_tools=allowed)

        max_attempts = 1 if settings.llm.stub_mode else 1 + settings.workflow.max_repair_attempts
        corrective_messages: list[dict[str, str]] = []

        for attempt in range(1, max_attempts + 1):
            raw: str | None = None
            try:
                raw = self._select_once(
                    request,
                    allowed,
                    corrective_messages,
                    attempt=attempt,
                    max_attempts=max_attempts,
                )
                call = (
                    ToolCall(name=allowed[0], arguments=request.arguments)
                    if raw is None
                    else self._parse_tool_call(
                        raw,
                        allowed,
                        attempt=attempt,
                        max_attempts=max_attempts,
                    )
                )
                self._validate_locked_arguments(call, request)
                if not execute:
                    self._validated_arguments(call, allowed_tools=allowed)
                    return call
                return self.execute_tool_call(call, allowed_tools=allowed)
            except _REPAIRABLE_SELECTION_ERRORS as exc:
                if attempt >= max_attempts:
                    raise
                if raw:
                    corrective_messages.append({"role": "assistant", "content": raw})
                corrective_messages.append(
                    {"role": "user", "content": self._corrective_message(exc)}
                )

        raise AssertionError("Tool selection loop exited without a result")

    @staticmethod
    def _validate_locked_arguments(call: ToolCall, request: ToolRequest) -> None:
        """Reject model output that changes workflow-owned argument values."""
        changed = [
            name
            for name, value in request.locked_arguments.items()
            if name not in call.arguments or call.arguments[name] != value
        ]
        if changed:
            names = ", ".join(sorted(changed))
            raise ToolSelectionError(f"Tool Agent changed locked argument(s): {names}")

    def select_tool_call(self, request: ToolRequest) -> ToolCall:
        result = self._select_with_repairs(request, execute=False)
        if not isinstance(result, ToolCall):
            raise AssertionError("Tool selection returned an unexpected result")
        return result

    def execute_tool_call(
        self,
        call: ToolCall,
        *,
        allowed_tools: list[str] | None = None,
    ) -> ToolResult:
        arguments = self._validated_arguments(call, allowed_tools=allowed_tools)

        resolved = resolve_model("tool", get_settings().models.tool)
        try:
            output = self.registry.call(call.name, **arguments)
        except (LLMCallError, ToolAgentError):
            raise
        except Exception as exc:
            return ToolResult(
                name=call.name,
                error=f"{type(exc).__name__}: {exc}",
                provider=resolved.provider,
                model=resolved.model,
            )
        return ToolResult(
            name=call.name,
            output=output,
            provider=resolved.provider,
            model=resolved.model,
        )

    def _validated_arguments(
        self,
        call: ToolCall,
        *,
        allowed_tools: list[str] | None = None,
    ) -> dict[str, Any]:
        """Validate a selected call without executing its registered tool."""
        if allowed_tools is not None and call.name not in allowed_tools:
            raise ToolSelectionError(f"Tool call is outside the request allowlist: {call.name}")
        if not self.registry.has(call.name):
            raise ToolSelectionError(f"Tool is not registered: {call.name}")

        func = self.registry.get(call.name)
        arguments_model = _argument_model(call.name, func)
        try:
            arguments = arguments_model.model_validate(call.arguments).model_dump()
        except ValidationError as exc:
            raise ToolCallValidationError(
                f"Invalid arguments for registered tool '{call.name}': "
                f"{exc.errors(include_url=False)}"
            ) from exc
        return cast(dict[str, Any], arguments)

    def run(self, request: ToolRequest) -> ToolResult:
        result = self._select_with_repairs(request, execute=True)
        if not isinstance(result, ToolResult):
            raise AssertionError("Tool execution returned an unexpected result")
        return result

    def _call_tool(self, objective: str, name: str, **arguments: Any) -> Any:
        result = self.run(
            ToolRequest(
                objective=objective,
                allowed_tools=[name],
                arguments=arguments,
                locked_arguments=arguments,
            )
        )
        if result.error:
            raise RuntimeError(result.error)
        return result.output

    def collect_context(self, vuln_input: VulnerabilityInput) -> CollectedContext:
        """Collect vulnerability context through bounded Tool Agent calls."""
        logger.debug("Collecting context for CVE %s", vuln_input.cve_id)
        ctx = CollectedContext(
            cve_id=vuln_input.cve_id,
            poc_text=vuln_input.poc_text,
            writeup_text=vuln_input.writeup_text,
            patch_diff=vuln_input.patch_diff,
        )

        if vuln_input.cve_id:
            try:
                cve_data = self._call_tool(
                    "Look up authoritative context for the supplied CVE",
                    "cve_lookup",
                    cve_id=vuln_input.cve_id,
                )
                lookup_status = cve_data.get("status", "success")
                if lookup_status == "success":
                    ctx.cve_description = cve_data.get("description", "")
                    ctx.references = cve_data.get("references", [])
                    if cve_data.get("published"):
                        ctx.extra_notes = (
                            f"CVSS: {cve_data.get('cvss', 'N/A')}, "
                            f"Published: {cve_data['published']}"
                        )
                elif lookup_status == "not_found":
                    ctx.extra_notes = (
                        "CVE lookup: not found in NVD. Proceeding with user-supplied context only."
                    )
                else:
                    error_category = cve_data.get("error_category", "unknown")
                    error_message = cve_data.get("error_message", "")
                    ctx.extra_notes = (
                        f"CVE lookup failed ({error_category}): {error_message}."
                        " Proceeding with degraded context —"
                        " generated artifacts may lack authoritative detail."
                    )
            except (LLMCallError, ToolAgentError):
                raise
            except Exception as exc:
                ctx.extra_notes = f"CVE lookup failed: {exc}"

        unsafe = False
        admitted_paths: list[str] = []
        if vuln_input.source_path:
            try:
                unsafe = get_settings().workflow.unsafe_source_collection
                files = self._call_tool(
                    "Read bounded source context from the supplied repository",
                    "read_source_files",
                    source_path=vuln_input.source_path,
                    unsafe=unsafe,
                )
                readable = [item for item in files if not item.get("skipped")]
                skipped = [item for item in files if item.get("skipped")]
                ctx.source_files = [SourceFile(**item) for item in readable]
                ctx.skipped_files = skipped
                admitted_paths = [source_file.path for source_file in ctx.source_files]

                if skipped:
                    ctx.extra_notes += (
                        f"\nSource collection skipped {len(skipped)} file(s) "
                        f"(secrets, symlinks, or gitignored)."
                    )

                if not vuln_input.writeup_text:
                    doc_parts = [
                        f"## {source_file.filename}\n\n{source_file.content[:8000]}"
                        for source_file in ctx.source_files
                        if source_file.category == "documentation"
                    ]
                    if doc_parts:
                        ctx.writeup_text = "\n\n---\n\n".join(doc_parts)
            except (LLMCallError, ToolAgentError):
                raise
            except Exception as exc:
                ctx.extra_notes += f"\nSource read failed: {exc}"

        if vuln_input.patch_diff:
            try:
                diff_info = self._call_tool(
                    "Inspect the supplied patch for changed files and lines",
                    "git_diff_inspect",
                    diff_text=vuln_input.patch_diff,
                )
                ctx.affected_versions = diff_info.get("diff_summary", "")
            except (LLMCallError, ToolAgentError):
                raise
            except Exception:
                pass

        if vuln_input.source_path and vuln_input.cve_id:
            try:
                pattern = vuln_input.cve_id.replace("CVE-", "")
                search_results = self._call_tool(
                    "Search admitted source files for the CVE identifier",
                    "search_code",
                    source_path=vuln_input.source_path,
                    pattern=pattern,
                    unsafe=unsafe,
                    allowed_paths=admitted_paths if not unsafe else None,
                )
                if search_results:
                    ctx.extra_notes += (
                        f"\nCode search found {len(search_results)} match(es) for '{pattern}'."
                    )
            except (LLMCallError, ToolAgentError):
                raise
            except Exception:
                pass

        return ctx

    def validate_artifact(
        self,
        content: str,
        artifact_type: str = "metasploit",
    ) -> ValidationResult:
        """Select and execute the registered validator for an artifact type."""
        logger.debug("Validating artifact type=%s", artifact_type)
        tool_name = f"validate_{artifact_type}"
        if not self.registry.has(tool_name):
            return ValidationResult(
                is_valid=False,
                errors=[f"No validator registered for artifact type: {artifact_type}"],
            )
        try:
            result = self._call_tool(
                "Validate the supplied artifact with its registered validator",
                tool_name,
                content=content,
            )
            return ValidationResult(**result)
        except (LLMCallError, ToolAgentError):
            raise
        except Exception as exc:
            return ValidationResult(
                is_valid=False,
                errors=[f"Validation tool error: {exc}"],
            )

    def list_available_tools(self) -> list[str]:
        return self.registry.names()
