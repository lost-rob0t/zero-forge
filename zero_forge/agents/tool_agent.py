"""Tool Agent model selection and deterministic tool execution."""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from typing import Any, get_type_hints

from pydantic import ConfigDict, ValidationError, create_model

from ..config import get_settings
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

TOOL_SYSTEM_PROMPT = """\
You are ZeroForge's Tool Agent. You only select one allowed registered tool and
construct its arguments. Never reason about exploit strategy, write or edit an
artifact, declare success, or add undeclared fields. Return only one JSON object:
{"name": "registered_tool_name", "arguments": {}}
"""


class ToolAgentError(RuntimeError):
    """Base error for a fail-closed Tool Agent boundary violation."""


class ToolSelectionError(ToolAgentError):
    """Raised when a Tool Agent call violates its request boundary."""


class ToolCallValidationError(ToolAgentError):
    """Raised before execution when tool arguments do not match the callable."""


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

    def select_tool_call(self, request: ToolRequest) -> ToolCall:
        settings = get_settings()
        available = set(self.registry.names())
        allowed = sorted(set(request.allowed_tools))
        if not allowed or any(name not in available for name in allowed):
            raise ToolSelectionError("Tool request contains an unregistered tool")
        if settings.llm.stub_mode:
            return ToolCall(name=allowed[0], arguments=request.arguments)

        user_prompt = json.dumps(
            {
                "objective": request.objective,
                "allowed_tools": allowed,
                "arguments": request.arguments,
            },
            sort_keys=True,
        )
        raw = call_model("tool", settings.models.tool, TOOL_SYSTEM_PROMPT, user_prompt)
        resolved = resolve_model("tool", settings.models.tool)
        try:
            call = ToolCall.model_validate(_extract_json_object(raw))
        except (json.JSONDecodeError, ValidationError, ValueError) as exc:
            raise LLMResponseError(
                "Tool Agent response was not a strict ToolCall",
                role="tool",
                provider=resolved.provider,
                model=resolved.model,
                retryable=False,
            ) from exc
        if call.name not in allowed:
            raise ToolSelectionError(f"Tool Agent selected disallowed tool '{call.name}'")
        return call

    def execute_tool_call(
        self,
        call: ToolCall,
        *,
        allowed_tools: list[str] | None = None,
    ) -> ToolResult:
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
                f"Invalid arguments for registered tool '{call.name}'"
            ) from exc

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

    def run(self, request: ToolRequest) -> ToolResult:
        call = self.select_tool_call(request)
        return self.execute_tool_call(call, allowed_tools=request.allowed_tools)

    def _call_tool(self, objective: str, name: str, **arguments: Any) -> Any:
        result = self.run(
            ToolRequest(
                objective=objective,
                allowed_tools=[name],
                arguments=arguments,
            )
        )
        if result.error:
            raise RuntimeError(result.error)
        return result.output

    def collect_context(self, vuln_input: VulnerabilityInput) -> CollectedContext:
        """Collect vulnerability context through bounded Tool Agent calls."""
        ctx = CollectedContext(
            cve_id=vuln_input.cve_id,
            poc_text=vuln_input.poc_text,
            writeup_text=vuln_input.writeup_text,
            patch_diff=vuln_input.patch_diff,
        )

        try:
            cve_data = self._call_tool(
                "Look up authoritative context for the supplied CVE",
                "cve_lookup",
                cve_id=vuln_input.cve_id,
            )
            ctx.cve_description = cve_data.get("description", "")
            ctx.references = cve_data.get("references", [])
            if cve_data.get("published"):
                ctx.extra_notes = (
                    f"CVSS: {cve_data.get('cvss', 'N/A')}, "
                    f"Published: {cve_data['published']}"
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
