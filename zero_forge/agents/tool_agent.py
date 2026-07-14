"""Tool Agent: performs tool calls, searches, repository inspection, and validation."""

from __future__ import annotations

from typing import Any

from ..schemas import CollectedContext, SourceFile, ValidationResult, VulnerabilityInput
from ..tools.registry import ToolRegistry, create_default_registry


class ToolAgent:
    """Agent that executes tool calls to collect context and validate artifacts."""

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self.registry = registry or create_default_registry()

    def collect_context(self, vuln_input: VulnerabilityInput) -> CollectedContext:
        """Collect vulnerability context using registered tools."""
        ctx = CollectedContext(
            cve_id=vuln_input.cve_id,
            poc_text=vuln_input.poc_text,
            writeup_text=vuln_input.writeup_text,
            patch_diff=vuln_input.patch_diff,
        )

        # CVE lookup
        try:
            cve_data = self.registry.call("cve_lookup", cve_id=vuln_input.cve_id)
            ctx.cve_description = cve_data.get("description", "")
            ctx.references = cve_data.get("references", [])
            if cve_data.get("published"):
                ctx.extra_notes = f"CVSS: {cve_data.get('cvss', 'N/A')}, Published: {cve_data['published']}"
        except Exception as e:
            ctx.extra_notes = f"CVE lookup failed: {e}"

        # Read source files
        if vuln_input.source_path:
            try:
                files = self.registry.call("read_source_files", source_path=vuln_input.source_path)
                ctx.source_files = [SourceFile(**f) for f in files]
            except Exception as e:
                ctx.extra_notes += f"\nSource read failed: {e}"

        # Inspect patch diff
        if vuln_input.patch_diff:
            try:
                diff_info = self.registry.call("git_diff_inspect", diff_text=vuln_input.patch_diff)
                ctx.affected_versions = diff_info.get("diff_summary", "")
            except Exception:
                pass

        # Search for patterns in source
        if vuln_input.source_path and vuln_input.cve_id:
            try:
                pattern = vuln_input.cve_id.replace("CVE-", "")
                search_results = self.registry.call("search_code", source_path=vuln_input.source_path, pattern=pattern)
                if search_results:
                    ctx.extra_notes += f"\nCode search found {len(search_results)} match(es) for '{pattern}'."
            except Exception:
                pass

        return ctx

    def validate_artifact(self, content: str, artifact_type: str = "metasploit") -> ValidationResult:
        """Validate a generated artifact using registered validation tools."""
        tool_name = f"validate_{artifact_type}"
        if self.registry.has(tool_name):
            try:
                result = self.registry.call(tool_name, content=content)
                return ValidationResult(**result)
            except Exception as e:
                return ValidationResult(is_valid=False, errors=[f"Validation tool error: {e}"])
        return ValidationResult(is_valid=False, errors=[f"No validator registered for artifact type: {artifact_type}"])

    def list_available_tools(self) -> list[str]:
        return self.registry.names()
