"""Typer CLI for ZeroForge."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

import typer
from rich.console import Console
from rich.table import Table

from .config import ensure_default_config, get_settings
from .lab_cli import register_lab_commands
from .logging_config import setup_logging_from_settings
from .schemas import ArtifactType, ToolRequest, VulnerabilityInput, WorkflowState
from .workflow import run_workflow

if TYPE_CHECKING:
    from .discovery.schemas import SourceSnapshot

app = typer.Typer(
    name="zero-forge",
    help="LLM-based security artifact generation harness",
    no_args_is_help=True,
)
console = Console()

_ARTIFACT_TYPE_OPTION = cast(
    ArtifactType,
    typer.Option(
        ArtifactType.METASPLOIT,
        "--type",
        "-t",
        help="Artifact type to generate (ignored when --all is set)",
        case_sensitive=False,
    ),
)
_WEB_QUERIES_OPTION = cast(
    list[str],
    typer.Option([], "--web-query", help="Repeat for multiple bounded research queries"),
)
_OUTPUT_FORMATS_OPTION = cast(
    list[str],
    typer.Option(
        [],
        "--format",
        "-f",
        help="Repeat to emit markdown, org, or json reports",
    ),
)


def _build_vuln_input(
    cve_id: str,
    artifact_type: ArtifactType,
    poc_text: str,
    writeup_text: str,
    source_path: str,
    patch_diff: str,
) -> VulnerabilityInput:
    return VulnerabilityInput(
        cve_id=cve_id,
        artifact_type=artifact_type,
        poc_text=poc_text,
        writeup_text=writeup_text,
        source_path=source_path or None,
        patch_diff=patch_diff,
    )


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace") if path else ""


def _load_env_file() -> None:
    """Load .env before settings are read."""
    import os

    from dotenv import dotenv_values

    path = os.environ.get("ZERO_FORGE_ENV_FILE") or ".env"
    values = dotenv_values(path)
    for key, value in values.items():
        if key not in os.environ and value is not None:
            os.environ[key] = value


def _ensure_config(config_file: str) -> None:
    _load_env_file()
    if config_file:
        return
    new_config = ensure_default_config()
    if new_config is not None:
        console.print(
            f"[yellow]Created default config at {new_config}.[/]\n"
            "[yellow]Edit it to configure your models and API keys, then re-run.[/]"
        )
        raise typer.Exit()


def _apply_env_overrides(*, output_dir: str, unsafe: bool, config_file: str) -> None:
    _load_env_file()
    if config_file:
        import os

        os.environ["ZERO_FORGE_CONFIG_PATH"] = config_file
        get_settings(reload=True)
    get_settings()
    if unsafe:
        import os

        os.environ["ZERO_FORGE_UNSAFE_SOURCE"] = "true"
        get_settings(reload=True)
    if output_dir:
        import os

        os.environ["ZERO_FORGE_OUTPUT_DIR"] = output_dir
        get_settings(reload=True)


def _print_result_table(results: list[tuple[ArtifactType, WorkflowState]]) -> None:
    table = Table(title="ZeroForge Results")
    table.add_column("Artifact Type", style="cyan")
    table.add_column("Status")
    table.add_column("Valid")
    table.add_column("Output")
    table.add_column("Errors")
    for artifact_type, result in results:
        valid = str(result.validation.is_valid) if result.validation else "—"
        errors = (
            "\n".join(result.validation.errors)
            if result.validation and result.validation.errors
            else (result.error or "")
        )
        table.add_row(
            artifact_type.value,
            result.status,
            valid,
            result.output_path or "—",
            errors or "—",
        )
    console.print(table)
    for artifact_type, result in results:
        if result.output_path:
            console.print(f"[green]✓[/] {artifact_type.value}: {result.output_path}")


def _resolve_output_formats(values: list[str], all_formats: bool) -> list[str]:
    allowed = ("markdown", "org", "json")
    if all_formats:
        return list(allowed)
    if not values:
        return ["markdown", "org"]
    normalized: list[str] = []
    for value in values:
        lowered = value.strip().lower()
        if lowered not in allowed:
            raise typer.BadParameter(f"unsupported format '{value}'; choose markdown, org, or json")
        if lowered not in normalized:
            normalized.append(lowered)
    return normalized


def _source_snapshots(source_path: str, unsafe: bool) -> list[SourceSnapshot]:
    if not source_path:
        return []
    from .agents.tool_agent import ToolAgent
    from .discovery.schemas import SourceSnapshot

    arguments = {
        "source_path": source_path,
        "max_files": 20,
        "max_file_size": 51200,
        "unsafe": unsafe,
    }
    result = ToolAgent().run(
        ToolRequest(
            objective="Collect bounded source context for exploit drafting",
            allowed_tools=["read_source_files"],
            arguments=arguments,
            locked_arguments=arguments,
        )
    )
    if result.error:
        raise typer.BadParameter(f"source collection failed: {result.error}")
    raw = result.output if isinstance(result.output, list) else []
    return [
        SourceSnapshot(
            path=str(item.get("path", "")),
            filename=str(item.get("filename", "")),
            language=str(item.get("language", "unknown")),
            category=str(item.get("category", "code")),
            content=str(item.get("content", "")),
        )
        for item in raw
        if isinstance(item, dict) and not item.get("skipped") and not item.get("truncated")
    ]


@app.command()
def generate(
    cve_id: str = typer.Option(
        "",
        "--cve",
        "-c",
        help="CVE identifier (e.g. CVE-2021-44228). Optional for source-only analysis.",
    ),
    artifact_type: ArtifactType = _ARTIFACT_TYPE_OPTION,
    all_types: bool = typer.Option(
        False, "--all", help="Generate artifacts for every supported type (overrides --type)"
    ),
    poc_file: str = typer.Option("", "--poc", "-p", help="Path to proof-of-concept file"),
    writeup_file: str = typer.Option("", "--writeup", "-w", help="Path to vulnerability write-up"),
    source_path: str = typer.Option("", "--source", "-s", help="Path to vulnerable source code"),
    patch_file: str = typer.Option("", "--patch", "-d", help="Path to patch/diff file"),
    output_dir: str = typer.Option(
        "", "--output", "-o", help="Output directory (overrides config)"
    ),
    config_file: str = typer.Option("", "--config", help="Path to YAML config file"),
    unsafe: bool = typer.Option(
        False,
        "--unsafe",
        help="Allow reading secrets and following symlinks during source collection",
    ),
) -> None:
    """Generate security artifact(s) from vulnerability context."""
    _ensure_config(config_file)
    _apply_env_overrides(output_dir=output_dir, unsafe=unsafe, config_file=config_file)
    setup_logging_from_settings()
    label = cve_id or "source-only analysis (no CVE)"
    console.print(f"[bold]ZeroForge[/] — generating artifact(s) for {label}")
    poc_text = _read(poc_file)
    writeup_text = _read(writeup_file)
    patch_diff = _read(patch_file)
    types_to_run = list[ArtifactType](ArtifactType) if all_types else [artifact_type]
    results: list[tuple[ArtifactType, WorkflowState]] = []
    for at in types_to_run:
        console.print(f"\n[cyan]→ {at.value}[/]")
        result = run_workflow(
            _build_vuln_input(
                cve_id=cve_id,
                artifact_type=at,
                poc_text=poc_text,
                writeup_text=writeup_text,
                source_path=source_path,
                patch_diff=patch_diff,
            )
        )
        results.append((at, result))
    console.print()
    _print_result_table(results)
    if any(result.status != "completed" for _, result in results):
        raise typer.Exit(code=1)


@app.command("draft")
def draft_exploit(
    candidate_file: str = typer.Option(..., "--candidate", help="Path to CandidateFinding JSON"),
    hypothesis_file: str = typer.Option(
        ..., "--hypothesis", help="Path to SecurityHypothesis JSON"
    ),
    artifact_type: str = typer.Option(
        "metasploit",
        "--type",
        "-t",
        help="metasploit, python, zap_active, or zap_passive",
    ),
    source_path: str = typer.Option("", "--source", "-s", help="Optional authorized source tree"),
    web_queries: list[str] = _WEB_QUERIES_OPTION,
    output_formats: list[str] = _OUTPUT_FORMATS_OPTION,
    all_formats: bool = typer.Option(
        False, "--all-formats", help="Emit Markdown, Org, and JSON reports"
    ),
    output_dir: str = typer.Option(
        "", "--output", "-o", help="Output directory (overrides config)"
    ),
    max_iterations: int = typer.Option(
        4,
        "--max-iterations",
        min=1,
        max=8,
        help="Maximum Smart Agent repair iterations",
    ),
    authorized: bool = typer.Option(
        False, "--authorized", help="Confirm that this investigation is explicitly authorized"
    ),
    config_file: str = typer.Option("", "--config", help="Path to YAML config file"),
    unsafe: bool = typer.Option(
        False,
        "--unsafe",
        help="Allow unsafe source collection for this authorized investigation",
    ),
) -> None:
    """Iteratively draft and validate an exploit artifact, then publish its bundle."""
    from .discovery.exploit_loop import ArtifactType as DraftArtifactType
    from .discovery.exploit_loop import (
        ExploitIterationRequest,
        OutputFormat,
        run_exploit_iteration,
    )
    from .discovery.schemas import CandidateFinding, SecurityHypothesis

    if not authorized:
        raise typer.BadParameter("--authorized is required")
    _ensure_config(config_file)
    _apply_env_overrides(output_dir=output_dir, unsafe=unsafe, config_file=config_file)
    setup_logging_from_settings()
    candidate = CandidateFinding.model_validate_json(_read(candidate_file))
    hypothesis = SecurityHypothesis.model_validate_json(_read(hypothesis_file))
    formats = _resolve_output_formats(output_formats, all_formats)
    result = run_exploit_iteration(
        ExploitIterationRequest(
            authorized=True,
            candidate=candidate,
            hypothesis=hypothesis,
            source_files=_source_snapshots(source_path, unsafe),
            web_queries=web_queries,
            artifact_type=cast(DraftArtifactType, artifact_type),
            max_iterations=max_iterations,
            output_dir=output_dir,
            output_formats=[cast(OutputFormat, value) for value in formats],
        )
    )
    table = Table(title="Exploit Draft Result")
    table.add_column("Status")
    table.add_column("Formats")
    table.add_column("Output")
    table.add_column("Artifact")
    table.add_column("Error")
    table.add_row(
        result.status,
        ", ".join(result.output_formats),
        result.output_path or result.workspace_path or "—",
        result.final_path or "—",
        result.error or "—",
    )
    console.print(table)
    if result.status != "completed":
        raise typer.Exit(code=1)


@app.command()
def tools() -> None:
    """List available tools in the registry."""
    from .agents.tool_agent import ToolAgent

    agent = ToolAgent()
    table = Table(title="Registered Tools")
    table.add_column("Name", style="cyan")
    table.add_column("Index")
    for index, name in enumerate(agent.list_available_tools(), 1):
        table.add_row(name, str(index))
    console.print(table)


@app.command()
def validate(
    file: str = typer.Argument(..., help="Path to artifact file"),
    artifact_type: str = typer.Option("metasploit", "--type", "-t", help="Artifact type"),
) -> None:
    """Validate an existing artifact file."""
    from .agents.tool_agent import ToolAgent

    content = Path(file).read_text(encoding="utf-8", errors="replace")
    result = ToolAgent().validate_artifact(content, artifact_type)
    if result.is_valid:
        console.print("[green]✓ Artifact is valid[/]")
    else:
        console.print("[red]✗ Artifact has errors[/]")
        for err in result.errors:
            console.print(f"  [red]•[/] {err}")
    for warn in result.warnings:
        console.print(f"  [yellow]![/] {warn}")


register_lab_commands(app, console, _ensure_config, _apply_env_overrides)

if __name__ == "__main__":
    app()
