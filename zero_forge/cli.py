"""Typer CLI for ZeroForge."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import typer
from rich.console import Console
from rich.table import Table

from .config import get_settings
from .logging_config import setup_logging_from_settings
from .schemas import ArtifactType, VulnerabilityInput, WorkflowState
from .workflow import run_workflow

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


def _apply_env_overrides(*, output_dir: str, unsafe: bool, config_file: str) -> None:
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


def _print_result_table(
    results: list[tuple[ArtifactType, WorkflowState]],
) -> None:
    """Print a combined results table for one or more artifact types."""
    table = Table(title="ZeroForge Results")
    table.add_column("Artifact Type", style="cyan")
    table.add_column("Status")
    table.add_column("Valid")
    table.add_column("Output")
    table.add_column("Errors")

    for artifact_type, result in results:
        valid = (
            str(result.validation.is_valid)
            if result.validation
            else "—"
        )
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
            console.print(
                f"[green]✓[/] {artifact_type.value}: {result.output_path}"
            )


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
        False,
        "--all",
        help="Generate artifacts for every supported type (overrides --type)",
    ),
    poc_file: str = typer.Option("", "--poc", "-p", help="Path to proof-of-concept file"),
    writeup_file: str = typer.Option("", "--writeup", "-w", help="Path to vulnerability write-up"),
    source_path: str = typer.Option("", "--source", "-s", help="Path to vulnerable source code"),
    patch_file: str = typer.Option("", "--patch", "-d", help="Path to patch/diff file"),
    output_dir: str = typer.Option("", "--output", "-o",
                              help="Output directory (overrides config)"),
    config_file: str = typer.Option("", "--config", help="Path to YAML config file"),
    unsafe: bool = typer.Option(
        False, "--unsafe",
        help="Allow reading secrets and following symlinks during source collection",
    ),
) -> None:
    """Generate security artifact(s) from vulnerability context.

    Use --all to generate every supported artifact type for the same CVE.
    New artifact types can be added by extending the ArtifactType enum,
    registering an ArtifactProfile, a validator, and example files.
    """
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
        vuln_input = _build_vuln_input(
            cve_id=cve_id,
            artifact_type=at,
            poc_text=poc_text,
            writeup_text=writeup_text,
            source_path=source_path,
            patch_diff=patch_diff,
        )
        result = run_workflow(vuln_input)
        results.append((at, result))

    console.print()
    _print_result_table(results)


@app.command()
def tools() -> None:
    """List available tools in the registry."""
    from .agents.tool_agent import ToolAgent
    agent = ToolAgent()
    table = Table(title="Registered Tools")
    table.add_column("Name", style="cyan")
    table.add_column("Index")
    for i, name in enumerate(agent.list_available_tools(), 1):
        table.add_row(name, str(i))
    console.print(table)


@app.command()
def validate(
    file: str = typer.Argument(..., help="Path to artifact file"),
    artifact_type: str = typer.Option("metasploit", "--type", "-t", help="Artifact type"),
) -> None:
    """Validate an existing artifact file."""
    from .agents.tool_agent import ToolAgent
    content = Path(file).read_text(encoding="utf-8", errors="replace")
    agent = ToolAgent()
    result = agent.validate_artifact(content, artifact_type)

    if result.is_valid:
        console.print("[green]✓ Artifact is valid[/]")
    else:
        console.print("[red]✗ Artifact has errors[/]")
        for err in result.errors:
            console.print(f"  [red]•[/] {err}")
    for warn in result.warnings:
        console.print(f"  [yellow]![/] {warn}")


if __name__ == "__main__":
    app()
