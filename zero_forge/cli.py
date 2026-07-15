"""Typer CLI for ZeroForge."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import typer
from rich.console import Console
from rich.table import Table

from .config import get_settings
from .schemas import ArtifactType, VulnerabilityInput
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
        help="Artifact type to generate",
        case_sensitive=False,
    ),
)


@app.command()
def generate(
    cve_id: str = typer.Option(..., "--cve", "-c", help="CVE identifier (e.g. CVE-2021-44228)"),
    artifact_type: ArtifactType = _ARTIFACT_TYPE_OPTION,
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
    """Generate a security artifact from vulnerability context."""
    # Load config if --config specified, refreshing the singleton
    if config_file:
        import os
        os.environ["ZERO_FORGE_CONFIG_PATH"] = config_file
        get_settings(reload=True)

    get_settings()

    console.print(f"[bold]ZeroForge[/] — generating artifact for {cve_id}")

    def _read(path: str) -> str:
        return Path(path).read_text(encoding="utf-8", errors="replace") if path else ""

    poc_text = _read(poc_file)
    writeup_text = _read(writeup_file)
    patch_diff = _read(patch_file)

    vuln_input = VulnerabilityInput(
        cve_id=cve_id,
        artifact_type=artifact_type,
        poc_text=poc_text,
        writeup_text=writeup_text,
        source_path=source_path or None,
        patch_diff=patch_diff,
    )

    # CLI --unsafe enables unsafe source collection via env var
    if unsafe:
        import os
        os.environ["ZERO_FORGE_UNSAFE_SOURCE"] = "true"
        get_settings(reload=True)

    # CLI --output overrides config; set it via env so config picks it up
    if output_dir:
        import os
        os.environ["ZERO_FORGE_OUTPUT_DIR"] = output_dir
        get_settings(reload=True)

    result = run_workflow(vuln_input)

    table = Table(title="ZeroForge Results")
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("Status", result.status)
    table.add_row("CVE", vuln_input.cve_id)
    table.add_row("Artifact Type", vuln_input.artifact_type.value)
    if result.output_path:
        table.add_row("Output", result.output_path)
    if result.validation:
        table.add_row("Valid", str(result.validation.is_valid))
        if result.validation.errors:
            table.add_row("Errors", "\n".join(result.validation.errors))
    table.add_row("Repair Attempts", str(result.repair_attempts))
    if result.error:
        table.add_row("Error", result.error)
    console.print(table)

    if result.output_path:
        console.print(f"\n[green]✓ Artifact saved to:[/] {result.output_path}")


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
    file: str = typer.Argument(..., help="Path to Metasploit module file"),
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
