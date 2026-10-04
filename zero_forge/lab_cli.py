"""Typer command registration for the native ZeroForge lab workflow."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast

import typer
from rich.console import Console
from rich.table import Table

from .lab import (
    DEFAULT_MSF_LAYOUT,
    LabError,
    LabWorkflowError,
    collect_exploitdb,
    get_lab_status,
    normalize_optional_cve,
    promote_lab_run,
    resolve_lab_root,
    run_lab,
    sanitize_name,
)
from .logging_config import setup_logging_from_settings
from .schemas import ArtifactType

ConfigEnsurer = Callable[[str], None]
EnvOverrideApplier = Callable[..., None]


def register_lab_commands(
    app: typer.Typer,
    console: Console,
    ensure_config: ConfigEnsurer,
    apply_env_overrides: EnvOverrideApplier,
) -> None:
    """Attach the ``zero-forge lab`` command group to the main CLI."""
    lab_app = typer.Typer(
        help="Acquire source, collect PoCs, stage generation runs, and promote reviewed artifacts",
        no_args_is_help=True,
    )
    app.add_typer(lab_app, name="lab")
    artifact_type_option = cast(
        ArtifactType,
        typer.Option(
            ArtifactType.METASPLOIT,
            "--type",
            "-t",
            help="Artifact type to generate",
            case_sensitive=False,
        ),
    )
    poc_output_option = cast(Path, typer.Option(..., "--output", help="Destination directory"))
    run_dir_option = cast(
        Path, typer.Option(..., "--run", help="Completed native lab run directory")
    )

    @lab_app.command("run")
    def lab_run_command(
        repo: str = typer.Option(..., "--repo", help="Git repository URL or local path"),
        cve_id: str = typer.Option("", "--cve", help="Optional CVE identifier"),
        query: str = typer.Option("", "--query", help="Source-only SearchSploit query"),
        name: str = typer.Option("", "--name", help="Override the source checkout name"),
        requested_ref: str = typer.Option(
            "",
            "--ref",
            help="Branch, tag, or commit to resolve and check out as an immutable commit",
        ),
        artifact_type: ArtifactType = artifact_type_option,
        lab_root: str = typer.Option(
            "",
            "--lab-root",
            help="Lab root; defaults to AI_HACKING_LAB or ~/Documents/AI/hacking",
        ),
        no_exploitdb: bool = typer.Option(
            False,
            "--no-exploitdb",
            help="Skip local SearchSploit evidence collection",
        ),
        promote: bool = typer.Option(
            False,
            "--promote",
            help="Promote immediately after a completed generation run",
        ),
        force: bool = typer.Option(
            False,
            "--force",
            help="Replace an existing promoted destination when used with --promote",
        ),
        msf_layout: str = typer.Option(
            DEFAULT_MSF_LAYOUT,
            "--msf-layout",
            help="Fallback Metasploit module path for flat Ruby artifacts",
        ),
        config_file: str = typer.Option("", "--config", help="Path to YAML config file"),
        unsafe: bool = typer.Option(
            False,
            "--unsafe",
            help="Allow unsafe source collection for this authorized run",
        ),
        dry_run: bool = typer.Option(
            False,
            "--dry-run",
            help="Validate arguments and print the planned paths without mutation",
        ),
    ) -> None:
        """Clone/update source, optionally collect PoCs, and stage one generation run."""
        if force and not promote:
            raise typer.BadParameter("--force requires --promote")
        try:
            root = resolve_lab_root(lab_root or None)
            cve = normalize_optional_cve(cve_id)
            repo_name = sanitize_name(name or repo)
            if cve and query.strip():
                raise LabError("--query cannot be combined with --cve")
            if no_exploitdb and query.strip():
                raise LabError("--query cannot be combined with --no-exploitdb")
            scope = cve or repo_name
            if dry_run:
                table = Table(title="ZeroForge Lab Run Plan")
                table.add_column("Field")
                table.add_column("Value")
                table.add_row("Repository", repo)
                table.add_row("Source", str(root / "source" / repo_name))
                table.add_row("Scope", scope)
                table.add_row("Requested ref", requested_ref or "remote default branch")
                table.add_row("Artifact type", artifact_type.value)
                table.add_row("Exploit-DB", "disabled" if no_exploitdb else "enabled")
                table.add_row("Promotion", "enabled" if promote else "review first")
                console.print(table)
                return

            ensure_config(config_file)
            apply_env_overrides(output_dir="", unsafe=unsafe, config_file=config_file)
            setup_logging_from_settings()
            result = run_lab(
                repo_url=repo,
                lab_root=root,
                cve_id=cve,
                query=query,
                name=repo_name,
                requested_ref=requested_ref,
                artifact_type=artifact_type,
                collect_poc=not no_exploitdb,
                promote=promote,
                force=force,
                msf_layout=msf_layout,
            )
        except LabWorkflowError as exc:
            console.print(f"[red]Lab generation failed:[/] {exc}")
            console.print(f"[yellow]Staged failure:[/] {exc.run_dir}")
            raise typer.Exit(code=1) from exc
        except LabError as exc:
            console.print(f"[red]Lab command failed:[/] {exc}")
            raise typer.Exit(code=1) from exc

        table = Table(title="ZeroForge Lab Run")
        table.add_column("Status")
        table.add_column("Commit")
        table.add_column("Run")
        table.add_column("Artifact")
        table.add_column("Promoted")
        table.add_row(
            result.workflow.status,
            result.source_commit,
            str(result.run_dir),
            result.workflow.output_path or "—",
            str(result.promoted_path) if result.promoted_path else "review required",
        )
        console.print(table)

    @lab_app.command("poc")
    def lab_poc_command(
        output: Path = poc_output_option,
        cve_id: str = typer.Option("", "--cve", help="CVE to search"),
        query: str = typer.Option("", "--query", help="Arbitrary SearchSploit query"),
        name: str = typer.Option("", "--name", help="Override the output filename label"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print the output path only"),
    ) -> None:
        """Collect raw local Exploit-DB evidence without running generation."""
        try:
            cve = normalize_optional_cve(cve_id)
            if bool(cve) == bool(query.strip()):
                raise LabError("Specify exactly one of --cve or --query")
            label = cve or name.strip() or query
            planned = output.expanduser().resolve() / f"poc-{sanitize_name(label)}.txt"
            if dry_run:
                console.print(planned)
                return
            result = collect_exploitdb(
                cve or query,
                planned,
                cve_id=cve,
            )
        except LabError as exc:
            console.print(f"[red]PoC collection failed:[/] {exc}")
            raise typer.Exit(code=1) from exc
        console.print(f"[green]Saved {result.result_count} Exploit-DB result(s):[/] {result.path}")

    @lab_app.command("promote")
    def lab_promote_command(
        run_dir: Path = run_dir_option,
        lab_root: str = typer.Option(
            "",
            "--lab-root",
            help="Lab root; defaults to AI_HACKING_LAB or ~/Documents/AI/hacking",
        ),
        msf_layout: str = typer.Option(
            DEFAULT_MSF_LAYOUT,
            "--msf-layout",
            help="Fallback Metasploit module path for flat Ruby artifacts",
        ),
        force: bool = typer.Option(False, "--force", help="Safely replace an existing bundle"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Validate and print destination"),
    ) -> None:
        """Promote a reviewed, completed run into the vulnerability database."""
        try:
            destination = promote_lab_run(
                run_dir=run_dir,
                lab_root=resolve_lab_root(lab_root or None),
                msf_layout=msf_layout,
                force=force,
                dry_run=dry_run,
            )
        except LabError as exc:
            console.print(f"[red]Promotion failed:[/] {exc}")
            raise typer.Exit(code=1) from exc
        prefix = "Would promote to" if dry_run else "Promoted"
        console.print(f"[green]{prefix}:[/] {destination}")

    @lab_app.command("status")
    def lab_status_command(
        cve_id: str = typer.Option("", "--cve", help="CVE-backed scope"),
        name: str = typer.Option("", "--name", help="Source-only repository scope"),
        lab_root: str = typer.Option(
            "",
            "--lab-root",
            help="Lab root; defaults to AI_HACKING_LAB or ~/Documents/AI/hacking",
        ),
    ) -> None:
        """Show staged and promoted paths for one lab scope."""
        try:
            status = get_lab_status(
                lab_root=resolve_lab_root(lab_root or None),
                cve_id=cve_id,
                name=name,
            )
        except LabError as exc:
            console.print(f"[red]Status failed:[/] {exc}")
            raise typer.Exit(code=1) from exc
        table = Table(title=f"ZeroForge Lab Status: {status.scope}")
        table.add_column("Field")
        table.add_column("Value")
        table.add_row("Staged root", str(status.staged_root))
        table.add_row("Run count", str(len(status.staged_runs)))
        table.add_row("Latest", str(status.latest) if status.latest else "—")
        table.add_row("Promoted root", str(status.promoted_root))
        table.add_row("Promoted", "yes" if status.promoted_exists else "no")
        console.print(table)
