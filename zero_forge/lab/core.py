"""Native source-lab orchestration."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from ..config import get_settings
from ..schemas import ArtifactType, VulnerabilityInput, WorkflowState
from ..workflow import run_workflow
from .git import CommandRunner, prepare_source_checkout, run_command
from .poc import collect_exploitdb
from .promotion import DEFAULT_MSF_LAYOUT, promote_lab_run
from .types import LabError, LabRunResult, LabStatus, LabWorkflowError
from .util import (
    atomic_write_json,
    ensure_under,
    make_run_id,
    normalize_optional_cve,
    resolve_lab_root,
    sanitize_name,
    update_latest,
)

WorkflowRunner = Callable[[VulnerabilityInput], WorkflowState]


def _git_identity(path: Path) -> dict[str, object]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=path,
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=path,
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
        )
    except OSError:
        commit, dirty = "", False
    try:
        package_version = version("zero-forge")
    except PackageNotFoundError:
        package_version = "uninstalled"
    return {"commit": commit, "dirty": dirty, "version": package_version}


@contextmanager
def _workflow_output(path: Path) -> Iterator[None]:
    old = os.environ.get("ZERO_FORGE_OUTPUT_DIR")
    os.environ["ZERO_FORGE_OUTPUT_DIR"] = str(path)
    get_settings(reload=True)
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("ZERO_FORGE_OUTPUT_DIR", None)
        else:
            os.environ["ZERO_FORGE_OUTPUT_DIR"] = old
        get_settings(reload=True)


def _validation_errors(workflow: WorkflowState) -> list[str]:
    if workflow.validation and workflow.validation.errors:
        return list(workflow.validation.errors)
    return [workflow.error] if workflow.error else []


def _manifest(
    *,
    run_id: str,
    repo_url: str,
    repo_name: str,
    source_dir: Path,
    source_commit: str,
    requested_ref: str,
    cve_id: str,
    query: str,
    artifact_type: ArtifactType,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "run_id": run_id,
        "created_at": datetime.now(UTC).isoformat(),
        "status": "prepared",
        "repo_url": repo_url,
        "repo_name": repo_name,
        "source_dir": str(source_dir),
        "source_commit": source_commit,
        "requested_ref": requested_ref,
        "cve_id": cve_id,
        "query": query,
        "artifact_type": artifact_type.value,
        "zero_forge": _git_identity(Path(__file__).resolve().parents[2]),
    }


def run_lab(
    *,
    repo_url: str,
    artifact_type: ArtifactType = ArtifactType.METASPLOIT,
    cve_id: str = "",
    query: str = "",
    name: str = "",
    requested_ref: str = "",
    lab_root: str | Path | None = None,
    collect_poc: bool = True,
    promote: bool = False,
    force: bool = False,
    msf_layout: str = DEFAULT_MSF_LAYOUT,
    runner: CommandRunner = run_command,
    workflow_runner: WorkflowRunner = run_workflow,
) -> LabRunResult:
    """Acquire source, collect evidence, run ZeroForge, and stage one manifest-backed run."""
    root = resolve_lab_root(lab_root)
    repo_name = sanitize_name(name or repo_url)
    cve = normalize_optional_cve(cve_id)
    search_query = query.strip() or cve or repo_name
    source_dir = ensure_under(root / "source" / repo_name, root / "source")
    source_commit = prepare_source_checkout(
        repo_url, source_dir, requested_ref=requested_ref, runner=runner
    )
    scope = cve or repo_name
    run_id = make_run_id()
    scope_root = root / "output" / scope
    run_dir = ensure_under(scope_root / run_id, root / "output")
    result_dir = run_dir / "zeroforge"
    poc_dir = run_dir / "poc"
    result_dir.mkdir(parents=True)
    poc_dir.mkdir(parents=True)
    manifest_path = run_dir / "run.json"
    manifest = _manifest(
        run_id=run_id,
        repo_url=repo_url,
        repo_name=repo_name,
        source_dir=source_dir,
        source_commit=source_commit,
        requested_ref=requested_ref,
        cve_id=cve,
        query=search_query,
        artifact_type=artifact_type,
    )
    atomic_write_json(manifest_path, manifest)
    poc_text = ""
    try:
        if collect_poc:
            collection = collect_exploitdb(
                search_query,
                poc_dir / f"poc-{repo_name}.txt",
                cve_id=cve,
                runner=runner,
            )
            manifest["poc_path"] = str(collection.path)
            manifest["poc_result_count"] = collection.result_count
            poc_text = collection.path.read_text(encoding="utf-8", errors="replace")
        manifest["status"] = "running"
        atomic_write_json(manifest_path, manifest)
        with _workflow_output(result_dir):
            workflow = workflow_runner(
                VulnerabilityInput(
                    cve_id=cve,
                    artifact_type=artifact_type,
                    poc_text=poc_text,
                    source_path=str(source_dir),
                )
            )
    except Exception as exc:
        manifest["status"] = "failed"
        manifest["workflow_error"] = str(exc)
        atomic_write_json(manifest_path, manifest)
        update_latest(scope_root, run_dir)
        raise LabWorkflowError(str(exc), run_dir) from exc

    output_path = Path(workflow.output_path).resolve() if workflow.output_path else None
    completed = (
        workflow.status == "completed"
        and workflow.validation is not None
        and workflow.validation.is_valid
        and output_path is not None
        and output_path.is_file()
    )
    if not completed:
        manifest["status"] = "failed"
        manifest["workflow_error"] = workflow.error or "ZeroForge workflow did not complete"
        manifest["validation_errors"] = _validation_errors(workflow)
        atomic_write_json(manifest_path, manifest)
        update_latest(scope_root, run_dir)
        raise LabWorkflowError(str(manifest["workflow_error"]), run_dir)
    assert output_path is not None
    ensure_under(output_path, result_dir)
    manifest["status"] = "completed"
    manifest["output_path"] = str(output_path)
    manifest["validation_errors"] = _validation_errors(workflow)
    atomic_write_json(manifest_path, manifest)
    update_latest(scope_root, run_dir)
    promoted: Path | None = None
    if promote:
        promoted = promote_lab_run(
            run_dir=run_dir,
            lab_root=root,
            msf_layout=msf_layout,
            force=force,
        )
        manifest["promoted_path"] = str(promoted)
        atomic_write_json(manifest_path, manifest)
    return LabRunResult(run_dir, manifest_path, source_dir, source_commit, workflow, promoted)


def get_lab_status(*, lab_root: str | Path | None, cve_id: str = "", name: str = "") -> LabStatus:
    """Resolve staged and promoted paths for one CVE or source-only project."""
    cve = normalize_optional_cve(cve_id)
    if bool(cve) == bool(name.strip()):
        raise LabError("Specify exactly one of cve_id or name")
    root = resolve_lab_root(lab_root)
    scope = cve or sanitize_name(name)
    staged_root = root / "output" / scope
    runs = (
        tuple(
            sorted(
                (p for p in staged_root.iterdir() if p.is_dir() and p.name != "latest"),
                reverse=True,
            )
        )
        if staged_root.is_dir()
        else ()
    )
    latest_link = staged_root / "latest"
    latest = latest_link.resolve() if latest_link.exists() or latest_link.is_symlink() else None
    promoted = (
        root / "vuln-db" / "artifacts" / cve
        if cve
        else root / "vuln-db" / "artifacts" / "unassigned" / scope
    )
    return LabStatus(scope, staged_root, runs, latest, promoted, promoted.exists())
