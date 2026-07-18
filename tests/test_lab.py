from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from zero_forge.lab import (
    LabError,
    LabWorkflowError,
    canonical_repo_url,
    collect_exploitdb,
    get_lab_status,
    make_run_id,
    prepare_source_checkout,
    promote_lab_run,
    run_lab,
)
from zero_forge.schemas import ArtifactType, ValidationResult, VulnerabilityInput, WorkflowState


def _run(*args: str, cwd: Path) -> str:
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def _remote(tmp_path: Path, name: str = "remote") -> tuple[Path, Path]:
    remote = tmp_path / f"{name}.git"
    work = tmp_path / f"{name}-work"
    _run("git", "init", "--bare", str(remote), cwd=tmp_path)
    _run("git", "clone", str(remote), str(work), cwd=tmp_path)
    _run("git", "config", "user.email", "test@example.invalid", cwd=work)
    _run("git", "config", "user.name", "Test", cwd=work)
    (work / "value.txt").write_text("one\n", encoding="utf-8")
    _run("git", "add", "value.txt", cwd=work)
    _run("git", "commit", "-m", "one", cwd=work)
    _run("git", "push", "origin", "HEAD:master", cwd=work)
    _run("git", "symbolic-ref", "HEAD", "refs/heads/master", cwd=remote)
    return remote, work


def _commit(work: Path, value: str) -> str:
    (work / "value.txt").write_text(value + "\n", encoding="utf-8")
    _run("git", "add", "value.txt", cwd=work)
    _run("git", "commit", "-m", value, cwd=work)
    _run("git", "push", "origin", "HEAD:master", cwd=work)
    return _run("git", "rev-parse", "HEAD", cwd=work)


def test_canonical_repo_url_matches_https_and_ssh() -> None:
    assert canonical_repo_url("https://example.com/org/repo.git") == canonical_repo_url(
        "git@example.com:org/repo.git"
    )


def test_checkout_refreshes_default_and_named_remote_branch(tmp_path: Path) -> None:
    remote, work = _remote(tmp_path)
    checkout = tmp_path / "checkout"
    first = prepare_source_checkout(str(remote), checkout)
    second_expected = _commit(work, "two")
    second = prepare_source_checkout(str(remote), checkout)
    third_expected = _commit(work, "three")
    third = prepare_source_checkout(str(remote), checkout, "master")
    assert first != second
    assert second == second_expected
    assert third == third_expected
    assert _run("git", "rev-parse", "HEAD", cwd=checkout) == third_expected


def test_checkout_rejects_origin_mismatch(tmp_path: Path) -> None:
    first, _ = _remote(tmp_path, "one")
    second, _ = _remote(tmp_path, "two")
    checkout = tmp_path / "checkout"
    prepare_source_checkout(str(first), checkout)
    with pytest.raises(LabError, match="origin"):
        prepare_source_checkout(str(second), checkout)


def test_collect_exploitdb_preserves_raw_sections(tmp_path: Path) -> None:
    first = tmp_path / "one.py"
    second = tmp_path / "two.txt"
    first.write_text("print('one')\n", encoding="utf-8")
    second.write_text("two\n", encoding="utf-8")
    payload = {
        "RESULTS_EXPLOIT": [
            {"EDB-ID": "1", "Title": "One", "Path": str(first)},
            {"EDB-ID": "2", "Title": "Two", "Path": str(second)},
        ]
    }

    def runner(args, *, cwd=None, check=True):
        del args, cwd, check
        return subprocess.CompletedProcess([], 0, json.dumps(payload), "")

    result = collect_exploitdb("project", tmp_path / "poc.txt", runner=runner)
    text = result.path.read_text(encoding="utf-8")
    assert result.result_count == 2
    assert "===== Exploit-DB 1 =====" in text
    assert "===== Exploit-DB 2 =====" in text
    assert "print('one')" in text


def test_failed_workflow_is_manifested_and_raises(tmp_path: Path) -> None:
    remote, _ = _remote(tmp_path)

    def failed(vuln_input: VulnerabilityInput) -> WorkflowState:
        return WorkflowState(vuln_input=vuln_input, status="failed", error="generation failed")

    with pytest.raises(LabWorkflowError, match="generation failed") as caught:
        run_lab(
            repo_url=str(remote),
            lab_root=tmp_path / "lab",
            collect_poc=False,
            workflow_runner=failed,
        )
    manifest = json.loads((caught.value.run_dir / "run.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert manifest["source_commit"]


def test_completed_run_records_output_and_status(tmp_path: Path) -> None:
    remote, _ = _remote(tmp_path)

    def completed(vuln_input: VulnerabilityInput) -> WorkflowState:
        output = Path(os.environ["ZERO_FORGE_OUTPUT_DIR"]) / "poc-test.rb"
        output.write_text("class MetasploitModule\nend\n", encoding="utf-8")
        return WorkflowState(
            vuln_input=vuln_input,
            status="completed",
            output_path=str(output),
            validation=ValidationResult(is_valid=True),
        )

    result = run_lab(
        repo_url=str(remote),
        lab_root=tmp_path / "lab",
        collect_poc=False,
        workflow_runner=completed,
    )
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    status = get_lab_status(lab_root=tmp_path / "lab", name="remote")
    assert manifest["status"] == "completed"
    assert Path(str(manifest["output_path"])).is_file()
    assert status.latest == result.run_dir
    assert status.staged_runs == (result.run_dir,)


def test_promotion_rejects_empty_bundle(tmp_path: Path) -> None:
    root = tmp_path / "lab"
    run_dir = root / "output" / "project" / "run"
    (run_dir / "zeroforge").mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "status": "completed",
                "artifact_type": "metasploit",
                "repo_name": "project",
                "run_id": "run",
                "cve_id": "",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(LabError, match="No promotable"):
        promote_lab_run(run_dir=run_dir, lab_root=root)


def test_zap_active_promotion_routes_javascript(tmp_path: Path) -> None:
    root = tmp_path / "lab"
    run_dir = root / "output" / "project" / "run"
    artifact = run_dir / "zeroforge" / "poc-rule.js"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("function scan() {}\n", encoding="utf-8")
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "status": "completed",
                "artifact_type": ArtifactType.ZAP_ACTIVE.value,
                "repo_name": "project",
                "run_id": "run",
                "cve_id": "",
            }
        ),
        encoding="utf-8",
    )
    destination = promote_lab_run(run_dir=run_dir, lab_root=root)
    assert (destination / "zap" / "active" / "rule.js").is_file()


def test_run_ids_are_collision_resistant() -> None:
    assert make_run_id() != make_run_id()
