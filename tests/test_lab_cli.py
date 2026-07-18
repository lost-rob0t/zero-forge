from __future__ import annotations

import zero_forge.cli as cli
from typer.testing import CliRunner
from zero_forge.schemas import WorkflowState

runner = CliRunner()


def test_lab_run_dry_run_is_registered() -> None:
    result = runner.invoke(
        cli.app,
        [
            "lab",
            "run",
            "--repo",
            "https://example.com/org/project.git",
            "--ref",
            "deadbeef",
            "--no-exploitdb",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "ZeroForge Lab Run Plan" in result.output
    assert "deadbeef" in result.output


def test_generate_returns_nonzero_for_failed_workflow(monkeypatch) -> None:
    monkeypatch.setattr(cli, "_ensure_config", lambda _path: None)
    monkeypatch.setattr(cli, "_apply_env_overrides", lambda **_kwargs: None)
    monkeypatch.setattr(cli, "setup_logging_from_settings", lambda: None)

    def failed(vuln_input):
        return WorkflowState(vuln_input=vuln_input, status="failed", error="test failure")

    monkeypatch.setattr(cli, "run_workflow", failed)
    result = runner.invoke(cli.app, ["generate", "--cve", "CVE-2025-1234"])
    assert result.exit_code == 1
    assert "test failure" in result.output
