"""Tests for the ZeroForge LangGraph workflow."""

from pathlib import Path

from zero_forge.schemas import VulnerabilityInput
from zero_forge.workflow import build_workflow, run_workflow


def test_workflow_builds():
    app = build_workflow()
    assert app is not None


def test_workflow_runs_end_to_end(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ZERO_FORGE_OUTPUT_DIR", str(tmp_path))

    vuln_input = VulnerabilityInput(
        cve_id="CVE-2021-44228",
        poc_text="print('pwned')",
        writeup_text="RCE via JNDI lookup",
        patch_diff="diff --git a/a.py b/a.py\n-old\n+new",
    )

    result = run_workflow(vuln_input)

    assert result.status == "completed"
    assert result.artifact is not None
    assert result.context is not None
    assert result.output_path is not None
    assert Path(result.output_path).exists()


def test_workflow_repair_loop(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ZERO_FORGE_OUTPUT_DIR", str(tmp_path))

    vuln_input = VulnerabilityInput(cve_id="CVE-2021-44228")
    result = run_workflow(vuln_input)

    assert result.repair_attempts >= 0
    assert result.validation is not None
    assert result.output_path is not None
