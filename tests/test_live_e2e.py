from __future__ import annotations

import json
from pathlib import Path

import pytest

from zero_forge.live_e2e import (
    LiveE2EConfig,
    build_command,
    build_environment,
    discover_artifact,
    validate_config,
    validate_metadata,
)


def config(tmp_path: Path, **overrides) -> LiveE2EConfig:
    values = {
        "cve_id": "CVE-2021-41773",
        "artifact_type": "metasploit",
        "output_dir": tmp_path,
    }
    values.update(overrides)
    return LiveE2EConfig(**values)


def test_validate_config_accepts_openrouter_defaults(tmp_path: Path) -> None:
    validate_config(config(tmp_path))


@pytest.mark.parametrize("cve_id", ["CVE-21-1", "2021-41773", "CVE-2021-ABC"])
def test_validate_config_rejects_invalid_cve(tmp_path: Path, cve_id: str) -> None:
    with pytest.raises(ValueError, match="Invalid CVE"):
        validate_config(config(tmp_path, cve_id=cve_id))


def test_build_environment_uses_two_openrouter_roles(tmp_path: Path) -> None:
    env = build_environment(config(tmp_path), {"OPENROUTER_API_KEY": "secret"})
    assert env["ZERO_FORGE_SMART_PROVIDER"] == "openrouter"
    assert env["ZERO_FORGE_SMART_MODEL"] == "z-ai/glm-5.2"
    assert env["ZERO_FORGE_TOOL_PROVIDER"] == "openrouter"
    assert env["ZERO_FORGE_TOOL_MODEL"] == "deepseek/deepseek-v4-pro"
    assert env["ZERO_FORGE_STUB_MODE"] == "false"
    assert env["OPENROUTER_API_KEY"] == "secret"


def test_build_environment_requires_key(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="OPENROUTER_API_KEY"):
        build_environment(config(tmp_path), {})


def test_build_command_runs_installed_cli(tmp_path: Path) -> None:
    command = build_command(config(tmp_path, artifact_type="zap_active_scan"))
    assert command[1:4] == ["-m", "zero_forge.cli", "generate"]
    assert command[-4:] == ["--type", "zap_active_scan", "--output", str(tmp_path)]


def test_discover_artifact_ignores_runner_logs(tmp_path: Path) -> None:
    artifact = tmp_path / "cve_2021_41773_exploit.rb"
    metadata = tmp_path / f"{artifact.name}.meta.json"
    artifact.write_text("module", encoding="utf-8")
    metadata.write_text("{}", encoding="utf-8")
    (tmp_path / "live-e2e.stdout.log").write_text("log", encoding="utf-8")
    (tmp_path / "live-e2e.stderr.log").write_text("log", encoding="utf-8")
    assert discover_artifact(tmp_path) == (artifact, metadata)


def test_validate_metadata_checks_model_and_non_stub(tmp_path: Path) -> None:
    metadata = tmp_path / "artifact.rb.meta.json"
    metadata.write_text(
        json.dumps(
            {
                "cve_id": "CVE-2021-41773",
                "artifact_type": "metasploit",
                "model": "z-ai/glm-5.2",
                "stub": False,
            }
        ),
        encoding="utf-8",
    )
    data = validate_metadata(config(tmp_path), metadata)
    assert data["stub"] is False


def test_validate_metadata_rejects_wrong_model(tmp_path: Path) -> None:
    metadata = tmp_path / "artifact.rb.meta.json"
    metadata.write_text(
        json.dumps(
            {
                "cve_id": "CVE-2021-41773",
                "artifact_type": "metasploit",
                "model": "wrong/model",
                "stub": False,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="metadata mismatch"):
        validate_metadata(config(tmp_path), metadata)
