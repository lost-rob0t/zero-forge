"""Paid, manually-invoked OpenRouter end-to-end runner for ZeroForge."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence

_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_ARTIFACT_TYPES = ("metasploit", "zap_active_scan", "zap_passive_scan")
_DEFAULT_SMART_MODEL = "z-ai/glm-5.2"
_DEFAULT_TOOL_MODEL = "deepseek/deepseek-v4-pro"


@dataclass(frozen=True, slots=True)
class LiveE2EConfig:
    cve_id: str
    artifact_type: str
    output_dir: Path
    smart_model: str = _DEFAULT_SMART_MODEL
    tool_model: str = _DEFAULT_TOOL_MODEL
    smart_max_tokens: int = 8192
    tool_max_tokens: int = 1024
    max_repair_attempts: int = 2
    timeout_seconds: int = 1200


@dataclass(frozen=True, slots=True)
class LiveE2ESummary:
    cve_id: str
    artifact_type: str
    smart_model: str
    tool_model: str
    command: list[str]
    process_returncode: int
    artifact_path: str | None
    metadata_path: str | None
    success: bool
    error: str | None


def validate_config(config: LiveE2EConfig) -> None:
    if not _CVE_RE.fullmatch(config.cve_id):
        raise ValueError(f"Invalid CVE identifier: {config.cve_id!r}")
    if config.artifact_type not in _ARTIFACT_TYPES:
        raise ValueError(f"Unsupported artifact type: {config.artifact_type!r}")
    if not config.smart_model.strip() or not config.tool_model.strip():
        raise ValueError("Smart and Tool model identifiers must not be empty")
    if config.smart_max_tokens < 1 or config.tool_max_tokens < 1:
        raise ValueError("Model token budgets must be positive")
    if config.max_repair_attempts < 0:
        raise ValueError("Repair attempts must not be negative")
    if config.timeout_seconds < 1:
        raise ValueError("Timeout must be positive")


def build_command(config: LiveE2EConfig) -> list[str]:
    return [
        sys.executable,
        "-m",
        "zero_forge.cli",
        "generate",
        "--cve",
        config.cve_id,
        "--type",
        config.artifact_type,
        "--output",
        str(config.output_dir),
    ]


def build_environment(config: LiveE2EConfig, environ: dict[str, str] | None = None) -> dict[str, str]:
    source = os.environ if environ is None else environ
    api_key = source.get("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is required for the live end-to-end run")

    env = dict(source)
    env.update(
        {
            "OPENROUTER_API_KEY": api_key,
            "ZERO_FORGE_SMART_PROVIDER": "openrouter",
            "ZERO_FORGE_SMART_MODEL": config.smart_model,
            "ZERO_FORGE_SMART_TEMPERATURE": "0.2",
            "ZERO_FORGE_SMART_MAX_TOKENS": str(config.smart_max_tokens),
            "ZERO_FORGE_TOOL_PROVIDER": "openrouter",
            "ZERO_FORGE_TOOL_MODEL": config.tool_model,
            "ZERO_FORGE_TOOL_TEMPERATURE": "0.0",
            "ZERO_FORGE_TOOL_MAX_TOKENS": str(config.tool_max_tokens),
            "ZERO_FORGE_STUB_MODE": "false",
            "ZERO_FORGE_MAX_REPAIR_ATTEMPTS": str(config.max_repair_attempts),
            "ZERO_FORGE_OUTPUT_DIR": str(config.output_dir),
        }
    )
    return env


def _prepare_output_dir(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    existing = [path for path in output_dir.iterdir() if path.name != ".gitkeep"]
    if existing:
        names = ", ".join(sorted(path.name for path in existing))
        raise RuntimeError(f"Live end-to-end output directory must be empty; found: {names}")


def discover_artifact(output_dir: Path) -> tuple[Path, Path]:
    artifacts = sorted(
        path
        for path in output_dir.iterdir()
        if path.is_file()
        and not path.name.endswith(".meta.json")
        and not path.name.startswith("live-e2e.")
    )
    if len(artifacts) != 1:
        raise RuntimeError(f"Expected exactly one generated artifact, found {len(artifacts)}")

    artifact = artifacts[0]
    metadata = artifact.with_name(f"{artifact.name}.meta.json")
    if not metadata.is_file():
        raise RuntimeError(f"Missing artifact metadata sidecar: {metadata.name}")
    return artifact, metadata


def validate_metadata(config: LiveE2EConfig, metadata_path: Path) -> dict[str, object]:
    data = json.loads(metadata_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("Artifact metadata sidecar must contain a JSON object")

    expected = {
        "cve_id": config.cve_id,
        "artifact_type": config.artifact_type,
        "model": config.smart_model,
        "stub": False,
    }
    mismatches = {
        key: {"expected": value, "actual": data.get(key)}
        for key, value in expected.items()
        if data.get(key) != value
    }
    if mismatches:
        raise RuntimeError(f"Artifact metadata mismatch: {json.dumps(mismatches, sort_keys=True)}")
    return data


def _write_summary(output_dir: Path, summary: LiveE2ESummary) -> None:
    path = output_dir / "live-e2e.summary.json"
    path.write_text(json.dumps(asdict(summary), indent=2, sort_keys=True), encoding="utf-8")


def run_live_e2e(config: LiveE2EConfig) -> LiveE2ESummary:
    validate_config(config)
    _prepare_output_dir(config.output_dir)
    command = build_command(config)
    env = build_environment(config)

    stdout_path = config.output_dir / "live-e2e.stdout.log"
    stderr_path = config.output_dir / "live-e2e.stderr.log"

    try:
        completed = subprocess.run(
            command,
            env=env,
            text=True,
            capture_output=True,
            timeout=config.timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout_path.write_text(exc.stdout or "", encoding="utf-8")
        stderr_path.write_text(exc.stderr or "", encoding="utf-8")
        summary = LiveE2ESummary(
            cve_id=config.cve_id,
            artifact_type=config.artifact_type,
            smart_model=config.smart_model,
            tool_model=config.tool_model,
            command=command,
            process_returncode=124,
            artifact_path=None,
            metadata_path=None,
            success=False,
            error=f"Live end-to-end run exceeded {config.timeout_seconds} seconds",
        )
        _write_summary(config.output_dir, summary)
        return summary

    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")

    artifact_path: Path | None = None
    metadata_path: Path | None = None
    error: str | None = None

    try:
        if completed.returncode != 0:
            raise RuntimeError(f"ZeroForge CLI exited with status {completed.returncode}")
        artifact_path, metadata_path = discover_artifact(config.output_dir)
        validate_metadata(config, metadata_path)
        if artifact_path.stat().st_size == 0:
            raise RuntimeError("Generated artifact is empty")
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        error = str(exc)

    summary = LiveE2ESummary(
        cve_id=config.cve_id,
        artifact_type=config.artifact_type,
        smart_model=config.smart_model,
        tool_model=config.tool_model,
        command=command,
        process_returncode=completed.returncode,
        artifact_path=str(artifact_path) if artifact_path else None,
        metadata_path=str(metadata_path) if metadata_path else None,
        success=error is None,
        error=error,
    )
    _write_summary(config.output_dir, summary)
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cve", required=True, dest="cve_id")
    parser.add_argument("--type", choices=_ARTIFACT_TYPES, default="metasploit", dest="artifact_type")
    parser.add_argument("--output", type=Path, default=Path("artifacts/live-e2e"), dest="output_dir")
    parser.add_argument("--smart-model", default=_DEFAULT_SMART_MODEL)
    parser.add_argument("--tool-model", default=_DEFAULT_TOOL_MODEL)
    parser.add_argument("--smart-max-tokens", type=int, default=8192)
    parser.add_argument("--tool-max-tokens", type=int, default=1024)
    parser.add_argument("--max-repair-attempts", type=int, default=2)
    parser.add_argument("--timeout-seconds", type=int, default=1200)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config = LiveE2EConfig(**vars(args))
    try:
        summary = run_live_e2e(config)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"live-e2e: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(asdict(summary), indent=2, sort_keys=True))
    return 0 if summary.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
