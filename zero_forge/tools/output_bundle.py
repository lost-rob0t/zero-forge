"""Publish completed exploit investigations from /tmp into the configured output tree."""

from __future__ import annotations

import errno
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Literal

OutputFormat = Literal["markdown", "org", "json"]

_WORKSPACE_ROOT = Path("/tmp/zeroforge")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_ALLOWED_FORMATS: set[str] = {"markdown", "org", "json"}


def _validate_identifier(value: str) -> str:
    normalized = value.strip()
    if not _ID_RE.fullmatch(normalized):
        raise ValueError("investigation_id must be a simple 1-64 character identifier")
    return normalized


def _workspace(path: str) -> Path:
    root = _WORKSPACE_ROOT.resolve()
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ValueError("workspace_path must be absolute")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("workspace_path must remain under /tmp/zeroforge") from exc
    if resolved == root or not resolved.is_dir() or resolved.is_symlink():
        raise ValueError("workspace_path must identify a real investigation directory")
    return resolved


def _formats(values: list[str]) -> list[OutputFormat]:
    normalized: list[OutputFormat] = []
    for value in values:
        lowered = value.strip().lower()
        if lowered not in _ALLOWED_FORMATS:
            raise ValueError(f"unsupported output format: {value}")
        typed: OutputFormat = lowered  # type: ignore[assignment]
        if typed not in normalized:
            normalized.append(typed)
    if not normalized:
        raise ValueError("at least one output format is required")
    return normalized


def _scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _markdown_value(value: Any, depth: int = 0) -> list[str]:
    indent = "  " * depth
    if isinstance(value, dict):
        lines: list[str] = []
        for key, child in value.items():
            label = str(key).replace("_", " ").title()
            if isinstance(child, (dict, list)):
                lines.append(f"{indent}- **{label}:**")
                lines.extend(_markdown_value(child, depth + 1))
            else:
                lines.append(f"{indent}- **{label}:** {_scalar(child)}")
        return lines
    if isinstance(value, list):
        lines = []
        for child in value:
            if isinstance(child, (dict, list)):
                lines.append(f"{indent}-")
                lines.extend(_markdown_value(child, depth + 1))
            else:
                lines.append(f"{indent}- {_scalar(child)}")
        return lines or [f"{indent}- (none)"]
    return [f"{indent}{_scalar(value)}"]


def _org_value(value: Any, depth: int = 0) -> list[str]:
    indent = "  " * depth
    if isinstance(value, dict):
        lines: list[str] = []
        for key, child in value.items():
            label = str(key).replace("_", " ").title()
            if isinstance(child, (dict, list)):
                lines.append(f"{indent}- {label} ::")
                lines.extend(_org_value(child, depth + 1))
            else:
                lines.append(f"{indent}- {label} :: {_scalar(child)}")
        return lines
    if isinstance(value, list):
        lines = []
        for child in value:
            if isinstance(child, (dict, list)):
                lines.append(f"{indent}-")
                lines.extend(_org_value(child, depth + 1))
            else:
                lines.append(f"{indent}- {_scalar(child)}")
        return lines or [f"{indent}- (none)"]
    return [f"{indent}{_scalar(value)}"]


def _render(title: str, data: Any, output_format: OutputFormat) -> str:
    if output_format == "json":
        return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if output_format == "markdown":
        return "\n".join([f"# {title}", "", *_markdown_value(data), ""])
    return "\n".join([f"#+title: {title}", "", *_org_value(data), ""])


def _extension(output_format: OutputFormat) -> str:
    return {"markdown": ".md", "org": ".org", "json": ".json"}[output_format]


def _write_document(
    directory: Path,
    basename: str,
    title: str,
    data: Any,
    output_formats: list[OutputFormat],
) -> list[str]:
    written: list[str] = []
    for output_format in output_formats:
        destination = directory / f"{basename}{_extension(output_format)}"
        destination.write_text(_render(title, data, output_format), encoding="utf-8")
        os.chmod(destination, 0o600)
        written.append(str(destination))
    return written


def _ensure_tree(workspace: Path) -> dict[str, Path]:
    paths = {
        "findings": workspace / "findings",
        "validation": workspace / "evidence" / "validation",
        "poc": workspace / "poc",
        "iterations": workspace / "poc" / "iterations",
        "research": workspace / "research",
    }
    for path in paths.values():
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path, 0o700)
    return paths


def _move_tree(source: Path, destination: Path) -> None:
    try:
        os.replace(source, destination)
        return
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
    shutil.copytree(source, destination, copy_function=shutil.copy2)
    shutil.rmtree(source)


def publish_exploit_bundle(
    workspace_path: str,
    output_dir: str,
    investigation_id: str,
    filename: str,
    output_formats: list[str],
    candidate: dict[str, Any],
    hypothesis: dict[str, Any],
    result: dict[str, Any],
    iterations: list[dict[str, Any]],
    web_results: list[dict[str, Any]],
    fetched_pages: list[dict[str, Any]],
    research_errors: list[str],
) -> dict[str, Any]:
    """Write the structured bundle and move a completed workspace into output."""

    workspace = _workspace(workspace_path)
    normalized_id = _validate_identifier(investigation_id)
    formats = _formats(output_formats)
    tree = _ensure_tree(workspace)

    written: list[str] = []
    written.extend(
        _write_document(tree["findings"], "hypothesis", "Security Hypothesis", hypothesis, formats)
    )
    written.extend(
        _write_document(tree["findings"], "candidate", "Candidate Finding", candidate, formats)
    )
    written.extend(
        _write_document(tree["findings"], "result", "Investigation Result", result, formats)
    )

    for index, iteration in enumerate(iterations, start=1):
        number = int(iteration.get("iteration", index))
        written.extend(
            _write_document(
                tree["validation"],
                f"iteration-{number:02d}",
                f"Validation Iteration {number}",
                iteration,
                formats,
            )
        )

    written.extend(
        _write_document(tree["research"], "web-results", "Web Search Results", web_results, formats)
    )
    written.extend(
        _write_document(tree["research"], "fetched-pages", "Fetched Research Pages", fetched_pages, formats)
    )
    written.extend(
        _write_document(tree["research"], "errors", "Research Errors", research_errors, formats)
    )

    final_artifact = tree["poc"] / filename
    if not final_artifact.exists() or not final_artifact.is_file() or final_artifact.is_symlink():
        raise FileNotFoundError(f"completed artifact not found in poc/: {filename}")

    root = Path(output_dir).expanduser().resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("output_dir must identify a real directory")
    destination = root / normalized_id
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"investigation output already exists: {destination}")

    staging = Path(tempfile.mkdtemp(prefix=f".{normalized_id}.", suffix=".tmp", dir=root))
    staging.rmdir()
    try:
        _move_tree(workspace, staging)
        os.replace(staging, destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)

    published_artifact = destination / "poc" / filename
    return {
        "output_path": str(destination),
        "final_path": str(published_artifact),
        "formats": formats,
        "written_documents": [
            str(destination / Path(path).relative_to(workspace)) for path in written
        ],
    }
