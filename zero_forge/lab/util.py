"""Contained filesystem helpers for native lab commands."""

from __future__ import annotations

import json
import os
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from ..schemas import normalize_cve_id
from .types import LabError

DEFAULT_LAB_ROOT = Path.home() / "Documents" / "AI" / "hacking"
OPTIONAL_CVE_ALIASES = {"", "0", "none", "null", "no", "false", "-"}


def resolve_lab_root(value: str | Path | None = None) -> Path:
    configured = value or os.environ.get("AI_HACKING_LAB") or DEFAULT_LAB_ROOT
    return Path(configured).expanduser().resolve()


def sanitize_name(value: str) -> str:
    raw = value.strip().rstrip("/")
    parsed = urlsplit(raw)
    if parsed.scheme and parsed.path:
        raw = parsed.path
    elif ":" in raw and "://" not in raw:
        raw = raw.split(":", 1)[1]
    raw = raw.rsplit("/", 1)[-1].removesuffix(".git")
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip("-")
    if not cleaned or cleaned in {".", ".."}:
        raise LabError("Name resolves to an unsafe path component")
    return cleaned


def normalize_optional_cve(value: str) -> str:
    if value.strip().lower() in OPTIONAL_CVE_ALIASES:
        return ""
    try:
        return normalize_cve_id(value)
    except ValueError as exc:
        raise LabError(str(exc)) from exc


def ensure_under(path: Path, root: Path) -> Path:
    resolved_root = root.expanduser().resolve()
    resolved_path = path.expanduser().resolve(strict=False)
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError as exc:
        raise LabError(f"Path escapes lab root: {resolved_path}") from exc
    return resolved_path


def make_run_id() -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    return f"{stamp}-{secrets.token_hex(4)}"


def atomic_write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    temp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temp, path)


def update_latest(scope_root: Path, run_dir: Path) -> None:
    link = scope_root / "latest"
    temp = scope_root / f".latest-{secrets.token_hex(8)}"
    temp.symlink_to(run_dir.name)
    os.replace(temp, link)
