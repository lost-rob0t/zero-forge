"""Raw Exploit-DB acquisition for native lab runs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .git import CommandRunner, run_command
from .types import LabError, PocCollection


def _rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("RESULTS_EXPLOIT", "results", "exploits"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def collect_exploitdb(
    query: str,
    destination: Path,
    *,
    cve_id: str = "",
    limit: int = 3,
    runner: CommandRunner = run_command,
) -> PocCollection:
    """Collect a bounded raw multi-result SearchSploit evidence bundle."""
    if not query.strip():
        raise LabError("SearchSploit query must not be empty")
    result = runner(["searchsploit", "-j", query], check=True)
    try:
        rows = _rows(json.loads(result.stdout))[:limit]
    except json.JSONDecodeError as exc:
        raise LabError("SearchSploit returned invalid JSON") from exc
    destination.parent.mkdir(parents=True, exist_ok=True)
    sections: list[str] = []
    for row in rows:
        edb_id = str(row.get("EDB-ID") or row.get("id") or "unknown")
        title = str(row.get("Title") or row.get("title") or "")
        source = str(row.get("Path") or row.get("path") or "")
        content = ""
        source_path = Path(source).expanduser()
        if source and source_path.is_file():
            content = source_path.read_text(encoding="utf-8", errors="replace")
        provenance = [f"===== Exploit-DB {edb_id} ====="]
        provenance.append(f"CVE: {cve_id}" if cve_id else f"Query: {query}")
        provenance.extend([f"Title: {title}", f"Source: {source}", "", content])
        sections.append("\n".join(provenance).rstrip())
    destination.write_text(
        "\n\n".join(sections) + ("\n" if sections else ""), encoding="utf-8"
    )
    return PocCollection(path=destination, result_count=len(rows))
