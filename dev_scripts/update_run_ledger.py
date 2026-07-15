#!/usr/bin/env python3
"""Append a steward run to an Org-mode ledger."""

from __future__ import annotations

import argparse
from pathlib import Path

RUN_LEDGER_HEADING = "* Run Ledger"


def render_entry(values: dict[str, str]) -> str:
    return "\n".join(
        [
            f"** {values['outcome'].upper()} {values['run_id']}",
            ":PROPERTIES:",
            f":STARTED_AT: {values['started_at']}",
            f":ENDED_AT: {values['ended_at']}",
            f":WINDOW_START: {values['window_start']}",
            f":WINDOW_END: {values['window_end']}",
            f":MASTER_SHA: {values['master_sha']}",
            f":OUTCOME: {values['outcome']}",
            ":END:",
            f"- Actions :: {values.get('actions', 'none')}",
            f"- Validation :: {values.get('validation', 'not run')}",
            f"- Blockers :: {values.get('blockers', 'none')}",
            f"- Research :: {values.get('research', 'not started')}",
        ]
    )


def append_entry(document: str, entry: str) -> str:
    if RUN_LEDGER_HEADING not in document:
        document = document.rstrip() + f"\n\n{RUN_LEDGER_HEADING}\n"
    return document.rstrip() + "\n\n" + entry.rstrip() + "\n"


def self_check() -> None:
    values = {
        "run_id": "run-1",
        "started_at": "start",
        "ended_at": "end",
        "window_start": "start",
        "window_end": "end",
        "master_sha": "abc",
        "outcome": "completed",
    }
    result = append_entry("* Open Issues\n", render_entry(values))
    assert "** COMPLETED run-1" in result
    assert result.count(RUN_LEDGER_HEADING) == 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=Path, default=Path("wiki/issues.org"))
    parser.add_argument("--run-id")
    parser.add_argument("--started-at")
    parser.add_argument("--ended-at")
    parser.add_argument("--window-start")
    parser.add_argument("--window-end")
    parser.add_argument("--master-sha")
    parser.add_argument("--outcome", choices=("completed", "blocked", "failed"))
    parser.add_argument("--actions", default="none")
    parser.add_argument("--validation", default="not run")
    parser.add_argument("--blockers", default="none")
    parser.add_argument("--research", default="not started")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if args.self_check:
        self_check()
        return
    required = (
        "run_id",
        "started_at",
        "ended_at",
        "window_start",
        "window_end",
        "master_sha",
        "outcome",
    )
    missing = [name for name in required if not getattr(args, name)]
    if missing:
        parser.error(f"missing required arguments: {', '.join(missing)}")
    existing = args.file.read_text(encoding="utf-8") if args.file.exists() else ""
    rendered = append_entry(existing, render_entry(vars(args)))
    if args.dry_run:
        print(rendered, end="")
        return
    args.file.parent.mkdir(parents=True, exist_ok=True)
    args.file.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
