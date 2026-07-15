#!/usr/bin/env python3
"""Synchronize GitHub issues into the canonical Org tracker."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
RUN_LEDGER_HEADING = "* Run Ledger"


def _validate_repository(repository: str) -> str:
    if not REPOSITORY_RE.fullmatch(repository):
        raise ValueError("repository must use owner/name syntax")
    return repository


def _gh_json(*arguments: str) -> Any:
    completed = subprocess.run(
        ["gh", *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def collect_issues(repository: str) -> list[dict[str, Any]]:
    repository = _validate_repository(repository)
    issues = _gh_json(
        "issue",
        "list",
        "--repo",
        repository,
        "--state",
        "open",
        "--limit",
        "200",
        "--json",
        "number,title,state,labels,assignees,url,updatedAt",
    )
    for issue in issues:
        detail = _gh_json(
            "issue",
            "view",
            str(issue["number"]),
            "--repo",
            repository,
            "--json",
            "body,comments",
        )
        issue.update(detail)
    return sorted(issues, key=lambda item: item["number"])


def _compact(text: str, limit: int = 240) -> str:
    compact = " ".join(text.split())
    return compact if len(compact) <= limit else f"{compact[: limit - 1]}…"


def render_issue(issue: dict[str, Any]) -> str:
    labels = ", ".join(label["name"] for label in issue.get("labels", [])) or "none"
    assignees = ", ".join(item["login"] for item in issue.get("assignees", [])) or "none"
    comments = issue.get("comments", [])
    direction = comments[-1]["body"] if comments else issue.get("body", "")
    return "\n".join(
        [
            f"** TODO #{issue['number']} {_compact(issue['title'], 120)}",
            ":PROPERTIES:",
            f":ID: issue-{issue['number']}",
            f":STATE: {str(issue['state']).lower()}",
            f":LABELS: {labels}",
            f":ASSIGNEES: {assignees}",
            f":UPDATED_AT: {issue.get('updatedAt', '')}",
            f":URL: {issue['url']}",
            ":END:",
            f"Latest direction: {_compact(direction) or 'Issue body is current.'}",
        ]
    )


def render_tracker(repository: str, issues: list[dict[str, Any]], existing: str = "") -> str:
    ledger = ""
    if RUN_LEDGER_HEADING in existing:
        ledger = existing[existing.index(RUN_LEDGER_HEADING) :].rstrip()
    header = "\n".join(
        [
            "#+TITLE: ZeroForge Issue Tracker and Steward Runs",
            "#+STARTUP: overview",
            "",
            "* Tracker Metadata",
            ":PROPERTIES:",
            f":REPOSITORY: {repository}",
            ":END:",
            "",
            "* Open Issues",
        ]
    )
    sections = [header, *(render_issue(issue) for issue in issues)]
    sections.append(ledger or f"{RUN_LEDGER_HEADING}\n")
    return "\n\n".join(sections).rstrip() + "\n"


def self_check() -> None:
    sample = {
        "number": 7,
        "title": "Safe writes",
        "state": "OPEN",
        "labels": [{"name": "priority:P1"}],
        "assignees": [],
        "url": "https://example.invalid/7",
        "updatedAt": "2026-01-01T00:00:00Z",
        "body": "Keep writes atomic.",
        "comments": [],
    }
    rendered = render_tracker("owner/repo", [sample])
    assert ":ID: issue-7" in rendered
    assert "* Run Ledger" in rendered
    assert _validate_repository("owner/repo") == "owner/repo"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo")
    parser.add_argument("--output", type=Path, default=Path("wiki/issues.org"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if args.self_check:
        self_check()
        return
    if not args.repo:
        parser.error("--repo is required")
    existing = args.output.read_text(encoding="utf-8") if args.output.exists() else ""
    rendered = render_tracker(args.repo, collect_issues(args.repo), existing)
    if args.dry_run:
        print(rendered, end="")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
