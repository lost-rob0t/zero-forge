"""Tests for maintainer automation helpers."""

from dev_scripts.changed_docs import recommendations
from dev_scripts.sync_issues_org import render_tracker
from dev_scripts.update_run_ledger import append_entry, render_entry


def test_issue_tracker_preserves_run_ledger():
    issue = {
        "number": 45,
        "title": "Bootstrap maintenance",
        "state": "OPEN",
        "labels": [{"name": "priority:P2"}],
        "assignees": [],
        "url": "https://example.invalid/issues/45",
        "updatedAt": "2026-07-15T00:00:00Z",
        "closedAt": None,
        "stateReason": None,
        "body": "Create the tracker.",
        "comments": [],
    }
    existing = "* Run Ledger\n\n** COMPLETED old-run\n"
    rendered = render_tracker("owner/repo", [issue], existing)
    assert ":ID: issue-45" in rendered
    assert rendered.count("* Run Ledger") == 1
    assert "** COMPLETED old-run" in rendered


def test_issue_tracker_separates_recently_closed_issues():
    issue = {
        "number": 12,
        "title": "Ruby preflight",
        "state": "CLOSED",
        "stateReason": "COMPLETED",
        "labels": [],
        "assignees": [],
        "url": "https://example.invalid/issues/12",
        "updatedAt": "2026-07-15T00:48:10Z",
        "closedAt": "2026-07-15T00:48:10Z",
        "body": "Preflight Ruby.",
        "comments": [],
    }
    rendered = render_tracker("owner/repo", [issue])
    assert "* Recently Closed" in rendered
    assert "** DONE #12 Ruby preflight" in rendered
    assert ":STATE_REASON: COMPLETED" in rendered


def test_run_entry_is_append_only():
    values = {
        "run_id": "run-1",
        "started_at": "start",
        "ended_at": "end",
        "window_start": "start",
        "window_end": "end",
        "master_sha": "abc",
        "outcome": "completed",
    }
    rendered = append_entry("* Run Ledger\n", render_entry(values))
    assert "** COMPLETED run-1" in rendered
    assert ":MASTER_SHA: abc" in rendered


def test_changed_paths_map_to_documentation():
    assert recommendations(
        ["zero_forge/agents/tool_agent.py", "dev_scripts/sync_issues_org.py"]
    ) == ["docs/architecture.md", "docs/maintenance.md"]
