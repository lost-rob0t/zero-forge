#!/usr/bin/env python3
"""Map changed repository paths to documentation areas that need review."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def recommendations(paths: list[str]) -> list[str]:
    areas: set[str] = set()
    for path in paths:
        if path.startswith("zero_forge/agents/") or path.endswith("workflow.py"):
            areas.add("docs/architecture.md")
        if path.endswith("config.py") or path == "config.example.yaml":
            areas.update(("README.md", "docs/architecture.md"))
        if path.startswith("zero_forge/cli.py") or path.startswith("zero_forge/output.py"):
            areas.add("README.md")
        if path.startswith(".github/") or path == "pyproject.toml":
            areas.add("docs/maintenance.md")
        if path.startswith("dev_scripts/"):
            areas.add("docs/maintenance.md")
    return sorted(areas)


def changed_paths(repository: Path, from_ref: str, to_ref: str) -> list[str]:
    completed = subprocess.run(
        ["git", "-C", str(repository), "diff", "--name-only", from_ref, to_ref, "--"],
        check=True,
        capture_output=True,
        text=True,
    )
    return [line for line in completed.stdout.splitlines() if line]


def self_check() -> None:
    result = recommendations(["zero_forge/config.py", "dev_scripts/tool.py"])
    assert result == ["README.md", "docs/architecture.md", "docs/maintenance.md"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-path", type=Path, default=Path("."))
    parser.add_argument("--from-ref")
    parser.add_argument("--to-ref", default="master")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if args.self_check:
        self_check()
        return
    if not args.from_ref:
        parser.error("--from-ref is required")
    paths = changed_paths(args.repo_path, args.from_ref, args.to_ref)
    for path in recommendations(paths):
        print(path)


if __name__ == "__main__":
    main()
