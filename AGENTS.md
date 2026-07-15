# ZeroForge AGENTS.md

## Purpose

ZeroForge is an LLM-based exploit-development harness that generates security artifacts from vulnerability context for authorized testing. This file defines project-wide rules; add child `AGENTS.md` files only for durable subtree-specific contracts.

## GitHub Identity

- Every agent-authored GitHub issue, pull request, review, comment, or reply MUST start with `Hey <model-name> here.` or `t. <model-name>`.
- Use the exact runtime model name. If unavailable, use `Codex`; never invent a version or substitute a role handle.
- Never use the repository owner's personal name or login in agent-generated GitHub text, commits, logs, or documentation; use `maintainer` or `operator`.
- Do not fabricate identities or personal identifiers, or create an `@mention`, unless requested. Platform attribution is outside this rule.

## GitHub Flow and Coordination

- Assume agents work concurrently across computers, sessions, clones, branches, and worktrees. GitHub remote state is the source of truth.
- Before acting or posting, refresh `master`, the linked issue/PR and comments/threads, related open issues/PRs/branches, and current CI.
- Never commit to `master`. Branch from current `master`; prefer `<model-slug>/<issue-number>-<task-slug>-<short-id>`. Keep one focused PR and open it as a draft early.
- Relevant tests must pass before committing. For documentation-only changes, inspect the Markdown and diff; CI remains the merge gate.
- Put scope, blockers, decisions, and review responses in the relevant GitHub thread. Stop conflicting edits and coordinate when work overlaps.
- Never reuse, reset, force-push, delete, overwrite, or amend another agent's branch or commits without explicit authorization.

## Code Review

- Inspect the PR body and full patch, linked issues and latest comments, conversation and unresolved threads, current-head CI, and related open PRs/issues.
- Re-fetch GitHub state before posting. Post findings or answers to the relevant thread with the required introduction, concrete references, and blockers separated from suggestions.

## Project

- Python 3.12+; LangGraph, Pydantic v2, Typer, Rich, LiteLLM, and PyYAML.
- Install: `uv sync --locked --extra dev`; run project commands with `uv run`.
- CLI: `zero-forge` or `python -m zero_forge.cli`.
- Human-facing documentation belongs in `README.md`.

## Ownership

| Path | Responsibility |
| --- | --- |
| `zero_forge/schemas.py` | Input, workflow-state, artifact, and validation schemas |
| `zero_forge/config.py` | Settings, environment/YAML mapping, singleton cache |
| `zero_forge/workflow.py` | LangGraph nodes, routing, retries, and repair loop |
| `zero_forge/cli.py` | Typer commands |
| `zero_forge/output.py` | Safe artifact and metadata-sidecar writes |
| `zero_forge/agents/smart_agent.py` | LLM generation, repair, prompts, and provider errors |
| `zero_forge/agents/tool_agent.py` | Context collection and validation dispatch |
| `zero_forge/tools/` | Registry, CVE/source tools, and validators |
| `tests/` | Pytest contracts; `conftest.py` resets settings |
| `config.example.yaml` | Non-secret configuration defaults |
| `.github/workflows/` | CI and release pipelines |

## Core Contracts

- `WorkflowState` is the integration boundary. Nodes return `dict[str, Any]` patches for LangGraph to merge.
- `get_settings()` is cached. Tests reset it; CLI configuration changes call `get_settings(reload=True)`.
- API keys are environment-only and `repr=False`. Provider priority is OpenRouter, OpenAI, then Anthropic; `_resolve_provider()` applies LiteLLM prefixes.
- LLM failures become typed workflow failures with provider, model, retryability, and attempt context. Never silently substitute a stub.
- `ZERO_FORGE_STUB_MODE=true` is plumbing-only. Stub artifacts are marked and must not be validated, saved, or reported as completed exploits.
- Tools are registered functions. Validators use `validate_{artifact_type}`; `ToolAgent` dispatches them.
- Repairs always revalidate and stop at `WorkflowConfig.max_repair_attempts`.
- `save_artifact()` validates CVE IDs and rejects unsafe, escaping, or symlinked paths; metadata uses a sibling `.meta.json`.
- Source inspection skips binaries, caps reads at 20 files and 50 KB each, prefers `rg`, and parses Git diffs.

## Work Rules

- Read the target module and matching tests first. Make focused changes using existing style: double quotes, type hints, and `from __future__ import annotations`.
- Do not edit `pyproject.toml`, `config.example.yaml`, workflows, or generated files unless required.
- New tools need implementation, registry entry, and tests. New artifact types need enum, validator, registration, and dispatch updates.
- Config changes update `config.py`, `config.example.yaml`, the README environment table, and tests.
- Clean up temporary files, caches, and background processes you create.

## Verification and Merge Gate

- Targeted: `uv run pytest tests/test_<module>.py -v`
- Full: `uv run pytest tests/ -v`
- Static checks: `uv run ruff check .` and `uv run mypy zero_forge`
- No-key smoke test: `uv run python -m zero_forge.cli generate --cve CVE-2021-44228` must fail without writing an artifact.
- Confirm artifacts land in configured `output.dir` (default `./output/`).
- Never merge or enable auto-merge until `lint`, `type-check`, `test (3.12)`, and `test (3.13)` succeed on the current head. Any other state is not a pass; a new head invalidates old results.

## Permissions and Scope

- Allowed: read the project, edit `zero_forge/` and `tests/`, and add modules under `zero_forge/`.
- Ask before changing dependencies/`pyproject.toml`, editing workflows, or deleting outside `output/` and temporary directories.
- No child `AGENTS.md` files exist. Ignore generated `output/`, `.a0proj/`, caches, bytecode, egg-info, and `venv/`.
