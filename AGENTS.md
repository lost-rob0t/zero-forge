# ZeroForge AGENTS.md

## Purpose

ZeroForge is an LLM-based exploit-development harness for security artifact generation. It takes vulnerability context (CVE, PoC, write-up, source code, patch diff) and generates security artifacts for authorized testing.

This document owns project-wide engineering rules for the ZeroForge codebase. Detailed contracts for subtrees should live in child `AGENTS.md` files when durable boundaries emerge.

## Agent Identity in GitHub Conversations

- Every agent-authored GitHub issue, pull request, review, comment, or reply MUST begin with exactly one of these introductions:
  - `Hey <model-name> here.`
  - `t. <model-name>`
- Use the exact model name exposed by the runtime. If the runtime does not expose a versioned model name, use the product identity `Codex`; never invent a model version.
- Do not substitute role handles such as `validation-reviewer` for the model identity.
- Never use the repository owner's personal name or GitHub login in agent-generated issues, pull requests, reviews, comments, commit messages, logs, or documentation.
- Refer to the human owner only as `maintainer` or `operator`.
- Do not fabricate real identities, use personal identifiers, or create an `@mention` unless the operator explicitly requests it.
- GitHub's platform attribution may still show the authenticated account; these rules govern the text agents generate.

## Distributed Agent Coordination and GitHub Flow

- Assume multiple agents are working concurrently from different computers, sessions, clones, branches, and worktrees.
- Never treat local filesystem, branch, issue, review, or test state as globally current or exclusively owned.
- GitHub is the coordination source of truth: remote branches, issues, pull requests, comments, review threads, and CI status.
- All repository changes MUST use GitHub flow. Never commit directly to `master`.
- Before starting work:
  1. fetch or inspect the current remote `master`;
  2. read the linked issue and its latest comments;
  3. inspect open pull requests and issues for duplicate or overlapping work;
  4. inspect remote branches when the task may already be in progress;
  5. announce or confirm the intended scope in the relevant GitHub thread.
- Create a unique branch from current `master`. Prefer `<model-slug>/<issue-number>-<task-slug>-<short-id>` so concurrent agents do not collide.
- Do not reuse, reset, force-push, delete, or overwrite another agent's branch. Do not amend commits that another agent may already have based work on.
- Keep each branch and pull request focused on one issue or coherent change.
- Run relevant tests before committing. A commit is allowed only when those tests pass. For documentation-only changes, inspect the rendered Markdown/diff and rely on PR CI for the repository gate.
- Push the branch and open a draft pull request early enough for other agents to discover the work. Link the issue and state the files/scope being changed.
- Put coordination updates, blockers, design decisions, and review responses in the issue or pull request—not only in a local session.
- Immediately before pushing, reviewing, replying, or merging, refresh the relevant GitHub state because another agent may have changed it.
- If overlapping work is discovered, stop making conflicting edits and coordinate in the GitHub thread. Reuse or build on the existing branch only when its owner or the operator explicitly authorizes it.
- Never merge until the current-head CI requirements in this file pass.

## GitHub-Aware Code Review

- A code review is not limited to the local diff. Reviewers MUST inspect:
  - the pull request body and complete patch;
  - linked issues and their latest comments;
  - current PR conversation, reviews, and unresolved review threads;
  - current CI/check state for the PR head SHA;
  - related or overlapping open pull requests and issues.
- If the review starts from an issue, inspect its linked or candidate pull requests. If it starts from a pull request, inspect its linked issue and nearby issues that may change the intended scope.
- Re-fetch GitHub state immediately before posting the review so findings do not duplicate work already addressed by another agent.
- Post actionable review findings or answers to the relevant GitHub issue or pull request thread. Do not leave the result only in local chat.
- Every posted review or reply must follow the model-identity introduction rule above.
- Cite concrete files, lines, checks, commits, or issue requirements. Clearly separate blocking findings from non-blocking suggestions.

## Project

- Stack: Python 3.12+, LangGraph, Pydantic v2, Typer, Rich, LiteLLM, PyYAML.
- Install with `pip install -e .` (or `pip install -e ".[dev]"` for development extras including ruff, mypy, pytest-cov).
- CLI entry point: `python -m zero_forge.cli` or the `zero-forge` console script.
- Run tests with `pytest tests/ -v`.
- CI: GitHub Actions on push/PR to `master` — ruff lint, mypy type-check, pytest with coverage on Python 3.12 and 3.13.
- Human-facing documentation lives in `README.md`.

## Ownership

| Path | Owner | Scope |
| --- | --- | --- |
| `zero_forge/schemas.py` | Pydantic input, state, and artifact schemas | `ArtifactType`, `VulnerabilityInput`, `SourceFile`, `CollectedContext`, `Artifact`, `ValidationResult`, `WorkflowState` |
| `zero_forge/config.py` | Centralized configuration | `Settings`, `LLMConfig`, `WorkflowConfig`, `OutputConfig`, env-var mapping, YAML loading, singleton cache |
| `zero_forge/workflow.py` | LangGraph workflow and node functions | `build_workflow()`, `run_workflow()`, all node functions, conditional edges, repair loop |
| `zero_forge/cli.py` | Typer CLI | `generate`, `tools`, `validate` commands |
| `zero_forge/output.py` | Filesystem output | `save_artifact()`, path validation, symlink/escape guards, metadata sidecar |
| `zero_forge/agents/smart_agent.py` | LLM-powered artifact generation and repair | `generate_artifact()`, `repair_artifact()`, prompt building, provider resolution, typed LLM failures, explicit stub mode |
| `zero_forge/agents/tool_agent.py` | Context collection and validation dispatch | `ToolAgent` class, `collect_context()`, `validate_artifact()`, `list_available_tools()` |
| `zero_forge/tools/registry.py` | Tool registry | `ToolRegistry` class, `create_default_registry()` |
| `zero_forge/tools/cve_lookup.py` | NVD API CVE lookup | `cve_lookup()` |
| `zero_forge/tools/source_inspect.py` | Source inspection | `read_source_files()`, `search_code()`, `git_diff_inspect()`, file categorization and language detection |
| `zero_forge/tools/validator.py` | Metasploit module validation | `validate_metasploit()` |
| `tests/` | Pytest regression and contract tests | One test file per module; `conftest.py` resets config singleton |
| `config.example.yaml` | Configuration template | Non-secret YAML defaults |
| `.github/workflows/` | CI/CD pipelines | `ci.yml` (lint, type-check, test), `release.yml` |

## Local Contracts

- **Schemas are the integration boundary.** All workflow state flows through `WorkflowState` (Pydantic). Nodes return `dict[str, Any]` patches; LangGraph merges them into state.
- **Config singleton.** `get_settings()` returns a cached `Settings` instance. Tests must call `reset_settings()` (handled by `conftest.py` autouse fixture) before and after each test. CLI `--config` and `--output` flags set env vars then call `get_settings(reload=True)`.
- **API keys are environment-only.** Never load API keys from YAML. Provider priority: OpenRouter > OpenAI > Anthropic. Keys are `repr=False` on `Settings`.
- **LLM provider resolution.** `_resolve_provider()` in `smart_agent.py` auto-prefixes model names (`openrouter/`, `anthropic/`) for LiteLLM routing. OpenAI models need no prefix.
- **LLM failures fail closed.** Missing credentials, provider exceptions, and malformed responses become typed workflow failures with provider, model, retryability, and attempt context. Never substitute a stub for a failed LLM call.
- **Stub mode is explicit and non-successful.** `ZERO_FORGE_STUB_MODE=true` may generate a placeholder for local plumbing tests. Stub artifacts are marked in metadata and must never be validated, saved, or reported as completed exploits.
- **Tool registry.** Tools are plain functions registered by name in `ToolRegistry`. `ToolAgent` dispatches by name. New validators follow the `validate_{artifact_type}` naming convention.
- **Repair loop.** `should_repair_or_finish()` gates the repair→validate cycle. After repair, `should_repair_after_fix()` always re-validates. Max attempts from `WorkflowConfig.max_repair_attempts` (default 3).
- **Output safety.** `save_artifact()` validates CVE ID format, rejects path separators/parent refs/absolute paths/symlinks in filenames, and ensures destinations stay inside the output root. A `.meta.json` sidecar is written alongside each artifact.
- **Source inspection.** `read_source_files()` categorizes files (documentation > config > data > code), skips binaries, caps at 20 files / 50 KB each. `search_code()` prefers `rg` (ripgrep) with Python fallback. `git_diff_inspect()` parses diff text for changed files and additions/deletions.

## Work Guidance

- Read the target module and its tests before editing. Tests mirror the module name (e.g., `test_config.py` ↔ `config.py`).
- Make minimal focused changes. Match existing style (double quotes, type hints, `from __future__ import annotations`).
- Do not edit `pyproject.toml`, `config.example.yaml`, `.github/workflows/`, or generated files unless the task requires it.
- When adding a new tool: implement the function in `tools/`, register it in `create_default_registry()`, add a test in `tests/`.
- When adding a new artifact type: extend `ArtifactType` enum, add a `validate_{type}` function, register it, and update `ToolAgent.validate_artifact()` dispatch.
- When changing config: update `config.py`, `config.example.yaml`, env var table in `README.md`, and `test_config.py`.
- Clean up temp files, caches, and background processes you create.

## Pull Request Merge Gate

- Never merge a pull request or enable auto-merge until every required CI job has succeeded on the pull request's current head SHA.
- Required CI jobs are `lint`, `type-check`, `test (3.12)`, and `test (3.13)` from the `CI` workflow.
- A pending, skipped, cancelled, timed-out, action-required, neutral, or failed job is not a pass.
- If the pull request head changes, discard the previous result and wait for CI to succeed again.

## Verification

- Run targeted tests: `pytest tests/test_<module>.py -v`
- Run full suite: `pytest tests/ -v`
- Lint: `ruff check .`
- Type-check: `mypy zero_forge`
- CLI failure smoke test (no API key): `python -m zero_forge.cli generate --cve CVE-2021-44228` must report a failed workflow and write no artifact.
- Verify output artifacts land in the configured `output.dir` (default `./output/`)

## Permissions

Allowed without asking:

- Read all project files.
- Edit files under `zero_forge/` and `tests/`.
- Create new modules under `zero_forge/`.

Ask before:

- Modifying `pyproject.toml` or adding dependencies.
- Editing `.github/workflows/`.
- Deleting files outside of `output/` or temp directories.

## Child DOX Index

No child `AGENTS.md` files exist yet. Create one only when a subtree (e.g., `zero_forge/tools/` or `zero_forge/agents/`) develops a durable boundary with distinct ownership or workflow.

| Child | Scope |
| --- | --- |
| _(none yet)_ | _Create when a subtree needs its own contract._ |

## Intentionally Unindexed

| Path | Reason |
| --- | --- |
| `output/` | Generated artifacts and metadata sidecars. |
| `.a0proj/` | Agent Zero project data, memory, plugins, and settings. |
| `.mypy_cache/`, `.ruff_cache/`, `.pytest_cache/` | Generated tool caches. |
| `__pycache__/`, `*.egg-info/` | Python bytecode and packaging artifacts. |
| `venv/` | Local virtual environment. |
