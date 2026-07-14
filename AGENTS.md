# ZeroForge AGENTS.md

## Purpose

ZeroForge is an LLM-based exploit-development harness for security artifact generation. It takes vulnerability context (CVE, PoC, write-up, source code, patch diff) and generates security artifacts for authorized testing.

This document owns project-wide engineering rules for the ZeroForge codebase. Detailed contracts for subtrees should live in child `AGENTS.md` files when durable boundaries emerge.

## Agent Conversation Identities

- Never use the repository owner's personal name or GitHub login in agent-generated issues, pull requests, reviews, comments, commit messages, logs, or documentation.
- Use a stable role handle when a conversation needs named speakers. Approved handles are `forge-maintainer`, `validation-reviewer`, `workflow-reviewer`, `tooling-reviewer`, and `ci-reviewer`.
- Prefix conversational GitHub text with the selected handle, for example: `**validation-reviewer:** The file parses as Ruby but defines no module class.`
- Keep one handle per agent for the lifetime of a thread. Refer to the human owner only as `maintainer` or `operator`.
- Do not fabricate real identities, use personal identifiers, or create an `@mention` unless the operator explicitly requests it.
- GitHub's platform attribution may still show the authenticated account; these rules govern the text agents generate.

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
| `zero_forge/agents/smart_agent.py` | LLM-powered artifact generation and repair | `generate_artifact()`, `repair_artifact()`, prompt building, LLM provider resolution, stub fallback |
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
- **API keys are environment-only.** Never load API keys from YAML. Provider priority: OpenRouter > OpenAI > Anthropic > stub. Keys are `repr=False` on `Settings`.
- **LLM provider resolution.** `_resolve_provider()` in `smart_agent.py` auto-prefixes model names (`openrouter/`, `anthropic/`) for LiteLLM routing. OpenAI models need no prefix.
- **Stub mode.** When no API key is set, or LLM call fails, `_stub_metasploit_module()` generates a minimal valid Metasploit template. All tests must pass without API keys.
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

## Verification

- Run targeted tests: `pytest tests/test_<module>.py -v`
- Run full suite: `pytest tests/ -v`
- Lint: `ruff check .`
- Type-check: `mypy zero_forge`
- CLI smoke test (stub mode, no API key): `python -m zero_forge.cli generate --cve CVE-2021-44228`
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
