# ZeroForge

LLM-based exploit-development harness for security artifact generation.

## Overview

ZeroForge takes vulnerability context (CVE, PoC, write-up, source code, patch diff) and generates security artifacts for authorized testing:

- **Metasploit exploit modules** (implemented)
- ZAP active scan rules (planned)
- ZAP passive scan rules (planned)

## Architecture

```
input CVE + context
  → Tool Agent collects context (CVE lookup, source inspection, git diff)
  → Smart Agent generates Metasploit module with an LLM
  → Tool Agent validates the artifact
  → Smart Agent repairs errors (loop, max 3 attempts)
  → Save result to filesystem
```

- **Smart Agent** (`agents/smart_agent.py`): uses the independently configured Smart model for analysis, artifact writing, repair, and review.
- **Tool Agent** (`agents/tool_agent.py`): uses the independently configured cheap/fast Tool model only to select allowlisted registered tools and construct strict calls. Deterministic Python validates arguments and executes them.
- **LangGraph** (`workflow.py`): controls the workflow and passes results between both agents.
- **Tool Registry** (`tools/registry.py`): simple registration and dispatch of named tool functions.

## Project Structure

```
zero_forge/
├── config.py           # Centralized YAML + env var configuration
├── schemas.py          # Pydantic input/state/artifact schemas
├── workflow.py         # LangGraph workflow with repair loop
├── output.py           # Filesystem output
├── cli.py              # Typer CLI
├── agents/
│   ├── smart_agent.py  # LLM-powered artifact generation + repair
│   └── tool_agent.py    # Context collection + validation
└── tools/
    ├── registry.py      # Tool registry
    ├── cve_lookup.py    # NVD API CVE lookup
    ├── source_inspect.py # Source reading, code search, git diff
    └── validator.py     # Metasploit module validation
```

## Quick Start

ZeroForge requires Python 3.12 or newer. Metasploit module validation also
requires Ruby 3.3.8; validation fails closed when Ruby is unavailable.

```bash
# Create the locked development environment
uv sync --locked --extra dev

# Generate an artifact (requires a configured provider key)
uv run python -m zero_forge.cli generate --cve CVE-2021-44228

# With source code and PoC
uv run python -m zero_forge.cli generate --cve CVE-2021-44228 --source /path/to/code --poc poc.txt

# With a custom config file
uv run python -m zero_forge.cli generate --cve CVE-2021-44228 --config my_config.yaml

# List available tools
uv run python -m zero_forge.cli tools

# Validate an existing module
uv run python -m zero_forge.cli validate exploit.rb
```

`uv sync --locked --extra dev` creates `.venv/` from the committed `uv.lock`
without changing dependency resolution. Package consumers can still install ZeroForge
with `pip install .`.

## Configuration

ZeroForge supports centralized configuration via YAML files and environment variables.

### Config File

Copy the example and edit as needed:

```bash
cp config.example.yaml zeroforge.yaml
```

Config search order (first match wins):
1. `--config <path>` CLI flag (sets `ZERO_FORGE_CONFIG_PATH`)
2. `ZERO_FORGE_CONFIG_PATH` env var
3. `./zeroforge.yaml`
4. `./zeroforge.yml`
5. `~/.config/zeroforge/config.yaml`
6. Built-in defaults

### Environment Variables

All settings can be overridden via environment variables (take priority over YAML):

| Variable | Setting | Default |
|---|---|---|
| `ZERO_FORGE_SMART_PROVIDER` | `models.smart.provider` | `auto` |
| `ZERO_FORGE_SMART_MODEL` | `models.smart.model` | `gpt-4o` |
| `ZERO_FORGE_SMART_TEMPERATURE` | `models.smart.temperature` | `0.3` |
| `ZERO_FORGE_SMART_MAX_TOKENS` | `models.smart.max_tokens` | `4096` |
| `ZERO_FORGE_SMART_BASE_URL` | `models.smart.base_url` | `""` |
| `ZERO_FORGE_TOOL_PROVIDER` | `models.tool.provider` | `auto` |
| `ZERO_FORGE_TOOL_MODEL` | `models.tool.model` | `gpt-4o-mini` |
| `ZERO_FORGE_TOOL_TEMPERATURE` | `models.tool.temperature` | `0.0` |
| `ZERO_FORGE_TOOL_MAX_TOKENS` | `models.tool.max_tokens` | `1024` |
| `ZERO_FORGE_TOOL_BASE_URL` | `models.tool.base_url` | `""` |
| `ZERO_FORGE_STUB_MODE` | `llm.stub_mode` | `false` |
| `ZERO_FORGE_OUTPUT_DIR` | `output.dir` | `./output` |
| `ZERO_FORGE_MAX_REPAIR_ATTEMPTS` | `workflow.max_repair_attempts` | `3` |
| `OPENROUTER_API_KEY` | `openrouter_api_key` | `""` |
| `OPENAI_API_KEY` | `openai_api_key` | `""` |
| `ANTHROPIC_API_KEY` | `anthropic_api_key` | `""` |

> **Security:** API keys are read exclusively from environment variables and are never loaded from YAML files.

### Programmatic Access

```python
from zero_forge.config import get_settings

settings = get_settings()
print(settings.models.smart.model)    # gpt-4o
print(settings.models.tool.model)     # gpt-4o-mini
print(settings.output.dir)           # ./output
print(settings.workflow.max_repair_attempts)  # 3
```

## LLM Mode

ZeroForge supports multiple LLM providers via LiteLLM. Smart and Tool roles have independent provider, model, temperature, token, and base-URL settings. With `provider: auto`, provider priority is **OpenRouter > OpenAI > Anthropic**. Missing credentials, provider errors, malformed Tool calls, disallowed tools, and invalid arguments fail closed with role/provider/model context.

Legacy single-model YAML such as `llm.model` and environment variables such as `ZERO_FORGE_MODEL` are rejected with a migration error. Configure both roles explicitly instead of silently sharing one model.

### OpenRouter (preferred)

```bash
export OPENROUTER_API_KEY=sk-or-...
export ZERO_FORGE_SMART_MODEL=anthropic/claude-sonnet-4
export ZERO_FORGE_TOOL_MODEL=openai/gpt-4o-mini

# Optional independent OpenRouter-compatible endpoints
export ZERO_FORGE_SMART_BASE_URL=https://smart.endpoint/v1
export ZERO_FORGE_TOOL_BASE_URL=https://tool.endpoint/v1
```

### OpenAI

```bash
export OPENAI_API_KEY=sk-...
export ZERO_FORGE_SMART_PROVIDER=openai
export ZERO_FORGE_SMART_MODEL=gpt-4o
export ZERO_FORGE_TOOL_PROVIDER=openai
export ZERO_FORGE_TOOL_MODEL=gpt-4o-mini
```

### Anthropic

```bash
export ANTHROPIC_API_KEY=sk-...
export ZERO_FORGE_SMART_PROVIDER=anthropic
export ZERO_FORGE_SMART_MODEL=claude-3.5-sonnet
export ZERO_FORGE_TOOL_PROVIDER=anthropic
export ZERO_FORGE_TOOL_MODEL=claude-3-haiku
```

### Stub mode (explicit testing only)

Set `ZERO_FORGE_STUB_MODE=true` only for local plumbing tests. The generated placeholder is marked as a stub; the workflow terminates as failed and never validates or saves it as a completed exploit.

## Testing

```bash
uv run pytest tests/ -v
```

## License

For authorized security testing only.
