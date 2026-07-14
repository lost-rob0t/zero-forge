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

- **Smart Agent** (`agents/smart_agent.py`): analyzes the vulnerability and writes artifacts using LiteLLM.
- **Tool Agent** (`agents/tool_agent.py`): performs tool calls, searches, repository inspection, and validation.
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

```bash
# Install
pip install -e .

# Generate an artifact (requires a configured provider key)
python -m zero_forge.cli generate --cve CVE-2021-44228

# With source code and PoC
python -m zero_forge.cli generate --cve CVE-2021-44228 --source /path/to/code --poc poc.txt

# With a custom config file
python -m zero_forge.cli generate --cve CVE-2021-44228 --config my_config.yaml

# List available tools
python -m zero_forge.cli tools

# Validate an existing module
python -m zero_forge.cli validate exploit.rb
```

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
| `ZERO_FORGE_MODEL` | `llm.model` | `gpt-4o-mini` |
| `ZERO_FORGE_LLM_TEMPERATURE` | `llm.temperature` | `0.3` |
| `ZERO_FORGE_LLM_MAX_TOKENS` | `llm.max_tokens` | `4096` |
| `ZERO_FORGE_STUB_MODE` | `llm.stub_mode` | `false` |
| `ZERO_FORGE_OPENROUTER_BASE_URL` | `llm.openrouter_base_url` | `""` |
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
print(settings.llm.model)             # gpt-4o-mini
print(settings.output.dir)           # ./output
print(settings.workflow.max_repair_attempts)  # 3
```

## LLM Mode

ZeroForge supports multiple LLM providers via LiteLLM. Provider priority: **OpenRouter > OpenAI > Anthropic**. Missing credentials, provider errors, and malformed responses fail the workflow with structured provider/model/retry context.

### OpenRouter (preferred)

```bash
export OPENROUTER_API_KEY=sk-or-...
# Model name without prefix; ZeroForge auto-adds openrouter/
export ZERO_FORGE_MODEL=meta-llama/llama-3-70b-instruct

# Optional: custom OpenRouter-compatible base URL
export OPENROUTER_BASE_URL=https://custom.endpoint/v1
```

### OpenAI

```bash
export OPENAI_API_KEY=sk-...
export ZERO_FORGE_MODEL=gpt-4o
```

### Anthropic

```bash
export ANTHROPIC_API_KEY=sk-...
export ZERO_FORGE_MODEL=claude-3.5-sonnet
```

### Stub mode (explicit testing only)

Set `ZERO_FORGE_STUB_MODE=true` only for local plumbing tests. The generated placeholder is marked as a stub; the workflow terminates as failed and never validates or saves it as a completed exploit.

## Testing

```bash
pytest tests/ -v
```

## License

For authorized security testing only.
