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
  → Smart Agent generates Metasploit module (LLM or stub mode)
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

# Generate an artifact (stub mode, no API key needed)
python -m zero_forge.cli generate --cve CVE-2021-44228

# With source code and PoC
python -m zero_forge.cli generate --cve CVE-2021-44228 --source /path/to/code --poc poc.txt

# List available tools
python -m zero_forge.cli tools

# Validate an existing module
python -m zero_forge.cli validate exploit.rb
```

## LLM Mode

ZeroForge supports multiple LLM providers via LiteLLM. Provider priority: **OpenRouter > OpenAI > Anthropic > stub**.

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

### Stub mode (default)

No API key required — generates a minimal valid Metasploit module template.

## Testing

```bash
pytest tests/ -v
```

## License

For authorized security testing only.
