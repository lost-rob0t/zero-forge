<p align="center">
  <img src=".github/assets/zero-forge-mark.png" width="360" alt="ZeroForge mark">
</p>

<h1 align="center">ZERO//FORGE</h1>

<p align="center">
  <strong>Exploit engineering, constrained.</strong><br>
  Turn vulnerability evidence into validated security artifacts.
</p>

<p align="center">
  <a href="https://github.com/lost-rob0t/zero-forge/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/lost-rob0t/zero-forge/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Python 3.12+" src="https://img.shields.io/badge/python-3.12%2B-111111?logo=python&logoColor=ff1e1e">
  <img alt="License GPLv3" src="https://img.shields.io/badge/license-GPLv3-111111?logo=gnu&logoColor=ff1e1e">
  <img alt="Status experimental" src="https://img.shields.io/badge/status-experimental-ff1e1e">
</p>

---

ZeroForge is an LLM-driven exploit-development harness for **authorized security research**. Feed it a CVE, proof of concept, source tree, advisory, or patch. It collects evidence, generates an artifact, validates the result, and drives repair attempts before anything is accepted.

> **The forge does not trust the first draft.**

## What comes out

| Artifact | Output | Validation stance |
|---|---|---|
| Metasploit exploit | Ruby module | Ruby syntax and structural contract |
| ZAP active scan rule | JavaScript | Must send a bounded, non-destructive probe and produce evidence-backed alerts |
| ZAP passive scan rule | JavaScript | Must remain passive; network calls and request mutation are rejected |

## The pipeline

```text
                    ┌────────────────────────────┐
                    │ CVE · PoC · source · patch │
                    └─────────────┬──────────────┘
                                  │
                           collect evidence
                                  │
                    ┌─────────────▼──────────────┐
                    │        SMART AGENT         │
                    │ reason · design · generate │
                    └─────────────┬──────────────┘
                                  │ artifact
                    ┌─────────────▼──────────────┐
                    │      HARD VALIDATORS       │
                    │ syntax · contract · policy │
                    └───────┬─────────────┬──────┘
                            │ reject      │ accept
                            ▼             ▼
                       repair loop    write artifact
```

Two models. Hard role separation.

- **Smart Agent** — reads bounded context, reasons about the target, writes the artifact, and repairs validation failures.
- **Tool Agent** — selects allowlisted tools and constructs strict arguments. It does not write exploit logic.
- **LangGraph** — owns routing, state, retry budgets, and completion.
- **Deterministic Python** — validates tool calls and artifacts. Model output is never trusted by default.

## Strike the forge

### Requirements

- Python **3.12+**
- [`uv`](https://docs.astral.sh/uv/)
- Ruby **3.3.8** for Metasploit validation
- An OpenRouter, OpenAI, or Anthropic API key

```bash
git clone https://github.com/lost-rob0t/zero-forge.git
cd zero-forge
uv sync --locked --extra dev
cp config.example.yaml zeroforge.yaml
```

Set a provider key:

```bash
export OPENROUTER_API_KEY='sk-or-...'
```

ZeroForge automatically loads a `.env` file from the working directory before resolving settings. Shell variables always take precedence over `.env` values. To use a custom path:

```bash
export ZERO_FORGE_ENV_FILE=/path/to/.env
```

Generate a Metasploit module:

```bash
uv run zero-forge generate --cve CVE-2021-44228
```

Generate ZAP rules:

```bash
uv run zero-forge generate --cve CVE-2021-44228 --type zap_active_scan
uv run zero-forge generate --cve CVE-2021-44228 --type zap_passive_scan
```

Forge every supported artifact type:

```bash
uv run zero-forge generate --cve CVE-2021-44228 --all
```

Bring your own evidence:

```bash
uv run zero-forge generate \
  --cve CVE-2021-44228 \
  --source /path/to/source \
  --poc ./poc.txt
```

Validate an existing artifact without generating anything:

```bash
uv run zero-forge validate exploit.rb
uv run zero-forge validate active-rule.js --type zap_active_scan
uv run zero-forge validate passive-rule.js --type zap_passive_scan
```

## Configuration

Smart and Tool roles are configured independently. Do not point both roles at one model and pretend they are separate agents.

```yaml
models:
  smart:
    provider: openrouter
    model: anthropic/claude-sonnet-4
    temperature: 0.3

  tool:
    provider: openrouter
    model: openai/gpt-4o-mini
    temperature: 0.0

workflow:
  max_repair_attempts: 3

output:
  dir: ./output
```

Environment variables override YAML:

```bash
export ZERO_FORGE_SMART_PROVIDER=openrouter
export ZERO_FORGE_SMART_MODEL=anthropic/claude-sonnet-4
export ZERO_FORGE_TOOL_PROVIDER=openrouter
export ZERO_FORGE_TOOL_MODEL=openai/gpt-4o-mini
export ZERO_FORGE_MAX_REPAIR_ATTEMPTS=3
```

API keys are read from environment variables. They are not loaded from YAML.
A `.env` file in the working directory is loaded before settings resolution; existing shell variables take precedence over `.env` values. Use `ZERO_FORGE_ENV_FILE` to specify a custom `.env` path.

## Failure is a result

ZeroForge is built to fail closed:

- malformed or disallowed Tool Agent calls are rejected and repaired within budget;
- artifact examples are selected by type and bounded by count and total size;
- oversized examples are skipped instead of silently truncated;
- missing Ruby blocks Metasploit validation;
- passive ZAP rules fail when they attempt active behavior;
- stub mode never produces a successful artifact.

## Layout

```text
zero_forge/
├── agents/          smart and tool role implementations
├── tools/           allowlisted research and validation tools
├── llm_examples/    bounded Metasploit and ZAP references
├── workflow.py      LangGraph orchestration and repair loop
├── schemas.py       typed state, input, and artifact contracts
├── examples.py      artifact-specific example loading
├── output.py        contained filesystem writes
└── cli.py           Typer command line interface
```

## Development

```bash
uv sync --locked --extra dev
uv run ruff check .
uv run mypy zero_forge
uv run pytest tests/ -v
```

## License

ZeroForge is released under the **GNU General Public License v3.0**. See [`LICENSE`](LICENSE).

Use it only on systems you own or are explicitly authorized to test.
