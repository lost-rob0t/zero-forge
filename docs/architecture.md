# ZeroForge Architecture

ZeroForge is an LLM-based exploit-development harness for authorized testing. The
current implementation generates Metasploit modules and deliberately separates model
reasoning from registered-tool invocation.

## Agent boundary

| Role | Owns | Must not own |
| --- | --- | --- |
| Smart Agent | vulnerability analysis, artifact generation, repair, final writing | direct tool execution |
| Tool Agent | selecting one allowlisted registered tool and constructing validated arguments | exploit strategy, artifact content, completion decisions |
| LangGraph workflow | ordering, state, repair ceilings, routing, terminal status | silently converting failures into success |
| Deterministic Python | schema validation, callable-argument validation, tool execution, normalization | model reasoning |

The Smart and Tool roles have independent provider, model, temperature, token, and
base-URL configuration under `models.smart` and `models.tool`. Legacy shared-model
configuration is rejected instead of silently assigning one model to both roles.

## Tool-selection repair

`ToolAgent.select_tool_call()` and `ToolAgent.run()` use a bounded repair loop. There is
one initial attempt plus `workflow.max_repair_attempts` corrective attempts. These
selection-boundary failures are repairable:

- empty model content;
- malformed or non-object JSON;
- a response that is not a strict `ToolCall`;
- selection of a tool outside the request allowlist;
- arguments that do not match the registered callable.

When a response is rejected, its assistant content is retained when present and the
boundary error is appended as a corrective user message. Arguments are validated before
the registered function can execute. Configuration failures, provider failures, and
errors raised by the registered tool are not selection repairs and fail immediately.

## Workflow-owned argument integrity

A strict `ToolRequest` may declare `locked_arguments`. The workflow includes those
values in the Tool-model prompt, then rejects a selected call when a locked value is
missing or changed. Built-in workflow calls lock every argument they supply, including
source paths and safety policy, CVE and patch inputs, and artifact-validation content.

A rejected substitution enters the existing bounded Tool-selection repair loop and is
never executed. Requests without locked arguments remain model-constructible for callers
that intentionally delegate argument construction to the Tool Agent.

## Fail-closed workflow

- Provider and response failures carry role, provider, model, retryability, and attempt
  context in `WorkflowError`.
- Stub mode is explicit plumbing only. Stub artifacts cannot validate, save, or complete.
- Artifact validation is mandatory before persistence, and every Smart repair is
  revalidated.
- Metasploit validation preflights the Ruby runtime before generation; an unavailable
  validator runtime fails at startup instead of consuming artifact-repair attempts.
- Output paths reject unsafe CVE IDs, traversal, escaping destinations, and symlinks.
- Source collection skips secrets, symlinks, binaries, and gitignored paths unless the
  operator explicitly enables unsafe collection.

## Current workflow

```text
VulnerabilityInput
  -> validator-runtime preflight
  -> Tool Agent context calls
  -> Smart Agent generation
  -> Tool Agent validator call
  -> Smart Agent repair and revalidation (bounded)
  -> safe output publication or failed terminal state
```

The public Python/Context API, typed planning, additional artifact types, discovery
workflows, and deterministic exploit verification remain roadmap work tracked in GitHub
issues. They are not implied capabilities of the current release.

## Discovery workflow

The discovery subpackage (`zero_forge/discovery/`) implements a separate LangGraph
subgraph for vulnerability discovery.  It is distinct from the artifact-generation
workflow and does not share state with it.

### Execution graph vs investigation graph

ZeroForge maintains two separate graph structures during discovery:

| Graph | Type | Purpose |
| --- | --- | --- |
| Execution graph | LangGraph `StateGraph` | Owns phase ordering, routing, budgets, retries, authorization gates, and terminal states.  Nodes are functions that return state patches. |
| Investigation graph | `InvestigationGraph` (Pydantic) | Persistent, typed storage of investigation entities (Target, Component, Observation, Hypothesis, Experiment, Evidence, Finding) and their relationships.  Negative and inconclusive results are retained so the system does not repeat disproven theories. |

The execution graph drives the workflow; the investigation graph stores the evidence.
An event journal records phase transitions, escalation reasons, and budget
consumption so the full execution trace is inspectable.

### Four-phase operational mode

```text
RESEARCH (iterative deep research loop)
    → attack surface, trust boundaries, entry points, sinks
PLAN (strategy design, readiness gate)
    → hypothesis with success/refutation conditions, typed experiment
EXPLOIT (construction + execution)
    → tool execution, evidence capture, classification
VERIFY (independent reproduction gate)
    → flag retrieval check, repeatability, Finding promotion
```

Backward escalation paths: VERIFY→EXPLOIT (repair), VERIFY→PLAN (strategy revision),
VERIFY→RESEARCH (information gap), EXPLOIT→RESEARCH, PLAN→RESEARCH.

### Flag-based verification

Per the maintainer's simplified direction: the SWE agent places a randomized flag
(via `flag_gen.sh` reading `/dev/urandom`) at a known path.  The exploit phase
reads the flag path.  Verification is a deterministic substring match — no LLM
judgment and no Prolog.  A Finding cannot be created without successful reproduction.

### Finding → artifact-generation bridge

Confirmed findings can feed the existing artifact-generation workflow via
`finding_to_vulnerability_input()`, which converts a `Finding` into a
`VulnerabilityInput`-compatible dict.

### Budgets and safety gates

The discovery subgraph enforces configurable maximums for experiments, research
iterations, requests, hypothesis depth, repair attempts, and runtime.  Authorization
is checked before any filesystem or Docker operations.  Intrusive or destructive
experiments require explicit approval.
