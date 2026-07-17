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
source paths and safety policy, CVE and patch inputs, advisory research filters, and
artifact-validation content.

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

## Discovery subgraph

The first discovery slice is a seeded, specification-first variant-analysis workflow. It
starts from a historical bug, CVE, GHSA, package coordinate, root-cause description, or
patch. `COLLECT` admits bounded source, inspects a supplied patch, and can enrich the seed
through locked OSV, GitHub global-advisory, and CISA KEV tool calls. Network records retain
provenance and remain context only.

The Smart Agent records an explicit threat model and falsifiable invariants. The Tool Agent
performs bounded source searches. Static support may create a candidate, but independent
repeated runtime verification and a passing control case are mandatory before promotion to
a confirmed finding.

See [`docs/discovery.md`](discovery.md) for the design basis, advisory-source policy,
promotion gate, and complete implementation backlog.

The public Python/Context API, additional artifact types, runtime discovery adapters,
durable investigation storage, and deterministic exploit verification remain roadmap work
tracked in GitHub issues. They are not implied capabilities of the current release.
