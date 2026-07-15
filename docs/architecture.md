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

## Fail-closed workflow

- Provider and response failures carry role, provider, model, retryability, and attempt
  context in `WorkflowError`.
- Stub mode is explicit plumbing only. Stub artifacts cannot validate, save, or complete.
- Artifact validation is mandatory before persistence, and every Smart repair is
  revalidated.
- Output paths reject unsafe CVE IDs, traversal, escaping destinations, and symlinks.
- Source collection skips secrets, symlinks, binaries, and gitignored paths unless the
  operator explicitly enables unsafe collection.

## Current workflow

```text
VulnerabilityInput
  -> Tool Agent context calls
  -> Smart Agent generation
  -> Tool Agent validator call
  -> Smart Agent repair and revalidation (bounded)
  -> safe output publication or failed terminal state
```

The public Python/Context API, typed planning, additional artifact types, discovery
workflows, and deterministic exploit verification remain roadmap work tracked in GitHub
issues. They are not implied capabilities of the current release.
