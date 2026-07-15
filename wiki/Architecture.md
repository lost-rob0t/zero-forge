# Architecture

ZeroForge keeps one Smart model for analysis and artifact writing and one independently
configured Tool model for strict registered-tool calls. LangGraph owns orchestration and
repair budgets; deterministic Python validates and executes selected calls.

Tool selection is fail-closed but repairable for malformed JSON, empty responses,
disallowed names, and invalid callable arguments. The rejected response and error are fed
back through a bounded corrective conversation. Provider and tool-execution failures are
not silently retried as selection repairs.

Workflow-owned paths, safety flags, CVE inputs, patch text, and validation content are
locked in each Tool request; model output cannot replace them before execution.
Metasploit generation also preflights Ruby 3.3.8 and fails without spending the Smart
Agent repair budget when the validator runtime is unavailable.

See [`docs/architecture.md`](../docs/architecture.md) for the maintained detailed contract.
