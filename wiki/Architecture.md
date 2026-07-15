# Architecture

ZeroForge keeps one Smart model for analysis and artifact writing and one independently
configured Tool model for strict registered-tool calls. LangGraph owns orchestration and
repair budgets; deterministic Python validates and executes selected calls.

Tool selection is fail-closed but repairable for malformed JSON, empty responses,
disallowed names, and invalid callable arguments. The rejected response and error are fed
back through a bounded corrective conversation. Provider and tool-execution failures are
not silently retried as selection repairs.

See [`docs/architecture.md`](../docs/architecture.md) for the maintained detailed contract.
