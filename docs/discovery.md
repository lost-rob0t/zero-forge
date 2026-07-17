# Vulnerability Discovery Architecture

ZeroForge discovery starts with **seeded variant analysis**, not an unbounded instruction to
"find a vulnerability." A seed may be a historical bug, CVE, GHSA, affected package, root
cause, security patch, or patch diff. The workflow uses that concrete theory to search for
related violations in an authorized source tree.

This is a separate LangGraph subgraph that preserves the existing two-agent contract:

- the **Smart Agent** constructs the threat model, invariants, and hypotheses;
- the **Tool Agent** executes one bounded, typed, allowlisted tool request at a time;
- **LangGraph** owns authorization gates, phase order, budgets, and terminal status;
- deterministic Python validates schemas, executes tools, records evidence, and enforces
  finding-promotion rules.

## Research basis

The architecture is based on four current results:

1. [Big Sleep](https://googleprojectzero.blogspot.com/2024/11/from-naptime-to-big-sleep.html)
   reports that variant analysis seeded by a previous vulnerability is a better-defined task
   for current models than open-ended vulnerability research. Supplying the commit message
   and patch creates a concrete starting theory.
2. [Code-Augur](https://arxiv.org/abs/2606.18619) uses a specification-first loop: make the
   agent's implicit security assumptions explicit as falsifiable invariants, attempt to
   falsify them dynamically, then refine either the bug theory or the specification.
3. [Agentic Fuzzing](https://arxiv.org/abs/2605.10074) similarly starts from a reference bug,
   derives related scenarios, and verifies each hypothesis by execution. It identifies
   harness engineering, duplicate investigations, and scheduling as first-class problems.
4. [CyberGym](https://www.cybergym.io/cybergym/) shows that richer vulnerability context,
   including stack traces and patches, materially improves reproduction success. It also
   demonstrates that real-world reproduction remains difficult, so static plausibility must
   not be treated as confirmation.

## Known-bug seed research

`COLLECT` can enrich an explicit seed through three official public sources:

- [OSV](https://google.github.io/osv.dev/api/) for package and version vulnerability records;
- [GitHub global security advisories](https://docs.github.com/en/rest/security-advisories/global-advisories)
  for CVE/GHSA aliases, vulnerable ranges, vulnerable functions, CWEs, and references;
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) as an
  exploitation-in-the-wild annotation and prioritization signal.

Every network call is a fully locked Tool Agent request with bounded result count and timeout.
The normalized `KnownBugRecord` retains source identity and references. Advisory data is seed
context only: it cannot directly create static evidence, a candidate, or a confirmed finding.
Network failures are retained in `research_errors`, and local analysis continues when valid
source context is available.

## Current vertical slice

```text
VariantAnalysisRequest
  -> SCOPE
     require explicit authorization and a concrete manual, advisory, or package seed
  -> COLLECT
     admit bounded source, inspect a supplied patch, and enrich known-bug context
  -> HYPOTHESIZE
     Smart Agent emits a strict threat model and falsifiable invariants
  -> INVESTIGATE
     Tool Agent performs bounded searches over admitted paths only
  -> COMPLETE
     return inconclusive hypotheses or candidates awaiting runtime verification
```

A source match is only **static support**. It may create a `CandidateFinding`, but it cannot
create a `ConfirmedFinding`.

## Finding promotion gate

`promote_candidate()` requires all of the following:

- the candidate is still awaiting verification;
- the positive case reproduces for the configured number of runs;
- the control case executes for the same required number of runs;
- the control case passes;
- runtime evidence demonstrates a violated security property;
- the violation is reproducible;
- static and runtime evidence identifiers remain linked to the result.

This prevents the workflow from converting advisory text, scanner output, source similarity,
model confidence, or a self-created flag into a confirmed vulnerability.

## Work required for a complete workflow

The current implementation stops after static candidate generation. A complete discovery
workflow still requires these slices, in dependency order:

1. **Target and build identity**
   - resolve repository commit, package versions, lockfiles, build flags, enabled features,
     service topology, and platform details;
   - produce a stable target fingerprint used by every later evidence record.
2. **Patch and provenance resolver**
   - follow advisory references to vendor bulletins, fix commits, release notes, and patch
     diffs through a bounded URL allowlist;
   - hash fetched content, retain retrieval time and final URL, and distinguish primary from
     secondary sources;
   - add a generic web-search fallback only after structured advisory sources are exhausted.
3. **Iterative hypothesis controller**
   - rank multiple hypotheses, retain refuted and inconclusive results, deduplicate equivalent
     theories, and refine specifications from negative evidence;
   - enforce request, token, search, experiment, runtime, and depth budgets across iterations.
4. **Static analysis adapters**
   - add typed Semgrep, tree-sitter query, dependency-callgraph, and language-specific analyzer
     adapters;
   - normalize analyzer output into evidence without treating tool severity as confirmation.
5. **Runtime experiment planner and harnesses**
   - let the Smart Agent propose typed experiments while deterministic code validates them;
   - implement narrow adapters for unit-test execution, parser inputs, HTTP replay/mutation,
     sanitizer builds, and selected fuzzing harnesses instead of a generic unrestricted shell.
6. **Isolation, approval, and durable checkpoints**
   - run intrusive experiments in an operator-approved container or VM with explicit network,
     filesystem, process, time, and resource policy;
   - pause through LangGraph interrupts before execution and resume from a persistent
     checkpointer after approval or process restart.
7. **Independent verification and controls**
   - rerun positive cases, execute patched or invariant-enforcing controls, compare observable
     behavior, and classify supported, refuted, or inconclusive outcomes;
   - prevent the same model-generated assertion from serving as both hypothesis and proof.
8. **Evidence and finding store**
   - persist immutable raw outputs, input artifacts, tool versions, commands, environment,
     target fingerprint, timestamps, hashes, and parent hypothesis relationships;
   - deduplicate findings by root cause and affected code path, not only by title or CVE.
9. **Generation bridge and operator interfaces**
   - convert confirmed findings into `VulnerabilityInput` only after promotion;
   - expose CLI/API commands for starting, inspecting, approving, resuming, cancelling, and
     exporting investigations.
10. **Evaluation suite**
    - test known vulnerable and patched targets across languages and bug classes;
    - measure candidate precision, confirmation precision, reproduction rate, duplicate rate,
      cost, time, and regression behavior before calling the workflow autonomous.

The next implementation slice should be one narrow runtime adapter plus durable approval and
checkpoint handling. Open-ended fuzzing and broad autonomous scheduling should come only after
one real positive/control verification path is reliable.
