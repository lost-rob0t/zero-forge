# Vulnerability Discovery Architecture

ZeroForge discovery starts with **seeded variant analysis**, not an unbounded instruction to
"find a vulnerability." A seed is a historical bug, root-cause description, security patch,
or patch diff. The workflow uses that concrete theory to search for related violations in an
authorized source tree.

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

## Current vertical slice

```text
VariantAnalysisRequest
  -> SCOPE
     require explicit authorization and a concrete seed
  -> COLLECT
     Tool Agent reads bounded, admitted source and inspects the supplied patch
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

This prevents the workflow from converting scanner output, source similarity, model
confidence, or a self-created flag into a confirmed vulnerability.

## Next implementation slice

The next slice should add one narrow runtime adapter rather than a generic shell tool. The
adapter must:

1. accept a typed experiment with locked target, input, timeout, and resource limits;
2. execute only inside an operator-approved isolated environment;
3. capture exact build identity, input, stdout, stderr, exit status, and sanitizer output;
4. run repeated positive cases and a patched or invariant-enforcing control case;
5. return immutable evidence for `promote_candidate()`;
6. pause through a LangGraph interrupt before intrusive execution and resume from a durable
   checkpoint.

Open-ended fuzzing, additional analyzers, hypothesis scheduling, and deduplication belong in
later slices after one real positive/control verification path is reliable.
