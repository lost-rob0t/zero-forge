# Issue #28 Milestone Tracker

> **Epic**: [#28 — Vulnerability discovery: hypothesis–experiment–evidence workflow](https://github.com/lost-rob0t/zero-forge/issues/28)
> **Epic code**: `ZF-DSC-00`
> **Label namespace**: `area:discovery`
> **Target branch**: `docs/research`

---

## Naming Scheme

### Structure

```
ZF-DSC-<milestone>.<subtask>
         └─┬───┘ └──┬───┘
           │        │
           │        └─ sub-task within milestone (optional)
           └─ milestone number (01–07)
```

- **Prefix**: `ZF-DSC` — ZeroForge Discovery namespace (separate from the existing `ZF-NNN` bug/task series)
- **Milestone codes**: `ZF-DSC-01` through `ZF-DSC-07` (maps to M1–M7)
- **Sub-task codes**: `ZF-DSC-01.1`, `ZF-DSC-01.2`, etc. (decimal notation for granular tracking)
- **Epic code**: `ZF-DSC-00` (the parent issue #28 itself)

### Branch Naming

```
feature/zf-dsc-<MM>-<short-slug>
```

Examples:
- `feature/zf-dsc-01-investigation-schemas`
- `feature/zf-dsc-03-four-phase-subgraphs`
- `feature/zf-dsc-04-verification-oracle`

### GitHub Milestone Titles

```
ZF-DSC-01: Investigation Graph Schemas
ZF-DSC-02: Hypothesis + Discovery Agent
ZF-DSC-03: Four-Phase LangGraph Subgraphs
ZF-DSC-04: Formal Verification Oracle
ZF-DSC-05: Discovery Tool Adapters
ZF-DSC-06: Budgets + Safety Gates
ZF-DSC-07: SWE/Docker + Integration + Tests + Docs
ZF-DSC-08: Vulnerability + Code Scanning Tools
```

### Label Scheme (extends existing)

| Label | Purpose |
|---|---|
| `area:discovery` | Existing — all #28 work carries this |
| `epic:zf-dsc-00` | New — links issue/PR to this epic |
| `milestone:zf-dsc-01` … `milestone:zf-dsc-07` | New — links issue/PR to a specific milestone |
| Existing: `priority:*`, `type:*`, `status:*` | Unchanged — applied per sub-task as needed |

---

## Milestone Registry

| Code | M# | Title | Status | Est. PRs | Branch Slug | Depends On |
|---|---|---|---|---|---|---|
| `ZF-DSC-01` | M1 | Investigation Graph Schemas | 🔲 Not started | 1 | `investigation-schemas` | — |
| `ZF-DSC-02` | M2 | Hypothesis + Discovery Agent | 🔲 Not started | 1–2 | `hypothesis-discovery-agent` | `ZF-DSC-01` |
| `ZF-DSC-03` | M3 | Four-Phase LangGraph Subgraphs | 🔲 Not started | 2–3 | `four-phase-subgraphs` | `ZF-DSC-02`, `ZF-DSC-06` |
| `ZF-DSC-04` | M4 | Formal Verification Oracle | 🔲 Not started | 1–2 | `verification-oracle` | `ZF-DSC-03` (partial) |
| `ZF-DSC-05` | M5 | Discovery Tool Adapters | 🔲 Not started | 2–3 | `discovery-tool-adapters` | `ZF-DSC-03` (partial) |
| `ZF-DSC-06` | M6 | Budgets + Safety Gates | 🔲 Not started | 1 | `budget-safety-gates` | `ZF-DSC-01` |
| `ZF-DSC-07` | M7 | SWE/Docker + Integration + Tests + Docs | 🔲 Not started | 2–3 | `swe-docker-integration` | `ZF-DSC-03`, `ZF-DSC-04`, `ZF-DSC-05`, `ZF-DSC-06` |
| `ZF-DSC-08` | M8 | Vulnerability + Code Scanning Tools | 🔲 Not started | 2–3 | `scanner-integration` | `ZF-DSC-01`, `ZF-DSC-05` (partial) |

### Parallelization

```
ZF-DSC-01 ──→ ZF-DSC-02 ──→ ZF-DSC-06 ──→ ZF-DSC-03 ──→ ZF-DSC-04 ──→ ZF-DSC-05 ──→ ZF-DSC-07
                                   └──────────────┘        └──────────┘            ↗
                                  (M6 ∥ M3 start)         (M4 ∥ M5)             │
                                                                               │
              ZF-DSC-01 ──→ ZF-DSC-08 ────────────────────────────────────────────┘
                            (M8 ∥ M5, feeds M7 RESEARCH phase)
```

---

## Sub-Task Breakdown

### ZF-DSC-01: Investigation Graph Schemas

| Sub-code | Title | Files | Status |
|---|---|---|---|
| `ZF-DSC-01.1` | Entity schemas (Target, Component, Observation, Hypothesis, Experiment, TestRun, Evidence, Counterevidence, Finding, Artifact) | `zero_forge/investigation.py` | 🔲 |
| `ZF-DSC-01.2` | Enums (AccessMode, HypothesisStatus, EvidenceKind, RelationshipKind) | `zero_forge/investigation.py` | 🔲 |
| `ZF-DSC-01.3` | Relationship record + InvestigationGraph container (add, link, query, get_refuted, get_supported) | `zero_forge/investigation.py` | 🔲 |
| `ZF-DSC-01.4` | JSONL append-only investigation store with provenance | `zero_forge/investigation_store.py` | 🔲 |
| `ZF-DSC-01.5` | DiscoveryConfig in Settings (budgets, store dir, approval flag) | `zero_forge/config.py` | 🔲 |
| `ZF-DSC-01.6` | Tests: entity creation, relationship linking, query filters, refuted-hypothesis retention, schema validation | `tests/test_investigation.py` | 🔲 |

### ZF-DSC-02: Hypothesis + Discovery Agent

| Sub-code | Title | Files | Status |
|---|---|---|---|
| `ZF-DSC-02.1` | DISCOVERY_SYSTEM_PROMPT + hypothesis generation LLM call | `zero_forge/agents/discovery_agent.py` | 🔲 |
| `ZF-DSC-02.2` | Structured Hypothesis JSON output parsing and validation | `zero_forge/agents/discovery_agent.py` | 🔲 |
| `ZF-DSC-02.3` | Hypothesis ranking (evidence-basis quality, counterevidence awareness) | `zero_forge/agents/discovery_agent.py` | 🔲 |
| `ZF-DSC-02.4` | Experiment design (bounded ToolRequest from hypothesis) | `zero_forge/agents/discovery_agent.py` | 🔲 |
| `ZF-DSC-02.5` | Result classification (supported / refuted / inconclusive) | `zero_forge/agents/discovery_agent.py` | 🔲 |
| `ZF-DSC-02.6` | Hypothesis refinement from evidence | `zero_forge/agents/discovery_agent.py` | 🔲 |
| `ZF-DSC-02.7` | Tests: mock LLM hypothesis generation, ranking with counterevidence, experiment design, classification, refinement | `tests/test_discovery_agent.py` | 🔲 |

### ZF-DSC-03: Four-Phase LangGraph Subgraphs

| Sub-code | Title | Files | Status |
|---|---|---|---|
| `ZF-DSC-03.1` | RESEARCH subgraph: plan → execute → observe → assess → check_termination | `zero_forge/phases/research.py` | 🔲 |
| `ZF-DSC-03.2` | ResearchConfig (max_iterations, confidence_threshold, diminishing_returns) | `zero_forge/config.py` | 🔲 |
| `ZF-DSC-03.3` | RESEARCH output artifacts (VulnerabilityBrief, RootCauseReport, AttackSurfaceMap, MitigationProfile, PriorArtCollection, ResearchSummary) | `zero_forge/phases/research.py` | 🔲 |
| `ZF-DSC-03.4` | PLAN subgraph: strategy → primitives → mitigation bypass → capability ladder → success oracle → readiness gate | `zero_forge/phases/plan.py` | 🔲 |
| `ZF-DSC-03.5` | EXPLOIT subgraph: scaffold → trigger → primitive → chain → repair loop | `zero_forge/phases/exploit.py` | 🔲 |
| `ZF-DSC-03.6` | VERIFY subgraph: syntax → runtime → oracle → repeatability → control case → crash analysis → capability tier | `zero_forge/phases/verify.py` | 🔲 |
| `ZF-DSC-03.7` | Phase router: DiscoveryWorkflowState, backward escalation edges, event journal | `zero_forge/discovery_workflow.py` | 🔲 |
| `ZF-DSC-03.8` | Tests: each phase independently, full pipeline, backward escalation, budget exhaustion, event journal | `tests/test_discovery_workflow.py` | 🔲 |

### ZF-DSC-04: Formal Verification Oracle

| Sub-code | Title | Files | Status |
|---|---|---|---|
| `ZF-DSC-04.1` | VerificationProgram, EvidenceRecord, VerificationResult schemas | `zero_forge/verification/schemas.py` | 🔲 |
| `ZF-DSC-04.2` | Pure-Python typed IR predicate evaluator (fallback backend) | `zero_forge/verification/engine.py` | 🔲 |
| `ZF-DSC-04.3` | Prolog backend via pyswip/janus (optional) | `zero_forge/verification/engine.py` | 🔲 |
| `ZF-DSC-04.4` | Capability ladder predicate support | `zero_forge/verification/engine.py` | 🔲 |
| `ZF-DSC-04.5` | Proof tree / evaluation trace persistence | `zero_forge/verification/engine.py` | 🔲 |
| `ZF-DSC-04.6` | Tests: satisfied, refuted, partial, contradictory, determinism, capability tiers, Prolog/IR parity | `tests/test_verification_oracle.py` | 🔲 |

### ZF-DSC-05: Discovery Tool Adapters

| Sub-code | Title | Files | Status |
|---|---|---|---|
| `ZF-DSC-05.1` | Source-assisted: repo_dependency_inspect | `zero_forge/tools/discovery/deps.py` | 🔲 |
| `ZF-DSC-05.2` | Source-assisted: ast_query | `zero_forge/tools/discovery/ast_tools.py` | 🔲 |
| `ZF-DSC-05.3` | Source-assisted: data_flow_analysis | `zero_forge/tools/discovery/taint.py` | 🔲 |
| `ZF-DSC-05.4` | Source-assisted: semgrep_scan | `zero_forge/tools/discovery/semgrep.py` | 🔲 |
| `ZF-DSC-05.5` | Source-assisted: git_history_compare | `zero_forge/tools/discovery/git_history.py` | 🔲 |
| `ZF-DSC-05.6` | Source-assisted: config_permission_analysis | `zero_forge/tools/discovery/config_perms.py` | 🔲 |
| `ZF-DSC-05.7` | Source-assisted: test_executor | `zero_forge/tools/discovery/test_run.py` | 🔲 |
| `ZF-DSC-05.8` | Runtime: http_request | `zero_forge/tools/discovery/http.py` | 🔲 |
| `ZF-DSC-05.9` | Runtime: request_replay | `zero_forge/tools/discovery/replay.py` | 🔲 |
| `ZF-DSC-05.10` | Runtime: response_compare | `zero_forge/tools/discovery/compare.py` | 🔲 |
| `ZF-DSC-05.11` | Runtime: auth_state_test | `zero_forge/tools/discovery/auth_test.py` | 🔲 |
| `ZF-DSC-05.12` | Runtime: fuzzer | `zero_forge/tools/discovery/fuzz.py` | 🔲 |
| `ZF-DSC-05.13` | Runtime: crash_monitor | `zero_forge/tools/discovery/crash.py` | 🔲 |
| `ZF-DSC-05.14` | Runtime: env_reset | `zero_forge/tools/discovery/env.py` | 🔲 |
| `ZF-DSC-05.15` | Runtime: process_trace | `zero_forge/tools/discovery/trace.py` | 🔲 |
| `ZF-DSC-05.16` | Registry update + tests | `zero_forge/tools/registry.py`, `tests/test_discovery_tools.py` | 🔲 |

### ZF-DSC-08: Vulnerability + Code Scanning Tools

| Sub-code | Title | Files | Status |
|---|---|---|---|
| `ZF-DSC-08.1` | ScanFinding + ScanResult normalized schemas | `zero_forge/tools/discovery/scanners/__init__.py` | 🔲 |
| `ZF-DSC-08.2` | ScanFinding → Observation conversion (investigation graph integration) | `zero_forge/tools/discovery/scanners/normalize.py` | 🔲 |
| `ZF-DSC-08.3` | SAST: `semgrep_scan` adapter | `zero_forge/tools/discovery/scanners/semgrep.py` | 🔲 |
| `ZF-DSC-08.4` | SAST: `bandit_scan` adapter | `zero_forge/tools/discovery/scanners/bandit.py` | 🔲 |
| `ZF-DSC-08.5` | SAST: `codeql_scan` adapter (optional) | `zero_forge/tools/discovery/scanners/codeql.py` | 🔲 |
| `ZF-DSC-08.6` | SCA: `pip_audit_scan` adapter | `zero_forge/tools/discovery/scanners/pip_audit.py` | 🔲 |
| `ZF-DSC-08.7` | SCA: `trivy_fs_scan` adapter | `zero_forge/tools/discovery/scanners/trivy.py` | 🔲 |
| `ZF-DSC-08.8` | SCA: `syft_sbom` adapter (SBOM generation) | `zero_forge/tools/discovery/scanners/syft.py` | 🔲 |
| `ZF-DSC-08.9` | SCA: `grype_scan` adapter (SBOM vuln matching) | `zero_forge/tools/discovery/scanners/grype.py` | 🔲 |
| `ZF-DSC-08.10` | Secret: `gitleaks_scan` adapter | `zero_forge/tools/discovery/scanners/gitleaks.py` | 🔲 |
| `ZF-DSC-08.11` | Secret: `trufflehog_scan` adapter | `zero_forge/tools/discovery/scanners/trufflehog.py` | 🔲 |
| `ZF-DSC-08.12` | DAST: `zap_active_scan` + `zap_passive_scan` adapters | `zero_forge/tools/discovery/scanners/zap.py` | 🔲 |
| `ZF-DSC-08.13` | DAST: `nuclei_scan` adapter | `zero_forge/tools/discovery/scanners/nuclei.py` | 🔲 |
| `ZF-DSC-08.14` | Binary: `checksec_scan` adapter | `zero_forge/tools/discovery/scanners/checksec.py` | 🔲 |
| `ZF-DSC-08.15` | Binary: `ropgadget_scan` adapter | `zero_forge/tools/discovery/scanners/ropgadget.py` | 🔲 |
| `ZF-DSC-08.16` | Binary: `angr_analysis` adapter (optional, heavy dep) | `zero_forge/tools/discovery/scanners/angr.py` | 🔲 |
| `ZF-DSC-08.17` | Container: `trivy_image_scan` adapter | `zero_forge/tools/discovery/scanners/trivy_image.py` | 🔲 |
| `ZF-DSC-08.18` | Container: `grype_image_scan` adapter | `zero_forge/tools/discovery/scanners/grype_image.py` | 🔲 |
| `ZF-DSC-08.19` | ScannerConfig (enabled_scanners, rule_packs, timeout, severity filter, SBOM format) | `zero_forge/config.py` | 🔲 |
| `ZF-DSC-08.20` | Registry update: scanner registration + missing-binary graceful skip | `zero_forge/tools/registry.py` | 🔲 |
| `ZF-DSC-08.21` | Tests: mock subprocess per scanner, ScanResult validation, ScanFinding→Observation, severity filtering, max-findings truncation, missing-binary skip, empty results, multi-scanner aggregation | `tests/test_scanners.py` | 🔲 |

### ZF-DSC-06: Budgets + Safety Gates

| Sub-code | Title | Files | Status |
|---|---|---|---|
| `ZF-DSC-06.1` | BudgetTracker (experiments, runtime, requests, mutations, hypothesis depth, retries, repair) | `zero_forge/budget.py` | 🔲 |
| `ZF-DSC-06.2` | AuthorizationGate (access-mode enforcement, destructive experiment approval) | `zero_forge/budget.py` | 🔲 |
| `ZF-DSC-06.3` | LangGraph conditional edge integration (terminal budget_exhausted state) | `zero_forge/discovery_workflow.py` | 🔲 |
| `ZF-DSC-06.4` | Tests: budget tracking, exhaustion, authorization gate, access-mode, destructive approval | `tests/test_budget.py` | 🔲 |

### ZF-DSC-07: SWE/Docker + Integration + Tests + Docs

| Sub-code | Title | Files | Status |
|---|---|---|---|
| `ZF-DSC-07.1` | DockerTargetMode enum + setup_docker_target (image/dockerfile/compose modes) | `zero_forge/tools/discovery/docker_env.py` | 🔲 |
| `ZF-DSC-07.2` | TargetEnvironment + ServiceEndpoint schemas (multi-service topology) | `zero_forge/investigation.py` | 🔲 |
| `ZF-DSC-07.3` | Companion tools: reset, inspect, exec_in_target, teardown, capture_docker_state | `zero_forge/tools/discovery/docker_env.py` | 🔲 |
| `ZF-DSC-07.4` | run_discovery_workflow() entry point + Finding → VulnerabilityInput bridge | `zero_forge/discovery_workflow.py` | 🔲 |
| `ZF-DSC-07.5` | CLI: `zero-forge discover` with --target/--docker-image/--dockerfile/--compose-file | `zero_forge/cli.py` | 🔲 |
| `ZF-DSC-07.6` | Tests: all three Docker modes, multi-service topology, reset/teardown, exec, capture, user-supplied vs agent-generated, build failures, port conflicts | `tests/test_docker_env.py` | 🔲 |
| `ZF-DSC-07.7` | End-to-end integration test: discovery → finding → artifact generation (stub LLM) | `tests/test_discovery_integration.py` | 🔲 |
| `ZF-DSC-07.8` | Documentation: architecture.md (execution vs investigation graph), discovery.md, verification-oracle.md | `docs/` | 🔲 |
| `ZF-DSC-07.9` | README.md + config.example.yaml updates | `README.md`, `config.example.yaml` | 🔲 |

---

## Status Legend

| Icon | Meaning |
|---|---|
| 🔲 | Not started |
| 🔨 | In progress |
| 🔀 | In PR / review |
| ✅ | Merged / complete |
| ⛔ | Blocked |

---

## Cross-Reference: Existing Issues

| Existing issue | Relation to #28 |
|---|---|
| [#35 — Typed internal planning phase](https://github.com/lost-rob0t/zero-forge/issues/35) | `ArtifactPlan` schema feeds into `ZF-DSC-03.4` (PLAN subgraph) |
| [#47 — Tool Agent argument replacement](https://github.com/lost-rob0t/zero-forge/issues/47) | Security fix — must be merged before `ZF-DSC-05` (tool adapters) |
| [#12 — Ruby runtime preflight](https://github.com/lost-rob0t/zero-forge/issues/12) | Blocks Metasploit validation path used by `ZF-DSC-07.7` integration tests |

---

## Org-Mode Sync

The `wiki/issues.org` tracker should be updated with a new top-level section for epic #28:

```org
* Epic #28: Vulnerability Discovery (ZF-DSC-00)
:PROPERTIES:
:ID: issue-28
:STATE: open
:LABELS: priority:P3, type:epic, status:roadmap, area:discovery
:CODE: ZF-DSC-00
:END:

** TODO ZF-DSC-01: Investigation Graph Schemas
:PROPERTIES:
:CODE: ZF-DSC-01
:STATUS: not-started
:BRANCH: feature/zf-dsc-01-investigation-schemas
:DEPENDS_ON: none
:END:

** TODO ZF-DSC-02: Hypothesis + Discovery Agent
:PROPERTIES:
:CODE: ZF-DSC-02
:STATUS: not-started
:BRANCH: feature/zf-dsc-02-hypothesis-discovery-agent
:DEPENDS_ON: ZF-DSC-01
:END:

... (etc for ZF-DSC-03 through ZF-DSC-08)
```

Run `python dev_scripts/sync_issues_org.py` after creating GitHub milestones/issues to keep the org tracker in sync.
