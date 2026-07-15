# Implementation Plan: Issue #28 — Vulnerability Discovery: Hypothesis–Experiment–Evidence Workflow

> **Issue**: [lost-rob0t/zero-forge#28](https://github.com/lost-rob0t/zero-forge/issues/28)
> **Labels**: `priority:P3`, `type:epic`, `status:roadmap`, `area:discovery`
> **Status**: Draft

---

## 1. Overview

ZeroForge currently implements a linear exploit-generation workflow: `collect_context → generate_artifact → validate → repair → save`. Issue #28 requests a first-class **vulnerability discovery** capability — forming hypotheses, running bounded experiments, retaining counterevidence, and requiring reproducible confirmation before promoting findings.

The issue body and three comments define:

1. A persistent **investigation/evidence graph** (separate from the LangGraph execution graph)
2. A **hypothesis schema** with explicit success/refutation conditions
3. A bounded **discovery workflow** (14 steps: authorize → acquire → map → hypothesize → experiment → evidence → classify → refine → reproduce → promote → artifact)
4. A **four-phase operational mode** (RESEARCH → PLAN → EXPLOIT → VERIFY) that unifies discovery and exploit generation
5. A **formal verification oracle** (Prolog rules or typed IR) replacing LLM-judgment verification
6. **Budgets and safety gates** for all intrusive operations
7. A **SWE agent** integration for Docker-based target setup
8. Comprehensive **tests and documentation**

This plan decomposes the epic into 7 milestones, each independently mergeable.

---

## 2. Current Architecture (Baseline)

| File | Lines | Responsibility |
|---|---|---|
| `schemas.py` | 130 | `VulnerabilityInput`, `CollectedContext`, `Artifact`, `ValidationResult`, `ToolRequest`, `ToolCall`, `ToolResult`, `WorkflowError`, `WorkflowState` |
| `workflow.py` | 256 | Linear LangGraph: collect → generate → validate → repair → save with conditional routing |
| `config.py` | 224 | `Settings` (ModelsConfig, WorkflowConfig, OutputConfig), env override, YAML loading, singleton cache |
| `agents/smart_agent.py` | 223 | LLM prompt for Metasploit generation, context prompt builder, generate/repair functions |
| `agents/tool_agent.py` | 429 | Tool Agent: LLM-based tool selection, Pydantic argument validation, context collection, validation dispatch |
| `tools/registry.py` | 56 | Simple name→callable registry, `create_default_registry()` |
| `tools/` | — | `cve_lookup`, `source_inspect` (read_source_files, search_code, git_diff_inspect), `validator` (validate_metasploit) |
| `cli.py` | 133 | Typer CLI: `generate --cve --source --poc --output` |
| `output.py` | 145 | `save_artifact()` with CVE validation, path safety, `.meta.json` sidecar |

**Key invariants to preserve:**
- `WorkflowState` is the LangGraph integration boundary; nodes return `dict[str, Any]` patches
- Two-agent boundary: Smart Agent reasons; Tool Agent only executes typed tool requests
- `get_settings()` is cached; tests reset via `conftest.py`
- API keys are environment-only, `repr=False`
- Stub mode is plumbing-only; stub artifacts are never saved

---

## 3. Milestone Breakdown

### Milestone 1: Investigation Graph Schemas
**Goal**: Define typed Pydantic schemas for all investigation entities and relationships.

**New file**: `zero_forge/investigation.py`

**Entities** (all `StrictSchema` subclasses with `schema_id` versioning):

```python
class InvestigationEntity(StrictSchema):
    id: str  # UUID
    created_at: datetime
    schema_id: str  # e.g. "zero-forge/target@1"

class Target(InvestigationEntity):
    identifier: str  # repo URL, binary hash, hostname
    build_identity: str  # git commit, Docker image digest
    access_mode: AccessMode  # informational, remote, local

class Component(InvestigationEntity):
    target_id: str
    name: str  # module, package, binary
    path: str  # file path, endpoint
    kind: str  # parser, sink, entry_point, state_transition

class Observation(InvestigationEntity):
    source: str  # tool name, scanner, manual
    content: str
    target_id: str
    component_id: str | None

class Hypothesis(InvestigationEntity):
    claimed_weakness: str  # CWE class
    affected_component_id: str
    entry_point: str
    suspected_sink: str
    preconditions: list[str]
    required_access_mode: AccessMode
    attacker_controlled_input: str
    expected_vulnerable_behavior: str
    expected_safe_behavior: str
    experiment_strategy: str
    success_condition: str
    refutation_condition: str
    possible_side_effects: list[str]
    confidence: float  # 0.0–1.0
    confidence_basis: str  # evidence-based justification
    supporting_evidence_ids: list[str]
    counterevidence_ids: list[str]
    status: HypothesisStatus  # open, testing, supported, refuted, inconclusive, closed

class Experiment(InvestigationEntity):
    hypothesis_id: str
    tool_request: ToolRequest
    authorized: bool = False
    authorization_reason: str = ""
    estimated_cost: str = ""
    destructive: bool = False

class TestRun(InvestigationEntity):
    experiment_id: str
    tool_result: ToolResult
    started_at: datetime
    completed_at: datetime
    environment: dict[str, Any]

class Evidence(InvestigationEntity):
    test_run_id: str
    kind: EvidenceKind  # stdout, stderr, exit_code, file_change, network, memory, timing
    content: str
    provenance: dict[str, Any]  # tool name, version, environment

class Counterevidence(Evidence):
    refutes_hypothesis_id: str
    refutation_reason: str

class Finding(InvestigationEntity):
    target_id: str
    hypothesis_id: str
    reproduction_run_ids: list[str]  # must be ≥ 1
    exact_target_identity: str
    exact_input: str
    exact_environment: str
    captured_output: str
    control_case: str
    violated_security_property: str
    reproduction_stable: bool

class Artifact(InvestigationEntity):  # extends existing Artifact
    finding_id: str
```

**Enums**:

```python
class AccessMode(StrEnum):
    INFORMATIONAL = "informational"
    REMOTE = "remote"
    LOCAL = "local"

class HypothesisStatus(StrEnum):
    OPEN = "open"
    TESTING = "testing"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    CLOSED = "closed"

class EvidenceKind(StrEnum):
    STDOUT = "stdout"
    STDERR = "stderr"
    EXIT_CODE = "exit_code"
    FILE_CHANGE = "file_change"
    NETWORK = "network"
    MEMORY = "memory"
    TIMING = "timing"

class RelationshipKind(StrEnum):
    DERIVED_FROM = "derived_from"
    TARGETS = "targets"
    TESTS = "tests"
    SUPPORTS = "supports"
    REFUTES = "refutes"
    REQUIRES_ACCESS = "requires_access"
    REPRODUCES = "reproduces"
    AFFECTS = "affects"
    DUPLICATES = "duplicates"
    MITIGATED_BY = "mitigated_by"
```

**Relationship record**:

```python
class Relationship(StrictSchema):
    source_id: str
    target_id: str
    kind: RelationshipKind
    metadata: dict[str, Any] = Field(default_factory=dict)
```

**Investigation graph container**:

```python
class InvestigationGraph(BaseModel):
    entities: dict[str, InvestigationEntity] = Field(default_factory=dict)
    relationships: list[Relationship] = Field(default_factory=list)

    def add(self, entity: InvestigationEntity) -> None: ...
    def link(self, source_id: str, target_id: str, kind: RelationshipKind, **meta) -> None: ...
    def get(self, entity_id: str) -> InvestigationEntity | None: ...
    def query(self, kind: type, **filters) -> list[InvestigationEntity]: ...
    def get_refuted_hypotheses(self) -> list[Hypothesis]: ...
    def get_supported_hypotheses(self) -> list[Hypothesis]: ...
```

**Persistence**: `zero_forge/investigation_store.py` — JSONL-based append-only store with provenance. Each entity gets a `.jsonl` file per investigation. Immutable evidence records.

**Config additions** (`config.py`):

```python
class DiscoveryConfig(BaseModel):
    max_experiments: int = Field(default=20, ge=1)
    max_workflow_runtime_seconds: int = Field(default=3600, ge=60)
    max_requests: int = Field(default=500, ge=1)
    max_mutations: int = Field(default=100, ge=0)
    max_hypothesis_depth: int = Field(default=5, ge=1)
    max_retries: int = Field(default=3, ge=0)
    max_repair_attempts: int = Field(default=3, ge=0, le=20)
    require_explicit_approval: bool = Field(default=True)
    investigation_store_dir: str = Field(default="./investigations")
```

**Tests**: `tests/test_investigation.py` — entity creation, relationship linking, query filters, refuted-hypothesis retention, schema validation.

**Acceptance criteria covered**: Typed schemas for minimum investigation entities and relationships.

---

### Milestone 2: Hypothesis Schema + Smart Agent Discovery Mode
**Goal**: Smart Agent can generate and rank vulnerability hypotheses from context.

**New file**: `zero_forge/agents/discovery_agent.py`

**Responsibilities**:
- `generate_hypotheses(context: CollectedContext, investigation: InvestigationGraph) -> list[Hypothesis]`
- `rank_hypotheses(hypotheses: list[Hypothesis], investigation: InvestigationGraph) -> list[Hypothesis]`
- `design_experiment(hypothesis: Hypothesis, investigation: InvestigationGraph) -> Experiment`
- `classify_result(hypothesis: Hypothesis, test_run: TestRun, evidence: list[Evidence]) -> HypothesisStatus`
- `refine_hypothesis(hypothesis: Hypothesis, evidence: list[Evidence]) -> Hypothesis`

**LLM prompt design** (new `DISCOVERY_SYSTEM_PROMPT`):

```
You are ZeroForge's Discovery Agent. You form and rank vulnerability hypotheses
from collected context. You design bounded experiments with explicit success
and refutation conditions. You never declare a vulnerability confirmed —
only reproduction and the verification oracle can do that.

Every hypothesis MUST include:
- claimed weakness (CWE class)
- affected component
- entry point and suspected sink
- preconditions
- required access mode
- attacker-controlled input
- expected vulnerable behavior
- expected safe behavior
- experiment strategy
- success condition
- failure/refutation condition
- possible side effects
- confidence and its evidence basis
```

**Key constraints**:
- The Smart Agent outputs structured JSON matching `Hypothesis` schema, not freeform text
- Ranking uses evidence basis quality, not unsupported LLM confidence scores
- Counterevidence from the investigation graph influences ranking (disproven theories are not repeated)
- Access mode and authorization are checked before any experiment is designed

**Tests**: `tests/test_discovery_agent.py` — hypothesis generation (mock LLM), ranking with counterevidence, experiment design, result classification (supported/refuted/inconclusive), refinement.

**Acceptance criteria covered**: Hypotheses have explicit success and refutation conditions; negative/inconclusive results retained.

---

### Milestone 3: Four-Phase LangGraph Subgraphs (RESEARCH → PLAN → EXPLOIT → VERIFY)
**Goal**: Implement the four-phase operational mode as typed LangGraph subgraphs with backward escalation.

**New file**: `zero_forge/phases.py`

#### 3a. RESEARCH Subgraph

**Pattern**: ReAct-based iterative deep research loop (Plan → Act → Observe → Reason → Assess → loop).

**Nodes**:
1. `plan_research` — Smart Agent identifies the most critical information gap
2. `execute_research` — Tool Agent invokes a bounded tool (cve_lookup, source_inspect, search)
3. `observe_research` — Normalize tool output into `Observation` entities
4. `assess_research` — Smart Agent evaluates coverage across 6 dimensions: vulnerability metadata, root cause, attack surface, mitigation profile, prior art, environment context
5. `check_termination` — Conditional edge: terminate if all critical dimensions covered, max iterations reached, confidence threshold met, or no new info in last N iterations

**Output artifacts** (stored in investigation graph):
- `VulnerabilityBrief`, `RootCauseReport`, `AttackSurfaceMap`, `MitigationProfile`, `PriorArtCollection`, `ResearchSummary`

**Config**: `ResearchConfig` with `max_iterations: int = 20`, `confidence_threshold: float = 0.8`, `diminishing_returns_threshold: int = 3`

#### 3b. PLAN Subgraph

**Nodes**:
1. `create_strategy` — Smart Agent designs exploit strategy from research artifacts
2. `build_primitive_catalog` — Enumerate available exploit primitives with preconditions
3. `plan_mitigation_bypass` — Specific technique per active protection
4. `map_capability_ladder` — coverage → crash → primitive → control → execution
5. `define_success_oracle` — Smart Agent emits `VerificationProgram` (Prolog rules or typed IR)
6. `check_readiness` — Conditional edge: if blocking unknowns remain, route back to RESEARCH; if ready, proceed to EXPLOIT

**Output**: `ArtifactPlan` (ready status required before EXPLOIT)

#### 3c. EXPLOIT Subgraph

**Nodes**:
1. `create_scaffold` — Initial exploit code structure from plan
2. `implement_trigger` — Reliable vulnerability activation
3. `construct_primitive` — Build exploit primitives
4. `assemble_chain` — Connect primitives into complete exploit
5. `repair_loop` — If execution fails, diagnose and fix (up to `max_repair_attempts`)

**Backward escalation**: EXPLOIT failures can escalate to PLAN (strategy change) or RESEARCH (missing info), not just code repair.

**Developer-critic pattern**: Developer agent generates; critic agent reviews; verifier runs automated testing.

#### 3d. VERIFY Subgraph

**Nodes**:
1. `syntax_validation` — AST parse, import resolution
2. `runtime_validation` — Execute in isolated environment
3. `evaluate_oracle` — Run formal verification program against captured `EvidenceRecord`
4. `check_repeatability` — N/N deterministic reruns (default N=3)
5. `control_case` — Confirm exploit fails against patched version
6. `crash_analysis` — On failure, capture faulting address, registers, stack trace
7. `assess_capability_tier` — ExploitBench ladder classification

**Independence**: VERIFY runs in a fresh model context, not sharing EXPLOIT's conversation.

#### 3e. Phase Router (Orchestrator)

**New file**: `zero_forge/discovery_workflow.py`

```python
OperationalPhase = StrEnum("OperationalPhase", ["RESEARCH", "PLAN", "EXPLOIT", "VERIFY"])

class DiscoveryWorkflowState(WorkflowState):
    phase: OperationalPhase = OperationalPhase.RESEARCH
    investigation: InvestigationGraph = Field(default_factory=InvestigationGraph)
    research_state: ResearchState | None = None
    plan_state: ArtifactPlan | None = None
    exploit_state: ExploitDraft | None = None
    verify_state: VerifyResult | None = None
    phase_budgets: dict[OperationalPhase, BudgetTracker] = Field(default_factory=dict)
    event_journal: list[PhaseEvent] = Field(default_factory=list)
```

**Backward escalation paths** (all typed and budget-bounded):
- VERIFY → EXPLOIT (repair)
- VERIFY → PLAN (strategy revision)
- VERIFY → RESEARCH (information gap)
- EXPLOIT → PLAN (strategy change)
- EXPLOIT → RESEARCH (missing information)
- PLAN → RESEARCH (blocking unknowns)

**Event journal**: Records phase transitions, escalation reasons, budget consumption.

**Compatibility**: Existing `run_workflow()` continues to work for artifact generation from known CVEs. The discovery workflow is a separate entry point: `run_discovery_workflow(target_input)`.

**Tests**: `tests/test_discovery_workflow.py` — each phase independently, full four-phase pipeline, backward escalation, budget exhaustion, event journal.

**Acceptance criteria covered**: Four named phases are typed LangGraph subgraphs; RESEARCH implements iterative loop; PLAN readiness gate; EXPLOIT repair with escalation; backward escalation typed and budget-bounded; event journal.

---

### Milestone 4: Formal Verification Oracle (Prolog/IR)
**Goal**: Deterministic verification replacing LLM-judgment success checks.

**New file**: `zero_forge/verification/oracle.py`

**Architecture**:

```
PLAN phase → Smart Agent emits VerificationProgram (Prolog or typed IR)
EXPLOIT phase → Tool Agent executes, captures structured EvidenceRecord
VERIFY phase → Deterministic engine evaluates program against evidence facts
```

**VerificationProgram schema** (in `investigation.py` or new `verification/schemas.py`):

```python
class Predicate(StrictSchema):
    name: str
    expression: str  # formal expression in IR or Prolog rule body
    required: bool  # must be satisfied for success
    description: str = ""

class VerificationProgram(StrictSchema):
    schema_id: Literal["zero-forge/verify-program@1"] = "zero-forge/verify-program@1"
    success_predicates: list[Predicate]
    failure_predicates: list[Predicate]
    required_reruns: int = 3
    evidence_kinds: list[EvidenceKind]
    capability_tier_predicates: list[Predicate] = Field(default_factory=list)

class EvidenceRecord(StrictSchema):
    schema_id: Literal["zero-forge/evidence-record@1"] = "zero-forge/evidence-record@1"
    run_id: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    interactive_shell: bool = False
    files_read: dict[str, str | None] = Field(default_factory=dict)
    files_modified: list[str] = Field(default_factory=list)
    memory_state: dict[str, str] | None = None
    network_captures: list[dict[str, Any]] = Field(default_factory=list)
    timing_ms: float = 0.0
    rerun_results: list[bool] = Field(default_factory=list)

class VerificationResult(StrictSchema):
    schema_id: Literal["zero-forge/verify-result@1"] = "zero-forge/verify-result@1"
    verified: bool
    satisfied: list[str]  # predicate names
    refuted: list[str]   # failure predicates that fired
    unsatisfied: list[str]  # required predicates not met
    evidence: EvidenceRecord
    program_digest: str  # hash of VerificationProgram
    proof_trace: dict[str, Any] | None = None  # inspectable proof tree
    capability_tier: str | None = None
```

**Engine implementation** (`verification/engine.py`):

Two backends:
1. **Prolog backend** — Uses `pyswip` (SWI-Prolog Python interface) or `janus` (Python-Prolog bridge). Asserts `EvidenceRecord` fields as Prolog facts, evaluates the program, returns proof tree.
2. **Typed IR fallback** — Pure-Python predicate evaluator for environments without SWI-Prolog. Implements a minimal rule engine with: fact assertion, predicate matching, negation-as-failure, conjunction, and proof-tree construction.

**Prolog example** (ret2libc exploit):

```prolog
exploit_succeeded :-
    libc_base_leaked,
    shell_or_flag_obtained,
    deterministic_reruns(N),
    N >= 3.

libc_base_leaked :-
    stdout_contains("libc base"),
    stdout_contains("0x").

shell_or_flag_obtained :-
    interactive_shell(true).
shell_or_flag_obtained :-
    file_read("/flag.txt", _),
    flag_format_valid.
```

**Capability ladder predicates** (ExploitBench pattern):

```prolog
capability_tier(coverage) :- reached_vulnerable_code.
capability_tier(crash) :- exit_code(-11), faulting_address(_).
capability_tier(primitive) :- memory_write(_, _).
capability_tier(control) :- control_flow_hijacked.
capability_tier(execution) :- arbitrary_code_executed.
```

**Dependencies**: `pyswip` (optional, for Prolog backend), `janus` (alternative). Add as optional extras in `pyproject.toml`: `pip install -e ".[verification]"`.

**Tests**: `tests/test_verification_oracle.py` — satisfied, refuted, partial-satisfaction, contradictory-evidence, capability-tier classification, determinism (same facts + same program = same verdict), Prolog and IR backend parity.

**Acceptance criteria covered**: Smart Agent emits VerificationProgram; VERIFY captures EvidenceRecord; deterministic engine evaluates; result includes satisfied/refuted/unsatisfied; proof tree persisted; determinism; capability ladder; independence from EXPLOIT context.

---

### Milestone 5: Tool Adapters (Source-Assisted + Runtime)
**Goal**: Register discovery-specific tools for the Tool Agent.

**New directory**: `zero_forge/tools/discovery/`

#### 5a. Source-Assisted Adapters

| Tool name | Implementation | Purpose |
|---|---|---|
| `repo_dependency_inspect` | `tools/discovery/deps.py` | Inspect package manifests (requirements.txt, package.json, go.mod, Cargo.toml) for vulnerable dependencies |
| `ast_query` | `tools/discovery/ast_tools.py` | AST and call-graph queries using `ast`/`libcsdt`/`tree-sitter` |
| `data_flow_analysis` | `tools/discovery/taint.py` | Data-flow/taint analysis from entry points to sinks |
| `semgrep_scan` | `tools/discovery/semgrep.py` | Run Semgrep rules against source tree |
| `git_history_compare` | `tools/discovery/git_history.py` | Git log/blame, patch comparison across versions |
| `config_permission_analysis` | `tools/discovery/config_perms.py` | Configuration and filesystem permission analysis |
| `test_executor` | `tools/discovery/test_run.py` | Run test suite with coverage, sanitizers, instrumentation |

#### 5b. Runtime Adapters

| Tool name | Implementation | Purpose |
|---|---|---|
| `http_request` | `tools/discovery/http.py` | HTTP/protocol requests with method, headers, body |
| `request_replay` | `tools/discovery/replay.py` | Replay captured requests with controlled mutation |
| `response_compare` | `tools/discovery/compare.py` | Diff two responses (status, headers, body, timing) |
| `auth_state_test` | `tools/discovery/auth_test.py` | Authentication/state-machine testing |
| `fuzzer` | `tools/discovery/fuzz.py` | Fuzzing or property-based testing integration |
| `crash_monitor` | `tools/discovery/crash.py` | Crash, exception, timing, and resource monitoring |
| `env_reset` | `tools/discovery/env.py` | Isolated environment reset (Docker container restart) |
| `process_trace` | `tools/discovery/trace.py` | Network/process tracing (strace, tcpdump, ltrace) |

**Registration**: Update `create_default_registry()` to optionally include discovery tools when `DiscoveryConfig` is active.

**Constraint**: Every tool receives a bounded `ToolRequest`, not a general instruction. Tools return `ToolResult` with structured output.

**Tests**: `tests/test_discovery_tools.py` — each tool with mock inputs, error handling, bounded execution.

**Acceptance criteria covered**: Tool execution routed exclusively through typed Tool Agent requests; raw evidence is immutable and linked to tool/version/environment provenance.

---

### Milestone 8: Vulnerability and Code Scanning Tools
**Goal**: Integrate structured vulnerability and code scanning tools that produce `Observation` entities in the investigation graph. Scanner output **must remain an observation** until connected to a testable hypothesis and reproduced — scanners never directly create Findings.

**New directory**: `zero_forge/tools/discovery/scanners/`

**Scanner normalization**: All scanners return a normalized `ScanResult` (extends `ToolResult`) that the Tool Agent converts into `Observation` entities:

```python
class ScanFinding(StrictSchema):
    """A single finding from a scanner — NOT a confirmed vulnerability."""
    rule_id: str  # e.g. "semgrep:python.lang.security.XSS"
    severity: str  # info, low, medium, high, critical
    confidence: str  # low, medium, high
    description: str
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    snippet: str = ""
    cwe: str = ""  # associated CWE if known
    metadata: dict[str, Any] = Field(default_factory=dict)

class ScanResult(StrictSchema):
    """Normalized output from any scanner tool."""
    scanner: str  # tool name + version
    target: str  # what was scanned
    findings: list[ScanFinding] = Field(default_factory=list)
    raw_output: str = ""  # raw scanner output for provenance
    scan_duration_ms: float = 0.0
    exit_code: int = 0
    error: str = ""
```

**Integration with investigation graph**: The Tool Agent converts each `ScanFinding` into an `Observation` entity linked to the target and relevant `Component`. Observations feed hypothesis generation in the RESEARCH phase. No `ScanFinding` becomes a `Hypothesis`, `Finding`, or `Artifact` without independent reproduction.

#### 8a. SAST (Static Application Security Testing)

| Tool name | Implementation | Backend | Purpose |
|---|---|---|---|
| `semgrep_scan` | `scanners/semgrep.py` | Semgrep CLI + rule packs | Pattern-based SAST across 30+ languages; custom rule support |
| `bandit_scan` | `scanners/bandit.py` | Bandit (Python-only) | Python-specific security analysis |
| `codeql_scan` | `scanners/codeql.py` | CodeQL CLI (optional) | Semantic code analysis with custom queries |

#### 8b. SCA (Software Composition Analysis) / Dependency Scanning

| Tool name | Implementation | Backend | Purpose |
|---|---|---|---|
| `pip_audit_scan` | `scanners/pip_audit.py` | pip-audit | Python dependency vulnerability scan (OSV/PyPI advisories) |
| `trivy_fs_scan` | `scanners/trivy.py` | Trivy CLI | Filesystem dependency + secret scan (multi-language) |
| `syft_sbom` | `scanners/syft.py` | Syft CLI | Generate SBOM (CycloneDX/SPDX) for dependency inventory |
| `grype_scan` | `scanners/grype.py` | Grype CLI | Vulnerability matching against SBOM |

#### 8c. Secret Scanning

| Tool name | Implementation | Backend | Purpose |
|---|---|---|---|
| `gitleaks_scan` | `scanners/gitleaks.py` | Gitleaks CLI | Detect hardcoded secrets in git history and working tree |
| `trufflehog_scan` | `scanners/trufflehog.py` | TruffleHog CLI | Secret detection with verification (multi-cloud) |

#### 8d. DAST (Dynamic Application Security Testing)

| Tool name | Implementation | Backend | Purpose |
|---|---|---|---|
| `zap_active_scan` | `scanners/zap.py` | OWASP ZAP CLI/API | Active web vulnerability scanning (existing artifact type reused) |
| `zap_passive_scan` | `scanners/zap.py` | OWASP ZAP passive mode | Passive spider + passive scan |
| `nuclei_scan` | `scanners/nuclei.py` | Nuclei CLI + templates | Template-based DAST with community templates |

#### 8e. Binary Analysis

| Tool name | Implementation | Backend | Purpose |
|---|---|---|---|
| `checksec_scan` | `scanners/checksec.py` | checksec.sh / pwntools | Binary hardening analysis (NX, PIE, RELRO, stack canary) |
| `ropgadget_scan` | `scanners/ropgadget.py` | ROPgadget CLI | ROP gadget enumeration for binary exploitation |
| `angr_analysis` | `scanners/angr.py` | angr (optional, heavy dep) | Symbolic execution and CFG recovery for binary targets |

#### 8f. Container Scanning

| Tool name | Implementation | Backend | Purpose |
|---|---|---|---|
| `trivy_image_scan` | `scanners/trivy_image.py` | Trivy CLI | Container image vulnerability + misconfiguration scan |
| `grype_image_scan` | `scanners/grype_image.py` | Grype CLI | Container image vulnerability matching |

#### 8g. Scanner Configuration

**New config section**:

```python
class ScannerConfig(BaseModel):
    enabled_scanners: list[str] = Field(default_factory=lambda: ["semgrep", "pip_audit"])
    scanner_rule_packs: dict[str, str] = Field(default_factory=dict)  # custom rule paths
    scanner_timeout_seconds: int = Field(default=300, ge=30)
    scanner_max_findings: int = Field(default=500, ge=1)  # truncate noisy output
    scanner_severity_filter: str = Field(default="low")  # min severity to retain
    sbom_format: Literal["cyclonedx", "spdx"] = Field(default="cyclonedx")
    model_config = ConfigDict(extra="forbid")
```

**Registration**: Scanners register through `create_default_registry()` like all other tools. Each scanner receives a bounded `ToolRequest` and returns a `ScanResult` wrapped in `ToolResult.output`.

**Dependencies**: Most scanners are CLI tools invoked via subprocess — no Python SDK needed. Add `semgrep`, `bandit`, `pip-audit` as optional extras: `pip install -e ".[scanners]"`. Trivy, Syft, Grype, Nuclei, Gitleaks, TruffleHog, CodeQL are external binaries — detected at runtime, gracefully skipped if absent.

**Tests**: `tests/test_scanners.py` — mock subprocess for each scanner, normalized `ScanResult` validation, `ScanFinding`→`Observation` conversion, severity filtering, max-findings truncation, missing-binary graceful skip, empty-results handling, multi-scanner aggregation.

**Acceptance criteria covered**: Scanner output remains observation until hypothesis-tested and reproduced; tool execution routed through typed Tool Agent requests; raw evidence immutable with tool/version provenance.

---

### Milestone 6: Budgets, Safety Gates, and Authorization
**Goal**: Enforce configurable maximums and explicit approval transitions.

**New file**: `zero_forge/budget.py`

```python
class BudgetTracker(BaseModel):
    max_experiments: int
    max_runtime_seconds: int
    max_requests: int
    max_mutations: int
    max_hypothesis_depth: int
    max_retries: int
    max_repair_attempts: int
    consumed_experiments: int = 0
    consumed_requests: int = 0
    consumed_mutations: int = 0
    consumed_runtime_seconds: float = 0.0
    consumed_retries: int = 0
    consumed_repair_attempts: int = 0

    def can_execute(self, kind: str) -> bool: ...
    def consume(self, kind: str, amount: int = 1) -> None: ...
    def remaining(self, kind: str) -> int: ...
    def exhausted(self) -> bool: ...

class AuthorizationGate:
    def check_access(self, target: Target, required: AccessMode) -> bool: ...
    def authorize_experiment(self, experiment: Experiment) -> Experiment: ...
    def require_approval(self, experiment: Experiment) -> bool: ...
```

**Safety rules**:
- Intrusive or destructive experiments require an explicit approval transition (not automatic)
- Authorization and access-mode checks gate every experiment before execution
- Budget exhaustion routes to a terminal `budget_exhausted` state, not silent failure
- The gate is a LangGraph conditional edge function, not a model decision

**Config**: `DiscoveryConfig` (from Milestone 1) with all budget fields.

**Tests**: `tests/test_budget.py` — budget tracking, exhaustion, authorization gate, access-mode enforcement, destructive experiment approval.

**Acceptance criteria covered**: Authorization and access-mode checks gate every experiment; budgets configurable; intrusive experiments require approval.

---

### Milestone 7: SWE Agent + Docker Target Setup, Integration, Tests, Documentation

#### 7a. SWE Agent for Docker Target Setup

**Goal**: Automated Docker-based target environment setup supporting single-container, Dockerfile-only, and multi-service docker-compose scenarios for reproducible experiments.

**New file**: `zero_forge/tools/discovery/docker_env.py`

**Target environment modes**:

| Mode | Input | Use case |
|---|---|---|
| `image` | Pre-built image name + tag | Pull and run an existing target image |
| `dockerfile` | Path to a Dockerfile (+ build context) | Build from source; single-service target without external dependencies |
| `compose` | Path to a `docker-compose.yml` | Multi-service targets — service under test plus dependencies (databases, APIs, reverse proxies, message queues) |

**Users can manually pass Dockerfiles or compose files** — the agent does not require the user to pre-build images. The SWE agent can also generate a Dockerfile or compose file from target context when the user does not provide one, but user-supplied files always take precedence.

**Tool**: `setup_docker_target`

```python
class DockerTargetMode(StrEnum):
    IMAGE = "image"
    DOCKERFILE = "dockerfile"
    COMPOSE = "compose"

def setup_docker_target(
    mode: DockerTargetMode,
    # image mode
    image: str = "",
    tag: str = "latest",
    # dockerfile mode
    dockerfile_path: str = "",
    build_context: str = "",
    build_args: dict[str, str] | None = None,
    # compose mode
    compose_file: str = "",
    compose_services: list[str] | None = None,  # subset to start; None = all
    # shared
    commit: str = "",
    ports: list[int] | None = None,
    env_vars: dict[str, str] | None = None,
    volumes: list[str] | None = None,
    network: str = "",
) -> dict[str, Any]:
    """Set up a Docker target environment.

    - image mode: pull and run a pre-built image
    - dockerfile mode: build from a Dockerfile and run the resulting image
    - compose mode: docker-compose up for multi-service targets

    Returns connection info: container IDs, service endpoints, mapped ports,
    network name, image digests, and build identity.
    """
```

**Companion tools**:
- `reset_docker_target(target_id: str)` — Stop and restart container(s) or compose stack for reproducible runs
- `inspect_docker_target(target_id: str)` — Get container/compose state, per-service logs, network topology, mapped ports
- `exec_in_target(target_id: str, service: str = "", command: list[str] = [])` — Execute command in a running container or specific compose service
- `teardown_docker_target(target_id: str)` — Stop and remove containers, networks, volumes (cleanup)
- `capture_docker_state(target_id: str)` — Snapshot filesystem changes, network captures, and process state for evidence collection

**Multi-service topology schema** (added to `investigation.py`):

```python
class ServiceEndpoint(BaseModel):
    service_name: str
    container_id: str
    internal_host: str  # e.g. "db:5432"
    external_host: str  # e.g. "localhost:54321"
    port: int
    protocol: str = "tcp"

class TargetEnvironment(InvestigationEntity):
    """Records the full Docker target topology for reproducibility."""
    mode: DockerTargetMode
    image_digests: list[str]  # SHA256 per built/pulled image
    build_identity: str  # commit hash or Dockerfile digest
    compose_file_hash: str = ""  # SHA256 of compose file if used
    services: list[ServiceEndpoint]  # all running services and their endpoints
    network_name: str
    env_vars: dict[str, str]  # non-secret env vars used
    volumes: list[str]
    dockerfile_content: str = ""  # Dockerfile source if generated/provided
    compose_file_content: str = ""  # compose file source if generated/provided
```

**SWE agent integration**:
- The Smart Agent can request Docker target setup through the Tool Agent via a bounded `ToolRequest`
- The Tool Agent receives `allowed_tools: ["setup_docker_target"]` (or companion tools)
- Target identity (image digests, commit hash, Dockerfile/compose file hashes) is recorded in the investigation graph as a `TargetEnvironment` entity linked to the `Target`
- When the user provides a Dockerfile or compose file, the file content and hash are stored immutably for reproducibility
- When the SWE agent generates a Dockerfile/compose file (user did not provide one), the generated file is saved alongside artifacts and its content is recorded in the `TargetEnvironment`

**CLI additions** for Docker target setup:

```bash
# Pre-built image
zero-forge discover --docker-image vuln-target:latest --access local

# Dockerfile (user-supplied or agent-generated)
zero-forge discover --dockerfile ./Dockerfile --build-context ./target-src --access local

# docker-compose (multi-service with dependencies)
zero-forge discover --compose-file ./docker-compose.yml --access local
zero-forge discover --compose-file ./docker-compose.yml --services web,db --access local

# Repo URL — agent generates Dockerfile or compose as needed
zero-forge discover --target https://github.com/example/vuln-app --access local
```

**Dependencies**: `docker` Python SDK and `docker-compose` (optional extra: `pip install -e ".[docker]"`). Compose v2 CLI (`docker compose`) is preferred over the legacy `docker-compose` Python package.

**Tests**: `tests/test_docker_env.py` — all three modes (image, dockerfile, compose), multi-service topology recording, reset/teardown, exec_in_target with service selection, capture_docker_state for evidence, user-supplied vs agent-generated files, error handling (build failures, missing files, port conflicts).

#### 7b. End-to-End Integration

**Goal**: Wire all milestones together; confirmed findings feed existing artifact-generation workflow.

**Changes to `workflow.py`**:
- `run_workflow()` stays unchanged for direct CVE→artifact generation
- New `run_discovery_workflow()` entry point uses the four-phase subgraphs
- After VERIFY promotes a `Finding`, the finding feeds into the existing generate→validate→save path as a `VulnerabilityInput`

**CLI additions** (`cli.py`) — see M7a for the full Docker target CLI examples. The `discover` command unifies all input modes:

```bash
# Repo URL (agent generates Dockerfile/compose as needed)
zero-forge discover --target <repo-url> --access <mode> [--budget-experiments N] [--output DIR]

# Docker target options (mutually exclusive group)
zero-forge discover --docker-image <image:tag> --access local
zero-forge discover --dockerfile <path> --build-context <dir> --access local
zero-forge discover --compose-file <path> [--services web,db] --access local
```

#### 7c. Tests

| Test file | Coverage |
|---|---|
| `tests/test_investigation.py` | Entity/relationship schemas, query, retention |
| `tests/test_discovery_agent.py` | Hypothesis generation, ranking, experiment design, classification |
| `tests/test_discovery_workflow.py` | Four-phase pipeline, backward escalation, budget exhaustion |
| `tests/test_verification_oracle.py` | Satisfied, refuted, partial, contradictory, determinism, capability tiers |
| `tests/test_discovery_tools.py` | Source-assisted and runtime tools with mock inputs |
| `tests/test_budget.py` | Budget tracking, authorization gate, access-mode enforcement |
| `tests/test_docker_env.py` | All three modes (image, dockerfile, compose), multi-service topology recording, reset/teardown, exec_in_target with service selection, capture_docker_state for evidence, user-supplied vs agent-generated files, build failures, missing files, port conflicts (mocked Docker SDK) |
| `tests/test_discovery_integration.py` | End-to-end: discovery → finding → artifact generation (stub LLM) |

**Acceptance criteria test coverage**: supported, refuted, inconclusive, exhausted-budget, unauthorized, and failed-tool paths.

#### 7d. Documentation

| Document | Content |
|---|---|
| `docs/archure.md` (update) | Execution graph vs investigation graph; four-phase architecture diagram |
| `docs/discovery.md` (new) | Discovery workflow usage, configuration, safety gates, reproduction gate |
| `docs/verification-oracle.md` (new) | Prolog/IR verification program format, evidence records, capability ladder |
| `README.md` (update) | New `discover` CLI command, configuration table additions |
| `config.example.yaml` (update) | Discovery, budget, verification, Docker config sections |

---

## 4. Implementation Order and Dependencies

```
Milestone 1 (Investigation Schemas)
    ↓
Milestone 2 (Hypothesis + Discovery Agent)
    ↓
Milestone 6 (Budgets + Safety Gates)  ←── can parallel with M3
    ↓
Milestone 3 (Four-Phase Subgraphs)
    ↓
Milestone 4 (Verification Oracle)  ←── can parallel with M5
    ↓
Milestone 5 (Tool Adapters)  ←── can parallel with M8
    ↓
Milestone 8 (Scanners)  ←── feeds RESEARCH phase observations
    ↓
Milestone 7 (SWE/Docker + Integration + Tests + Docs)
```

**Suggested PR sequence** (GitHub Flow, one PR per milestone). See `docs/issue-28-milestone-tracker.md` for the full `ZF-DSC-*` naming scheme, sub-task breakdown, and status tracking.

| # | Code | Branch | Milestone |
|---|---|---|---|
| 1 | `ZF-DSC-01` | `feature/zf-dsc-01-investigation-schemas` | Investigation Graph Schemas |
| 2 | `ZF-DSC-02` | `feature/zf-dsc-02-hypothesis-discovery-agent` | Hypothesis + Discovery Agent |
| 3 | `ZF-DSC-06` | `feature/zf-dsc-06-budget-safety-gates` | Budgets + Safety Gates |
| 4 | `ZF-DSC-03` | `feature/zf-dsc-03-four-phase-subgraphs` | Four-Phase LangGraph Subgraphs |
| 5 | `ZF-DSC-04` | `feature/zf-dsc-04-verification-oracle` | Formal Verification Oracle |
| 6 | `ZF-DSC-05` | `feature/zf-dsc-05-discovery-tool-adapters` | Discovery Tool Adapters |
| 7 | `ZF-DSC-08` | `feature/zf-dsc-08-scanner-integration` | Vulnerability + Code Scanners |
| 8 | `ZF-DSC-07` | `feature/zf-dsc-07-swe-docker-integration` | SWE/Docker + Integration |

Each PR must pass: `ruff check .`, `mypy zero_forge`, `pytest tests/ -v`.

---

## 5. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Prolog engine dependency (`pyswip`) unavailable in CI | Medium | High | Typed IR fallback backend; Prolog is optional extra |
| Docker SDK not available in all environments | Medium | Medium | Mock-based tests; Docker tools are optional extras |
| LLM hypothesis quality insufficient for real discovery | High | Medium | Bounded experiments + counterevidence retention prevent loops; human review gate |
| LangGraph subgraph complexity (backward escalation) | Medium | High | Start with linear phases; add escalation paths incrementally |
| Investigation graph growth (memory) | Low | Medium | JSONL append-only store; compress older findings into summaries |
| Budget enforcement race conditions | Low | Medium | Budget checks are conditional edges, not concurrent |
| External scanner binaries (Trivy, Nuclei, etc.) not installed | High | Low | Runtime detection + graceful skip; scanners are optional extras or external binaries |

---

## 6. Acceptance Criteria Checklist

- [ ] Typed schemas exist for the minimum investigation entities and relationships. *(M1)*
- [ ] Hypotheses have explicit success and refutation conditions. *(M2)*
- [ ] LangGraph implements the bounded hypothesis → experiment → evidence loop. *(M3)*
- [ ] Tool execution is routed exclusively through typed Tool Agent requests. *(M5)*
- [ ] Authorization and access-mode checks gate every experiment. *(M6)*
- [ ] Raw evidence is immutable and linked to tool/version/environment provenance. *(M1, M5)*
- [ ] Negative and inconclusive results are retained. *(M1, M2)*
- [ ] Findings cannot be created without successful reproduction. *(M3, M4)*
- [ ] Confirmed findings can feed the existing artifact-generation workflow. *(M7)*
- [ ] IPX integration remains behind the versioned adapter. *(M7 — no IPX changes)*
- [ ] Unit and integration tests cover supported, refuted, inconclusive, exhausted-budget, unauthorized, and failed-tool paths. *(M7)*
- [ ] Documentation explains execution graph versus investigation graph. *(M7)*
- [ ] Four named phases (RESEARCH, PLAN, EXPLOIT, VERIFY) are typed LangGraph subgraphs. *(M3)*
- [ ] RESEARCH implements an iterative deep research loop with configurable termination criteria. *(M3)*
- [ ] RESEARCH produces structured artifacts consumed by PLAN. *(M3)*
- [ ] PLAN readiness gate blocks EXPLOIT until `ready`. *(M3)*
- [ ] EXPLOIT repair loop can escalate backward to PLAN or RESEARCH. *(M3)*
- [ ] VERIFY runs independently of EXPLOIT with deterministic repeatability checks. *(M3, M4)*
- [ ] Backward escalation paths are typed and budget-bounded. *(M3, M6)*
- [ ] Event journal records phase transitions, escalation reasons, and budget consumption. *(M3)*
- [ ] Tests cover each phase independently and the full four-phase pipeline. *(M7)*
- [ ] Smart Agent can emit a `VerificationProgram` during PLAN. *(M4)*
- [ ] VERIFY phase captures structured `EvidenceRecord` facts from exploit execution. *(M4)*
- [ ] A deterministic engine evaluates the program against the evidence. *(M4)*
- [ ] Verification result includes satisfied, refuted, and unsatisfied predicates. *(M4)*
- [ ] The proof tree / evaluation trace is persisted for audit. *(M4)*
- [ ] Same evidence + same program always produces the same verdict. *(M4)*
- [ ] The verification program can encode capability ladder tiers. *(M4)*
- [ ] The verification program is independent of the EXPLOIT phase's model context. *(M4)*
- [ ] Tests cover: satisfied, refuted, partial-satisfaction, and contradictory-evidence paths. *(M4)*
- [ ] Scanner output remains observation until hypothesis-tested and reproduced. *(M8)*
- [ ] Scanner adapters produce normalized ScanResult with tool/version provenance. *(M8)*

---

## 7. Effort Estimate

| Milestone | Estimated PRs | Complexity | Notes |
|---|---|---|---|
| M1: Investigation Schemas | 1 | Medium | Pure schema work, no LLM or LangGraph changes |
| M2: Hypothesis + Discovery Agent | 1–2 | High | New LLM prompts, structured output parsing |
| M3: Four-Phase Subgraphs | 2–3 | Very High | Largest milestone; LangGraph subgraph design |
| M4: Verification Oracle | 1–2 | High | Prolog engine integration + IR fallback |
| M5: Tool Adapters | 2–3 | Medium | Many small tools; each independently testable |
| M6: Budgets + Safety Gates | 1 | Medium | Budget tracker + authorization gate |
| M7: SWE/Docker + Integration | 2–3 | High | Docker SDK (image, dockerfile, compose modes), multi-service topology, CLI, end-to-end tests, docs |
| M8: Scanners | 2–3 | Medium | 18 scanner adapters across 6 categories; mostly subprocess wrappers; normalized ScanResult schema |

**Total**: ~12–18 PRs across 8 milestones.

---

## 8. Publication

- **Target branch**: `docs/research` on `lost-rob0t/zero-forge`
- **Status**: Draft — not yet ready for publication
- **Action**: Publish when implementation is complete and the plan has been reviewed
- **Process**: Create a PR from `docs/research` → `master` (or merge into `docs/research` directly if it's a long-lived research branch)
- **Note**: Follow GitHub Flow — branch from current `master`, create `docs/research` if it doesn't exist, push the plan document, and open a PR for review
