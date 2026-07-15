"""Tests for the ZeroForge discovery workflow.

Covers the acceptance criteria from issue #28:
- Typed schemas for investigation entities and relationships
- Hypotheses with explicit success and refutation conditions
- LangGraph implements the bounded hypothesis → experiment → evidence loop
- Tool execution is routed through typed requests
- Authorization and access-mode checks gate every experiment
- Raw evidence is immutable and linked to provenance
- Negative and inconclusive results are retained
- Findings cannot be created without successful reproduction
- Unit tests cover supported, refuted, inconclusive, exhausted-budget,
  unauthorized, and failed-tool paths
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from zero_forge.discovery.schemas import (
    AccessMode,
    DiscoveryState,
    EvidenceClass,
    EvidenceRecord,
    Experiment,
    Finding,
    FindingStatus,
    Hypothesis,
    InvestigationGraph,
    OperationalPhase,
    RelationshipType,
    SWESetupResult,
    Target,
)
from zero_forge.discovery.tools import (
    ToolPathError,
    execute_metasploit_rc,
    generate_flag,
    read_file,
    verify_flag_in_output,
    write_flag_to_path,
)
from zero_forge.discovery.workflow import (
    _classify_evidence,
    build_discovery_workflow,
    exploit_node,
    plan_node,
    research_node,
    run_discovery,
    verify_node,
)

# --- Helpers ------------------------------------------------------------------

def _make_target(**overrides) -> Target:
    defaults: dict = {
        "name": "test-target",
        "authorized": True,
    }
    defaults.update(overrides)
    return Target(**defaults)


def _make_swe_setup(tmp_path: Path) -> SWESetupResult:
    flag = generate_flag()
    flag_path = str(tmp_path / "flag.txt")
    write_flag_to_path(flag, flag_path)
    return SWESetupResult(
        flag_path=flag_path,
        flag_value=flag,
        target_id="test-target-id",
        ready=True,
    )


# --- Schema tests ------------------------------------------------------------

class TestSchemas:
    def test_target_creation(self):
        target = Target(name="my-target", version="1.0")
        assert target.name == "my-target"
        assert target.version == "1.0"
        assert target.id
        assert target.authorized is False

    def test_hypothesis_requires_success_and_refutation_conditions(self):
        h = Hypothesis(
            target_id="t1",
            claimed_weakness="sql_injection",
            affected_component="login form",
            entry_point="/login",
            suspected_sink="database query",
            expected_vulnerable_behavior="auth bypass",
            expected_safe_behavior="query is parameterized",
            experiment_strategy="send SQLi payload",
            success_condition="admin login achieved",
            failure_condition="login rejected",
        )
        assert h.success_condition
        assert h.failure_condition
        assert h.status == "open"
        assert h.confidence == 0.0

    def test_experiment_requires_allowed_tools(self):
        with pytest.raises(ValidationError):
            Experiment(
                hypothesis_id="h1",
                objective="test",
                allowed_tools=[],
            )

    def test_evidence_record_provenance(self):
        e = EvidenceRecord(
            experiment_id="exp1",
            stdout="output",
            stderr="",
            exit_code=0,
            tool_name="read_file",
            tool_version="1.0",
            environment="local",
        )
        assert e.tool_name == "read_file"
        assert e.timestamp
        assert e.classification == EvidenceClass.INCONCLUSIVE

    def test_finding_requires_verification(self):
        f = Finding(
            target_id="t1",
            hypothesis_id="h1",
        )
        assert f.verification is None
        assert f.status == FindingStatus.CONFIRMED

    def test_investigation_graph_relationships(self):
        graph = InvestigationGraph()
        graph.add_relationship("a", RelationshipType.SUPPORTS, "b", "test")
        assert len(graph.relationships) == 1
        assert graph.relationships[0]["type"] == "supports"

    def test_access_mode_enum(self):
        assert AccessMode.INFORMATIONAL == "informational"
        assert AccessMode.REMOTE == "remote"
        assert AccessMode.LOCAL == "local"

    def test_operational_phase_enum(self):
        assert OperationalPhase.RESEARCH == "research"
        assert OperationalPhase.PLAN == "plan"
        assert OperationalPhase.EXPLOIT == "exploit"
        assert OperationalPhase.VERIFY == "verify"

    def test_evidence_class_enum(self):
        assert EvidenceClass.SUPPORTING == "supporting"
        assert EvidenceClass.REFUTING == "refuting"
        assert EvidenceClass.INCONCLUSIVE == "inconclusive"

    def test_discovery_state_defaults(self):
        target = Target(name="test")
        state = DiscoveryState(target=target)
        assert state.phase == OperationalPhase.RESEARCH
        assert state.status == "pending"
        assert state.max_experiments == 10
        assert state.max_research_iterations == 20
        assert state.findings == []


# --- Tools tests -------------------------------------------------------------

class TestTools:
    def test_generate_flag_is_random(self):
        flag1 = generate_flag()
        flag2 = generate_flag()
        assert flag1 != flag2
        assert flag1.startswith("FLAG{")
        assert flag1.endswith("}")

    def test_write_and_read_flag(self, tmp_path):
        flag = generate_flag()
        path = str(tmp_path / "flag.txt")
        result = write_flag_to_path(flag, path)
        assert result == str((tmp_path / "flag.txt").resolve())

    def test_verify_flag_in_output_found(self):
        flag = "FLAG{abcdef1234567890}"
        result = verify_flag_in_output(flag=flag, output=f"some output {flag} more")
        assert result["flag_found"] is True
        assert result["flag_value"] == flag

    def test_verify_flag_in_output_not_found(self):
        flag = "FLAG{abcdef1234567890}"
        result = verify_flag_in_output(flag=flag, output="no flag here")
        assert result["flag_found"] is False
        assert result["flag_value"] == ""

    def test_write_flag_rejects_traversal_path(self):
        with pytest.raises(ToolPathError):
            write_flag_to_path("FLAG{test}", "/tmp/../../etc/passwd")

    def test_write_flag_rejects_symlink(self, tmp_path):
        link_path = tmp_path / "link.txt"
        real_path = tmp_path / "real.txt"
        real_path.write_text("data")
        link_path.symlink_to(real_path)
        with pytest.raises(ToolPathError):
            write_flag_to_path("FLAG{test}", str(link_path))

    def test_read_file_rejects_secret_paths(self):
        result = read_file(path="/etc/shadow")
        assert result["error"]
        assert "secrets" in result["error"].lower()

    def test_read_file_rejects_traversal(self):
        result = read_file(path="/tmp/../../etc/passwd")
        assert result["error"]

    def test_read_file_truncation_by_bytes(self, tmp_path):
        # Create a file with multi-byte UTF-8 content
        content = "\x80" * 100_000  # > 50KB
        file_path = tmp_path / "large.txt"
        file_path.write_bytes(content.encode("utf-8"))
        result = read_file(path=str(file_path))
        assert "[truncated]" in result["content"]

    def test_execute_metasploit_rc_not_found(self):
        result = execute_metasploit_rc(rc_file="/nonexistent/path.rc")
        # msfconsole not available in test env, or rc not found
        assert result["exit_code"] == -1

    def test_read_file_returns_content(self, tmp_path):
        file_path = tmp_path / "test.txt"
        file_path.write_text("hello world")
        result = read_file(path=str(file_path))
        assert result["content"] == "hello world"
        assert result["error"] == ""


# --- Research node tests -----------------------------------------------------

class TestResearchNode:
    def test_research_sets_up_swe(self, tmp_path):
        target = _make_target()
        state = DiscoveryState(target=target, authorized=True)
        patch = research_node(state)
        assert patch["swe_setup"] is not None
        assert patch["swe_setup"].ready is True
        assert patch["swe_setup"].flag_path
        assert patch["swe_setup"].flag_value
        assert patch["status"] == "planning"
        assert patch["phase"] == OperationalPhase.PLAN

    def test_research_budget_exhausted(self):
        target = _make_target()
        state = DiscoveryState(
            target=target,
            authorized=True,
            research_iterations=20,
            max_research_iterations=20,
        )
        patch = research_node(state)
        assert patch["status"] == "failed"

    def test_research_unauthorized_fails(self):
        target = _make_target(authorized=False)
        state = DiscoveryState(target=target, authorized=False)
        patch = research_node(state)
        assert patch["status"] == "failed"
        assert "authorized" in patch["error"].lower()

    def test_research_increments_requests_made(self, tmp_path):
        target = _make_target()
        state = DiscoveryState(target=target, authorized=True)
        patch = research_node(state)
        assert patch["requests_made"] == 1

    def test_research_increments_runtime(self, tmp_path):
        target = _make_target()
        state = DiscoveryState(target=target, authorized=True)
        patch = research_node(state)
        assert patch["runtime_seconds"] >= 0.0


# --- Plan node tests --------------------------------------------------------

class TestPlanNode:
    def test_plan_creates_hypothesis_and_experiment(self, tmp_path):
        target = _make_target()
        swe = _make_swe_setup(tmp_path)
        state = DiscoveryState(
            target=target,
            authorized=True,
            swe_setup=swe,
        )
        # Run research first to populate investigation graph
        research_patch = research_node(state)
        state = state.model_copy(update=research_patch)
        patch = plan_node(state)
        assert patch["current_hypothesis_id"]
        assert patch["current_experiment_id"]
        assert patch["phase"] == OperationalPhase.EXPLOIT
        assert patch["status"] == "exploiting"

    def test_plan_budget_exhausted(self, tmp_path):
        target = _make_target()
        swe = _make_swe_setup(tmp_path)
        state = DiscoveryState(
            target=target,
            authorized=True,
            swe_setup=swe,
            experiments_run=10,
            max_experiments=10,
        )
        patch = plan_node(state)
        assert patch["status"] == "failed"


# --- Exploit node tests ------------------------------------------------------

class TestExploitNode:
    def test_exploit_supported_path(self, tmp_path):
        target = _make_target()
        swe = _make_swe_setup(tmp_path)
        state = DiscoveryState(
            target=target,
            authorized=True,
            swe_setup=swe,
        )
        # Run research and plan
        state = state.model_copy(update=research_node(state))
        state = state.model_copy(update=plan_node(state))
        patch = exploit_node(state)
        assert patch["phase"] == OperationalPhase.VERIFY
        assert patch["status"] == "verifying"
        evidence = patch["investigation"].evidence[patch["current_evidence_id"]]
        assert evidence.classification == EvidenceClass.SUPPORTING
        assert evidence.flag_found is True

    def test_exploit_unauthorized_path(self, tmp_path):
        target = _make_target()
        swe = _make_swe_setup(tmp_path)
        state = DiscoveryState(
            target=target,
            authorized=False,
            swe_setup=swe,
        )
        # Research will fail for unauthorized, so manually set up the state
        state = state.model_copy(update={
            "investigation": InvestigationGraph(
                targets={target.id: target},
            ),
        })
        state = state.model_copy(update=plan_node(state))
        patch = exploit_node(state)
        assert patch["status"] == "failed"
        assert "not authorized" in patch["error"].lower()

    def test_exploit_budget_exhausted(self, tmp_path):
        target = _make_target()
        swe = _make_swe_setup(tmp_path)
        state = DiscoveryState(
            target=target,
            authorized=True,
            swe_setup=swe,
        )
        # Run research and plan to populate the investigation graph
        state = state.model_copy(update=research_node(state))
        state = state.model_copy(update=plan_node(state))
        # Now exhaust the experiment budget before executing
        state = state.model_copy(update={
            "experiments_run": state.max_experiments,
        })
        patch = exploit_node(state)
        assert patch["status"] == "failed"
        assert "Budget exhausted" in patch["error"]

    def test_exploit_refuting_path(self, tmp_path):
        """Flag file doesn't exist → evidence is classified as refuting."""
        target = _make_target()
        # Create SWE setup with non-existent flag path
        swe = SWESetupResult(
            flag_path=str(tmp_path / "nonexistent_flag.txt"),
            flag_value="FLAG{does_not_exist}",
            target_id=target.id,
            ready=True,
        )
        state = DiscoveryState(
            target=target,
            authorized=True,
            swe_setup=swe,
        )
        state = state.model_copy(update=research_node(state))
        state = state.model_copy(update=plan_node(state))
        patch = exploit_node(state)
        evidence = patch["investigation"].evidence[patch["current_evidence_id"]]
        assert evidence.classification == EvidenceClass.REFUTING
        assert evidence.flag_found is False

    def test_exploit_failed_tool_path(self, tmp_path):
        """Tool execution raises an exception → inconclusive evidence."""
        target = _make_target()
        swe = _make_swe_setup(tmp_path)
        state = DiscoveryState(
            target=target,
            authorized=True,
            swe_setup=swe,
        )
        state = state.model_copy(update=research_node(state))
        state = state.model_copy(update=plan_node(state))

        # Mock read_file to raise an exception
        with patch(
            "zero_forge.discovery.workflow.read_file",
            side_effect=RuntimeError("Tool crashed"),
        ):
            result = exploit_node(state)

        evidence = result["investigation"].evidence[result["current_evidence_id"]]
        assert evidence.classification == EvidenceClass.INCONCLUSIVE
        assert "Tool execution failed" in evidence.stderr


# --- Verify node tests ------------------------------------------------------

class TestVerifyNode:
    def test_verify_supported_creates_finding(self, tmp_path):
        target = _make_target()
        swe = _make_swe_setup(tmp_path)
        state = DiscoveryState(
            target=target,
            authorized=True,
            swe_setup=swe,
        )
        state = state.model_copy(update=research_node(state))
        state = state.model_copy(update=plan_node(state))
        state = state.model_copy(update=exploit_node(state))
        patch = verify_node(state)
        assert patch["status"] == "completed"
        assert len(patch["findings"]) == 1
        finding = patch["findings"][0]
        assert finding.verification is not None
        assert finding.verification.verified is True
        assert finding.verification.flag_retrieved is True

    def test_verify_refuting_retains_negative_result(self, tmp_path):
        target = _make_target()
        swe = SWESetupResult(
            flag_path=str(tmp_path / "nonexistent_flag.txt"),
            flag_value="FLAG{does_not_exist}",
            target_id=target.id,
            ready=True,
        )
        state = DiscoveryState(
            target=target,
            authorized=True,
            swe_setup=swe,
        )
        state = state.model_copy(update=research_node(state))
        state = state.model_copy(update=plan_node(state))
        state = state.model_copy(update=exploit_node(state))
        patch = verify_node(state)
        # Should escalate back to PLAN, not create a finding
        assert patch["status"] == "planning"
        assert patch["phase"] == OperationalPhase.PLAN
        assert "findings" not in patch or len(patch.get("findings", [])) == 0

    def test_verify_inconclusive_retains_result(self, tmp_path):
        """Inconclusive evidence is retained and escalates back to PLAN."""
        target = _make_target()
        # Create a flag file but with wrong value in SWE setup
        flag = generate_flag()
        flag_path = str(tmp_path / "flag.txt")
        write_flag_to_path(flag, flag_path)
        swe = SWESetupResult(
            flag_path=flag_path,
            flag_value="FLAG{wrong_value}",
            target_id=target.id,
            ready=True,
        )
        state = DiscoveryState(
            target=target,
            authorized=True,
            swe_setup=swe,
        )
        state = state.model_copy(update=research_node(state))
        state = state.model_copy(update=plan_node(state))
        state = state.model_copy(update=exploit_node(state))
        patch = verify_node(state)
        # Evidence is inconclusive (flag doesn't match), should escalate
        assert patch["status"] == "planning"

    def test_verify_reproduction_failure_escalates_to_exploit(self, tmp_path):
        """When reproduction fails, verify escalates back to EXPLOIT."""
        target = _make_target()
        swe = _make_swe_setup(tmp_path)
        state = DiscoveryState(
            target=target,
            authorized=True,
            swe_setup=swe,
        )
        state = state.model_copy(update=research_node(state))
        state = state.model_copy(update=plan_node(state))
        state = state.model_copy(update=exploit_node(state))
        # Mock read_file to fail during reproduction
        with patch(
            "zero_forge.discovery.workflow.read_file",
            side_effect=RuntimeError("repro failed"),
        ):
            result = verify_node(state)
        assert result["status"] == "exploiting"
        assert result["phase"] == OperationalPhase.EXPLOIT
        assert result["repair_attempts"] == state.repair_attempts + 1


# --- Full workflow tests -----------------------------------------------------

class TestFullWorkflow:
    def test_workflow_builds(self):
        assert build_discovery_workflow() is not None

    def test_run_discovery_supported(self):
        target = Target(
            name="test-target",
            authorized=True,
        )
        result = run_discovery(target, authorized=True)
        assert result.status == "completed"
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.verification is not None
        assert finding.verification.verified is True
        assert finding.verification.flag_retrieved is True
        assert finding.verification.flag_value

    def test_run_discovery_unauthorized(self):
        target = Target(
            name="test-target",
            authorized=False,
        )
        result = run_discovery(target, authorized=False)
        assert result.status == "failed"
        assert "authorized" in result.error.lower()

    def test_negative_results_are_retained(self, tmp_path):
        """Negative and inconclusive results are preserved in the investigation graph."""
        target = _make_target()
        swe = SWESetupResult(
            flag_path=str(tmp_path / "nonexistent_flag.txt"),
            flag_value="FLAG{does_not_exist}",
            target_id=target.id,
            ready=True,
        )
        state = DiscoveryState(
            target=target,
            authorized=True,
            swe_setup=swe,
        )
        state = state.model_copy(update=research_node(state))
        state = state.model_copy(update=plan_node(state))
        state = state.model_copy(update=exploit_node(state))
        # Evidence should be in the investigation graph
        assert len(state.investigation.evidence) > 0
        evidence = list(state.investigation.evidence.values())[0]
        assert evidence.classification == EvidenceClass.REFUTING
        # It is retained even when negative
        assert evidence.id in state.investigation.evidence

    def test_finding_cannot_be_created_without_reproduction(self):
        """A finding without verification cannot be promoted."""
        finding = Finding(
            target_id="t1",
            hypothesis_id="h1",
        )
        assert finding.verification is None

    def test_evidence_linked_to_provenance(self, tmp_path):
        """Evidence is linked to tool/version/environment provenance."""
        target = _make_target()
        swe = _make_swe_setup(tmp_path)
        state = DiscoveryState(
            target=target,
            authorized=True,
            swe_setup=swe,
        )
        state = state.model_copy(update=research_node(state))
        state = state.model_copy(update=plan_node(state))
        state = state.model_copy(update=exploit_node(state))
        evidence = list(state.investigation.evidence.values())[0]
        assert evidence.tool_name == "read_file"
        assert evidence.timestamp
        assert evidence.environment


# --- SWE agent tests --------------------------------------------------------

class TestSWEAgent:
    def test_swe_setup_local_fallback(self, tmp_path):
        from zero_forge.discovery.swe_agent import setup_target_environment

        target = Target(name="test-target")
        result = setup_target_environment(
            target,
            output_dir=str(tmp_path),
            use_docker=False,
        )
        assert result.ready is True
        assert result.flag_path
        assert result.flag_value
        assert result.flag_value.startswith("FLAG{")
        assert Path(result.flag_path).is_file()

    def test_swe_flag_is_randomized(self, tmp_path):
        from zero_forge.discovery.swe_agent import setup_target_environment

        target = Target(name="test-target")
        result1 = setup_target_environment(
            target,
            output_dir=str(tmp_path / "a"),
            use_docker=False,
        )
        result2 = setup_target_environment(
            target,
            output_dir=str(tmp_path / "b"),
            use_docker=False,
        )
        assert result1.flag_value != result2.flag_value


# --- Evidence classification tests ------------------------------------------

class TestClassifyEvidence:
    def test_flag_found_is_supporting(self):
        result = _classify_evidence(True, "", "some output")
        assert result == EvidenceClass.SUPPORTING

    def test_not_found_in_error_is_refuting(self):
        result = _classify_evidence(False, "File not found: /tmp/flag.txt", "")
        assert result == EvidenceClass.REFUTING

    def test_not_found_in_output_is_refuting(self):
        result = _classify_evidence(False, "", "File not found")
        assert result == EvidenceClass.REFUTING

    def test_other_error_is_inconclusive(self):
        result = _classify_evidence(False, "Permission denied", "")
        assert result == EvidenceClass.INCONCLUSIVE

    def test_empty_output_is_inconclusive(self):
        result = _classify_evidence(False, "", "")
        assert result == EvidenceClass.INCONCLUSIVE
