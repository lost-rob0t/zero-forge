"""Tests for the model-backed Tool Agent."""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from zero_forge.agents.llm import LLMResponseError
from zero_forge.agents.tool_agent import ToolAgent, ToolCallValidationError
from zero_forge.schemas import ToolCall, ToolRequest, VulnerabilityInput
from zero_forge.tools.registry import ToolRegistry


def _stub_selection(monkeypatch) -> None:
    monkeypatch.setenv("ZERO_FORGE_STUB_MODE", "true")


def test_tool_agent_lists_tools():
    tools = ToolAgent().list_available_tools()
    assert "cve_lookup" in tools
    assert "validate_metasploit" in tools


def test_tool_agent_validate_valid(monkeypatch):
    _stub_selection(monkeypatch)
    registry = ToolRegistry()
    registry.register(
        "validate_metasploit",
        lambda content: {"is_valid": "class MetasploitModule" in content},
    )
    content = """
class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Test',
      'Description' => 'Test desc',
      'Author' => ['Test'],
      'References' => [['CVE', '']],
      'License' => MSF_LICENSE
    ))
  end

  def exploit
  end
end
"""
    result = ToolAgent(registry).validate_artifact(content, "metasploit")
    assert result.is_valid is True


def test_tool_agent_validate_invalid(monkeypatch):
    _stub_selection(monkeypatch)
    registry = ToolRegistry()
    registry.register(
        "validate_metasploit",
        lambda content: {"is_valid": False, "errors": ["invalid"]},
    )
    result = ToolAgent(registry).validate_artifact("invalid content", "metasploit")
    assert result.is_valid is False
    assert result.errors


def test_tool_agent_validate_unknown_type():
    result = ToolAgent().validate_artifact("content", "unknown_type")
    assert result.is_valid is False
    assert "No validator" in result.errors[0]


def test_tool_agent_collect_context_offline(monkeypatch):
    _stub_selection(monkeypatch)
    registry = ToolRegistry()
    registry.register(
        "cve_lookup",
        lambda cve_id, timeout=15: {
            "cve_id": cve_id,
            "description": "",
            "references": [],
            "cvss": "",
            "published": "",
        },
    )
    context = ToolAgent(registry).collect_context(
        VulnerabilityInput(
            cve_id="CVE-2021-44228",
            poc_text="print('pwned')",
            writeup_text="Test writeup",
        )
    )
    assert context.cve_id == "CVE-2021-44228"
    assert context.poc_text == "print('pwned')"
    assert context.writeup_text == "Test writeup"


def test_tool_agent_uses_only_tool_model(monkeypatch):
    captured = {}

    def completion(**kwargs):
        captured.update(kwargs)
        message = SimpleNamespace(content='{"name":"doubler","arguments":{"value":4}}')
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=completion))
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("ZERO_FORGE_SMART_MODEL", "expensive-writer")
    monkeypatch.setenv("ZERO_FORGE_TOOL_MODEL", "cheap-tool-caller")
    monkeypatch.setenv("ZERO_FORGE_TOOL_MAX_TOKENS", "333")

    registry = ToolRegistry()
    registry.register("doubler", lambda value: value * 2)
    result = ToolAgent(registry).run(
        ToolRequest(
            objective="Double the supplied value",
            allowed_tools=["doubler"],
            arguments={"value": 4},
        )
    )

    assert result.output == 8
    assert result.role == "tool"
    assert result.model == "cheap-tool-caller"
    assert captured["model"] == "cheap-tool-caller"
    assert captured["max_tokens"] == 333
    assert captured["model"] != "expensive-writer"


def test_invalid_arguments_fail_before_execution(monkeypatch):
    _stub_selection(monkeypatch)
    executed = False

    def guarded(value: int) -> int:
        nonlocal executed
        executed = True
        return value

    registry = ToolRegistry()
    registry.register("guarded", guarded)
    agent = ToolAgent(registry)

    with pytest.raises(ToolCallValidationError):
        agent.execute_tool_call(ToolCall(name="guarded", arguments={"wrong": 1}))
    assert executed is False


def test_tool_agent_cannot_return_artifact_fields(monkeypatch):
    def completion(**_kwargs):
        message = SimpleNamespace(
            content='{"name":"noop","arguments":{},"artifact_content":"owned"}'
        )
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=completion))
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    registry = ToolRegistry()
    registry.register("noop", lambda: None)

    with pytest.raises(LLMResponseError):
        ToolAgent(registry).select_tool_call(
            ToolRequest(objective="Do nothing", allowed_tools=["noop"])
        )
