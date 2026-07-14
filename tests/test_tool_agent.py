"""Tests for the ToolAgent."""

from zero_forge.agents.tool_agent import ToolAgent
from zero_forge.schemas import VulnerabilityInput


def test_tool_agent_lists_tools():
    agent = ToolAgent()
    tools = agent.list_available_tools()
    assert "cve_lookup" in tools
    assert "validate_metasploit" in tools


def test_tool_agent_validate_valid():
    agent = ToolAgent()
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
    result = agent.validate_artifact(content, "metasploit")
    assert result.is_valid is True


def test_tool_agent_validate_invalid():
    agent = ToolAgent()
    result = agent.validate_artifact("invalid content", "metasploit")
    assert result.is_valid is False
    assert len(result.errors) > 0


def test_tool_agent_validate_unknown_type():
    agent = ToolAgent()
    result = agent.validate_artifact("content", "unknown_type")
    assert result.is_valid is False
    assert "No validator" in result.errors[0]


def test_tool_agent_collect_context_offline():
    agent = ToolAgent()
    vuln_input = VulnerabilityInput(
        cve_id="CVE-2021-44228",
        poc_text="print('pwned')",
        writeup_text="Test writeup",
    )
    ctx = agent.collect_context(vuln_input)
    assert ctx.cve_id == "CVE-2021-44228"
    assert ctx.poc_text == "print('pwned')"
    assert ctx.writeup_text == "Test writeup"
