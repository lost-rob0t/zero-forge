from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from zero_forge.tools.metasploit_validator import (
    MSFCONSOLE_UNAVAILABLE_ERROR,
    validate_metasploit_with_runners,
)
from zero_forge.tools.validator import ValidatorRuntimeUnavailable

VALID_MODULE = """
class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Test',
      'Description' => 'Test',
      'Author' => ['Test'],
      'References' => [],
      'License' => MSF_LICENSE
    ))
  end

  def exploit
  end
end
"""

BROKEN_LANGFLOW_MODULE = (
    Path(__file__).parent / "fixtures" / "langflow_generated_broken.rb"
).read_text(encoding="utf-8")

VALID_AST: dict[str, Any] = {
    "parseable": True,
    "has_metasploit_module_class": True,
    "has_metasploit_superclass": True,
    "has_initialize_method": True,
    "has_exploit_method": True,
    "metadata_keys_found": ["Name", "Description", "Author", "References", "License"],
}


class FakeRubyRunner:
    def check_syntax(self, content: str) -> tuple[int, str, str]:
        return 0, "Syntax OK", ""

    def analyze_ast(self, content: str) -> dict[str, Any]:
        return VALID_AST


class FakeMetasploitRunner:
    def __init__(
        self, result=(0, "Module: exploit/zeroforge/generated_validation\n", ""), exc=None
    ):
        self.result = result
        self.exc = exc
        self.calls = 0

    def load_module(self, content: str) -> tuple[int, str, str]:
        self.calls += 1
        if self.exc:
            raise self.exc
        return self.result


def test_valid_module_requires_and_passes_framework_load():
    runner = FakeMetasploitRunner()
    result = validate_metasploit_with_runners(
        VALID_MODULE,
        ruby_runner=FakeRubyRunner(),
        metasploit_runner=runner,
    )
    assert result["is_valid"] is True
    assert result["stages"] == {
        "ruby_structure": "passed",
        "metasploit_semantics": "passed",
        "metasploit_load": "passed",
    }
    assert runner.calls == 1


def test_langflow_regression_is_rejected_before_framework_load():
    runner = FakeMetasploitRunner()
    result = validate_metasploit_with_runners(
        BROKEN_LANGFLOW_MODULE,
        ruby_runner=FakeRubyRunner(),
        metasploit_runner=runner,
    )
    assert result["is_valid"] is False
    assert any("shell syntax" in error for error in result["errors"])
    assert any("Base64" in error for error in result["errors"])
    assert result["stages"]["metasploit_semantics"] == "failed"
    assert runner.calls == 0


def test_framework_load_failure_is_not_accepted():
    runner = FakeMetasploitRunner((0, "[-] Failed to load module\nNo module selected\n", ""))
    result = validate_metasploit_with_runners(
        VALID_MODULE,
        ruby_runner=FakeRubyRunner(),
        metasploit_runner=runner,
    )
    assert result["is_valid"] is False
    assert result["stages"]["metasploit_load"] == "failed"


def test_missing_msfconsole_fails_closed():
    runner = FakeMetasploitRunner(exc=ValidatorRuntimeUnavailable(MSFCONSOLE_UNAVAILABLE_ERROR))
    result = validate_metasploit_with_runners(
        VALID_MODULE,
        ruby_runner=FakeRubyRunner(),
        metasploit_runner=runner,
    )
    assert result["is_valid"] is False
    assert result["runtime_error"] is True
    assert result["stages"]["metasploit_load"] == "unavailable"


def test_msfconsole_timeout_fails_closed():
    runner = FakeMetasploitRunner(exc=subprocess.TimeoutExpired(cmd="msfconsole", timeout=1))
    result = validate_metasploit_with_runners(
        VALID_MODULE,
        ruby_runner=FakeRubyRunner(),
        metasploit_runner=runner,
    )
    assert result["is_valid"] is False
    assert result["runtime_error"] is True
    assert result["stages"]["metasploit_load"] == "timed_out"
