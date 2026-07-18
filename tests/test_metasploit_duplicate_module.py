from __future__ import annotations

from typing import Any

from zero_forge.tools.metasploit_validator import (
    validate_metasploit_with_runners,
)


MODULE = """class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'One',
      'Description' => 'One',
      'Author' => ['ZeroForge'],
      'References' => [],
      'License' => MSF_LICENSE
    ))
  end

  def exploit
  end
end
"""


class FakeRubyRunner:
    def check_syntax(self, content: str) -> tuple[int, str, str]:
        return 0, "Syntax OK", ""

    def analyze_ast(self, content: str) -> dict[str, Any]:
        return {
            "parseable": True,
            "has_metasploit_module_class": True,
            "has_metasploit_superclass": True,
            "has_initialize_method": True,
            "has_exploit_method": True,
            "metadata_keys_found": [
                "Name",
                "Description",
                "Author",
                "References",
                "License",
            ],
        }


class RecordingMetasploitRunner:
    def __init__(self) -> None:
        self.calls = 0

    def load_module(self, content: str) -> tuple[int, str, str]:
        self.calls += 1
        return 0, "Module: exploit/zeroforge/generated_validation\n", ""


def test_multiple_metasploit_module_classes_fail_before_framework_load():
    runner = RecordingMetasploitRunner()
    result = validate_metasploit_with_runners(
        MODULE + "\n" + MODULE.replace("'One'", "'Two'"),
        ruby_runner=FakeRubyRunner(),
        metasploit_runner=runner,
    )

    assert result["is_valid"] is False
    assert result["stages"]["metasploit_semantics"] == "failed"
    assert any("exactly one MetasploitModule" in error for error in result["errors"])
    assert runner.calls == 0
