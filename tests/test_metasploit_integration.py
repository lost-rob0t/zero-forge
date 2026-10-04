from __future__ import annotations

import shutil

import pytest

from zero_forge.examples import default_examples_root
from zero_forge.tools.metasploit_validator import validate_metasploit_loadable

ruby_available = shutil.which("ruby") is not None
msfconsole_available = shutil.which("msfconsole") is not None


@pytest.mark.skipif(
    not (ruby_available and msfconsole_available),
    reason="Ruby and msfconsole are required for Metasploit load integration",
)
def test_reference_module_loads_in_metasploit_framework():
    module = (default_examples_root() / "metasploit" / "http_command_injection.rb").read_text(
        encoding="utf-8"
    )

    result = validate_metasploit_loadable(module)

    assert result["is_valid"] is True, result
    assert result["stages"]["ruby_structure"] == "passed"
    assert result["stages"]["metasploit_semantics"] == "passed"
    assert result["stages"]["metasploit_load"] == "passed"
    assert "exploit/zeroforge/generated_validation" in result["evidence"]["metasploit_output"]
