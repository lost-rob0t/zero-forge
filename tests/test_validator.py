"""Tests for ZeroForge validator tool."""

from __future__ import annotations

import shutil
import subprocess
from typing import Any
from unittest.mock import patch

import pytest

from zero_forge.examples import default_examples_root
from zero_forge.tools.validator import (
    DefaultRubyRunner,
    ValidatorRuntimeUnavailable,
    require_node_runtime,
    require_ruby_runtime,
    validate_metasploit,
    validate_zap_active_scan,
    validate_zap_passive_scan,
)

# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

VALID_MODULE = """
class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Test Module',
      'Description' => 'Test description',
      'Author' => ['TestAuthor'],
      'References' => [['CVE', '2021-44228']],
      'License' => MSF_LICENSE
    ))
    register_options([
      Opt::RPORT(8080)
    ])
  end

  def exploit
    # exploit logic
  end
end
"""

COMMENTS_ONLY_MODULE = """# class MetasploitModule < Msf::Exploit::Remote
# 'Name' => 'x'
# 'Description' => 'x'
# 'Author' => ['x']
# 'References' => []
# 'License' => MSF_LICENSE
# def initialize
# end
# def exploit
# end
"""

HEREDOC_MODULE = """x = <<~RUBY
class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'x',
      'Description' => 'x',
      'Author' => ['x'],
      'References' => [],
      'License' => MSF_LICENSE
    ))
  end

  def exploit
  end
end
RUBY
"""

VALID_AST_RESULT: dict[str, Any] = {
    "parseable": True,
    "has_metasploit_module_class": True,
    "has_metasploit_superclass": True,
    "has_initialize_method": True,
    "has_exploit_method": True,
    "metadata_keys_found": ["Name", "Description", "Author", "References", "License"],
}


class FakeRubyRunner:
    """Injectable RubyRunner for unit tests — no ambient PATH dependency."""

    def __init__(
        self,
        syntax_result: tuple[int, str, str] = (0, "Syntax OK\n", ""),
        ast_result: dict[str, Any] | None = None,
        syntax_exc: Exception | None = None,
        ast_exc: Exception | None = None,
    ) -> None:
        self._syntax_result = syntax_result
        self._ast_result = ast_result if ast_result is not None else VALID_AST_RESULT
        self._syntax_exc = syntax_exc
        self._ast_exc = ast_exc

    def check_syntax(self, content: str) -> tuple[int, str, str]:
        if self._syntax_exc is not None:
            raise self._syntax_exc
        return self._syntax_result

    def analyze_ast(self, content: str) -> dict[str, Any]:
        if self._ast_exc is not None:
            raise self._ast_exc
        return self._ast_result


def _runner_with_ast(ast: dict[str, Any]) -> FakeRubyRunner:
    """Create a FakeRubyRunner whose syntax passes but AST returns *ast*."""
    return FakeRubyRunner(ast_result=ast)


# --------------------------------------------------------------------------- #
# 1. Valid module passes
# --------------------------------------------------------------------------- #


def test_valid_metasploit_module():
    runner = FakeRubyRunner()
    result = validate_metasploit(VALID_MODULE, ruby_runner=runner)
    assert result["is_valid"] is True
    assert len(result["errors"]) == 0


def test_valid_module_warnings_present():
    """Valid module should still produce warnings about optional items."""
    content = """
class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Test',
      'Description' => 'Test description',
      'Author' => ['Test'],
      'References' => [['CVE', '']],
      'License' => MSF_LICENSE
    ))
  end

  def exploit
    # exploit
  end
end
"""
    runner = FakeRubyRunner()
    result = validate_metasploit(content, ruby_runner=runner)
    assert result["is_valid"] is True
    assert len(result["warnings"]) > 0


# --------------------------------------------------------------------------- #
# 2. Ruby syntax error fails
# --------------------------------------------------------------------------- #


def test_ruby_syntax_error_fails():
    runner = FakeRubyRunner(syntax_result=(1, "", "syntax error, unexpected end"))
    result = validate_metasploit("def broken", ruby_runner=runner)
    assert result["is_valid"] is False
    assert any("Ruby syntax error" in e for e in result["errors"])


# --------------------------------------------------------------------------- #
# 3. Required tokens inside comments fail
# --------------------------------------------------------------------------- #


def test_comments_only_tokens_fail():
    """All required tokens appear only in comments — AST must not find them."""
    ast = {
        "parseable": True,
        "has_metasploit_module_class": False,
        "has_metasploit_superclass": False,
        "has_initialize_method": False,
        "has_exploit_method": False,
        "metadata_keys_found": [],
    }
    runner = _runner_with_ast(ast)
    result = validate_metasploit(COMMENTS_ONLY_MODULE, ruby_runner=runner)
    assert result["is_valid"] is False
    assert any("MetasploitModule" in e for e in result["errors"])
    assert any("superclass" in e for e in result["errors"])
    assert any("initialize" in e for e in result["errors"])
    assert any("exploit" in e for e in result["errors"])
    assert any("Name" in e for e in result["errors"])
    assert any("Description" in e for e in result["errors"])
    assert any("Author" in e for e in result["errors"])
    assert any("References" in e for e in result["errors"])
    assert any("License" in e for e in result["errors"])


# --------------------------------------------------------------------------- #
# 4. Required tokens inside a string/heredoc fail
# --------------------------------------------------------------------------- #


def test_heredoc_only_tokens_fail():
    """All required tokens exist only inside a heredoc — AST must not find them."""
    ast = {
        "parseable": True,
        "has_metasploit_module_class": False,
        "has_metasploit_superclass": False,
        "has_initialize_method": False,
        "has_exploit_method": False,
        "metadata_keys_found": [],
    }
    runner = _runner_with_ast(ast)
    result = validate_metasploit(HEREDOC_MODULE, ruby_runner=runner)
    assert result["is_valid"] is False
    assert any("MetasploitModule" in e for e in result["errors"])
    assert any("initialize" in e for e in result["errors"])
    assert any("exploit" in e for e in result["errors"])


# --------------------------------------------------------------------------- #
# 5. Missing MetasploitModule class fails
# --------------------------------------------------------------------------- #


def test_missing_metasploit_module_class_fails():
    ast = {**VALID_AST_RESULT, "has_metasploit_module_class": False}
    runner = _runner_with_ast(ast)
    result = validate_metasploit("class Foo; end", ruby_runner=runner)
    assert result["is_valid"] is False
    assert any("MetasploitModule" in e for e in result["errors"])


# --------------------------------------------------------------------------- #
# 6. Wrong superclass fails
# --------------------------------------------------------------------------- #


def test_wrong_superclass_fails():
    ast = {**VALID_AST_RESULT, "has_metasploit_superclass": False}
    runner = _runner_with_ast(ast)
    result = validate_metasploit("class MetasploitModule; end", ruby_runner=runner)
    assert result["is_valid"] is False
    assert any("superclass" in e for e in result["errors"])


# --------------------------------------------------------------------------- #
# 7. Missing initialize fails
# --------------------------------------------------------------------------- #


def test_missing_initialize_fails():
    ast = {**VALID_AST_RESULT, "has_initialize_method": False}
    runner = _runner_with_ast(ast)
    result = validate_metasploit("class MetasploitModule; end", ruby_runner=runner)
    assert result["is_valid"] is False
    assert any("initialize" in e for e in result["errors"])


# --------------------------------------------------------------------------- #
# 8. Missing exploit fails
# --------------------------------------------------------------------------- #


def test_missing_exploit_fails():
    ast = {**VALID_AST_RESULT, "has_exploit_method": False}
    runner = _runner_with_ast(ast)
    result = validate_metasploit("class MetasploitModule; end", ruby_runner=runner)
    assert result["is_valid"] is False
    assert any("exploit" in e for e in result["errors"])


# --------------------------------------------------------------------------- #
# 9. Missing required metadata fails
# --------------------------------------------------------------------------- #


def test_missing_metadata_fails():
    ast = {
        **VALID_AST_RESULT,
        "metadata_keys_found": ["Name"],  # only Name present
    }
    runner = _runner_with_ast(ast)
    result = validate_metasploit("class MetasploitModule; end", ruby_runner=runner)
    assert result["is_valid"] is False
    assert any("Description" in e for e in result["errors"])
    assert any("Author" in e for e in result["errors"])
    assert any("References" in e for e in result["errors"])
    assert any("License" in e for e in result["errors"])
    # Name should NOT be in errors since it's present
    assert not any("'Name'" in e for e in result["errors"])


# --------------------------------------------------------------------------- #
# 10. Empty content
# --------------------------------------------------------------------------- #


def test_empty_content():
    result = validate_metasploit("")
    assert result["is_valid"] is False
    assert "Empty module content" in result["errors"]


@pytest.mark.parametrize(
    "path",
    sorted((default_examples_root() / "zap" / "active").glob("*.js")),
)
def test_zap_active_examples_validate(path):
    result = validate_zap_active_scan(path.read_text(encoding="utf-8"))

    assert result["is_valid"] is True
    assert result["errors"] == []


@pytest.mark.parametrize(
    "path",
    sorted((default_examples_root() / "zap" / "passive").glob("*.js")),
)
def test_zap_passive_examples_validate(path):
    result = validate_zap_passive_scan(path.read_text(encoding="utf-8"))

    assert result["is_valid"] is True
    assert result["errors"] == []


def test_zap_active_rejects_invalid_javascript_syntax():
    content = (
        default_examples_root() / "zap" / "active" / "reflected_input.js"
    ).read_text(encoding="utf-8")
    content = content.replace(
        'const attack = "zf-reflection-8f7d3c";',
        'const broken = ([)];\n  const attack = "zf-reflection-8f7d3c";',
    )

    result = validate_zap_active_scan(content)

    assert result["is_valid"] is False
    assert any("JavaScript syntax error" in error for error in result["errors"])


def test_zap_active_rejects_invalid_metadata_yaml():
    content = (
        default_examples_root() / "zap" / "active" / "reflected_input.js"
    ).read_text(encoding="utf-8")
    content = content.replace(
        "references:\n  - https://www.zaproxy.org/docs/desktop/addons/script-console/",
        "references: [unterminated",
    )

    result = validate_zap_active_scan(content)

    assert result["is_valid"] is False
    assert any("Invalid ZAP metadata YAML" in error for error in result["errors"])


def test_zap_active_requires_category_metadata():
    content = (
        default_examples_root() / "zap" / "active" / "reflected_input.js"
    ).read_text(encoding="utf-8")
    content = content.replace("category: injection\n", "")

    result = validate_zap_active_scan(content)

    assert result["is_valid"] is False
    assert "Missing required ZAP metadata key: 'category'" in result["errors"]


def test_zap_active_requires_detection_flow():
    content = (default_examples_root() / "zap" / "active" / "reflected_input.js").read_text(
        encoding="utf-8"
    )
    content = content.replace("as.sendAndReceive(probe, false, false);", "")

    result = validate_zap_active_scan(content)

    assert result["is_valid"] is False
    assert any("send its probe" in error for error in result["errors"])


def test_zap_passive_rejects_network_side_effects():
    content = (default_examples_root() / "zap" / "passive" / "missing_csp.js").read_text(
        encoding="utf-8"
    )
    content = content.replace(
        "const responseHeader = msg.getResponseHeader();",
        "as.sendAndReceive(msg, false, false);\n"
        "  const responseHeader = msg.getResponseHeader();",
    )

    result = validate_zap_passive_scan(content)

    assert result["is_valid"] is False
    assert "Passive rules must not send requests" in result["errors"]


def test_zap_passive_ignores_forbidden_words_in_comments_and_strings():
    content = (default_examples_root() / "zap" / "passive" / "missing_csp.js").read_text(
        encoding="utf-8"
    )
    content += '\n// sendAndReceive fetch XMLHttpRequest\nconst note = "HttpSender";\n'

    result = validate_zap_passive_scan(content)

    assert result["is_valid"] is True


def test_zap_metadata_inside_comment_does_not_satisfy_contract():
    content = (default_examples_root() / "zap" / "passive" / "missing_csp.js").read_text(
        encoding="utf-8"
    )
    content = content.replace(
        "return ScanRuleMetadata.fromYaml(`",
        "return null;\n  /* ScanRuleMetadata.fromYaml(`",
    ).replace(
        "`);\n}",
        "`); */\n}",
        1,
    )

    result = validate_zap_passive_scan(content)

    assert result["is_valid"] is False
    assert "Missing ScanRuleMetadata YAML template literal" in result["errors"]


def test_node_preflight_returns_resolved_executable():
    with patch("zero_forge.tools.validator.shutil.which", return_value="/usr/bin/node"):
        assert require_node_runtime() == "/usr/bin/node"


def test_node_preflight_missing_is_actionable():
    with (
        patch("zero_forge.tools.validator.shutil.which", return_value=None),
        pytest.raises(ValidatorRuntimeUnavailable, match="install Node.js"),
    ):
        require_node_runtime()


def test_zap_validation_fails_closed_without_node():
    content = (
        default_examples_root() / "zap" / "passive" / "missing_csp.js"
    ).read_text(encoding="utf-8")
    with patch("zero_forge.tools.validator.shutil.which", return_value=None):
        result = validate_zap_passive_scan(content)

    assert result["is_valid"] is False
    assert result["runtime_error"] is True
    assert any("Node.js is required" in error for error in result["errors"])


def test_ruby_preflight_returns_resolved_executable():
    with patch("zero_forge.tools.validator.shutil.which", return_value="/usr/bin/ruby"):
        assert require_ruby_runtime() == "/usr/bin/ruby"


def test_ruby_preflight_missing_is_actionable():
    with (
        patch("zero_forge.tools.validator.shutil.which", return_value=None),
        pytest.raises(ValidatorRuntimeUnavailable, match="install Ruby 3.3.8"),
    ):
        require_ruby_runtime()


# --------------------------------------------------------------------------- #
# 11. Ruby executable unavailable fails closed
# --------------------------------------------------------------------------- #


def test_ruby_unavailable_fails_closed():
    """When the Ruby executable is not found, validation must fail closed."""
    runner = FakeRubyRunner(syntax_exc=FileNotFoundError("ruby not found"))
    result = validate_metasploit(VALID_MODULE, ruby_runner=runner)
    assert result["is_valid"] is False
    assert any("not found" in e for e in result["errors"])
    assert result["runtime_error"] is True


def test_ruby_ast_unavailable_fails_closed():
    """If Ruby disappears between syntax check and AST analysis, fail closed."""
    runner = FakeRubyRunner(ast_exc=FileNotFoundError("ruby not found"))
    result = validate_metasploit(VALID_MODULE, ruby_runner=runner)
    assert result["is_valid"] is False
    assert any("not found" in e for e in result["errors"])
    assert result["runtime_error"] is True


# --------------------------------------------------------------------------- #
# 12. Ruby validation timeout fails closed
# --------------------------------------------------------------------------- #


def test_syntax_timeout_fails_closed():
    runner = FakeRubyRunner(syntax_exc=subprocess.TimeoutExpired(cmd="ruby", timeout=1))
    result = validate_metasploit(VALID_MODULE, ruby_runner=runner)
    assert result["is_valid"] is False
    assert any("timed out" in e for e in result["errors"])


def test_ast_timeout_fails_closed():
    runner = FakeRubyRunner(ast_exc=subprocess.TimeoutExpired(cmd="ruby", timeout=1))
    result = validate_metasploit(VALID_MODULE, ruby_runner=runner)
    assert result["is_valid"] is False
    assert any("timed out" in e for e in result["errors"])


# --------------------------------------------------------------------------- #
# 13. Validator process failure fails closed
# --------------------------------------------------------------------------- #


def test_syntax_process_failure_fails_closed():
    runner = FakeRubyRunner(syntax_exc=RuntimeError("process crash"))
    result = validate_metasploit(VALID_MODULE, ruby_runner=runner)
    assert result["is_valid"] is False
    assert any("failed" in e for e in result["errors"])


def test_ast_process_failure_fails_closed():
    runner = FakeRubyRunner(ast_exc=RuntimeError("process crash"))
    result = validate_metasploit(VALID_MODULE, ruby_runner=runner)
    assert result["is_valid"] is False
    assert any("failed" in e for e in result["errors"])


# --------------------------------------------------------------------------- #
# 14. Temporary file is removed
# --------------------------------------------------------------------------- #


def test_temp_file_removed_after_syntax_check(monkeypatch):
    """Verify that DefaultRubyRunner cleans up temp files after syntax check."""
    created_paths: list[str] = []
    original_named_temp = __import__("tempfile").NamedTemporaryFile

    def tracking_named_temp(*args, **kwargs):
        f = original_named_temp(*args, **kwargs)
        created_paths.append(f.name)
        return f

    monkeypatch.setattr("zero_forge.tools.validator.tempfile.NamedTemporaryFile", tracking_named_temp)

    runner = DefaultRubyRunner()
    try:
        runner.check_syntax("puts 'hello'\n")
    except Exception:
        pass  # Ruby may not be installed

    for p in created_paths:
        assert not __import__("pathlib").Path(p).exists(), f"Temp file not removed: {p}"


def test_temp_file_removed_after_ast_analysis(monkeypatch):
    """Verify that DefaultRubyRunner cleans up temp files after AST analysis."""
    created_paths: list[str] = []
    original_named_temp = __import__("tempfile").NamedTemporaryFile

    def tracking_named_temp(*args, **kwargs):
        f = original_named_temp(*args, **kwargs)
        created_paths.append(f.name)
        return f

    monkeypatch.setattr("zero_forge.tools.validator.tempfile.NamedTemporaryFile", tracking_named_temp)

    runner = DefaultRubyRunner()
    try:
        runner.analyze_ast("puts 'hello'\n")
    except Exception:
        pass  # Ruby may not be installed

    for p in created_paths:
        assert not __import__("pathlib").Path(p).exists(), f"Temp file not removed: {p}"


# --------------------------------------------------------------------------- #
# 15. Result contract preserved
# --------------------------------------------------------------------------- #


def test_result_contract_shape():
    runner = FakeRubyRunner()
    result = validate_metasploit(VALID_MODULE, ruby_runner=runner)
    assert set(result.keys()) == {"is_valid", "errors", "warnings"}
    assert isinstance(result["is_valid"], bool)
    assert isinstance(result["errors"], list)
    assert isinstance(result["warnings"], list)


# --------------------------------------------------------------------------- #
# Integration tests — only run when Ruby is installed
# --------------------------------------------------------------------------- #

ruby_available = shutil.which("ruby") is not None


@pytest.mark.skipif(not ruby_available, reason="Ruby not installed")
class TestRubyIntegration:
    """Integration tests using the real Ruby interpreter."""

    def test_real_valid_module_passes(self):
        result = validate_metasploit(VALID_MODULE)
        assert result["is_valid"] is True
        assert len(result["errors"]) == 0

    def test_real_syntax_error_fails(self):
        result = validate_metasploit("def broken")
        assert result["is_valid"] is False
        assert any("Ruby syntax error" in e for e in result["errors"])

    def test_real_comments_only_fails(self):
        result = validate_metasploit(COMMENTS_ONLY_MODULE)
        assert result["is_valid"] is False
        assert any("MetasploitModule" in e for e in result["errors"])

    def test_real_heredoc_only_fails(self):
        result = validate_metasploit(HEREDOC_MODULE)
        assert result["is_valid"] is False
        assert any("MetasploitModule" in e for e in result["errors"])

    def test_real_missing_class_fails(self):
        result = validate_metasploit("puts 'hello'")
        assert result["is_valid"] is False
        assert any("MetasploitModule" in e for e in result["errors"])

    def test_real_wrong_superclass_fails(self):
        content = """
class MetasploitModule < Foo
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'x',
      'Description' => 'x',
      'Author' => ['x'],
      'References' => [],
      'License' => MSF_LICENSE
    ))
  end

  def exploit
  end
end
"""
        result = validate_metasploit(content)
        assert result["is_valid"] is False
        assert any("superclass" in e for e in result["errors"])

    def test_real_missing_initialize_fails(self):
        content = """
class MetasploitModule < Msf::Exploit::Remote
  def exploit
  end
end
"""
        result = validate_metasploit(content)
        assert result["is_valid"] is False
        assert any("initialize" in e for e in result["errors"])

    def test_real_missing_exploit_fails(self):
        content = """
class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'x',
      'Description' => 'x',
      'Author' => ['x'],
      'References' => [],
      'License' => MSF_LICENSE
    ))
  end
end
"""
        result = validate_metasploit(content)
        assert result["is_valid"] is False
        assert any("exploit" in e for e in result["errors"])

    def test_real_missing_metadata_fails(self):
        content = """
class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Test',
      'License' => MSF_LICENSE
    ))
  end

  def exploit
  end
end
"""
        result = validate_metasploit(content)
        assert result["is_valid"] is False
        assert any("Description" in e for e in result["errors"])
        assert any("Author" in e for e in result["errors"])
        assert any("References" in e for e in result["errors"])

    def test_real_ruby_unavailable_fails_closed(self):
        """Patch to use a nonexistent Ruby binary — must fail closed."""
        runner = DefaultRubyRunner(ruby_executable="/nonexistent/ruby")
        result = validate_metasploit(VALID_MODULE, ruby_runner=runner)
        assert result["is_valid"] is False
        assert any("not found" in e for e in result["errors"])

    def test_real_ast_timeout_fails_closed(self):
        """Patch DefaultRubyRunner.analyze_ast to raise TimeoutExpired."""
        runner = DefaultRubyRunner()
        with patch.object(runner, "analyze_ast", side_effect=subprocess.TimeoutExpired(cmd="ruby", timeout=1)):
            result = validate_metasploit(VALID_MODULE, ruby_runner=runner)
            assert result["is_valid"] is False
            assert any("timed out" in e for e in result["errors"])

    def test_real_temp_file_removed(self):
        """Run real syntax check and confirm temp files are gone."""
        runner = DefaultRubyRunner()
        runner.check_syntax("puts 'hello'\n")
        # If we got here without error, temp files were cleaned up.
        # Verify by checking /tmp for stale .rb files we created.
        import glob
        import os
        import tempfile

        tmp_dir = tempfile.gettempdir()
        stale = list(glob.glob(os.path.join(tmp_dir, "*.rb")))
        # Our temp files should not persist
        assert len(stale) == 0, f"Stale temp files found: {stale}"


# --------------------------------------------------------------------------- #
# 16. Adversarial tests — ZF-004: scope Ripper to MetasploitModule class
# --------------------------------------------------------------------------- #

# Module with empty MetasploitModule class; required methods and metadata
# live in a sibling class and a top-level hash. The old global walk would
# pass this; the scoped walk must reject it.
ADVERSARIAL_SIBLING_MODULE = """
class MetasploitModule < Msf::Exploit::Remote
end

class FakeModule
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

# Module with MetasploitModule class but metadata keys only in a top-level
# hash, not inside the class's initialize/update_info call.
ADVERSARIAL_TOPLEVEL_METADATA = """
metadata = {
  'Name' => 'Decoy',
  'Description' => 'Decoy',
  'Author' => ['Decoy'],
  'References' => [],
  'License' => 'Decoy'
}

class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(update_info(info,
      'License' => MSF_LICENSE
    ))
  end

  def exploit
  end
end
"""

# Module with MetasploitModule class containing superclass and exploit,
# but initialize is in a sibling class.
ADVERSARIAL_SIBLING_INITIALIZE = """
class MetasploitModule < Msf::Exploit::Remote
  def exploit
  end
end

class Helper
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Test',
      'Description' => 'Test',
      'Author' => ['Test'],
      'References' => [],
      'License' => MSF_LICENSE
    ))
  end
end
"""


def test_adversarial_sibling_class_methods_not_counted():
    """Methods in a sibling class must NOT satisfy MetasploitModule validation."""
    result = validate_metasploit(ADVERSARIAL_SIBLING_MODULE)
    assert result["is_valid"] is False
    assert any("initialize" in e for e in result["errors"])
    assert any("exploit" in e for e in result["errors"])
    assert any("Name" in e for e in result["errors"])


def test_adversarial_toplevel_metadata_not_counted():
    """Metadata keys in a top-level hash must NOT satisfy MetasploitModule validation."""
    result = validate_metasploit(ADVERSARIAL_TOPLEVEL_METADATA)
    assert result["is_valid"] is False
    assert any("Name" in e for e in result["errors"])
    assert any("Description" in e for e in result["errors"])
    assert any("Author" in e for e in result["errors"])
    assert any("References" in e for e in result["errors"])
    # License IS inside the class, so it should not be in errors
    assert not any("'License'" in e for e in result["errors"])


def test_adversarial_sibling_initialize_not_counted():
    """initialize in a sibling class must NOT satisfy MetasploitModule validation."""
    result = validate_metasploit(ADVERSARIAL_SIBLING_INITIALIZE)
    assert result["is_valid"] is False
    assert any("initialize" in e for e in result["errors"])
    assert any("Name" in e for e in result["errors"])
    assert any("Description" in e for e in result["errors"])


def test_valid_module_still_passes_scoped_walk():
    """A genuinely valid module must still pass after the scoping fix."""
    runner = FakeRubyRunner()
    result = validate_metasploit(VALID_MODULE, ruby_runner=runner)
    assert result["is_valid"] is True
    assert len(result["errors"]) == 0
