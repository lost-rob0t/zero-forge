"""Tests for ZeroForge validator tool."""

from zero_forge.tools.validator import validate_metasploit


def test_valid_metasploit_module():
    content = '''
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
'''
    result = validate_metasploit(content)
    assert result["is_valid"] is True
    assert len(result["errors"]) == 0


def test_invalid_missing_class():
    result = validate_metasploit("puts 'hello'")
    assert result["is_valid"] is False
    assert any("class definition" in e for e in result["errors"])


def test_invalid_missing_metadata():
    content = """
class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Test Module'
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
    assert any("License" in e for e in result["errors"])


def test_invalid_missing_methods():
    content = """
class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Test',
      'Description' => 'Test',
      'Author' => ['Test'],
      'References' => [['CVE', '']],
      'License' => MSF_LICENSE
    ))
  end
end
"""
    result = validate_metasploit(content)
    assert result["is_valid"] is False
    assert any("exploit" in e for e in result["errors"])


def test_empty_content():
    result = validate_metasploit("")
    assert result["is_valid"] is False
    assert "Empty module content" in result["errors"]


def test_warnings_present():
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
    result = validate_metasploit(content)
    assert result["is_valid"] is True
    assert len(result["warnings"]) > 0
