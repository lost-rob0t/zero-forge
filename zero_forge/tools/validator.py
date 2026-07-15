"""Artifact validation tools."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import yaml

META_REQUIRED_KEYS = {
    "Name": "Module name",
    "Description": "Module description",
    "Author": "Author",
    "References": "References",
    "License": "License",
}

RUBY_TIMEOUT = 10.0
RUBY_VERSION = "3.3.8"
RUBY_UNAVAILABLE_ERROR = (
    f"Ruby {RUBY_VERSION} is required for Metasploit validation but was not found "
    "on PATH; install Ruby 3.3.8 and retry"
)
NODE_TIMEOUT = 10.0
NODE_UNAVAILABLE_ERROR = (
    "Node.js is required for ZAP JavaScript syntax validation but was not found "
    "on PATH; install Node.js and retry"
)


class ValidatorRuntimeUnavailable(RuntimeError):
    """Raised when a required external validator runtime is unavailable."""


def require_ruby_runtime(ruby_executable: str = "ruby") -> str:
    """Return the Ruby executable path or raise one actionable preflight error."""
    path = shutil.which(ruby_executable)
    if path is None:
        raise ValidatorRuntimeUnavailable(RUBY_UNAVAILABLE_ERROR)
    return path


def require_node_runtime(node_executable: str = "node") -> str:
    """Return the Node.js executable path or raise one actionable preflight error."""
    path = shutil.which(node_executable)
    if path is None:
        raise ValidatorRuntimeUnavailable(NODE_UNAVAILABLE_ERROR)
    return path


def _javascript_syntax_failure(content: str) -> dict[str, Any] | None:
    """Return a fail-closed validation result when Node.js rejects JavaScript syntax."""
    try:
        node = require_node_runtime()
        result = subprocess.run(
            [node, "--check"],
            input=content,
            capture_output=True,
            text=True,
            timeout=NODE_TIMEOUT,
            shell=False,
        )
    except ValidatorRuntimeUnavailable as exc:
        return {
            "is_valid": False,
            "errors": [str(exc)],
            "warnings": [],
            "runtime_error": True,
        }
    except subprocess.TimeoutExpired:
        return {
            "is_valid": False,
            "errors": ["JavaScript syntax check timed out"],
            "warnings": [],
            "runtime_error": True,
        }
    except Exception as exc:
        return {
            "is_valid": False,
            "errors": [f"JavaScript syntax check failed: {exc}"],
            "warnings": [],
            "runtime_error": True,
        }

    if result.returncode == 0:
        return None
    detail = (result.stderr.strip() or result.stdout.strip() or "unknown syntax error")[:500]
    return {
        "is_valid": False,
        "errors": [f"JavaScript syntax error: {detail}"],
        "warnings": [],
    }


# Ruby AST analysis script using the standard-library Ripper parser.
# Walks the Ripper sexp to verify that required structural elements exist
# as real syntax nodes (not text inside comments, strings, or heredocs).
_RIPPER_SCRIPT = r'''require 'ripper'
require 'json'

code = STDIN.read
sexp = Ripper.sexp(code)

if sexp.nil?
  puts JSON.generate({
    'parseable' => false,
    'has_metasploit_module_class' => false,
    'has_metasploit_superclass' => false,
    'has_initialize_method' => false,
    'has_exploit_method' => false,
    'metadata_keys_found' => []
  })
  exit
end

REQUIRED_KEYS = ['Name', 'Description', 'Author', 'References', 'License']

def extract_consts(node)
  consts = []
  return consts unless node.is_a?(Array)
  consts << node[1] if node[0] == :@const && node[1].is_a?(String)
  node.each { |child| consts.concat(extract_consts(child)) }
  consts
end

def extract_string_value(node)
  return '' unless node.is_a?(Array)
  result = ''
  node.each do |child|
    if child.is_a?(Array) && child[0] == :@tstring_content && child[1].is_a?(String)
      result += child[1]
    elsif child.is_a?(Array)
      result += extract_string_value(child)
    end
  end
  result
end

found = {
  'has_metasploit_module_class' => false,
  'has_metasploit_superclass' => false,
  'has_initialize_method' => false,
  'has_exploit_method' => false,
  'metadata_keys_found' => []
}

def walk(node, found, required_keys)
  return unless node.is_a?(Array)

  if node[0] == :class && node[1].is_a?(Array) && node[1][0] == :const_ref
    const_node = node[1]
    if const_node[1].is_a?(Array) && const_node[1][0] == :@const && const_node[1][1] == 'MetasploitModule'
      found['has_metasploit_module_class'] = true
      superclass = node[2]
      if superclass
        consts = extract_consts(superclass)
        if consts.include?('Msf') && consts.include?('Exploit')
          found['has_metasploit_superclass'] = true
        end
      end
    end
  end

  if node[0] == :def && node[1].is_a?(Array) && node[1][0] == :@ident
    method_name = node[1][1]
    found['has_initialize_method'] = true if method_name == 'initialize'
    found['has_exploit_method'] = true if method_name == 'exploit'
  end

  if node[0] == :assoc_new
    key_node = node[1]
    if key_node.is_a?(Array)
      str_val = nil
      if key_node[0] == :string_literal
        str_val = extract_string_value(key_node[1]) if key_node[1].is_a?(Array)
      elsif key_node[0] == :symbol_literal
        inner = key_node[1]
        if inner.is_a?(Array) && inner[0] == :@ident && inner[1].is_a?(String)
          str_val = inner[1]
        end
      end
      if str_val && required_keys.include?(str_val)
        found['metadata_keys_found'] << str_val unless found['metadata_keys_found'].include?(str_val)
      end
    end
  end

  node.each { |child| walk(child, found, required_keys) }
end

walk(sexp, found, REQUIRED_KEYS)

puts JSON.generate({
  'parseable' => true,
  'has_metasploit_module_class' => found['has_metasploit_module_class'],
  'has_metasploit_superclass' => found['has_metasploit_superclass'],
  'has_initialize_method' => found['has_initialize_method'],
  'has_exploit_method' => found['has_exploit_method'],
  'metadata_keys_found' => found['metadata_keys_found']
})
'''


@runtime_checkable
class RubyRunner(Protocol):
    """Interface for running Ruby syntax checks and AST analysis."""

    def check_syntax(self, content: str) -> tuple[int, str, str]:
        """Run ``ruby -c`` on *content*. Return ``(returncode, stdout, stderr)``."""
        ...

    def analyze_ast(self, content: str) -> dict[str, Any]:
        """Run Ripper-based AST analysis. Return parsed JSON dict."""
        ...


class DefaultRubyRunner:
    """Runs Ruby syntax checks and AST analysis via :mod:`subprocess`.

    Uses argument-array invocation with ``shell=False``, captured
    stdout/stderr, a bounded timeout, and temporary-file cleanup.
    """

    def __init__(self, ruby_executable: str = "ruby", timeout: float = RUBY_TIMEOUT) -> None:
        self._ruby = ruby_executable
        self._timeout = timeout

    def check_syntax(self, content: str) -> tuple[int, str, str]:
        """Run ``ruby -c`` on *content* using a temporary file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rb", delete=False, encoding="utf-8"
        ) as f:
            f.write(content)
            temp_path = f.name
        try:
            result = subprocess.run(
                [self._ruby, "-c", temp_path],
                capture_output=True,
                text=True,
                timeout=self._timeout,
                shell=False,
            )
            return (result.returncode, result.stdout, result.stderr)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def analyze_ast(self, content: str) -> dict[str, Any]:
        """Run the Ripper-based AST analysis script with *content* on stdin."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rb", delete=False, encoding="utf-8"
        ) as f:
            f.write(_RIPPER_SCRIPT)
            script_path = f.name
        try:
            result = subprocess.run(
                [self._ruby, script_path],
                input=content,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                shell=False,
            )
            if result.returncode != 0:
                raise RuntimeError(f"Ruby AST analysis failed: {result.stderr}")
            data: dict[str, Any] = json.loads(result.stdout)
            return data
        finally:
            Path(script_path).unlink(missing_ok=True)


def validate_metasploit(
    content: str, ruby_runner: RubyRunner | None = None
) -> dict[str, Any]:
    """Validate a Metasploit exploit module.

    Uses a real Ruby syntax gate (``ruby -c``) followed by AST inspection
    via the standard-library ``Ripper`` parser.  Required class names,
    methods, and metadata keys must exist as actual syntax nodes—text
    inside comments, string literals, or heredocs does **not** satisfy
    validation.

    Fails closed when Ruby is unavailable, exits nonzero, times out, or
    the validator process fails.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not content or not content.strip():
        return {"is_valid": False, "errors": ["Empty module content"], "warnings": []}

    runner = ruby_runner or DefaultRubyRunner()

    # --- 1. Ruby syntax gate -------------------------------------------------
    try:
        returncode, stdout, stderr = runner.check_syntax(content)
    except FileNotFoundError:
        return {
            "is_valid": False,
            "errors": [RUBY_UNAVAILABLE_ERROR],
            "warnings": [],
            "runtime_error": True,
        }
    except subprocess.TimeoutExpired:
        return {
            "is_valid": False,
            "errors": ["Ruby syntax check timed out"],
            "warnings": [],
            "runtime_error": True,
        }
    except Exception as e:
        return {
            "is_valid": False,
            "errors": [f"Ruby syntax check failed: {e}"],
            "warnings": [],
            "runtime_error": True,
        }

    if returncode != 0:
        detail = stderr.strip() or stdout.strip() or "unknown syntax error"
        return {
            "is_valid": False,
            "errors": [f"Ruby syntax error: {detail}"],
            "warnings": [],
        }

    # --- 2. Ruby AST inspection ---------------------------------------------
    try:
        ast = runner.analyze_ast(content)
    except FileNotFoundError:
        return {
            "is_valid": False,
            "errors": [RUBY_UNAVAILABLE_ERROR],
            "warnings": [],
            "runtime_error": True,
        }
    except subprocess.TimeoutExpired:
        return {
            "is_valid": False,
            "errors": ["Ruby AST analysis timed out"],
            "warnings": [],
            "runtime_error": True,
        }
    except Exception as e:
        return {
            "is_valid": False,
            "errors": [f"Ruby AST analysis failed: {e}"],
            "warnings": [],
            "runtime_error": True,
        }

    if not ast.get("parseable", False):
        return {
            "is_valid": False,
            "errors": ["Ruby code could not be parsed (invalid syntax)"],
            "warnings": [],
        }

    # --- 3. Structural checks -----------------------------------------------
    if not ast.get("has_metasploit_module_class", False):
        errors.append("Missing 'MetasploitModule' class definition")

    if not ast.get("has_metasploit_superclass", False):
        errors.append("Missing Metasploit superclass (e.g., 'Msf::Exploit::Remote')")

    if not ast.get("has_initialize_method", False):
        errors.append("Missing required method: 'initialize'")

    if not ast.get("has_exploit_method", False):
        errors.append("Missing required method: 'exploit'")

    found_keys = set(ast.get("metadata_keys_found", []))
    for key, desc in META_REQUIRED_KEYS.items():
        if key not in found_keys:
            errors.append(f"Missing required metadata key: '{key}' ({desc})")

    # --- 4. Optional recommendations (warnings) -----------------------------
    if "Targets" not in content and "'Targets'" not in content:
        warnings.append("Consider adding 'Targets' metadata for target specification")

    if not re.search(r"register_options|register_advanced_options", content):
        warnings.append("Consider registering options for configurability")

    if "# " not in content:
        warnings.append("Consider adding comments for maintainability")

    return {"is_valid": len(errors) == 0, "errors": errors, "warnings": warnings}

_ZAP_COMMON_METADATA_KEYS = (
    "id",
    "name",
    "description",
    "solution",
    "references",
    "risk",
    "confidence",
    "cweId",
    "wascId",
    "status",
)
_ZAP_ACTIVE_METADATA_KEYS = (*_ZAP_COMMON_METADATA_KEYS, "category")
_ZAP_RISK_VALUES = {"info", "low", "medium", "high"}
_ZAP_CONFIDENCE_VALUES = {
    "false_positive",
    "low",
    "medium",
    "high",
    "user_confirmed",
}
_ZAP_ACTIVE_CATEGORY_VALUES = {
    "info_gather",
    "browser",
    "server",
    "misc",
    "injection",
}


def _strip_javascript_literals(content: str) -> str:
    """Replace JavaScript comments and string contents while preserving structure."""
    output: list[str] = []
    index = 0
    state = "code"
    quote = ""
    while index < len(content):
        current = content[index]
        following = content[index + 1] if index + 1 < len(content) else ""

        if state == "code":
            if current == "/" and following == "/":
                output.extend((" ", " "))
                index += 2
                state = "line_comment"
                continue
            if current == "/" and following == "*":
                output.extend((" ", " "))
                index += 2
                state = "block_comment"
                continue
            if current in ("'", '"', "`"):
                quote = current
                output.append(" ")
                index += 1
                state = "string"
                continue
            output.append(current)
            index += 1
            continue

        if state == "line_comment":
            output.append("\n" if current == "\n" else " ")
            index += 1
            if current == "\n":
                state = "code"
            continue

        if state == "block_comment":
            if current == "*" and following == "/":
                output.extend((" ", " "))
                index += 2
                state = "code"
                continue
            output.append("\n" if current == "\n" else " ")
            index += 1
            continue

        if current == "\\":
            output.append(" ")
            if following:
                output.append("\n" if following == "\n" else " ")
                index += 2
            else:
                index += 1
            continue
        output.append("\n" if current == "\n" else " ")
        index += 1
        if current == quote:
            state = "code"

    return "".join(output)


def _validate_zap_metadata(
    content: str,
    code: str,
    errors: list[str],
    *,
    active: bool,
) -> None:
    if not re.search(r"\bfunction\s+getMetadata\s*\(\s*\)", code):
        errors.append("Missing required function: 'getMetadata'")
    if "ScanRuleMetadata.fromYaml" not in code:
        errors.append("getMetadata must return ScanRuleMetadata.fromYaml(...)")

    matches = re.finditer(
        r"ScanRuleMetadata\.fromYaml\s*\(\s*`(?P<yaml>.*?)`\s*\)",
        content,
        re.DOTALL,
    )
    token = "ScanRuleMetadata.fromYaml"
    match = next(
        (
            candidate
            for candidate in matches
            if code[candidate.start() : candidate.start() + len(token)] == token
        ),
        None,
    )
    if match is None:
        errors.append("Missing ScanRuleMetadata YAML template literal")
        return

    try:
        metadata = yaml.safe_load(match.group("yaml"))
    except yaml.YAMLError as exc:
        errors.append(f"Invalid ZAP metadata YAML: {exc}")
        return
    if not isinstance(metadata, dict):
        errors.append("ZAP metadata YAML must define a mapping")
        return

    required_keys = _ZAP_ACTIVE_METADATA_KEYS if active else _ZAP_COMMON_METADATA_KEYS
    for key in required_keys:
        if key not in metadata:
            errors.append(f"Missing required ZAP metadata key: '{key}'")

    metadata_id = metadata.get("id")
    if not isinstance(metadata_id, int) or isinstance(metadata_id, bool):
        errors.append("ZAP metadata 'id' must be numeric")

    risk = str(metadata.get("risk", "")).lower()
    if risk not in _ZAP_RISK_VALUES:
        errors.append("ZAP metadata 'risk' must be info, low, medium, or high")

    confidence = str(metadata.get("confidence", "")).lower()
    if confidence not in _ZAP_CONFIDENCE_VALUES:
        errors.append("ZAP metadata 'confidence' has an unsupported value")

    references = metadata.get("references")
    if not isinstance(references, list) or not references:
        errors.append("ZAP metadata 'references' must be a non-empty list")

    for key in ("cweId", "wascId"):
        value = metadata.get(key)
        if not isinstance(value, int) or isinstance(value, bool):
            errors.append(f"ZAP metadata '{key}' must be numeric")

    if active:
        category = str(metadata.get("category", "")).lower()
        if category not in _ZAP_ACTIVE_CATEGORY_VALUES:
            errors.append(
                "ZAP active metadata 'category' must be info_gather, browser, "
                "server, misc, or injection"
            )

def _missing_tokens(code: str, requirements: dict[str, str], errors: list[str]) -> None:
    for token, message in requirements.items():
        if token not in code:
            errors.append(message)


def validate_zap_active_scan(content: str) -> dict[str, Any]:
    """Validate a JavaScript ZAP Active Rule detection artifact."""
    if not content or not content.strip():
        return {"is_valid": False, "errors": ["Empty ZAP active rule content"], "warnings": []}

    syntax_failure = _javascript_syntax_failure(content)
    if syntax_failure is not None:
        return syntax_failure

    errors: list[str] = []
    warnings: list[str] = []
    code = _strip_javascript_literals(content)
    _validate_zap_metadata(content, code, errors, active=True)

    if not re.search(
        r"\bfunction\s+scan\s*\(\s*as\s*,\s*msg\s*,\s*param\s*,\s*value\s*\)",
        code,
    ):
        errors.append("Active rule must define function scan(as, msg, param, value)")

    _missing_tokens(
        code,
        {
            "cloneRequest": "Active rule must clone the request before mutation",
            "as.setParam": "Active rule must inject its probe with as.setParam(...)",
            "as.sendAndReceive": "Active rule must send its probe with as.sendAndReceive(...)",
            "as.newAlert": "Active rule must create an alert with as.newAlert(...)",
            ".setParam": "Active alert must identify the tested parameter",
            ".setAttack": "Active alert must record the probe value",
            ".setEvidence": "Active alert must record response evidence",
            ".setMessage": "Active alert must attach the probe message",
            ".raise": "Active rule must raise the constructed alert",
        },
        errors,
    )
    if "getResponseBody" not in code and "getResponseHeader" not in code:
        errors.append("Active rule must inspect the probe response")
    if not re.search(r"\bif\s*\(", code):
        errors.append("Active rule must gate its alert on a detection condition")
    if "as.isStop" not in code:
        warnings.append("Check as.isStop() before sending active probes")

    return {"is_valid": not errors, "errors": errors, "warnings": warnings}


def validate_zap_passive_scan(content: str) -> dict[str, Any]:
    """Validate a JavaScript ZAP Passive Rule and reject network side effects."""
    if not content or not content.strip():
        return {"is_valid": False, "errors": ["Empty ZAP passive rule content"], "warnings": []}

    syntax_failure = _javascript_syntax_failure(content)
    if syntax_failure is not None:
        return syntax_failure

    errors: list[str] = []
    warnings: list[str] = []
    code = _strip_javascript_literals(content)
    _validate_zap_metadata(content, code, errors, active=False)

    if not re.search(
        r"\bfunction\s+scan\s*\(\s*(?:ps|helper)\s*,\s*msg\s*,\s*src\s*\)",
        code,
    ):
        errors.append("Passive rule must define function scan(ps, msg, src)")

    _missing_tokens(
        code,
        {
            ".newAlert": "Passive rule must create an alert",
            ".setEvidence": "Passive alert must record precise evidence",
            ".setMessage": "Passive alert must attach the inspected message",
            ".raise": "Passive rule must raise the constructed alert",
        },
        errors,
    )
    if not any(
        token in code
        for token in (
            "getRequestHeader",
            "getRequestBody",
            "getResponseHeader",
            "getResponseBody",
        )
    ):
        errors.append("Passive rule must inspect the supplied HTTP message")
    if not re.search(r"\bif\s*\(", code):
        errors.append("Passive rule must gate its alert on a detection condition")

    forbidden_patterns = {
        r"\bsendAndReceive\b": "Passive rules must not send requests",
        r"\bfetch\s*\(": "Passive rules must not call fetch",
        r"\bXMLHttpRequest\b": "Passive rules must not use XMLHttpRequest",
        r"\bHttpSender\b": "Passive rules must not use HttpSender",
        r"\bURLConnection\b|\bjava\.net\b": "Passive rules must not use network APIs",
        r"\b(?:ps|helper)\s*\.\s*setParam\s*\(": "Passive rules must not mutate parameters",
        r"\bmsg\s*\.\s*set(?:Request|Response)": "Passive rules must not mutate messages",
    }
    for pattern, message in forbidden_patterns.items():
        if re.search(pattern, code):
            errors.append(message)

    return {"is_valid": not errors, "errors": errors, "warnings": warnings}
