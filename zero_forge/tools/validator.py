"""Artifact validation tools."""

from __future__ import annotations

import re
from typing import Any


META_REQUIRED_KEYS = {
    "Name": "Module name",
    "Description": "Module description",
    "Author": "Author",
    "References": "References",
    "License": "License",
}

META_REQUIRED_METHODS = ["initialize", "exploit"]


def validate_metasploit(content: str) -> dict[str, Any]:
    """Validate a Metasploit exploit module."""
    errors: list[str] = []
    warnings: list[str] = []

    if not content or not content.strip():
        return {"is_valid": False, "errors": ["Empty module content"], "warnings": []}

    if not re.search(r"class\s+\w+", content):
        errors.append("Missing class definition (e.g., 'class MetasploitModule')")

    if "MetasploitModule" not in content and "Msf::Exploit" not in content:
        errors.append("Missing 'MetasploitModule' or 'Msf::Exploit' superclass")

    for key, desc in META_REQUIRED_KEYS.items():
        pattern = rf"['\"]{re.escape(key)}['\"]\s*=>"
        if not re.search(pattern, content):
            errors.append(f"Missing required metadata key: '{key}' ({desc})")

    for method in META_REQUIRED_METHODS:
        pattern = rf"def\s+{method}\b"
        if not re.search(pattern, content):
            errors.append(f"Missing required method: '{method}'")

    if not re.search(r"def\s+(exploit|check)\b", content):
        errors.append("Missing 'exploit' or 'check' method")

    if "Targets" not in content and "'Targets'" not in content:
        warnings.append("Consider adding 'Targets' metadata for target specification")

    if not re.search(r"register_options|register_advanced_options", content):
        warnings.append("Consider registering options for configurability")

    if "# " not in content:
        warnings.append("Consider adding comments for maintainability")

    return {"is_valid": len(errors) == 0, "errors": errors, "warnings": warnings}
