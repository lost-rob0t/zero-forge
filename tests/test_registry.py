"""Tests for ZeroForge tool registry."""

import pytest

from zero_forge.tools.registry import ToolRegistry, create_default_registry


def test_registry_register_and_call():
    reg = ToolRegistry()
    reg.register("doubler", lambda x: x * 2)
    assert reg.has("doubler")
    assert reg.call("doubler", x=5) == 10


def test_registry_duplicate():
    reg = ToolRegistry()
    reg.register("foo", lambda: "bar")
    with pytest.raises(ValueError, match="already registered"):
        reg.register("foo", lambda: "baz")


def test_registry_missing():
    reg = ToolRegistry()
    with pytest.raises(KeyError, match="not found"):
        reg.get("nonexistent")


def test_registry_names():
    reg = ToolRegistry()
    reg.register("alpha", lambda: 1)
    reg.register("beta", lambda: 2)
    assert reg.names() == ["alpha", "beta"]


def test_default_registry():
    reg = create_default_registry()
    names = reg.names()
    assert "cve_lookup" in names
    assert "osv_query" in names
    assert "github_advisory_search" in names
    assert "cisa_kev_lookup" in names
    assert "web_search" in names
    assert "fetch_web_page" in names
    assert "prepare_exploit_workspace" in names
    assert "write_exploit_draft" in names
    assert "validate_exploit_draft" in names
    assert "publish_exploit_bundle" in names
    assert "read_source_files" in names
    assert "search_code" in names
    assert "git_diff_inspect" in names
    assert "validate_metasploit" in names
    assert "validate_zap_active_scan" in names
    assert "validate_zap_passive_scan" in names
