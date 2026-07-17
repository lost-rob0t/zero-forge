"""Tool registry: register and dispatch named tool functions."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ToolFunc(Protocol):
    def __call__(self, **kwargs: Any) -> Any: ...


class ToolRegistry:
    """Simple registry mapping tool names to callable functions."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., Any]] = {}

    def register(self, name: str, func: Callable[..., Any]) -> None:
        """Register a tool under *name*."""
        if name in self._tools:
            raise ValueError(f"Tool '{name}' is already registered")
        self._tools[name] = func

    def get(self, name: str) -> Callable[..., Any]:
        """Get a registered tool by name."""
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' not found in registry")
        return self._tools[name]

    def call(self, name: str, **kwargs: Any) -> Any:
        """Call a registered tool with keyword arguments."""
        return self.get(name)(**kwargs)

    def names(self) -> list[str]:
        """List all registered tool names."""
        return sorted(self._tools.keys())

    def has(self, name: str) -> bool:
        return name in self._tools


def create_default_registry() -> ToolRegistry:
    """Create and populate a registry with the default built-in tools."""
    from .advisory_lookup import cisa_kev_lookup, github_advisory_search, osv_query
    from .cve_lookup import cve_lookup
    from .source_inspect import git_diff_inspect, read_source_files, search_code
    from .validator import (
        validate_metasploit,
        validate_zap_active_scan,
        validate_zap_passive_scan,
    )

    reg = ToolRegistry()
    reg.register("cve_lookup", cve_lookup)
    reg.register("osv_query", osv_query)
    reg.register("github_advisory_search", github_advisory_search)
    reg.register("cisa_kev_lookup", cisa_kev_lookup)
    reg.register("read_source_files", read_source_files)
    reg.register("search_code", search_code)
    reg.register("git_diff_inspect", git_diff_inspect)
    reg.register("validate_metasploit", validate_metasploit)
    reg.register("validate_zap_active_scan", validate_zap_active_scan)
    reg.register("validate_zap_passive_scan", validate_zap_passive_scan)
    return reg
