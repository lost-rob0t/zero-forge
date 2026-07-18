"""ZeroForge: LLM-based security artifact generation harness."""

from __future__ import annotations

import importlib
from typing import Protocol, cast

__version__ = "0.1.0"


class _LiteLLMModule(Protocol):
    suppress_debug_info: bool
    suppress_debug_messages: bool
    set_verbose: bool


def _configure_litellm(module: _LiteLLMModule | None = None) -> None:
    """Suppress LiteLLM provider-debug noise without muting ZeroForge logs."""
    target = module
    if target is None:
        try:
            target = cast(_LiteLLMModule, importlib.import_module("litellm"))
        except ImportError:
            return

    target.suppress_debug_info = True
    target.suppress_debug_messages = True
    target.set_verbose = False


_configure_litellm()
