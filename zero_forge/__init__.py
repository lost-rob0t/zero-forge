"""ZeroForge: LLM-based security artifact generation harness."""

from __future__ import annotations

from types import ModuleType

__version__ = "0.1.0"


def _configure_litellm(module: ModuleType | None = None) -> None:
    """Suppress LiteLLM provider-debug noise without muting ZeroForge logs."""
    if module is None:
        try:
            import litellm as module
        except ImportError:
            return

    module.suppress_debug_info = True
    module.suppress_debug_messages = True
    module.set_verbose = False


_configure_litellm()
