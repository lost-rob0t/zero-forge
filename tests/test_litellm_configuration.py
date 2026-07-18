from __future__ import annotations

from types import ModuleType

from zero_forge import _configure_litellm


def test_configure_litellm_suppresses_provider_debug_noise() -> None:
    module = ModuleType("litellm")
    module.suppress_debug_info = False
    module.suppress_debug_messages = False
    module.set_verbose = True

    _configure_litellm(module)

    assert module.suppress_debug_info is True
    assert module.suppress_debug_messages is True
    assert module.set_verbose is False
