from __future__ import annotations

from types import SimpleNamespace

from zero_forge import _configure_litellm


def test_configure_litellm_suppresses_provider_debug_noise() -> None:
    module = SimpleNamespace(
        suppress_debug_info=False,
        suppress_debug_messages=False,
        set_verbose=True,
    )

    _configure_litellm(module)

    assert module.suppress_debug_info is True
    assert module.suppress_debug_messages is True
    assert module.set_verbose is False
