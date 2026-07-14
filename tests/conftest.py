"""Shared pytest fixtures for ZeroForge tests."""

import pytest

from zero_forge.config import reset_settings


@pytest.fixture(autouse=True)
def _reset_config_singleton():
    """Reset the config singleton before and after every test.

    This ensures monkeypatch.setenv calls in tests are actually picked up
    by get_settings() rather than returning a stale cached Settings.
    """
    reset_settings()
    yield
    reset_settings()
