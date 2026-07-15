"""Tests for LLM max_tokens auto-inference in llm.py."""

from __future__ import annotations

import os
from unittest import mock

import pytest

from zero_forge.agents.llm import (
    call_model,
    reset_model_limits_cache,
    resolve_model_limits,
)
from zero_forge.config import ModelConfig, reset_settings


@pytest.fixture(autouse=True)
def _reset():
    reset_settings()
    reset_model_limits_cache()
    yield
    reset_settings()
    reset_model_limits_cache()


@pytest.fixture
def clean_env(monkeypatch):
    for key in list(os.environ):
        if key.startswith("ZERO_FORGE_") or key in (
            "OPENROUTER_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
        ):
            monkeypatch.delenv(key, raising=False)
    return monkeypatch


# --- resolve_model_limits ---


def test_resolve_openrouter_limit_caches_result(clean_env, monkeypatch):
    """OpenRouter API result is cached after first call."""
    mock_resp = mock.MagicMock()
    mock_resp.read.return_value = b'{"data": [{"id": "z-ai/glm-5.2", "top_provider": {"max_completion_tokens": 131072}}]}'
    mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = mock.MagicMock(return_value=False)

    with mock.patch("zero_forge.agents.llm.urllib.request.urlopen", return_value=mock_resp) as m:
        result1 = resolve_model_limits("openrouter/z-ai/glm-5.2", "openrouter", "sk-test")
        result2 = resolve_model_limits("openrouter/z-ai/glm-5.2", "openrouter", "sk-test")

    assert result1 == 131072
    assert result2 == 131072
    assert m.call_count == 1  # cached


def test_resolve_openrouter_limit_returns_none_on_failure(clean_env):
    """Returns None when OpenRouter API is unreachable."""
    with mock.patch(
        "zero_forge.agents.llm.urllib.request.urlopen",
        side_effect=Exception("network error"),
    ):
        result = resolve_model_limits("openrouter/z-ai/glm-5.2", "openrouter", "sk-test")
    assert result is None


def test_resolve_openrouter_limit_returns_none_when_model_not_found(clean_env):
    """Returns None when model is not in the API response."""
    mock_resp = mock.MagicMock()
    mock_resp.read.return_value = b'{"data": [{"id": "other/model"}]}'
    mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = mock.MagicMock(return_value=False)

    with mock.patch("zero_forge.agents.llm.urllib.request.urlopen", return_value=mock_resp):
        result = resolve_model_limits("openrouter/unknown/model", "openrouter", "sk-test")
    assert result is None


def test_resolve_returns_none_for_unknown_provider(clean_env):
    """Returns None for providers without a lookup path."""
    result = resolve_model_limits("some-model", "none", None)
    assert result is None


def test_reset_model_limits_cache_clears(clean_env, monkeypatch):
    """reset_model_limits_cache clears the cache so the next call re-fetches."""
    mock_resp = mock.MagicMock()
    mock_resp.read.return_value = b'{"data": [{"id": "z-ai/glm-5.2", "top_provider": {"max_completion_tokens": 131072}}]}'
    mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = mock.MagicMock(return_value=False)

    with mock.patch("zero_forge.agents.llm.urllib.request.urlopen", return_value=mock_resp) as m:
        resolve_model_limits("openrouter/z-ai/glm-5.2", "openrouter", "sk-test")
        reset_model_limits_cache()
        resolve_model_limits("openrouter/z-ai/glm-5.2", "openrouter", "sk-test")

    assert m.call_count == 2


# --- call_model auto-inference integration ---


class _FakeResponse:
    def __init__(self, content: str):
        self.choices = [type("Choice", (), {"message": type("Msg", (), {"content": content})()})()]


def test_call_model_auto_infers_max_tokens(clean_env, monkeypatch):
    """call_model uses inferred max_tokens when auto_max_tokens=True and no env override."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096)

    captured = {}

    def fake_completion(**kwargs):
        captured.update(kwargs)
        return _FakeResponse("hello world")

    mock_resp = mock.MagicMock()
    mock_resp.read.return_value = b'{"data": [{"id": "z-ai/glm-5.2", "top_provider": {"max_completion_tokens": 131072}}]}'
    mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = mock.MagicMock(return_value=False)

    with mock.patch("zero_forge.agents.llm.urllib.request.urlopen", return_value=mock_resp):
        with mock.patch("litellm.completion", side_effect=fake_completion):
            result = call_model("smart", config, "sys", "user")

    assert result == "hello world"
    assert captured["max_tokens"] == 8192  # min(131072, cap=8192)


def test_call_model_respects_explicit_env_max_tokens(clean_env, monkeypatch):
    """When ZERO_FORGE_SMART_MAX_TOKENS is set, auto-inference is skipped."""
    from zero_forge.config import get_settings

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("ZERO_FORGE_SMART_MAX_TOKENS", "2048")
    # Load from settings so env override is applied to config.max_tokens.
    settings = get_settings(reload=True)
    config = settings.models.smart

    captured = {}

    def fake_completion(**kwargs):
        captured.update(kwargs)
        return _FakeResponse("hello")

    mock_resp = mock.MagicMock()
    mock_resp.read.return_value = b'{"data": [{"id": "z-ai/glm-5.2", "top_provider": {"max_completion_tokens": 131072}}]}'
    mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = mock.MagicMock(return_value=False)

    with mock.patch("zero_forge.agents.llm.urllib.request.urlopen", return_value=mock_resp) as m:
        with mock.patch("litellm.completion", side_effect=fake_completion):
            result = call_model("smart", config, "sys", "user")

    assert result == "hello"
    assert captured["max_tokens"] == 2048  # env override, not inferred
    assert m.call_count == 0  # OpenRouter API not queried


def test_call_model_disabled_auto_max_tokens(clean_env, monkeypatch):
    """When auto_max_tokens=False, uses config.max_tokens without inference."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(
        provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False,
    )

    captured = {}

    def fake_completion(**kwargs):
        captured.update(kwargs)
        return _FakeResponse("hello")

    with mock.patch("zero_forge.agents.llm.urllib.request.urlopen") as m:
        with mock.patch("litellm.completion", side_effect=fake_completion):
            result = call_model("smart", config, "sys", "user")

    assert result == "hello"
    assert captured["max_tokens"] == 4096  # config default, no inference
    assert m.call_count == 0


def test_call_model_falls_back_on_api_failure(clean_env, monkeypatch):
    """When provider API fails, falls back to config.max_tokens."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096)

    captured = {}

    def fake_completion(**kwargs):
        captured.update(kwargs)
        return _FakeResponse("hello")

    with mock.patch(
        "zero_forge.agents.llm.urllib.request.urlopen",
        side_effect=Exception("network error"),
    ):
        with mock.patch("litellm.completion", side_effect=fake_completion):
            result = call_model("smart", config, "sys", "user")

    assert result == "hello"
    assert captured["max_tokens"] == 4096  # fallback to config default


def test_call_model_caps_inferred_tokens(clean_env, monkeypatch):
    """Inferred max_tokens is capped at inferred_max_token_cap."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(
        provider="openrouter",
        model="z-ai/glm-5.2",
        max_tokens=4096,
        inferred_max_token_cap=4096,
    )

    captured = {}

    def fake_completion(**kwargs):
        captured.update(kwargs)
        return _FakeResponse("hello")

    mock_resp = mock.MagicMock()
    mock_resp.read.return_value = b'{"data": [{"id": "z-ai/glm-5.2", "top_provider": {"max_completion_tokens": 131072}}]}'
    mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = mock.MagicMock(return_value=False)

    with mock.patch("zero_forge.agents.llm.urllib.request.urlopen", return_value=mock_resp):
        with mock.patch("litellm.completion", side_effect=fake_completion):
            result = call_model("smart", config, "sys", "user")

    assert result == "hello"
    assert captured["max_tokens"] == 4096  # capped at custom cap
