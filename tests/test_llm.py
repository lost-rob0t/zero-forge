"""Tests for LLM max_tokens auto-inference in llm.py."""

from __future__ import annotations

import os
from unittest import mock

import pytest

from zero_forge.agents.llm import (
    call_model,
    reset_model_limits_cache,
    resolve_model,
    resolve_model_limits,
)
from zero_forge.config import ModelConfig, get_settings, reset_settings


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


def test_default_models_include_upstream_provider_for_openrouter(clean_env, monkeypatch):
    """Default role models must resolve to valid OpenRouter model identifiers."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    settings = get_settings(reload=True)

    smart = resolve_model("smart", settings.models.smart)
    tool = resolve_model("tool", settings.models.tool)

    assert smart.model == "openrouter/openai/gpt-4o"
    assert tool.model == "openrouter/openai/gpt-4o-mini"


# --- call_model auto-inference integration ---


class _FakeResponse:
    def __init__(self, content: str, finish_reason: str = "stop", reasoning_tokens: int | None = None):
        self.choices = [type("Choice", (), {
            "message": type("Msg", (), {"content": content})(),
            "finish_reason": finish_reason,
        })()]
        if reasoning_tokens is not None:
            self.usage = type("Usage", (), {
                "completion_tokens_details": type("Details", (), {
                    "reasoning_tokens": reasoning_tokens,
                })(),
            })()
        else:
            self.usage = type("Usage", (), {})()


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


# --- Token exhaustion retry (issue #80) ---


def test_token_exhaustion_retries_with_doubled_max_tokens(clean_env, monkeypatch):
    """finish_reason=length with empty content triggers retry with doubled max_tokens."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    captured = []

    def fake_completion(**kwargs):
        captured.append(dict(kwargs))
        if len(captured) == 1:
            return _FakeResponse(content="", finish_reason="length", reasoning_tokens=4096)
        return _FakeResponse("hello world")

    with mock.patch("litellm.completion", side_effect=fake_completion):
        result = call_model("smart", config, "sys", "user")

    assert result == "hello world"
    assert len(captured) == 2
    assert captured[0]["max_tokens"] == 4096
    assert captured[1]["max_tokens"] == 8192  # doubled


def test_token_exhaustion_non_retryable_on_stop(clean_env, monkeypatch):
    """finish_reason=stop with empty content is non-retryable (genuine refusal)."""
    from zero_forge.agents.llm import LLMResponseError

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    call_count = 0

    def fake_completion(**kwargs):
        nonlocal call_count
        call_count += 1
        return _FakeResponse(content="", finish_reason="stop")

    with mock.patch("litellm.completion", side_effect=fake_completion):
        with pytest.raises(LLMResponseError, match="empty message content"):
            call_model("smart", config, "sys", "user")

    assert call_count == 1  # no retries


def test_token_exhaustion_all_attempts_exhausted(clean_env, monkeypatch):
    """All retries exhausted with finish_reason=length raises retryable error."""
    from zero_forge.agents.llm import LLMResponseError

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    captured = []

    def fake_completion(**kwargs):
        captured.append(dict(kwargs))
        return _FakeResponse(content="", finish_reason="length", reasoning_tokens=4096)

    with mock.patch("litellm.completion", side_effect=fake_completion):
        with pytest.raises(LLMResponseError, match="Token budget exhausted") as exc_info:
            call_model("smart", config, "sys", "user")

    assert len(captured) == 3  # default max_attempts=3
    assert exc_info.value.retryable is True
    assert exc_info.value.attempt == 3


def test_token_exhaustion_max_tokens_capped_at_ceiling(clean_env, monkeypatch):
    """Doubled max_tokens is capped at _MAX_TOKENS_HARD_CEILING."""
    from zero_forge.agents.llm import _MAX_TOKENS_HARD_CEILING

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=65536, auto_max_tokens=False)

    captured = []

    def fake_completion(**kwargs):
        captured.append(dict(kwargs))
        if len(captured) == 1:
            return _FakeResponse(content="", finish_reason="length", reasoning_tokens=65536)
        return _FakeResponse("hello")

    with mock.patch("litellm.completion", side_effect=fake_completion):
        result = call_model("smart", config, "sys", "user")

    assert result == "hello"
    assert captured[0]["max_tokens"] == 65536
    assert captured[1]["max_tokens"] == _MAX_TOKENS_HARD_CEILING  # capped, not 131072


def test_call_model_default_max_attempts_is_three(clean_env, monkeypatch):
    """Default max_attempts is now 3 (enabling token-exhaustion retries)."""
    import inspect

    from zero_forge.agents.llm import call_model as _cm

    sig = inspect.signature(_cm)
    assert sig.parameters["max_attempts"].default == 3



# --- Async tests (issue #83) ---------------------------------------------

import asyncio  # noqa: E402


def test_call_model_async_returns_content(clean_env, monkeypatch):
    """call_model_async returns content from litellm.acompletion."""
    from zero_forge.agents.llm import call_model_async

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    async def fake_acompletion(**kwargs):
        return _FakeResponse("hello async world")

    with mock.patch("litellm.acompletion", side_effect=fake_acompletion):
        result = asyncio.run(call_model_async("smart", config, "sys", "user"))

    assert result == "hello async world"


def test_call_model_async_streaming_with_on_chunk(clean_env, monkeypatch):
    """call_model_async with on_chunk streams chunks."""
    from zero_forge.agents.llm import call_model_async

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    chunks_received = []

    class _FakeChunk:
        def __init__(self, content):
            self.choices = [type("C", (), {
                "delta": type("D", (), {"content": content})(),
            })()]

    async def fake_acompletion(**kwargs):
        assert kwargs.get("stream") is True
        async def _gen():
            for c in ("Hello", " ", "World"):
                yield _FakeChunk(c)
        return _gen()

    with mock.patch("litellm.acompletion", side_effect=fake_acompletion):
        result = asyncio.run(call_model_async(
            "smart", config, "sys", "user",
            on_chunk=chunks_received.append,
        ))

    assert result == "Hello World"
    assert chunks_received == ["Hello", " ", "World"]


def test_call_model_async_raises_on_no_api_key(clean_env, monkeypatch):
    """call_model_async raises LLMConfigurationError without API key."""
    from zero_forge.agents.llm import LLMConfigurationError, call_model_async

    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    with pytest.raises(LLMConfigurationError, match="No API key"):
        asyncio.run(call_model_async("smart", config, "sys", "user"))


def test_call_model_async_raises_on_provider_error(clean_env, monkeypatch):
    """call_model_async raises LLMProviderError on request failure."""
    from zero_forge.agents.llm import LLMProviderError, call_model_async

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    async def fake_acompletion(**kwargs):
        raise Exception("connection timeout")

    with mock.patch("litellm.acompletion", side_effect=fake_acompletion):
        with pytest.raises(LLMProviderError, match="LLM async request failed"):
            asyncio.run(call_model_async("smart", config, "sys", "user"))


def test_stream_model_yields_chunks(clean_env, monkeypatch):
    """stream_model async generator yields text chunks."""
    from zero_forge.agents.llm import stream_model

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    class _FakeChunk:
        def __init__(self, content):
            self.choices = [type("C", (), {
                "delta": type("D", (), {"content": content})(),
            })()]

    async def fake_acompletion(**kwargs):
        assert kwargs.get("stream") is True
        async def _gen():
            for c in ("chunk1", "chunk2", "chunk3"):
                yield _FakeChunk(c)
        return _gen()

    with mock.patch("litellm.acompletion", side_effect=fake_acompletion):
        async def _collect():
            chunks = []
            async for c in stream_model("smart", config, "sys", "user"):
                chunks.append(c)
            return chunks
        result = asyncio.run(_collect())

    assert result == ["chunk1", "chunk2", "chunk3"]


# --- Additional async/streaming tests (PR #116 review) -------------------


def test_call_model_async_streaming_empty_content_raises(clean_env, monkeypatch):
    """Empty streamed content raises LLMResponseError, not silent success."""
    from zero_forge.agents.llm import LLMResponseError, call_model_async

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    class _FakeChunk:
        def __init__(self, content):
            self.choices = [type("C", (), {
                "delta": type("D", (), {"content": content})(),
            })()]

    async def fake_acompletion(**kwargs):
        async def _gen():
            yield _FakeChunk("")
        return _gen()

    chunks = []
    with mock.patch("litellm.acompletion", side_effect=fake_acompletion):
        with pytest.raises(LLMResponseError, match="empty content"):
            asyncio.run(call_model_async(
                "smart", config, "sys", "user",
                on_chunk=chunks.append,
            ))


def test_call_model_async_streaming_malformed_chunks_skipped(clean_env, monkeypatch):
    """Malformed or no-choice chunks are safely skipped during streaming."""
    from zero_forge.agents.llm import call_model_async

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    class _FakeChunk:
        def __init__(self, content):
            self.choices = [type("C", (), {
                "delta": type("D", (), {"content": content})(),
            })()]

    class _MalformedChunk:
        choices = []

    class _BadAttrChunk:
        choices = [object()]  # no .delta

    async def fake_acompletion(**kwargs):
        async def _gen():
            yield _MalformedChunk()
            yield _BadAttrChunk()
            yield _FakeChunk("good")
        return _gen()

    chunks = []
    with mock.patch("litellm.acompletion", side_effect=fake_acompletion):
        result = asyncio.run(call_model_async(
            "smart", config, "sys", "user",
            on_chunk=chunks.append,
        ))

    assert result == "good"
    assert chunks == ["good"]


def test_call_model_async_additional_messages_ordering(clean_env, monkeypatch):
    """additional_messages are appended after system/user in async calls."""
    from zero_forge.agents.llm import call_model_async

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    captured = {}

    async def fake_acompletion(**kwargs):
        captured.update(kwargs)
        return _FakeResponse("ok")

    extra = [{"role": "assistant", "content": "prior"}, {"role": "user", "content": "more"}]
    with mock.patch("litellm.acompletion", side_effect=fake_acompletion):
        asyncio.run(call_model_async(
            "smart", config, "sys", "user",
            additional_messages=extra,
        ))

    msgs = captured["messages"]
    assert msgs[0]["role"] == "system"
    assert msgs[1]["role"] == "user"
    assert msgs[2] == {"role": "assistant", "content": "prior"}
    assert msgs[3] == {"role": "user", "content": "more"}


def test_call_model_async_streaming_additional_messages_ordering(clean_env, monkeypatch):
    """additional_messages ordering preserved in streaming path."""
    from zero_forge.agents.llm import call_model_async

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    captured = {}

    class _FakeChunk:
        def __init__(self, content):
            self.choices = [type("C", (), {
                "delta": type("D", (), {"content": content})(),
            })()]

    async def fake_acompletion(**kwargs):
        captured.update(kwargs)
        async def _gen():
            yield _FakeChunk("hi")
        return _gen()

    extra = [{"role": "assistant", "content": "ctx"}]
    with mock.patch("litellm.acompletion", side_effect=fake_acompletion):
        result = asyncio.run(call_model_async(
            "smart", config, "sys", "user",
            additional_messages=extra,
            on_chunk=lambda _: None,
        ))

    assert result == "hi"
    msgs = captured["messages"]
    assert msgs[0]["role"] == "system"
    assert msgs[1]["role"] == "user"
    assert msgs[2] == {"role": "assistant", "content": "ctx"}


def test_call_model_async_auto_infers_max_tokens(clean_env, monkeypatch):
    """call_model_async uses inferred max_tokens when auto_max_tokens=True."""
    from zero_forge.agents.llm import call_model_async

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096)

    captured = {}

    async def fake_acompletion(**kwargs):
        captured.update(kwargs)
        return _FakeResponse("hello")

    async def fake_resolve_limits(model, provider, api_key):
        return 131072

    with mock.patch("zero_forge.agents.llm.resolve_model_limits_async", side_effect=fake_resolve_limits):
        with mock.patch("litellm.acompletion", side_effect=fake_acompletion):
            result = asyncio.run(call_model_async("smart", config, "sys", "user"))

    assert result == "hello"
    assert captured["max_tokens"] == 8192  # min(131072, cap=8192)


def test_call_model_async_streaming_provider_failure_before_iterator(clean_env, monkeypatch):
    """Provider failure before the iterator is returned raises LLMProviderError."""
    from zero_forge.agents.llm import LLMProviderError, call_model_async

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    async def fake_acompletion(**kwargs):
        raise Exception("service unavailable")

    with mock.patch("litellm.acompletion", side_effect=fake_acompletion):
        with pytest.raises(LLMProviderError, match="streaming request failed"):
            asyncio.run(call_model_async(
                "smart", config, "sys", "user",
                on_chunk=lambda _: None,
            ))


def test_call_model_async_streaming_provider_failure_during_iteration(clean_env, monkeypatch):
    """Provider failure during chunk iteration raises LLMProviderError."""
    from zero_forge.agents.llm import LLMProviderError, call_model_async

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    class _FakeChunk:
        def __init__(self, content):
            self.choices = [type("C", (), {
                "delta": type("D", (), {"content": content})(),
            })()]

    async def fake_acompletion(**kwargs):
        async def _gen():
            yield _FakeChunk("partial")
            raise Exception("connection dropped")
        return _gen()

    chunks = []
    with mock.patch("litellm.acompletion", side_effect=fake_acompletion):
        with pytest.raises(LLMProviderError, match="streaming failed"):
            asyncio.run(call_model_async(
                "smart", config, "sys", "user",
                on_chunk=chunks.append,
            ))

    assert chunks == ["partial"]


def test_call_model_async_provider_error_includes_attempt_context(clean_env, monkeypatch):
    """LLMProviderError from async path includes attempt and max_attempts."""
    from zero_forge.agents.llm import LLMProviderError, call_model_async

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    async def fake_acompletion(**kwargs):
        raise Exception("timeout")

    with mock.patch("litellm.acompletion", side_effect=fake_acompletion):
        with pytest.raises(LLMProviderError) as exc_info:
            asyncio.run(call_model_async(
                "smart", config, "sys", "user",
                attempt=2, max_attempts=5,
            ))

    assert exc_info.value.attempt == 2
    assert exc_info.value.max_attempts == 5


def test_call_model_async_callback_error_propagates_unchanged(clean_env, monkeypatch):
    """Consumer callback errors propagate as-is, not wrapped as LLMProviderError."""
    from zero_forge.agents.llm import call_model_async

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    class _FakeChunk:
        def __init__(self, content):
            self.choices = [type("C", (), {
                "delta": type("D", (), {"content": content})(),
            })()]

    async def fake_acompletion(**kwargs):
        async def _gen():
            yield _FakeChunk("data")
        return _gen()

    def bad_callback(_delta: str) -> None:
        raise ValueError("consumer UI failure")

    with mock.patch("litellm.acompletion", side_effect=fake_acompletion):
        with pytest.raises(ValueError, match="consumer UI failure"):
            asyncio.run(call_model_async(
                "smart", config, "sys", "user",
                on_chunk=bad_callback,
            ))


def test_stream_model_provider_failure_includes_attempt_context(clean_env, monkeypatch):
    """stream_model LLMProviderError includes attempt and max_attempts."""
    from zero_forge.agents.llm import LLMProviderError, stream_model

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    async def fake_acompletion(**kwargs):
        raise Exception("timeout")

    with mock.patch("litellm.acompletion", side_effect=fake_acompletion):
        async def _collect():
            async for _ in stream_model(
                "smart", config, "sys", "user",
                attempt=2, max_attempts=4,
            ):
                pass
        with pytest.raises(LLMProviderError) as exc_info:
            asyncio.run(_collect())

    assert exc_info.value.attempt == 2
    assert exc_info.value.max_attempts == 4


def test_stream_model_additional_messages(clean_env, monkeypatch):
    """stream_model accepts and orders additional_messages."""
    from zero_forge.agents.llm import stream_model

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    config = ModelConfig(provider="openrouter", model="z-ai/glm-5.2", max_tokens=4096, auto_max_tokens=False)

    captured = {}

    class _FakeChunk:
        def __init__(self, content):
            self.choices = [type("C", (), {
                "delta": type("D", (), {"content": content})(),
            })()]

    async def fake_acompletion(**kwargs):
        captured.update(kwargs)
        async def _gen():
            yield _FakeChunk("ok")
        return _gen()

    extra = [{"role": "assistant", "content": "ctx"}]
    with mock.patch("litellm.acompletion", side_effect=fake_acompletion):
        async def _collect():
            chunks = []
            async for c in stream_model(
                "smart", config, "sys", "user",
                additional_messages=extra,
            ):
                chunks.append(c)
            return chunks
        result = asyncio.run(_collect())

    assert result == ["ok"]
    msgs = captured["messages"]
    assert msgs[2] == {"role": "assistant", "content": "ctx"}
