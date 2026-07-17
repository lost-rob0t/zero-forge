"""Role-aware LiteLLM calls shared by ZeroForge agents."""

from __future__ import annotations

import json
import os
import urllib.request
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

from ..config import ModelConfig, Settings, get_settings
from ..logging_config import get_logger
from ..schemas import WorkflowError

logger = get_logger(__name__)

_MODEL_LIMITS_CACHE: dict[str, int | None] = {}

_OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"

_MAX_TOKENS_HARD_CEILING = 131_072


def reset_model_limits_cache() -> None:
    """Clear the session-level model limits cache (for tests)."""
    _MODEL_LIMITS_CACHE.clear()


def _resolve_openrouter_limit(model_id: str) -> int | None:
    """Query the public OpenRouter models endpoint for max_completion_tokens."""
    bare = model_id.removeprefix("openrouter/")
    try:
        with urllib.request.urlopen(_OPENROUTER_MODELS_URL, timeout=10) as resp:  # noqa: S310
            data = json.loads(resp.read())
    except Exception as exc:
        logger.debug("OpenRouter models lookup failed for %s: %s", bare, exc)
        return None
    for entry in data.get("data", []):
        if entry.get("id") == bare:
            top = entry.get("top_provider") or {}
            val = top.get("max_completion_tokens")
            if isinstance(val, int) and val > 0:
                return val
    return None


def _resolve_litellm_limit(model: str) -> int | None:
    """Use litellm.model_cost for OpenAI/Anthropic models."""
    try:
        import litellm

        cost = litellm.model_cost  # type: ignore[attr-defined]
    except Exception as exc:
        logger.debug("litellm model_cost lookup failed for %s: %s", model, exc)
        return None
    for key in (model, model.split("/", 1)[-1]):
        entry = cost.get(key, {})
        val = entry.get("max_tokens") or entry.get("max_output_tokens")
        if isinstance(val, int) and val > 0:
            return val
    return None


def resolve_model_limits(model: str, provider: str, api_key: str | None) -> int | None:
    """Query provider API for model max_completion_tokens. Cached per model.

    Returns None if the lookup fails so callers fall back to config defaults.
    """
    cache_key = f"{provider}:{model}"
    if cache_key in _MODEL_LIMITS_CACHE:
        return _MODEL_LIMITS_CACHE[cache_key]

    result: int | None = None
    if provider == "openrouter":
        result = _resolve_openrouter_limit(model)
    elif provider in ("openai", "anthropic"):
        result = _resolve_litellm_limit(model)

    _MODEL_LIMITS_CACHE[cache_key] = result
    return result





@dataclass(frozen=True)
class ResolvedModel:
    role: str
    provider: str
    api_key: str | None
    model: str
    extra_kwargs: dict[str, str]


class LLMCallError(RuntimeError):
    """Base error for a failed role-specific LLM call."""

    code = "llm_call_error"

    def __init__(
        self,
        message: str,
        *,
        provider: str,
        model: str,
        retryable: bool,
        role: str = "smart",
        attempt: int = 1,
        max_attempts: int = 1,
    ) -> None:
        self.role = role
        self.provider = provider
        self.model = model
        self.retryable = retryable
        self.attempt = attempt
        self.max_attempts = max_attempts
        detail = (
            f"{message} (role={role}, provider={provider}, model={model}, "
            f"attempt={attempt}/{max_attempts}, retryable={str(retryable).lower()})"
        )
        super().__init__(detail)

    def as_workflow_error(self) -> WorkflowError:
        return WorkflowError(
            code=self.code,
            message=str(self),
            role=self.role,
            provider=self.provider,
            model=self.model,
            retryable=self.retryable,
            attempt=self.attempt,
            max_attempts=self.max_attempts,
        )


class LLMConfigurationError(LLMCallError):
    code = "llm_configuration_error"


class LLMProviderError(LLMCallError):
    code = "llm_provider_error"


class LLMResponseError(LLMCallError):
    code = "llm_response_error"


def _provider_key(settings: Settings, provider: str) -> str:
    return {
        "openrouter": settings.openrouter_api_key,
        "openai": settings.openai_api_key,
        "anthropic": settings.anthropic_api_key,
    }[provider]


def _choose_provider(settings: Settings, config: ModelConfig) -> str:
    if config.provider != "auto":
        return config.provider
    for provider in ("openrouter", "openai", "anthropic"):
        if _provider_key(settings, provider):
            return provider
    return "none"


def resolve_model(role: str, config: ModelConfig) -> ResolvedModel:
    """Resolve credentials and LiteLLM routing for one model role."""
    settings = get_settings()
    provider = _choose_provider(settings, config)
    model = config.model

    if provider == "openrouter" and not model.startswith("openrouter/"):
        model = f"openrouter/{model}"
    if provider == "anthropic" and not model.startswith("anthropic/"):
        model = f"anthropic/{model}"

    extra_kwargs: dict[str, str] = {}
    if config.base_url:
        extra_kwargs["api_base"] = config.base_url

    api_key = None if provider == "none" else _provider_key(settings, provider)
    return ResolvedModel(
        role=role,
        provider=provider,
        api_key=api_key or None,
        model=model,
        extra_kwargs=extra_kwargs,
    )


def _is_retryable_provider_error(exc: Exception) -> bool:
    name = type(exc).__name__.lower()
    return any(
        marker in name
        for marker in ("timeout", "ratelimit", "connection", "serviceunavailable")
    )


def _safe_finish_reason(response: Any) -> str | None:
    """Safely extract finish_reason from a LiteLLM response."""
    try:
        val = response.choices[0].finish_reason
        return str(val) if val is not None else None
    except (AttributeError, IndexError, TypeError):
        return None


def _safe_reasoning_tokens(response: Any) -> int | None:
    """Extract reasoning token count from a LiteLLM response, if available."""
    try:
        details = response.usage.completion_tokens_details  # type: ignore[attr-defined]
        val = details.reasoning_tokens  # type: ignore[attr-defined]
        return int(val) if val is not None else None
    except (AttributeError, TypeError):
        return None


def call_model(
    role: str,
    config: ModelConfig,
    system_prompt: str,
    user_prompt: str,
    *,
    additional_messages: list[dict[str, str]] | None = None,
    attempt: int = 1,
    max_attempts: int = 3,
) -> str:
    """Call exactly the configured role model and return non-empty text.

    When a reasoning model exhausts its token budget on internal reasoning
    (``finish_reason == "length"`` with empty content), the call is retried
    with a doubled ``max_tokens`` up to ``max_attempts`` times.
    """
    resolved = resolve_model(role, config)
    if not resolved.api_key:
        raise LLMConfigurationError(
            "No API key configured for the selected model provider",
            role=role,
            provider=resolved.provider,
            model=resolved.model,
            retryable=False,
            attempt=attempt,
            max_attempts=max_attempts,
        )

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    if additional_messages:
        messages.extend(additional_messages)

    # Determine effective max_tokens: auto-infer from provider API when enabled
    # and the user has not explicitly set the role-specific max_tokens env var.
    max_tokens = config.max_tokens
    if config.auto_max_tokens:
        env_var = f"ZERO_FORGE_{role.upper()}_MAX_TOKENS"
        if not os.environ.get(env_var):
            inferred = resolve_model_limits(
                resolved.model, resolved.provider, resolved.api_key,
            )
            if inferred is not None:
                max_tokens = min(inferred, config.inferred_max_token_cap)
                logger.debug(
                    "Auto-inferred max_tokens=%d for role=%s model=%s "
                    "(inferred=%d, cap=%d)",
                    max_tokens, role, resolved.model,
                    inferred, config.inferred_max_token_cap,
                )

    import litellm

    current_max_tokens = max_tokens
    for current_attempt in range(attempt, attempt + max_attempts):
        logger.trace(  # type: ignore[attr-defined]
            "LLM request role=%s provider=%s model=%s attempt=%d/%d "
            "max_tokens=%d system_prompt=%r user_prompt=%.500r",
            role, resolved.provider, resolved.model, current_attempt,
            max_attempts, current_max_tokens, system_prompt, user_prompt,
        )

        try:
            response = litellm.completion(
                model=resolved.model,
                api_key=resolved.api_key,
                messages=messages,
                temperature=config.temperature,
                max_tokens=current_max_tokens,
                **resolved.extra_kwargs,
            )
        except Exception as exc:
            logger.error(
                "LLM request failed role=%s provider=%s model=%s "
                "error_type=%s retryable=%s",
                role, resolved.provider, resolved.model,
                type(exc).__name__, _is_retryable_provider_error(exc),
            )
            raise LLMProviderError(
                f"LLM request failed with {type(exc).__name__}",
                role=role,
                provider=resolved.provider,
                model=resolved.model,
                retryable=_is_retryable_provider_error(exc),
                attempt=current_attempt,
                max_attempts=max_attempts,
            ) from exc

        try:
            content = response.choices[0].message.content
        except (AttributeError, IndexError, KeyError, TypeError) as exc:
            logger.error(
                "LLM response missing message role=%s provider=%s model=%s",
                role, resolved.provider, resolved.model,
            )
            raise LLMResponseError(
                "LLM response did not contain a message",
                role=role,
                provider=resolved.provider,
                model=resolved.model,
                retryable=False,
                attempt=current_attempt,
                max_attempts=max_attempts,
            ) from exc

        if isinstance(content, str) and content.strip():
            logger.trace(  # type: ignore[attr-defined]
                "LLM response role=%s provider=%s model=%s content=%.1000r",
                role, resolved.provider, resolved.model, content,
            )
            return content

        # Empty content - inspect finish_reason to decide retryability.
        finish_reason = _safe_finish_reason(response)
        reasoning_tokens = _safe_reasoning_tokens(response)
        if finish_reason == "length":
            if current_attempt < attempt + max_attempts - 1:
                new_max = min(current_max_tokens * 2, _MAX_TOKENS_HARD_CEILING)
                logger.warning(
                    "LLM token exhaustion (finish_reason=length) "
                    "role=%s provider=%s model=%s attempt=%d/%d "
                    "max_tokens=%d reasoning_tokens=%s; retrying with %d",
                    role, resolved.provider, resolved.model, current_attempt,
                    max_attempts, current_max_tokens,
                    reasoning_tokens, new_max,
                )
                current_max_tokens = new_max
                continue
            logger.error(
                "LLM token exhaustion (finish_reason=length) after all "
                "attempts role=%s provider=%s model=%s "
                "max_tokens=%d reasoning_tokens=%s",
                role, resolved.provider, resolved.model,
                current_max_tokens, reasoning_tokens,
            )
            raise LLMResponseError(
                "Token budget exhausted on reasoning "
                f"(finish_reason=length, reasoning_tokens={reasoning_tokens})",
                role=role,
                provider=resolved.provider,
                model=resolved.model,
                retryable=True,
                attempt=current_attempt,
                max_attempts=max_attempts,
            )

        logger.error(
            "LLM response empty role=%s provider=%s model=%s "
            "finish_reason=%s",
            role, resolved.provider, resolved.model, finish_reason,
        )
        raise LLMResponseError(
            "LLM response contained empty message content",
            role=role,
            provider=resolved.provider,
            model=resolved.model,
            retryable=False,
            attempt=current_attempt,
            max_attempts=max_attempts,
        )

    # Defensive: loop exited without returning or raising.
    raise LLMResponseError(
        "LLM call loop exited without producing a result",
        role=role,
        provider=resolved.provider,
        model=resolved.model,
        retryable=False,
        attempt=attempt + max_attempts - 1,
        max_attempts=max_attempts,
    )


# --- Async variants (issue #83) -----------------------------------------


async def _resolve_openrouter_limit_async(model_id: str) -> int | None:
    """Query the OpenRouter models endpoint asynchronously using httpx."""
    bare = model_id.removeprefix("openrouter/")
    try:
        import httpx

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(_OPENROUTER_MODELS_URL)
            data = resp.json()
    except Exception as exc:
        logger.debug("OpenRouter async models lookup failed for %s: %s", bare, exc)
        return None
    for entry in data.get("data", []):
        if entry.get("id") == bare:
            top = entry.get("top_provider") or {}
            val = top.get("max_completion_tokens")
            if isinstance(val, int) and val > 0:
                return val
    return None


async def resolve_model_limits_async(
    model: str, provider: str, api_key: str | None
) -> int | None:
    """Async variant of resolve_model_limits using httpx."""
    cache_key = f"{provider}:{model}"
    if cache_key in _MODEL_LIMITS_CACHE:
        return _MODEL_LIMITS_CACHE[cache_key]

    result: int | None = None
    if provider == "openrouter":
        result = await _resolve_openrouter_limit_async(model)
    elif provider in ("openai", "anthropic"):
        result = _resolve_litellm_limit(model)

    _MODEL_LIMITS_CACHE[cache_key] = result
    return result


async def call_model_async(
    role: str,
    config: ModelConfig,
    system_prompt: str,
    user_prompt: str,
    *,
    additional_messages: list[dict[str, str]] | None = None,
    attempt: int = 1,
    max_attempts: int = 3,
    on_chunk: Callable[[str], None] | None = None,
) -> str:
    """Async variant of call_model using litellm.acompletion.

    When ``on_chunk`` is provided, enables streaming (``stream=True``)
    and invokes the callback for each text chunk as it arrives.

    Streaming does not retry on token exhaustion.  Once partial chunks have
    been delivered to the caller via ``on_chunk``, replaying the request
    would duplicate already-seen output.  The non-streaming path retains
    the full token-exhaustion retry loop.  If a streaming response yields
    empty content, an ``LLMResponseError`` is raised so the caller can
    decide whether to fall back to a non-streaming retry.
    """
    resolved = resolve_model(role, config)
    if not resolved.api_key:
        raise LLMConfigurationError(
            "No API key configured for the selected model provider",
            role=role,
            provider=resolved.provider,
            model=resolved.model,
            retryable=False,
            attempt=attempt,
            max_attempts=max_attempts,
        )

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    if additional_messages:
        messages.extend(additional_messages)

    max_tokens = config.max_tokens
    if config.auto_max_tokens:
        env_var = f"ZERO_FORGE_{role.upper()}_MAX_TOKENS"
        if not os.environ.get(env_var):
            inferred = await resolve_model_limits_async(
                resolved.model, resolved.provider, resolved.api_key,
            )
            if inferred is not None:
                max_tokens = min(inferred, config.inferred_max_token_cap)
                logger.debug(
                    "Auto-inferred max_tokens=%d for role=%s model=%s "
                    "(inferred=%d, cap=%d)",
                    max_tokens, role, resolved.model,
                    inferred, config.inferred_max_token_cap,
                )

    import litellm

    # --- Streaming path ---
    # Streaming does not retry on token exhaustion. Once partial chunks have
    # been delivered to the caller via on_chunk, replaying the request would
    # duplicate already-seen output. The non-streaming path retains the full
    # token-exhaustion retry loop.
    if on_chunk is not None:
        try:
            response = await litellm.acompletion(
                model=resolved.model,
                api_key=resolved.api_key,
                messages=messages,
                temperature=config.temperature,
                max_tokens=max_tokens,
                stream=True,
                **resolved.extra_kwargs,
            )
        except Exception as exc:
            raise LLMProviderError(
                f"LLM async streaming request failed with {type(exc).__name__}",
                role=role,
                provider=resolved.provider,
                model=resolved.model,
                retryable=_is_retryable_provider_error(exc),
                attempt=attempt,
                max_attempts=max_attempts,
            ) from exc

        collected: list[str] = []
        _callback_phase = False
        try:
            async for chunk in response:
                try:
                    delta = chunk.choices[0].delta.content
                except (AttributeError, IndexError, TypeError):
                    continue
                if isinstance(delta, str) and delta:
                    collected.append(delta)
                    # Callback errors are consumer/UI failures, not provider
                    # failures.  Use a phase flag so the except handler below
                    # can distinguish provider-iteration errors from callback
                    # errors and let the latter propagate unchanged.
                    _callback_phase = True
                    on_chunk(delta)
                    _callback_phase = False
        except Exception as exc:
            if _callback_phase:
                raise
            raise LLMProviderError(
                f"LLM async streaming failed with {type(exc).__name__}",
                role=role,
                provider=resolved.provider,
                model=resolved.model,
                retryable=_is_retryable_provider_error(exc),
                attempt=attempt,
                max_attempts=max_attempts,
            ) from exc

        content = "".join(collected)
        if content.strip():
            return content
        raise LLMResponseError(
            "LLM async streaming produced empty content",
            role=role,
            provider=resolved.provider,
            model=resolved.model,
            retryable=False,
            attempt=attempt,
            max_attempts=max_attempts,
        )

    # --- Non-streaming async path ---
    current_max_tokens = max_tokens
    for current_attempt in range(attempt, attempt + max_attempts):
        try:
            response = await litellm.acompletion(
                model=resolved.model,
                api_key=resolved.api_key,
                messages=messages,
                temperature=config.temperature,
                max_tokens=current_max_tokens,
                **resolved.extra_kwargs,
            )
        except Exception as exc:
            raise LLMProviderError(
                f"LLM async request failed with {type(exc).__name__}",
                role=role,
                provider=resolved.provider,
                model=resolved.model,
                retryable=_is_retryable_provider_error(exc),
                attempt=current_attempt,
                max_attempts=max_attempts,
            ) from exc

        try:
            content = response.choices[0].message.content
        except (AttributeError, IndexError, KeyError, TypeError) as exc:
            raise LLMResponseError(
                "LLM async response did not contain a message",
                role=role,
                provider=resolved.provider,
                model=resolved.model,
                retryable=False,
                attempt=current_attempt,
                max_attempts=max_attempts,
            ) from exc

        if isinstance(content, str) and content.strip():
            return content

        finish_reason = _safe_finish_reason(response)
        reasoning_tokens = _safe_reasoning_tokens(response)
        if finish_reason == "length":
            if current_attempt < attempt + max_attempts - 1:
                new_max = min(current_max_tokens * 2, _MAX_TOKENS_HARD_CEILING)
                current_max_tokens = new_max
                continue
            raise LLMResponseError(
                "Token budget exhausted on reasoning "
                f"(finish_reason=length, reasoning_tokens={reasoning_tokens})",
                role=role,
                provider=resolved.provider,
                model=resolved.model,
                retryable=True,
                attempt=current_attempt,
                max_attempts=max_attempts,
            )

        raise LLMResponseError(
            "LLM async response contained empty message content",
            role=role,
            provider=resolved.provider,
            model=resolved.model,
            retryable=False,
            attempt=current_attempt,
            max_attempts=max_attempts,
        )

    raise LLMResponseError(
        "LLM async call loop exited without producing a result",
        role=role,
        provider=resolved.provider,
        model=resolved.model,
        retryable=False,
        attempt=attempt + max_attempts - 1,
        max_attempts=max_attempts,
    )


async def stream_model(
    role: str,
    config: ModelConfig,
    system_prompt: str,
    user_prompt: str,
    *,
    additional_messages: list[dict[str, str]] | None = None,
    attempt: int = 1,
    max_attempts: int = 1,
) -> AsyncIterator[str]:
    """Async generator yielding text chunks from litellm.acompletion(stream=True).

    Raises the same ``LLMCallError`` hierarchy on failure, including
    ``attempt`` and ``max_attempts`` context.

    Streaming does not retry on token exhaustion.  Once partial chunks have
    been yielded to the caller, replaying the request would duplicate
    already-seen output.  Callers that need token-exhaustion retry semantics
    should use :func:`call_model_async` without ``on_chunk``.
    """
    resolved = resolve_model(role, config)
    if not resolved.api_key:
        raise LLMConfigurationError(
            "No API key configured for the selected model provider",
            role=role,
            provider=resolved.provider,
            model=resolved.model,
            retryable=False,
            attempt=attempt,
            max_attempts=max_attempts,
        )

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    if additional_messages:
        messages.extend(additional_messages)

    max_tokens = config.max_tokens
    if config.auto_max_tokens:
        env_var = f"ZERO_FORGE_{role.upper()}_MAX_TOKENS"
        if not os.environ.get(env_var):
            inferred = await resolve_model_limits_async(
                resolved.model, resolved.provider, resolved.api_key,
            )
            if inferred is not None:
                max_tokens = min(inferred, config.inferred_max_token_cap)

    import litellm

    try:
        response = await litellm.acompletion(
            model=resolved.model,
            api_key=resolved.api_key,
            messages=messages,
            temperature=config.temperature,
            max_tokens=max_tokens,
            stream=True,
            **resolved.extra_kwargs,
        )
    except Exception as exc:
        raise LLMProviderError(
            f"LLM stream request failed with {type(exc).__name__}",
            role=role,
            provider=resolved.provider,
            model=resolved.model,
            retryable=_is_retryable_provider_error(exc),
            attempt=attempt,
            max_attempts=max_attempts,
        ) from exc

    try:
        async for chunk in response:
            try:
                delta = chunk.choices[0].delta.content
            except (AttributeError, IndexError, TypeError):
                continue
            if isinstance(delta, str) and delta:
                yield delta
    except Exception as exc:
        raise LLMProviderError(
            f"LLM streaming failed with {type(exc).__name__}",
            role=role,
            provider=resolved.provider,
            model=resolved.model,
            retryable=_is_retryable_provider_error(exc),
            attempt=attempt,
            max_attempts=max_attempts,
        ) from exc
