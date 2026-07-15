"""Role-aware LiteLLM calls shared by ZeroForge agents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..config import ModelConfig, Settings, get_settings
from ..schemas import WorkflowError


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


def call_model(
    role: str,
    config: ModelConfig,
    system_prompt: str,
    user_prompt: str,
    *,
    additional_messages: list[dict[str, str]] | None = None,
    attempt: int = 1,
    max_attempts: int = 1,
) -> str:
    """Call exactly the configured role model and return non-empty text."""
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

    try:
        import litellm

        response = litellm.completion(
            model=resolved.model,
            api_key=resolved.api_key,
            messages=messages,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            **resolved.extra_kwargs,
        )
    except Exception as exc:
        raise LLMProviderError(
            f"LLM request failed with {type(exc).__name__}",
            role=role,
            provider=resolved.provider,
            model=resolved.model,
            retryable=_is_retryable_provider_error(exc),
            attempt=attempt,
            max_attempts=max_attempts,
        ) from exc

    try:
        content = response.choices[0].message.content
    except (AttributeError, IndexError, KeyError, TypeError) as exc:
        raise LLMResponseError(
            "LLM response did not contain a message",
            role=role,
            provider=resolved.provider,
            model=resolved.model,
            retryable=False,
            attempt=attempt,
            max_attempts=max_attempts,
        ) from exc

    if not isinstance(content, str) or not content.strip():
        raise LLMResponseError(
            "LLM response contained empty message content",
            role=role,
            provider=resolved.provider,
            model=resolved.model,
            retryable=False,
            attempt=attempt,
            max_attempts=max_attempts,
        )
    return content
