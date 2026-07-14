"""Centralized configuration for ZeroForge.

Loads settings from (in priority order):
1. Programmatic overrides (set on the singleton)
2. Environment variables (prefix: ZERO_FORGE_)
3. YAML config file (default: ./zeroforge.yaml)
4. Built-in defaults

API keys are read exclusively from environment variables and are never
loaded from YAML files for security reasons.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


# --- Sub-models -----------------------------------------------------------

class LLMConfig(BaseModel):
    """LLM provider and generation settings."""

    model: str = Field(default="gpt-4o-mini", description="LiteLLM model identifier")
    temperature: float = Field(default=0.3, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, ge=1)
    openrouter_base_url: str = Field(default="", description="Custom OpenRouter-compatible base URL")


class WorkflowConfig(BaseModel):
    """Workflow execution settings."""

    max_repair_attempts: int = Field(default=3, ge=0, le=20)


class OutputConfig(BaseModel):
    """Artifact output settings."""

    dir: str = Field(default="./output", description="Directory for saved artifacts")


# --- Root settings --------------------------------------------------------

class Settings(BaseModel):
    """Root ZeroForge configuration."""

    llm: LLMConfig = Field(default_factory=LLMConfig)
    workflow: WorkflowConfig = Field(default_factory=WorkflowConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)

    # API keys — environment-only, never loaded from YAML
    openrouter_api_key: str = Field(default="", repr=False)
    openai_api_key: str = Field(default="", repr=False)
    anthropic_api_key: str = Field(default="", repr=False)

    model_config = {"arbitrary_types_allowed": True}


# --- Env-var mapping ------------------------------------------------------

_ENV_MAP: dict[str, tuple[str, str]] = {
    # (env var name, dotted settings path)
    "ZERO_FORGE_MODEL": ("llm.model",),
    "ZERO_FORGE_LLM_TEMPERATURE": ("llm.temperature",),
    "ZERO_FORGE_LLM_MAX_TOKENS": ("llm.max_tokens",),
    "ZERO_FORGE_OPENROUTER_BASE_URL": ("llm.openrouter_base_url",),
    "OPENROUTER_BASE_URL": ("llm.openrouter_base_url",),
    "ZERO_FORGE_OUTPUT_DIR": ("output.dir",),
    "ZERO_FORGE_MAX_REPAIR_ATTEMPTS": ("workflow.max_repair_attempts",),
    "OPENROUTER_API_KEY": ("openrouter_api_key",),
    "OPENAI_API_KEY": ("openai_api_key",),
    "ANTHROPIC_API_KEY": ("anthropic_api_key",),
}


def _coerce(value: str, current: Any) -> Any:
    """Coerce a string env value to the type of the current value."""
    if isinstance(current, bool):
        return value.lower() in ("1", "true", "yes", "on")
    if isinstance(current, int):
        return int(value)
    if isinstance(current, float):
        return float(value)
    return value


def _apply_env_overrides(settings: Settings) -> Settings:
    """Overlay environment variable overrides onto *settings*."""
    data = settings.model_dump()
    for env_name, (dotted,) in _ENV_MAP.items():
        raw = os.environ.get(env_name)
        if raw is None:
            continue
        # Navigate nested dict by dotted path
        parts = dotted.split(".")
        target = data
        for part in parts[:-1]:
            target = target[part]
        key = parts[-1]
        target[key] = _coerce(raw, target[key])
    return Settings(**data)


# --- Public API -----------------------------------------------------------

DEFAULT_CONFIG_PATHS: list[str] = [
    "./zeroforge.yaml",
    "./zeroforge.yml",
    "~/.config/zeroforge/config.yaml",
]


def load_config(path: str | Path | None = None) -> Settings:
    """Load settings from YAML file, env vars, and defaults.

    Args:
        path: Explicit config file path. If *None*, searches
            DEFAULT_CONFIG_PATHS for the first existing file.

    Returns:
        Fully-resolved Settings instance.
    """
    yaml_data: dict[str, Any] = {}

    # Explicit path takes priority; fall back to ZERO_FORGE_CONFIG_PATH env var
    if path is None:
        path = os.environ.get("ZERO_FORGE_CONFIG_PATH")

    if path is not None:
        p = Path(path).expanduser()
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {p}")
        yaml_data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    else:
        for candidate in DEFAULT_CONFIG_PATHS:
            p = Path(candidate).expanduser()
            if p.exists():
                yaml_data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
                break

    settings = Settings(**yaml_data)
    settings = _apply_env_overrides(settings)
    return settings


_settings_cache: Settings | None = None


def get_settings(reload: bool = False) -> Settings:
    """Return the cached singleton Settings instance.

    Pass reload=True to force a fresh load (e.g. after changing env vars).
    """
    global _settings_cache
    if _settings_cache is None or reload:
        _settings_cache = load_config()
    return _settings_cache


def reset_settings() -> None:
    """Clear the cached settings singleton (useful in tests)."""
    global _settings_cache
    _settings_cache = None
