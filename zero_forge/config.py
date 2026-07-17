"""Centralized configuration for ZeroForge.

Loads settings from YAML, then applies role-specific environment overrides.
Provider credentials are read exclusively from environment variables.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


class ModelConfig(BaseModel):
    """Configuration for one model role."""

    provider: Literal["auto", "openrouter", "openai", "anthropic"] = "auto"
    model: str = Field(default="gpt-4o", min_length=1)
    temperature: float = Field(default=0.3, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, ge=1)
    auto_max_tokens: bool = Field(
        default=True,
        description="Infer max_tokens from the provider API when unset",
    )
    inferred_max_token_cap: int = Field(
        default=8192,
        ge=1,
        description="Upper bound for provider-inferred max_tokens (cost control)",
    )
    base_url: str = ""

    model_config = ConfigDict(extra="forbid")


class SmartModelConfig(ModelConfig):
    """Smart Agent defaults."""


class ToolModelConfig(ModelConfig):
    """Tool Agent defaults."""

    model: str = Field(default="gpt-4o-mini", min_length=1)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_tokens: int = Field(default=1024, ge=1)


class ModelsConfig(BaseModel):
    """Independent Smart and Tool Agent model settings."""

    smart: SmartModelConfig = Field(default_factory=SmartModelConfig)
    tool: ToolModelConfig = Field(default_factory=ToolModelConfig)

    model_config = ConfigDict(extra="forbid")


class LLMConfig(BaseModel):
    """LLM runtime switches shared by both roles."""

    stub_mode: bool = Field(
        default=False,
        description="Explicitly generate a placeholder for local plumbing tests",
    )

    model_config = ConfigDict(extra="forbid")


class LoggingConfig(BaseModel):
    """Logging configuration for the ZeroForge hierarchy."""

    level: str = Field(
        default="INFO",
        description="Minimum log level for the root zero_forge logger",
    )
    model_io_level: str = Field(
        default="TRACE",
        description=(
            "Minimum log level for model I/O (prompts and responses). "
            "Set to TRACE to capture raw LLM input/output."
        ),
    )

    model_config = ConfigDict(extra="forbid")


class WorkflowConfig(BaseModel):
    """Workflow execution settings."""

    max_repair_attempts: int = Field(default=3, ge=0, le=20)
    unsafe_source_collection: bool = Field(
        default=False,
        description="Allow reading secret files and following symlinks during source collection",
    )

    model_config = ConfigDict(extra="forbid")


class OutputConfig(BaseModel):
    """Artifact output settings."""

    dir: str = Field(default="./output", description="Directory for saved artifacts")

    model_config = ConfigDict(extra="forbid")


class Settings(BaseModel):
    """Root ZeroForge configuration."""

    models: ModelsConfig = Field(default_factory=ModelsConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    workflow: WorkflowConfig = Field(default_factory=WorkflowConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)

    openrouter_api_key: str = Field(default="", repr=False)
    openai_api_key: str = Field(default="", repr=False)
    anthropic_api_key: str = Field(default="", repr=False)

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)


_ENV_MAP: dict[str, str] = {
    "ZERO_FORGE_SMART_PROVIDER": "models.smart.provider",
    "ZERO_FORGE_SMART_MODEL": "models.smart.model",
    "ZERO_FORGE_SMART_TEMPERATURE": "models.smart.temperature",
    "ZERO_FORGE_SMART_MAX_TOKENS": "models.smart.max_tokens",
    "ZERO_FORGE_SMART_AUTO_MAX_TOKENS": "models.smart.auto_max_tokens",
    "ZERO_FORGE_SMART_INFERRED_MAX_TOKEN_CAP": "models.smart.inferred_max_token_cap",
    "ZERO_FORGE_SMART_BASE_URL": "models.smart.base_url",
    "ZERO_FORGE_TOOL_PROVIDER": "models.tool.provider",
    "ZERO_FORGE_TOOL_MODEL": "models.tool.model",
    "ZERO_FORGE_TOOL_TEMPERATURE": "models.tool.temperature",
    "ZERO_FORGE_TOOL_MAX_TOKENS": "models.tool.max_tokens",
    "ZERO_FORGE_TOOL_AUTO_MAX_TOKENS": "models.tool.auto_max_tokens",
    "ZERO_FORGE_TOOL_INFERRED_MAX_TOKEN_CAP": "models.tool.inferred_max_token_cap",
    "ZERO_FORGE_TOOL_BASE_URL": "models.tool.base_url",
    "ZERO_FORGE_STUB_MODE": "llm.stub_mode",
    "ZERO_FORGE_LOG_LEVEL": "logging.level",
    "ZERO_FORGE_LOG_MODEL_IO_LEVEL": "logging.model_io_level",
    "ZERO_FORGE_OUTPUT_DIR": "output.dir",
    "ZERO_FORGE_MAX_REPAIR_ATTEMPTS": "workflow.max_repair_attempts",
    "ZERO_FORGE_UNSAFE_SOURCE": "workflow.unsafe_source_collection",
    "OPENROUTER_API_KEY": "openrouter_api_key",
    "OPENAI_API_KEY": "openai_api_key",
    "ANTHROPIC_API_KEY": "anthropic_api_key",
}

_LEGACY_ENV_VARS = {
    "ZERO_FORGE_MODEL",
    "ZERO_FORGE_LLM_TEMPERATURE",
    "ZERO_FORGE_LLM_MAX_TOKENS",
    "ZERO_FORGE_OPENROUTER_BASE_URL",
}

_LEGACY_LLM_KEYS = {"model", "temperature", "max_tokens", "openrouter_base_url"}


def _coerce(value: str, current: Any) -> Any:
    if isinstance(current, bool):
        return value.lower() in ("1", "true", "yes", "on")
    if isinstance(current, int):
        return int(value)
    if isinstance(current, float):
        return float(value)
    return value


def _reject_legacy_environment() -> None:
    configured = sorted(name for name in _LEGACY_ENV_VARS if name in os.environ)
    if not configured:
        return
    names = ", ".join(configured)
    raise ValueError(
        f"Legacy single-model environment variable(s) are not supported: {names}. "
        "Configure ZERO_FORGE_SMART_* and ZERO_FORGE_TOOL_* independently."
    )


def _reject_legacy_yaml(data: dict[str, Any]) -> None:
    llm = data.get("llm")
    if not isinstance(llm, dict):
        return
    configured = sorted(_LEGACY_LLM_KEYS.intersection(llm))
    if not configured:
        return
    names = ", ".join(f"llm.{name}" for name in configured)
    raise ValueError(
        f"Legacy single-model setting(s) are not supported: {names}. "
        "Move them to models.smart and configure models.tool independently."
    )


def _apply_env_overrides(settings: Settings) -> Settings:
    data = settings.model_dump()
    for env_name, dotted in _ENV_MAP.items():
        raw = os.environ.get(env_name)
        if raw is None:
            continue
        parts = dotted.split(".")
        target = data
        for part in parts[:-1]:
            target = target[part]
        key = parts[-1]
        target[key] = _coerce(raw, target[key])
    return Settings(**data)


def _user_config_paths() -> list[str]:
    """Return XDG-aware config file paths under the user config directory.

    Respects XDG_CONFIG_HOME when set to an absolute path; falls back to
    ~/.config when unset, empty, or relative (per the XDG Base Directory
    Specification, relative values are invalid and must be ignored).
    """
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME", "")
    candidate = Path(xdg_config_home).expanduser() if xdg_config_home else None
    if candidate is not None and candidate.is_absolute():
        config_dir = candidate
    else:
        config_dir = Path.home() / ".config"
    app_dir = config_dir / "zeroforge"
    return [
        str(app_dir / "config.yaml"),
        str(app_dir / "config.yml"),
    ]


DEFAULT_CONFIG_PATHS: list[str] = [
    "./zeroforge.yaml",
    "./zeroforge.yml",
    *_user_config_paths(),
]


DEFAULT_CONFIG_TEMPLATE = """\
# ZeroForge configuration
# Edit this file to customize model, logging, and workflow settings.
# API keys are environment-only.  A .env file in the working directory is
# loaded automatically before settings resolution; shell variables take
# precedence over .env values.  Use ZERO_FORGE_ENV_FILE for a custom path:
#   export ZERO_FORGE_ENV_FILE=/path/to/.env
#   export OPENROUTER_API_KEY="sk-..."
#   export OPENAI_API_KEY="sk-..."
#   export ANTHROPIC_API_KEY="sk-..."

models:
  smart:
    provider: "auto"            # auto, openrouter, openai, or anthropic
    model: "gpt-4o"             # reasoning and artifact-writing model
    temperature: 0.3
    max_tokens: 4096
    auto_max_tokens: true       # infer max_tokens from provider API
    inferred_max_token_cap: 8192 # upper bound for inferred max_tokens
    base_url: ""                # optional LiteLLM-compatible endpoint

  tool:
    provider: "auto"            # independently resolved provider
    model: "gpt-4o-mini"        # cheap/fast registered-tool caller
    temperature: 0.0
    max_tokens: 1024
    auto_max_tokens: true       # infer max_tokens from provider API
    inferred_max_token_cap: 8192 # upper bound for inferred max_tokens
    base_url: ""                # may differ from the Smart model endpoint

llm:
  stub_mode: false              # placeholder mode; never completes or saves

logging:
  level: "INFO"                 # TRACE, DEBUG, INFO, WARNING, ERROR, CRITICAL
  model_io_level: "TRACE"       # minimum level for model I/O (prompts/responses)

workflow:
  max_repair_attempts: 3
  unsafe_source_collection: false

output:
  dir: "./output"
"""


def ensure_default_config() -> Path | None:
    """Write a default config to the XDG path if no config exists.

    Returns the path to the newly written file, or None if a config
    already exists in any search location (including ZERO_FORGE_CONFIG_PATH).
    """
    # Respect ZERO_FORGE_CONFIG_PATH — if it points to an existing file,
    # the user already has a config and we should not write a new one.
    env_path = os.environ.get("ZERO_FORGE_CONFIG_PATH")
    if env_path and Path(env_path).expanduser().exists():
        return None

    search_paths = ["./zeroforge.yaml", "./zeroforge.yml", *_user_config_paths()]
    for candidate in search_paths:
        if Path(candidate).expanduser().exists():
            return None

    # Use the same XDG resolution as _user_config_paths() for the target dir.
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME", "")
    candidate_dir = Path(xdg_config_home).expanduser() if xdg_config_home else None
    if candidate_dir is not None and candidate_dir.is_absolute():
        config_dir = candidate_dir
    else:
        config_dir = Path.home() / ".config"
    app_dir = config_dir / "zeroforge"
    # XDG spec: newly created config dirs should have mode 0700.
    app_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Respect the mode even if the directory already existed with broader perms.
    os.chmod(app_dir, 0o700)
    config_path = app_dir / "config.yaml"
    config_path.write_text(DEFAULT_CONFIG_TEMPLATE, encoding="utf-8")
    return config_path


def load_config(path: str | Path | None = None) -> Settings:
    """Load settings from YAML, environment variables, and defaults."""
    yaml_data: dict[str, Any] = {}

    if path is None:
        path = os.environ.get("ZERO_FORGE_CONFIG_PATH")

    if path is not None:
        config_path = Path(path).expanduser()
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        yaml_data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    else:
        search_paths = ["./zeroforge.yaml", "./zeroforge.yml", *_user_config_paths()]
        for candidate in search_paths:
            config_path = Path(candidate).expanduser()
            if config_path.exists():
                yaml_data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
                break

    if not isinstance(yaml_data, dict):
        raise ValueError("ZeroForge configuration root must be a mapping")

    _reject_legacy_yaml(yaml_data)
    _reject_legacy_environment()
    return _apply_env_overrides(Settings(**yaml_data))


_settings_cache: Settings | None = None


def get_settings(reload: bool = False) -> Settings:
    """Return cached settings, optionally forcing a reload."""
    global _settings_cache
    if _settings_cache is None or reload:
        _settings_cache = load_config()
    return _settings_cache


def reset_settings() -> None:
    """Clear the cached settings singleton."""
    global _settings_cache
    _settings_cache = None
