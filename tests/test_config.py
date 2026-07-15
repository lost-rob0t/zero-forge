"""Tests for the ZeroForge config system."""

from __future__ import annotations

import os

import pytest
import yaml

from zero_forge.config import (
    DEFAULT_CONFIG_PATHS,
    LLMConfig,
    ModelConfig,
    ModelsConfig,
    OutputConfig,
    WorkflowConfig,
    get_settings,
    load_config,
    reset_settings,
)


@pytest.fixture(autouse=True)
def _reset_settings():
    reset_settings()
    yield
    reset_settings()


@pytest.fixture
def clean_env(monkeypatch):
    for key in list(os.environ):
        if key.startswith("ZERO_FORGE_") or key in (
            "OPENROUTER_API_KEY",
            "OPENROUTER_BASE_URL",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
        ):
            monkeypatch.delenv(key, raising=False)
    return monkeypatch


def test_defaults(clean_env):
    settings = load_config()
    assert settings.models.smart.model == "gpt-4o"
    assert settings.models.smart.temperature == 0.3
    assert settings.models.smart.max_tokens == 4096
    assert settings.models.tool.model == "gpt-4o-mini"
    assert settings.models.tool.temperature == 0.0
    assert settings.models.tool.max_tokens == 1024
    assert settings.llm.stub_mode is False
    assert settings.workflow.max_repair_attempts == 3
    assert settings.output.dir == "./output"


def test_sub_models():
    smart = ModelConfig(model="smart", temperature=0.2, max_tokens=8000)
    tool = ModelConfig(model="tool", temperature=0.0, max_tokens=800)
    models = ModelsConfig(smart=smart.model_dump(), tool=tool.model_dump())
    assert models.smart.model == "smart"
    assert models.tool.model == "tool"
    assert LLMConfig().stub_mode is False
    assert WorkflowConfig().max_repair_attempts == 3
    assert OutputConfig().dir == "./output"


def test_yaml_loads_independent_models(tmp_path, clean_env):
    config_path = tmp_path / "zeroforge.yaml"
    config_path.write_text(
        yaml.dump(
            {
                "models": {
                    "smart": {
                        "provider": "openai",
                        "model": "smart-model",
                        "temperature": 0.7,
                        "max_tokens": 8192,
                        "base_url": "https://smart.example/v1",
                    },
                    "tool": {
                        "provider": "openrouter",
                        "model": "tool-model",
                        "temperature": 0.0,
                        "max_tokens": 512,
                        "base_url": "https://tool.example/v1",
                    },
                },
                "workflow": {"max_repair_attempts": 5},
                "output": {"dir": "/tmp/artifacts"},
            }
        )
    )
    settings = load_config(config_path)
    assert settings.models.smart.model == "smart-model"
    assert settings.models.smart.base_url == "https://smart.example/v1"
    assert settings.models.tool.model == "tool-model"
    assert settings.models.tool.base_url == "https://tool.example/v1"
    assert settings.workflow.max_repair_attempts == 5
    assert settings.output.dir == "/tmp/artifacts"


def test_yaml_partial_model_uses_role_defaults(tmp_path, clean_env):
    config_path = tmp_path / "partial.yaml"
    config_path.write_text(yaml.dump({"models": {"smart": {"model": "custom-smart"}}}))
    settings = load_config(config_path)
    assert settings.models.smart.model == "custom-smart"
    assert settings.models.smart.temperature == 0.3
    assert settings.models.tool.model == "gpt-4o-mini"


def test_legacy_yaml_fails_with_migration_message(tmp_path, clean_env):
    config_path = tmp_path / "legacy.yaml"
    config_path.write_text(yaml.dump({"llm": {"model": "shared-model"}}))
    with pytest.raises(ValueError, match="models.smart"):
        load_config(config_path)


def test_yaml_missing_file(clean_env):
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/path.yaml")


def test_role_specific_env_overrides(clean_env, monkeypatch):
    monkeypatch.setenv("ZERO_FORGE_SMART_MODEL", "smart-env")
    monkeypatch.setenv("ZERO_FORGE_SMART_BASE_URL", "https://smart.env/v1")
    monkeypatch.setenv("ZERO_FORGE_TOOL_MODEL", "tool-env")
    monkeypatch.setenv("ZERO_FORGE_TOOL_BASE_URL", "https://tool.env/v1")
    settings = load_config()
    assert settings.models.smart.model == "smart-env"
    assert settings.models.smart.base_url == "https://smart.env/v1"
    assert settings.models.tool.model == "tool-env"
    assert settings.models.tool.base_url == "https://tool.env/v1"


def test_legacy_model_env_fails_with_migration_message(clean_env, monkeypatch):
    monkeypatch.setenv("ZERO_FORGE_MODEL", "shared-model")
    with pytest.raises(ValueError, match="ZERO_FORGE_SMART"):
        load_config()


def test_env_overrides_output_and_workflow(clean_env, monkeypatch):
    monkeypatch.setenv("ZERO_FORGE_OUTPUT_DIR", "/tmp/out")
    monkeypatch.setenv("ZERO_FORGE_MAX_REPAIR_ATTEMPTS", "7")
    settings = load_config()
    assert settings.output.dir == "/tmp/out"
    assert settings.workflow.max_repair_attempts == 7


def test_env_enables_explicit_stub_mode(clean_env, monkeypatch):
    monkeypatch.setenv("ZERO_FORGE_STUB_MODE", "true")
    assert load_config().llm.stub_mode is True


def test_logging_defaults(clean_env):
    settings = load_config()
    assert settings.logging.level == "INFO"
    assert settings.logging.model_io_level == "TRACE"


def test_logging_env_overrides(clean_env, monkeypatch):
    monkeypatch.setenv("ZERO_FORGE_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("ZERO_FORGE_LOG_MODEL_IO_LEVEL", "WARNING")
    settings = load_config()
    assert settings.logging.level == "DEBUG"
    assert settings.logging.model_io_level == "WARNING"


def test_env_api_keys(clean_env, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-123")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-oai-456")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-789")
    settings = load_config()
    assert settings.openrouter_api_key == "sk-or-123"
    assert settings.openai_api_key == "sk-oai-456"
    assert settings.anthropic_api_key == "sk-ant-789"


def test_singleton_caching(clean_env):
    first = get_settings()
    second = get_settings()
    assert first is second


def test_singleton_reload_uses_role_override(clean_env, monkeypatch):
    first = get_settings()
    monkeypatch.setenv("ZERO_FORGE_SMART_MODEL", "new-smart-model")
    second = get_settings(reload=True)
    assert second.models.smart.model == "new-smart-model"
    assert first is not second


def test_reset(clean_env):
    first = get_settings()
    reset_settings()
    second = get_settings()
    assert first is not second


def test_default_config_paths_exist():
    assert isinstance(DEFAULT_CONFIG_PATHS, list)
    assert DEFAULT_CONFIG_PATHS
