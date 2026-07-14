"""Tests for the ZeroForge config system."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from zero_forge.config import (
    DEFAULT_CONFIG_PATHS,
    LLMConfig,
    OutputConfig,
    Settings,
    WorkflowConfig,
    get_settings,
    load_config,
    reset_settings,
)


@pytest.fixture(autouse=True)
def _reset_settings():
    """Ensure the singleton is reset before and after each test."""
    reset_settings()
    yield
    reset_settings()


@pytest.fixture
def clean_env(monkeypatch):
    """Strip all ZERO_FORGE_/provider env vars so tests are deterministic."""
    for key in list(os.environ):
        if key.startswith("ZERO_FORGE_") or key in (
            "OPENROUTER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
        ):
            monkeypatch.delenv(key, raising=False)
    return monkeypatch


# --- Defaults -------------------------------------------------------------

def test_defaults(clean_env):
    s = load_config()
    assert s.llm.model == "gpt-4o-mini"
    assert s.llm.temperature == 0.3
    assert s.llm.max_tokens == 4096
    assert s.workflow.max_repair_attempts == 3
    assert s.output.dir == "./output"
    assert s.openrouter_api_key == ""


def test_sub_models():
    llm = LLMConfig()
    assert llm.model == "gpt-4o-mini"
    wf = WorkflowConfig()
    assert wf.max_repair_attempts == 3
    out = OutputConfig()
    assert out.dir == "./output"


# --- YAML loading ---------------------------------------------------------

def test_yaml_load(tmp_path, clean_env):
    cfg = tmp_path / "zeroforge.yaml"
    cfg.write_text(yaml.dump({
        "llm": {"model": "claude-3-opus", "temperature": 0.7, "max_tokens": 8192},
        "workflow": {"max_repair_attempts": 5},
        "output": {"dir": "/tmp/artifacts"},
    }))
    s = load_config(cfg)
    assert s.llm.model == "claude-3-opus"
    assert s.llm.temperature == 0.7
    assert s.llm.max_tokens == 8192
    assert s.workflow.max_repair_attempts == 5
    assert s.output.dir == "/tmp/artifacts"


def test_yaml_partial(tmp_path, clean_env):
    """YAML with only some fields should still get defaults for the rest."""
    cfg = tmp_path / "partial.yaml"
    cfg.write_text(yaml.dump({"llm": {"model": "gpt-4"}}))
    s = load_config(cfg)
    assert s.llm.model == "gpt-4"
    assert s.llm.temperature == 0.3  # default
    assert s.workflow.max_repair_attempts == 3  # default


def test_yaml_missing_file(clean_env):
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/path.yaml")


# --- Env overrides --------------------------------------------------------

def test_env_overrides_model(clean_env, monkeypatch):
    monkeypatch.setenv("ZERO_FORGE_MODEL", "gpt-4-turbo")
    s = load_config()
    assert s.llm.model == "gpt-4-turbo"


def test_env_overrides_output_dir(clean_env, monkeypatch):
    monkeypatch.setenv("ZERO_FORGE_OUTPUT_DIR", "/tmp/out")
    s = load_config()
    assert s.output.dir == "/tmp/out"


def test_env_overrides_repair_attempts(clean_env, monkeypatch):
    monkeypatch.setenv("ZERO_FORGE_MAX_REPAIR_ATTEMPTS", "7")
    s = load_config()
    assert s.workflow.max_repair_attempts == 7


def test_env_overrides_temperature(clean_env, monkeypatch):
    monkeypatch.setenv("ZERO_FORGE_LLM_TEMPERATURE", "0.9")
    s = load_config()
    assert s.llm.temperature == 0.9


def test_env_api_keys(clean_env, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-123")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-oai-456")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-789")
    s = load_config()
    assert s.openrouter_api_key == "sk-or-123"
    assert s.openai_api_key == "sk-oai-456"
    assert s.anthropic_api_key == "sk-ant-789"


def test_env_overrides_yaml(tmp_path, clean_env, monkeypatch):
    """Env vars should take priority over YAML values."""
    cfg = tmp_path / "zeroforge.yaml"
    cfg.write_text(yaml.dump({"llm": {"model": "yaml-model"}}))
    monkeypatch.setenv("ZERO_FORGE_MODEL", "env-model")
    s = load_config(cfg)
    assert s.llm.model == "env-model"


# --- Singleton ------------------------------------------------------------

def test_singleton_caching(clean_env):
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2


def test_singleton_reload(clean_env, monkeypatch):
    s1 = get_settings()
    monkeypatch.setenv("ZERO_FORGE_MODEL", "new-model")
    s2 = get_settings(reload=True)
    assert s2.llm.model == "new-model"
    assert s1 is not s2


def test_reset(clean_env):
    s1 = get_settings()
    reset_settings()
    s2 = get_settings()
    assert s1 is not s2


# --- Default path search --------------------------------------------------

def test_default_config_paths_exist():
    """DEFAULT_CONFIG_PATHS should be a non-empty list."""
    assert isinstance(DEFAULT_CONFIG_PATHS, list)
    assert len(DEFAULT_CONFIG_PATHS) > 0
