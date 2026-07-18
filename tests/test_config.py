"""Tests for the ZeroForge config system."""

from __future__ import annotations

import os
from pathlib import Path

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
    assert settings.models.smart.model == "openai/gpt-4o"
    assert settings.models.smart.temperature == 0.3
    assert settings.models.smart.max_tokens == 4096
    assert settings.models.tool.model == "openai/gpt-4o-mini"
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
    assert settings.models.tool.model == "openai/gpt-4o-mini"


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


def test_auto_max_tokens_defaults(clean_env):
    settings = load_config()
    assert settings.models.smart.auto_max_tokens is True
    assert settings.models.tool.auto_max_tokens is True
    assert settings.models.smart.inferred_max_token_cap == 8192
    assert settings.models.tool.inferred_max_token_cap == 8192


def test_auto_max_tokens_env_overrides(clean_env, monkeypatch):
    monkeypatch.setenv("ZERO_FORGE_SMART_AUTO_MAX_TOKENS", "false")
    monkeypatch.setenv("ZERO_FORGE_TOOL_AUTO_MAX_TOKENS", "false")
    monkeypatch.setenv("ZERO_FORGE_SMART_INFERRED_MAX_TOKEN_CAP", "16384")
    monkeypatch.setenv("ZERO_FORGE_TOOL_INFERRED_MAX_TOKEN_CAP", "2048")
    settings = load_config()
    assert settings.models.smart.auto_max_tokens is False
    assert settings.models.tool.auto_max_tokens is False
    assert settings.models.smart.inferred_max_token_cap == 16384
    assert settings.models.tool.inferred_max_token_cap == 2048


def test_yaml_auto_max_tokens(tmp_path, clean_env):
    config_path = tmp_path / "zeroforge.yaml"
    config_path.write_text(
        yaml.dump(
            {
                "models": {
                    "smart": {"auto_max_tokens": False, "inferred_max_token_cap": 2048},
                    "tool": {"auto_max_tokens": False, "inferred_max_token_cap": 1024},
                }
            }
        )
    )
    settings = load_config(config_path)
    assert settings.models.smart.auto_max_tokens is False
    assert settings.models.smart.inferred_max_token_cap == 2048
    assert settings.models.tool.auto_max_tokens is False
    assert settings.models.tool.inferred_max_token_cap == 1024


def test_default_config_paths_exist():
    assert isinstance(DEFAULT_CONFIG_PATHS, list)
    assert DEFAULT_CONFIG_PATHS


# --- XDG config path tests ------------------------------------------------


def test_user_config_paths_respects_xdg_config_home(tmp_path, monkeypatch):
    """_user_config_paths uses XDG_CONFIG_HOME when set."""
    from zero_forge.config import _user_config_paths

    xdg_dir = tmp_path / "custom-xdg"
    xdg_dir.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_dir))

    paths = _user_config_paths()
    assert len(paths) == 2
    assert paths[0] == str(xdg_dir / "zeroforge" / "config.yaml")
    assert paths[1] == str(xdg_dir / "zeroforge" / "config.yml")


def test_user_config_paths_falls_back_to_home(monkeypatch):
    """_user_config_paths falls back to ~/.config when XDG_CONFIG_HOME unset."""
    from zero_forge.config import _user_config_paths

    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

    paths = _user_config_paths()
    expected_dir = Path.home() / ".config" / "zeroforge"
    assert paths[0] == str(expected_dir / "config.yaml")
    assert paths[1] == str(expected_dir / "config.yml")


def test_user_config_paths_empty_xdg_falls_back(monkeypatch):
    """Empty XDG_CONFIG_HOME string falls back to ~/.config."""
    from zero_forge.config import _user_config_paths

    monkeypatch.setenv("XDG_CONFIG_HOME", "")

    paths = _user_config_paths()
    expected_dir = Path.home() / ".config" / "zeroforge"
    assert paths[0] == str(expected_dir / "config.yaml")


def test_load_config_from_xdg_path(tmp_path, monkeypatch, clean_env):
    """load_config picks up config.yaml from XDG_CONFIG_HOME."""
    xdg_dir = tmp_path / "xdg-config"
    app_dir = xdg_dir / "zeroforge"
    app_dir.mkdir(parents=True)
    config_file = app_dir / "config.yaml"
    config_file.write_text(yaml.dump({"models": {"smart": {"model": "xdg-model"}}}))

    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_dir))
    monkeypatch.chdir(tmp_path)

    settings = load_config()
    assert settings.models.smart.model == "xdg-model"


def test_local_config_takes_priority_over_xdg(tmp_path, monkeypatch, clean_env):
    """./zeroforge.yaml takes priority over XDG config path."""
    work_dir = tmp_path / "work"
    work_dir.mkdir()

    xdg_dir = tmp_path / "xdg-config"
    app_dir = xdg_dir / "zeroforge"
    app_dir.mkdir(parents=True)
    (app_dir / "config.yaml").write_text(yaml.dump({"models": {"smart": {"model": "xdg-model"}}}))

    local_config = work_dir / "zeroforge.yaml"
    local_config.write_text(yaml.dump({"models": {"smart": {"model": "local-model"}}}))

    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_dir))
    monkeypatch.chdir(work_dir)

    settings = load_config()
    assert settings.models.smart.model == "local-model"


# --- ensure_default_config tests -----------------------------------------


def test_ensure_default_config_writes_when_none(tmp_path, monkeypatch, clean_env):
    """ensure_default_config writes a default config to XDG path when none exists."""
    from zero_forge.config import ensure_default_config

    xdg_dir = tmp_path / "xdg"
    xdg_dir.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_dir))
    monkeypatch.chdir(tmp_path)

    result = ensure_default_config()
    assert result is not None
    assert result.exists()
    assert result == xdg_dir / "zeroforge" / "config.yaml"


def test_ensure_default_config_returns_none_when_exists(tmp_path, monkeypatch, clean_env):
    """ensure_default_config returns None when a config already exists."""
    from zero_forge.config import ensure_default_config

    xdg_dir = tmp_path / "xdg"
    app_dir = xdg_dir / "zeroforge"
    app_dir.mkdir(parents=True)
    (app_dir / "config.yaml").write_text("models:\n  smart:\n    model: existing\n")

    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_dir))
    monkeypatch.chdir(tmp_path)

    result = ensure_default_config()
    assert result is None


def test_ensure_default_config_returns_none_when_local_exists(tmp_path, monkeypatch, clean_env):
    """ensure_default_config returns None when a local config already exists."""
    from zero_forge.config import ensure_default_config

    work_dir = tmp_path / "work"
    work_dir.mkdir()
    (work_dir / "zeroforge.yaml").write_text("models:\n  smart:\n    model: local\n")

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.chdir(work_dir)

    result = ensure_default_config()
    assert result is None


def test_ensure_default_config_written_file_loads(tmp_path, monkeypatch, clean_env):
    """The default config written by ensure_default_config is loadable."""
    from zero_forge.config import ensure_default_config, load_config

    xdg_dir = tmp_path / "xdg"
    xdg_dir.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_dir))
    monkeypatch.chdir(tmp_path)

    written_path = ensure_default_config()
    assert written_path is not None

    settings = load_config()
    assert settings.models.smart.model == "gpt-4o"
    assert settings.models.tool.model == "gpt-4o-mini"
    assert settings.output.dir == "./output"


def test_ensure_default_config_falls_back_to_home(tmp_path, monkeypatch, clean_env):
    """ensure_default_config falls back to ~/.config when XDG_CONFIG_HOME unset."""
    from zero_forge.config import ensure_default_config

    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.chdir(tmp_path)

    # Use a fake home so we don't write to the real one
    fake_home = tmp_path / "fake-home"
    fake_home.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: fake_home)

    result = ensure_default_config()
    assert result is not None
    assert result == fake_home / ".config" / "zeroforge" / "config.yaml"
    assert result.exists()


def test_user_config_paths_rejects_relative_xdg(monkeypatch):
    """Relative XDG_CONFIG_HOME is ignored; falls back to ~/.config."""
    from zero_forge.config import _user_config_paths

    monkeypatch.setenv("XDG_CONFIG_HOME", "relative/path")

    paths = _user_config_paths()
    expected_dir = Path.home() / ".config" / "zeroforge"
    assert paths[0] == str(expected_dir / "config.yaml")
    assert paths[1] == str(expected_dir / "config.yml")


def test_ensure_default_config_respects_env_config_path(tmp_path, monkeypatch, clean_env):
    """ensure_default_config returns None when ZERO_FORGE_CONFIG_PATH points to existing file."""
    from zero_forge.config import ensure_default_config

    custom_config = tmp_path / "custom.yaml"
    custom_config.write_text(yaml.dump({"models": {"smart": {"model": "custom"}}}))

    monkeypatch.setenv("ZERO_FORGE_CONFIG_PATH", str(custom_config))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.chdir(tmp_path)

    result = ensure_default_config()
    assert result is None


def test_ensure_default_config_creates_dir_with_mode_0700(tmp_path, monkeypatch, clean_env):
    """XDG config directory is created with mode 0700 per XDG spec."""
    import stat

    from zero_forge.config import ensure_default_config

    xdg_dir = tmp_path / "xdg"
    xdg_dir.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_dir))
    monkeypatch.chdir(tmp_path)

    result = ensure_default_config()
    assert result is not None

    app_dir = xdg_dir / "zeroforge"
    mode = stat.S_IMODE(app_dir.stat().st_mode)
    assert mode == 0o700


def test_generate_exits_after_creating_default_config(tmp_path, monkeypatch, clean_env):
    """CLI generate exits after writing default config; run_workflow is not called."""
    from typer.testing import CliRunner

    from zero_forge.cli import app

    xdg_dir = tmp_path / "xdg"
    xdg_dir.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_dir))
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ZERO_FORGE_CONFIG_PATH", raising=False)

    runner = CliRunner()
    result = runner.invoke(app, ["generate", "--cve", "CVE-2021-44228"])

    assert result.exit_code == 0
    assert "Created default config" in result.stdout
    assert (xdg_dir / "zeroforge" / "config.yaml").exists()

    # Verify run_workflow was not called — no workflow output should exist
    assert "generating artifact" not in result.stdout.lower()


# --- .env file loading tests (issue #109) --------------------------------


def test_load_env_file_populates_os_environ(tmp_path, monkeypatch):
    """_load_env_file loads KEY=value pairs from .env into os.environ."""
    from zero_forge.cli import _load_env_file

    env_file = tmp_path / ".env"
    env_file.write_text("TEST_ENV_VAR=hello_from_dotenv\n")

    monkeypatch.setenv("ZERO_FORGE_ENV_FILE", str(env_file))
    monkeypatch.delenv("TEST_ENV_VAR", raising=False)

    _load_env_file()

    import os

    assert os.environ.get("TEST_ENV_VAR") == "hello_from_dotenv"


def test_load_env_file_handles_export_prefix(tmp_path, monkeypatch):
    """_load_env_file handles 'export KEY=value' syntax."""
    from zero_forge.cli import _load_env_file

    env_file = tmp_path / ".env"
    env_file.write_text("export TEST_EXPORT_VAR=exported_value\n")

    monkeypatch.setenv("ZERO_FORGE_ENV_FILE", str(env_file))
    monkeypatch.delenv("TEST_EXPORT_VAR", raising=False)

    _load_env_file()

    import os

    assert os.environ.get("TEST_EXPORT_VAR") == "exported_value"


def test_load_env_file_does_not_override_existing(tmp_path, monkeypatch):
    """_load_env_file does not override existing env vars."""
    from zero_forge.cli import _load_env_file

    env_file = tmp_path / ".env"
    env_file.write_text("EXISTING_VAR=from_file\n")

    monkeypatch.setenv("ZERO_FORGE_ENV_FILE", str(env_file))
    monkeypatch.setenv("EXISTING_VAR", "from_shell")

    _load_env_file()

    import os

    assert os.environ.get("EXISTING_VAR") == "from_shell"


def test_load_env_file_missing_file_is_silent(tmp_path, monkeypatch):
    """Missing .env file does not raise."""
    from zero_forge.cli import _load_env_file

    monkeypatch.setenv("ZERO_FORGE_ENV_FILE", str(tmp_path / "nonexistent.env"))
    _load_env_file()  # should not raise


def test_env_file_api_key_reaches_settings(tmp_path, monkeypatch, request):
    """API key loaded from default .env reaches get_settings() (#109)."""
    import os

    from zero_forge.cli import _apply_env_overrides

    env_file = tmp_path / ".env"
    env_file.write_text("OPENROUTER_API_KEY=sk-or-from-dotenv\n")

    monkeypatch.delenv("ZERO_FORGE_ENV_FILE", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    # _load_env_file mutates os.environ directly, bypassing monkeypatch;
    # clean up the leaked key so downstream tests are not polluted.
    request.addfinalizer(lambda: os.environ.pop("OPENROUTER_API_KEY", None))

    monkeypatch.chdir(tmp_path)
    _apply_env_overrides(output_dir="", unsafe=False, config_file="")

    settings = get_settings()
    assert settings.openrouter_api_key == "sk-or-from-dotenv"
