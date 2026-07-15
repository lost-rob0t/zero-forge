"""Tests for the ZeroForge logging configuration."""

from __future__ import annotations

import logging

import pytest

from zero_forge.logging_config import (
    TRACE,
    _resolve_level,
    get_logger,
    setup_logging,
)


@pytest.fixture(autouse=True)
def _reset_logging():
    """Reset the zero_forge logger hierarchy before and after each test."""
    zf = logging.getLogger("zero_forge")
    orig_level = zf.level
    orig_handlers = list(zf.handlers)
    orig_propagate = zf.propagate
    io_logger = logging.getLogger("zero_forge.agents.llm")
    io_orig_level = io_logger.level
    io_orig_propagate = io_logger.propagate
    yield
    zf.level = orig_level
    zf.handlers = list(orig_handlers)
    zf.propagate = orig_propagate
    io_logger.level = io_orig_level
    io_logger.propagate = io_orig_propagate


def test_trace_level_is_below_debug():
    assert TRACE == 5
    assert TRACE < logging.DEBUG
    assert logging.getLevelName(TRACE) == "TRACE"


def test_logger_trace_method_exists():
    logger = get_logger(__name__)
    assert hasattr(logger, "trace")
    assert callable(logger.trace)


def test_resolve_level_known():
    assert _resolve_level("TRACE") == TRACE
    assert _resolve_level("DEBUG") == logging.DEBUG
    assert _resolve_level("INFO") == logging.INFO
    assert _resolve_level("WARNING") == logging.WARNING
    assert _resolve_level("ERROR") == logging.ERROR
    assert _resolve_level("CRITICAL") == logging.CRITICAL


def test_resolve_level_case_insensitive():
    assert _resolve_level("info") == logging.INFO
    assert _resolve_level("Trace") == TRACE
    assert _resolve_level("debug") == logging.DEBUG


def test_resolve_level_unknown_raises():
    with pytest.raises(ValueError, match="Unknown log level"):
        _resolve_level("VERBOSE")


def test_get_logger_namespace():
    logger = get_logger("agents.llm")
    assert logger.name == "zero_forge.agents.llm"


def test_get_logger_already_namespaced():
    logger = get_logger("zero_forge.workflow")
    assert logger.name == "zero_forge.workflow"


def test_get_logger_none_returns_root():
    logger = get_logger()
    assert logger.name == "zero_forge"


def test_setup_logging_defaults_info_root():
    setup_logging()
    zf = logging.getLogger("zero_forge")
    assert zf.level == logging.INFO
    assert len(zf.handlers) == 1
    assert zf.propagate is False


def test_setup_logging_model_io_defaults_trace():
    setup_logging()
    io_logger = logging.getLogger("zero_forge.agents.llm")
    assert io_logger.level == TRACE
    assert io_logger.propagate is True


def test_setup_logging_custom_root_level():
    setup_logging(level="DEBUG")
    zf = logging.getLogger("zero_forge")
    assert zf.level == logging.DEBUG


def test_setup_logging_custom_model_io_level():
    setup_logging(model_io_level="INFO")
    io_logger = logging.getLogger("zero_forge.agents.llm")
    assert io_logger.level == logging.INFO


def test_setup_logging_idempotent_no_duplicate_handlers():
    setup_logging()
    setup_logging()
    zf = logging.getLogger("zero_forge")
    assert len(zf.handlers) == 1


def test_setup_logging_from_settings_defaults():
    from zero_forge.config import reset_settings
    reset_settings()
    from zero_forge.logging_config import setup_logging_from_settings
    setup_logging_from_settings()
    zf = logging.getLogger("zero_forge")
    io_logger = logging.getLogger("zero_forge.agents.llm")
    assert zf.level == logging.INFO
    assert io_logger.level == TRACE


def test_setup_logging_from_settings_env_override(monkeypatch):
    monkeypatch.setenv("ZERO_FORGE_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("ZERO_FORGE_LOG_MODEL_IO_LEVEL", "INFO")
    from zero_forge.config import reset_settings
    reset_settings()
    from zero_forge.logging_config import setup_logging_from_settings
    setup_logging_from_settings()
    zf = logging.getLogger("zero_forge")
    io_logger = logging.getLogger("zero_forge.agents.llm")
    assert zf.level == logging.DEBUG
    assert io_logger.level == logging.INFO


def test_trace_emits_when_enabled(caplog):
    setup_logging(level="TRACE")
    # setup_logging disables propagation; re-enable so caplog can capture.
    logging.getLogger("zero_forge").propagate = True
    logger = get_logger("test")
    with caplog.at_level(TRACE, logger="zero_forge.test"):
        logger.trace("trace message")  # type: ignore[attr-defined]
    assert any("trace message" in r.message for r in caplog.records)


def test_trace_suppressed_at_info(caplog):
    setup_logging(level="INFO")
    logger = get_logger("test")
    # caplog uses its own handler at WARNING level by default; verify our logger
    # would not emit TRACE
    assert not logger.isEnabledFor(TRACE)
