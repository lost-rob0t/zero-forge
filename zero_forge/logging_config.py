"""Centralized logging configuration for ZeroForge.

Provides a custom TRACE level (below DEBUG) for fine-grained model I/O logging,
a ``setup_logging()`` entry point driven by :class:`~zero_forge.config.Settings`,
and a ``get_logger()`` helper that returns named loggers under the ``zero_forge``
namespace.

Typical usage::

    from zero_forge.logging_config import setup_logging, get_logger
    setup_logging()
    logger = get_logger(__name__)
    logger.info("workflow started")
    logger.trace("raw model response: %s", text)      # model I/O only
"""

from __future__ import annotations

import logging
import sys
from typing import IO, Literal

# --- custom TRACE level -------------------------------------------------

TRACE = 5  # below DEBUG (10)

logging.addLevelName(TRACE, "TRACE")


def _trace(self: logging.Logger, msg: str, *args: object, **kwargs: object) -> None:
    """Log ``msg`` at the TRACE level."""
    if self.isEnabledFor(TRACE):
        self._log(TRACE, msg, args, **kwargs)  # type: ignore[arg-type]


# Attach ``logger.trace`` to the base Logger so all instances support it.
logging.Logger.trace = _trace  # type: ignore[attr-defined]

# --- level resolution ---------------------------------------------------

_VALID_LEVELS = {
    "TRACE": TRACE,
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


LogLevel = Literal["TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def _resolve_level(name: str) -> int:
    """Resolve a level name (case-insensitive) to its numeric value."""
    key = name.strip().upper()
    if key not in _VALID_LEVELS:
        raise ValueError(
            f"Unknown log level: {name!r}. "
            f"Valid levels: {', '.join(sorted(_VALID_LEVELS))}"
        )
    return _VALID_LEVELS[key]

# --- logger namespace ----------------------------------------------------

_ROOT_LOGGER_NAME = "zero_forge"
_MODEL_IO_LOGGER_NAME = "zero_forge.agents.llm"


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger under the ``zero_forge`` namespace.

    If *name* is ``None`` or already starts with ``zero_forge`` the name is
    used as-is; otherwise it is prefixed with ``zero_forge.``
    """
    if name is None:
        return logging.getLogger(_ROOT_LOGGER_NAME)
    if name.startswith(_ROOT_LOGGER_NAME + ".") or name == _ROOT_LOGGER_NAME:
        return logging.getLogger(name)
    return logging.getLogger(f"{_ROOT_LOGGER_NAME}.{name}")

# --- setup ---------------------------------------------------------------

_DEFAULT_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(
    *,
    level: str = "INFO",
    model_io_level: str = "TRACE",
    fmt: str = _DEFAULT_FORMAT,
    datefmt: str = _DATE_FORMAT,
    stream: IO[str] | None = None,
) -> None:
    """Configure the ``zero_forge`` logging hierarchy.

    Parameters
    ----------
    level
        Minimum level for the root ``zero_forge`` logger (default ``INFO``).
    model_io_level
        Minimum level for the model I/O sub-logger
        (``zero_forge.agents.llm``). Defaults to ``TRACE`` so raw prompts and
        responses are captured when the surrounding logger is verbose enough.
    fmt
        ``logging`` format string.
    datefmt
        Date/time format string.
    stream
        Output stream (defaults to ``sys.stderr``).
    """
    root_level = _resolve_level(level)
    io_level = _resolve_level(model_io_level)

    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))

    zf_logger = logging.getLogger(_ROOT_LOGGER_NAME)
    # Remove existing handlers to avoid duplicates on repeated calls.
    for existing in list(zf_logger.handlers):
        zf_logger.removeHandler(existing)
    zf_logger.addHandler(handler)
    zf_logger.setLevel(root_level)
    zf_logger.propagate = False  # avoid double output via root logger

    # Model I/O sub-logger: independently configurable, defaults to TRACE.
    io_logger = logging.getLogger(_MODEL_IO_LOGGER_NAME)
    io_logger.setLevel(io_level)
    # The sub-logger inherits the parent handler via propagation but keeps its
    # own minimum level so TRACE messages are emitted even when the parent is
    # at INFO.
    io_logger.propagate = True


def setup_logging_from_settings() -> None:
    """Configure logging using the current :class:`~zero_forge.config.Settings`.

    Safe to call at CLI entry points or in library code. Reads
    ``settings.logging.level`` and ``settings.logging.model_io_level``.
    """
    from .config import get_settings

    cfg = get_settings().logging
    setup_logging(level=cfg.level, model_io_level=cfg.model_io_level)
