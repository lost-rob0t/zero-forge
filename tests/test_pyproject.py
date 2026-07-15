"""Tests for pyproject.toml dependency contracts."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _load() -> dict:
    return tomllib.loads(PYPROJECT.read_text())


def test_litellm_capped_on_python_3_14() -> None:
    """litellm 1.92+ bundles a Rust/PyO3 0.23.5 bridge that fails on Python 3.14.

    Ensure an upper-bound marker is present so pipx/uv installs on 3.14 use a
    pure-Python litellm release until upstream adds official 3.14 support.

    See https://github.com/lost-rob0t/zero-forge/issues/101.
    """
    data = _load()
    deps = data["project"]["dependencies"]
    litellm_lines = [d for d in deps if "litellm" in d]

    # The unconditional base requirement must still be present.
    assert any("litellm>=1.0" in d for d in litellm_lines), (
        "Missing unconditional 'litellm>=1.0' dependency."
    )

    # A capped variant for Python >=3.14 must be present.
    capped = [
        d
        for d in litellm_lines
        if "python_version>='3.14'" in d.replace(" ", "").replace(chr(34), chr(39))
    ]
    assert len(capped) == 1, f"Expected exactly one litellm 3.14 cap, got: {capped}"
    assert re.search(r"litellm<1\.92", capped[0]), (
        f"Cap should be 'litellm<1.92', got: {capped[0]}"
    )


def test_requires_python_allows_3_14() -> None:
    """requires-python must not artificially exclude Python 3.14."""
    data = _load()
    requires = data["project"]["requires-python"]
    assert ">=3.12" in requires, f"Expected '>=3.12', got: {requires}"
    assert "<" not in requires, f"Python 3.14 must not be excluded: {requires}"
