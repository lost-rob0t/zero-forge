"""Tests for pyproject.toml dependency specification and uv.lock resolution.

These tests verify behavioral properties of the litellm dependency resolution
across Python 3.12, 3.13, and 3.14 — not merely that certain strings appear in
pyproject.toml.

The core contract is:
- Python <3.14 resolves litellm 1.92.0 (Rust bridge, supported on 3.12/3.13)
- Python >=3.14 resolves litellm 1.91.3 (pure Python, avoids PyO3 0.23.5 failure)
- The markers are mutually exclusive so the lockfile contains two entries
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT_PATH = PROJECT_ROOT / "pyproject.toml"
UV_LOCK_PATH = PROJECT_ROOT / "uv.lock"


def _load_pyproject() -> dict:
    with open(PYPROJECT_PATH, "rb") as f:
        return tomllib.load(f)


def _load_uv_lock() -> str:
    with open(UV_LOCK_PATH, encoding="utf-8") as f:
        return f.read()


def _split_spec_and_marker(dep: str) -> tuple[str, str]:
    """Split a PEP 508 dependency string into (specifier, marker)."""
    if ";" in dep:
        spec, marker = dep.split(";", 1)
        return spec.strip(), marker.strip()
    return dep.strip(), ""


def _get_litellm_deps() -> list[tuple[str, str]]:
    """Return list of (specifier, marker) for each litellm dependency."""
    pyproject = _load_pyproject()
    deps = pyproject["project"]["dependencies"]
    return [
        _split_spec_and_marker(d)
        for d in deps
        if d.startswith("litellm")
    ]


class TestPyprojectDependencies:
    """Verify pyproject.toml contains mutually exclusive litellm markers."""

    def test_no_unconditional_litellm_requirement(self) -> None:
        """There must be no unconditional litellm requirement that would cause
        the lockfile to collapse onto a single version for all interpreters."""
        litellm_deps = _get_litellm_deps()
        assert len(litellm_deps) == 2, (
            f"Expected exactly 2 litellm entries, found {len(litellm_deps)}: {litellm_deps}"
        )
        for spec, marker in litellm_deps:
            assert marker, (
                f"litellm dependency must have a marker, found unconditional: {spec}"
            )

    def test_mutually_exclusive_markers(self) -> None:
        """The two litellm entries must use mutually exclusive python_version markers
        so that uv creates separate lockfile entries per interpreter branch."""
        litellm_deps = _get_litellm_deps()
        markers = [marker for _, marker in litellm_deps]

        assert any("<" in m and "3.14" in m for m in markers), (
            f"Missing python_version<'3.14' marker in {markers}"
        )
        assert any(">=" in m and "3.14" in m for m in markers), (
            f"Missing python_version>='3.14' marker in {markers}"
        )

    def test_python_314_cap_below_1_92(self) -> None:
        """The Python 3.14+ marker must cap litellm below 1.92 to avoid the
        PyO3 0.23.5 build failure."""
        litellm_deps = _get_litellm_deps()
        # Find the entry whose marker contains >= '3.14'
        py314_entry = [
            (spec, marker) for spec, marker in litellm_deps
            if ">=" in marker and "3.14" in marker
        ]
        assert len(py314_entry) == 1, (
            f"Expected 1 3.14+ entry, found {py314_entry}"
        )
        spec, _ = py314_entry[0]
        assert "<1.92" in spec, (
            f"Python 3.14+ litellm must be capped <1.92, found: {spec}"
        )

    def test_python_below_314_no_upper_cap(self) -> None:
        """The Python <3.14 marker must not impose an upper cap so 1.92.0
        remains available for 3.12 and 3.13."""
        litellm_deps = _get_litellm_deps()
        # Find the entry whose marker contains < '3.14'
        pre_314_entry = [
            (spec, marker) for spec, marker in litellm_deps
            if "<" in marker and "3.14" in marker
        ]
        assert len(pre_314_entry) == 1, (
            f"Expected 1 <3.14 entry, found {pre_314_entry}"
        )
        spec, _ = pre_314_entry[0]
        assert ">=1.0" in spec, (
            f"Python <3.14 litellm should allow >=1.0, found: {spec}"
        )
        assert "<1.92" not in spec, (
            f"Python <3.14 must not cap below 1.92, found: {spec}"
        )

    def test_requires_python_allows_314(self) -> None:
        """requires-python must not exclude Python 3.14."""
        pyproject = _load_pyproject()
        requires_python = pyproject["project"]["requires-python"]
        assert "3.12" in requires_python, (
            f"requires-python must allow 3.12+, found: {requires_python}"
        )
        assert not any(cap in requires_python for cap in ["<3.13", "<3.14", "<3.15"]), (
            f"requires-python must not cap below 3.14, found: {requires_python}"
        )


def _extract_litellm_package_blocks(lock: str) -> list[dict]:
    """Extract litellm [[package]] blocks from uv.lock as dicts with version and wheels."""
    lines = lock.split("\n")
    blocks = []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line == "[[package]]":
            # Find the name within this block
            block_lines = []
            name = None
            version = None
            wheels = []
            in_wheels = False
            j = i + 1
            while j < len(lines):
                bline = lines[j].strip()
                if bline == "[[package]]":
                    break
                block_lines.append(bline)
                if bline.startswith('name = '):
                    name = bline.split('=', 1)[1].strip().strip('"')
                elif bline.startswith('version = '):
                    version = bline.split('=', 1)[1].strip().strip('"')
                elif bline == "wheels = [":
                    in_wheels = True
                elif in_wheels and bline.startswith("{ url ="):
                    wheels.append(bline)
                elif in_wheels and bline == "]":
                    in_wheels = False
                j += 1
            if name == "litellm":
                blocks.append({
                    "version": version,
                    "wheels": wheels,
                    "block_text": "\n".join(block_lines),
                })
            i = j
        else:
            i += 1
    return blocks


class TestUvLockResolution:
    """Verify uv.lock contains interpreter-specific litellm resolutions."""

    def test_lockfile_has_two_litellm_entries(self) -> None:
        """The lockfile must contain two separate litellm [[package]] entries
        (one per interpreter branch), not a single global version."""
        lock = _load_uv_lock()
        blocks = _extract_litellm_package_blocks(lock)
        assert len(blocks) == 2, (
            f"Expected 2 litellm [[package]] entries in uv.lock, found {len(blocks)}. "
            "A single entry means the lockfile collapsed onto one version."
        )

    def test_lockfile_has_1_91_3_for_314(self) -> None:
        """uv.lock must contain litellm 1.91.3 (pure Python) for Python 3.14+."""
        lock = _load_uv_lock()
        blocks = _extract_litellm_package_blocks(lock)
        versions = [b["version"] for b in blocks]
        assert "1.91.3" in versions, (
            f"uv.lock must contain litellm 1.91.3, found versions: {versions}"
        )

    def test_lockfile_has_1_92_0_for_pre_314(self) -> None:
        """uv.lock must contain litellm 1.92.0 (Rust bridge) for Python <3.14."""
        lock = _load_uv_lock()
        blocks = _extract_litellm_package_blocks(lock)
        versions = [b["version"] for b in blocks]
        assert "1.92.0" in versions, (
            f"uv.lock must contain litellm 1.92.0, found versions: {versions}"
        )

    def test_lockfile_314_entry_is_pure_python(self) -> None:
        """The 1.91.3 entry must have a py3-none-any wheel (pure Python, no Rust)."""
        lock = _load_uv_lock()
        blocks = _extract_litellm_package_blocks(lock)
        py314_block = [b for b in blocks if b["version"] == "1.91.3"][0]
        wheel_urls = " ".join(py314_block["wheels"])
        assert "py3-none-any" in wheel_urls, (
            "litellm 1.91.3 must use a pure Python wheel (py3-none-any), "
            "not a Rust/PyO3 wheel"
        )

    def test_lockfile_1_92_0_has_cpython_wheels(self) -> None:
        """The 1.92.0 entry must have platform-specific Rust/PyO3 wheels for 3.12/3.13."""
        lock = _load_uv_lock()
        blocks = _extract_litellm_package_blocks(lock)
        py_pre_314_block = [b for b in blocks if b["version"] == "1.92.0"][0]
        wheel_urls = " ".join(py_pre_314_block["wheels"])
        assert "cp312" in wheel_urls, "litellm 1.92.0 must have cp312 wheel"
        assert "cp313" in wheel_urls, "litellm 1.92.0 must have cp313 wheel"
        assert "cp314" not in wheel_urls, "litellm 1.92.0 must NOT have cp314 wheel"

    def test_lockfile_requires_dist_has_markers(self) -> None:
        """The [package.metadata] requires-dist section must list two litellm
        entries with mutually exclusive python_full_version markers."""
        lock = _load_uv_lock()
        lines = lock.split("\n")
        litellm_requires = [
            line.strip() for line in lines
            if "litellm" in line and "marker" in line and "requires-dist" not in line
        ]
        assert len(litellm_requires) >= 2, (
            f"Expected >=2 litellm marker lines in requires-dist, found: {litellm_requires}"
        )

        markers_text = " ".join(litellm_requires)
        assert "python_full_version >= '3.14'" in markers_text, (
            "Missing python_full_version >= '3.14' marker in requires-dist"
        )
        assert "python_full_version < '3.14'" in markers_text, (
            "Missing python_full_version < '3.14' marker in requires-dist"
        )

    def test_lockfile_314_resolves_below_1_92(self) -> None:
        """The lockfile's dependency entry for Python 3.14+ must resolve to 1.91.3."""
        lock = _load_uv_lock()
        lines = lock.split("\n")
        litellm_dep_lines = [
            line.strip() for line in lines
            if "litellm" in line and "version" in line and "marker" in line
        ]
        assert len(litellm_dep_lines) >= 2, (
            f"Expected >=2 litellm dep lines with version+marker, found: {litellm_dep_lines}"
        )

        found_314 = False
        found_pre_314 = False
        for line in litellm_dep_lines:
            if "1.91.3" in line and ">=" in line and "3.14" in line:
                found_314 = True
            if "1.92.0" in line and "<" in line and "3.14" in line:
                found_pre_314 = True

        assert found_314, (
            "Lockfile must pair litellm 1.91.3 with python_full_version >= '3.14'"
        )
        assert found_pre_314, (
            "Lockfile must pair litellm 1.92.0 with python_full_version < '3.14'"
        )


@pytest.fixture
def _check_uv_available():
    """Skip uv-dependent tests if uv is not available."""
    import shutil

    if shutil.which("uv") is None:
        pytest.skip("uv not available")


@pytest.mark.usefixtures("_check_uv_available")
class TestUvTreeResolution:
    """Verify actual uv resolution behavior for each Python version."""

    @pytest.mark.parametrize("py_version", ["3.12", "3.13"])
    def test_py312_313_resolves_1_92_0(self, py_version: str) -> None:
        """uv tree must resolve litellm 1.92.0 for Python 3.12 and 3.13."""
        import subprocess

        result = subprocess.run(
            ["uv", "tree", "--python", py_version],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
        )
        if result.returncode != 0:
            pytest.skip(f"uv tree --python {py_version} failed: {result.stderr}")
        assert "litellm v1.92.0" in result.stdout, (
            f"Python {py_version} should resolve litellm 1.92.0, got: {result.stdout}"
        )
        assert "litellm v1.91.3" not in result.stdout, (
            f"Python {py_version} must NOT resolve litellm 1.91.3, got: {result.stdout}"
        )

    def test_py314_resolves_1_91_3(self) -> None:
        """uv tree must resolve litellm 1.91.3 for Python 3.14."""
        import subprocess

        result = subprocess.run(
            ["uv", "tree", "--python", "3.14"],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
        )
        if result.returncode != 0:
            pytest.skip(f"uv tree --python 3.14 failed: {result.stderr}")
        assert "litellm v1.91.3" in result.stdout, (
            f"Python 3.14 should resolve litellm 1.91.3, got: {result.stdout}"
        )
        assert "litellm v1.92.0" not in result.stdout, (
            f"Python 3.14 must NOT resolve litellm 1.92.0, got: {result.stdout}"
        )
