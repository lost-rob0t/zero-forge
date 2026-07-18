"""Bounded loading of artifact-specific examples for LLM prompts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .schemas import ArtifactType

DEFAULT_MAX_EXAMPLES = 2
DEFAULT_MAX_CHARS = 12_000

_EXAMPLE_DIRECTORIES = {
    ArtifactType.METASPLOIT: Path("metasploit"),
    ArtifactType.ZAP_ACTIVE: Path("zap") / "active",
    ArtifactType.ZAP_PASSIVE: Path("zap") / "passive",
    ArtifactType.NUCLEI: Path("nuclei"),
}

_EXAMPLE_SUFFIXES = {
    ArtifactType.METASPLOIT: ".rb",
    ArtifactType.ZAP_ACTIVE: ".js",
    ArtifactType.ZAP_PASSIVE: ".js",
    ArtifactType.NUCLEI: ".yaml",
}


@dataclass(frozen=True, slots=True)
class ArtifactExample:
    """One complete example selected for an artifact prompt."""

    name: str
    content: str


def default_examples_root() -> Path:
    """Return the package-local example directory."""
    return Path(__file__).resolve().parent / "llm_examples"


def load_artifact_examples(
    artifact_type: ArtifactType,
    *,
    root: Path | None = None,
    max_examples: int = DEFAULT_MAX_EXAMPLES,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> list[ArtifactExample]:
    """Load complete examples deterministically within a total character budget.

    Missing or unreadable example directories fail open with an empty list. Files
    that would exceed the remaining budget are skipped instead of being truncated,
    so prompts never contain syntactically incomplete reference artifacts.
    """
    if max_examples < 0 or max_chars < 0:
        raise ValueError("Example limits must be non-negative")
    if max_examples == 0 or max_chars == 0:
        return []

    examples_root = root if root is not None else default_examples_root()
    directory = examples_root / _EXAMPLE_DIRECTORIES[artifact_type]
    suffix = _EXAMPLE_SUFFIXES[artifact_type]
    try:
        candidates = sorted(
            path for path in directory.iterdir() if path.is_file() and path.suffix == suffix
        )
    except OSError:
        return []

    selected: list[ArtifactExample] = []
    used = 0
    for path in candidates:
        if len(selected) >= max_examples:
            break
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        if not content.strip() or used + len(content) > max_chars:
            continue
        selected.append(ArtifactExample(name=path.name, content=content.rstrip()))
        used += len(content)
    return selected
