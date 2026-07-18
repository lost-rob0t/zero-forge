"""Shared native lab types."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..schemas import WorkflowState


class LabError(RuntimeError):
    """Raised when a native lab operation cannot complete safely."""


class LabWorkflowError(LabError):
    """Raised when generation fails after staging begins."""

    def __init__(self, message: str, run_dir: Path) -> None:
        super().__init__(message)
        self.run_dir = run_dir


@dataclass(frozen=True)
class PocCollection:
    path: Path
    result_count: int


@dataclass(frozen=True)
class LabRunResult:
    run_dir: Path
    manifest_path: Path
    source_dir: Path
    source_commit: str
    workflow: WorkflowState
    promoted_path: Path | None = None


@dataclass(frozen=True)
class LabStatus:
    scope: str
    staged_root: Path
    staged_runs: tuple[Path, ...]
    latest: Path | None
    promoted_root: Path
    promoted_exists: bool
