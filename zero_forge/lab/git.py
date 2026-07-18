"""Safe Git acquisition for native lab runs."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .types import LabError

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
_SCP_REMOTE_RE = re.compile(r"^(?:[^@/:]+@)?([^:/]+):(.+)$")
_HEX_REF_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


def run_command(
    args: Sequence[str], *, cwd: Path | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    """Run one bounded external command and normalize failures."""
    try:
        result = subprocess.run(
            list(args),
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise LabError(f"Required command is unavailable: {args[0]}") from exc
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip() or "command failed"
        raise LabError(f"{' '.join(args)}: {detail}")
    return result


def canonical_repo_url(value: str, *, base_dir: Path | None = None) -> str:
    """Return a protocol-neutral remote identity."""
    raw = value.strip()
    if not raw:
        raise LabError("Git repository URL must not be empty")
    if "://" not in raw and (match := _SCP_REMOTE_RE.fullmatch(raw)):
        host = match.group(1).lower()
        path = unquote(match.group(2)).strip("/").removesuffix(".git")
        return f"{host}/{path}"
    parsed = urlsplit(raw)
    if parsed.scheme and parsed.scheme != "file":
        host = (parsed.hostname or "").lower()
        path = unquote(parsed.path).strip("/").removesuffix(".git")
        if not host or not path:
            raise LabError(f"Invalid Git repository URL: {value}")
        try:
            port = parsed.port
        except ValueError as exc:
            raise LabError(f"Invalid Git repository URL: {value}") from exc
        return f"{host}:{port}/{path}" if port else f"{host}/{path}"
    local = Path(unquote(parsed.path if parsed.scheme == "file" else raw)).expanduser()
    if not local.is_absolute() and base_dir:
        local = base_dir / local
    return local.resolve(strict=False).as_uri()


def _git(
    source: Path, args: Sequence[str], *, runner: CommandRunner, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return runner(["git", *args], cwd=source, check=check)


def _rev(source: Path, value: str, *, runner: CommandRunner) -> str | None:
    result = _git(source, ["rev-parse", "--verify", value], runner=runner, check=False)
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None


def _requested_commit(source: Path, ref: str, *, runner: CommandRunner) -> str:
    candidates: list[str]
    if _HEX_REF_RE.fullmatch(ref):
        candidates = [f"{ref}^{{commit}}"]
    elif ref.startswith("refs/heads/"):
        branch = ref.removeprefix("refs/heads/")
        candidates = [f"refs/remotes/origin/{branch}^{{commit}}"]
    elif ref.startswith("refs/tags/"):
        candidates = [f"{ref}^{{commit}}"]
    else:
        candidates = [
            f"refs/remotes/origin/{ref}^{{commit}}",
            f"refs/tags/{ref}^{{commit}}",
            f"{ref}^{{commit}}",
        ]
    for candidate in candidates:
        if commit := _rev(source, candidate, runner=runner):
            return commit
    _git(source, ["fetch", "origin", ref], runner=runner)
    commit = _rev(source, "FETCH_HEAD^{commit}", runner=runner)
    if not commit:
        raise LabError(f"Could not resolve Git ref to a commit: {ref}")
    return commit


def _default_commit(source: Path, *, runner: CommandRunner) -> str:
    _git(source, ["remote", "set-head", "origin", "--auto"], runner=runner, check=False)
    symbolic = _git(
        source,
        ["symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"],
        runner=runner,
        check=False,
    ).stdout.strip()
    if not symbolic:
        advertised = _git(source, ["ls-remote", "--symref", "origin", "HEAD"], runner=runner)
        for line in advertised.stdout.splitlines():
            if line.startswith("ref: refs/heads/") and line.endswith("\tHEAD"):
                symbolic = "origin/" + line.split("\t", 1)[0].removeprefix("ref: refs/heads/")
                break
    commit = _rev(source, f"{symbolic}^{{commit}}", runner=runner) if symbolic else None
    if not commit:
        raise LabError("Could not resolve the remote default branch")
    return commit


def prepare_source_checkout(
    repo_url: str,
    source_dir: Path,
    requested_ref: str = "",
    *,
    runner: CommandRunner = run_command,
) -> str:
    """Clone/update a clean checkout and detach it at one immutable commit."""
    source = source_dir.expanduser().resolve(strict=False)
    source.parent.mkdir(parents=True, exist_ok=True)
    if source.exists():
        if source.is_symlink() or not (source / ".git").is_dir():
            raise LabError(f"Source path is not a safe Git checkout: {source}")
        origin = _git(source, ["remote", "get-url", "origin"], runner=runner).stdout.strip()
        if canonical_repo_url(origin, base_dir=source) != canonical_repo_url(
            repo_url, base_dir=source.parent
        ):
            raise LabError("Existing checkout origin does not match the requested repository")
        if _git(source, ["status", "--porcelain"], runner=runner).stdout.strip():
            raise LabError(f"Source checkout is dirty: {source}")
    else:
        runner(
            ["git", "clone", "--no-checkout", "--origin", "origin", "--", repo_url, str(source)],
            cwd=source.parent,
            check=True,
        )
    _git(
        source,
        ["fetch", "--prune", "--tags", "origin", "+refs/heads/*:refs/remotes/origin/*"],
        runner=runner,
    )
    commit = (
        _requested_commit(source, requested_ref.strip(), runner=runner)
        if requested_ref.strip()
        else _default_commit(source, runner=runner)
    )
    _git(source, ["checkout", "--detach", "--force", commit], runner=runner)
    if _git(source, ["status", "--porcelain"], runner=runner).stdout.strip():
        raise LabError(f"Source checkout became dirty: {source}")
    return commit
