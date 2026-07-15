"""SWE Agent: configures Docker target services and places a randomized flag.

Per the maintainer's simplified direction in issue #28:
- A single SWE agent configures the Docker services.
- The SWE agent places a randomized FLAG at a specified location.
- The exploit phase agent receives the file path to the flag.
- The flag must be randomized so it cannot be guessed.

Flag placement is delegated to ``flag_gen.sh`` for simplicity — a small
shell script that reads ``/dev/urandom`` and writes the flag to a file.
Docker compose setup is a separate concern handled when Docker is available.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from ..logging_config import get_logger
from .schemas import SWESetupResult, Target
from .tools import generate_flag, write_flag_to_path

logger = get_logger(__name__)

DOCKER_TIMEOUT = 60.0
DEFAULT_FLAG_DIR = "/tmp/zeroforge-target"
DEFAULT_FLAG_FILENAME = "flag.txt"
_SCRIPT_PATH = Path(__file__).resolve().parent / "flag_gen.sh"


def _check_docker_available() -> bool:
    """Return True if the ``docker`` CLI is available and the daemon is running."""
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def _write_docker_compose(
    compose_path: Path,
    service_name: str,
    image: str,
    flag_path_in_container: str,
) -> str:
    """Write a minimal docker-compose.yml for the target service.

    Returns the compose file path as a string.
    """
    compose_content = {
        "services": {
            service_name: {
                "image": image,
                "ports": ["8080:80"],
                "environment": {
                    "FLAG_PATH": flag_path_in_container,
                },
                "volumes": [],
            }
        },
    }
    compose_path.parent.mkdir(parents=True, exist_ok=True)
    compose_path.write_text(
        json.dumps(compose_content, indent=2),
        encoding="utf-8",
    )
    return str(compose_path.resolve())


def _generate_flag_via_script(output_dir: str, filename: str) -> dict[str, str]:
    """Run ``flag_gen.sh`` to generate and place a randomized flag.

    Falls back to the Python implementation if the script is unavailable.
    Returns a dict with ``flag`` and ``flag_path`` keys.
    """
    if _SCRIPT_PATH.is_file():
        try:
            result = subprocess.run(
                ["bash", str(_SCRIPT_PATH), output_dir, filename],
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
            )
            if result.returncode == 0:
                parsed = json.loads(result.stdout.strip())
                return {"flag": parsed["flag"], "flag_path": parsed["flag_path"]}
            logger.warning(
                "flag_gen.sh failed (rc=%d): %s; falling back to Python",
                result.returncode,
                result.stderr.strip(),
            )
        except Exception as exc:
            logger.warning("flag_gen.sh execution failed: %s; falling back to Python", exc)

    # Fallback: use the Python implementation
    flag = generate_flag()
    flag_path = str(Path(output_dir) / filename)
    resolved = write_flag_to_path(flag, flag_path)
    return {"flag": flag, "flag_path": resolved}


def setup_target_environment(
    target: Target,
    *,
    output_dir: str = DEFAULT_FLAG_DIR,
    docker_image: str = "",
    use_docker: bool = True,
) -> SWESetupResult:
    """Configure the target environment and place a randomized flag.

    Uses ``flag_gen.sh`` for flag placement when available — a simple
    shell script that reads ``/dev/urandom``.  Falls back to the Python
    implementation when the script is missing.

    When Docker is available and ``use_docker`` is True, this writes a
    docker-compose.yml and starts the service.  When Docker is unavailable,
    it falls back to placing the flag on the local filesystem so the
    workflow can still be exercised in tests.
    """
    flag_dir = Path(output_dir)
    flag_dir.mkdir(parents=True, exist_ok=True)

    # Generate and place the flag via flag_gen.sh (or Python fallback)
    flag_info = _generate_flag_via_script(str(flag_dir), DEFAULT_FLAG_FILENAME)
    flag = flag_info["flag"]
    local_flag_path = flag_info["flag_path"]

    image = docker_image or target.docker_image or "alpine:latest"
    service_name = target.name.lower().replace(" ", "-") or "target"
    flag_path_in_container = f"/tmp/{DEFAULT_FLAG_FILENAME}"

    if use_docker and _check_docker_available():
        compose_path = flag_dir / "docker-compose.yml"
        compose_str = _write_docker_compose(
            compose_path,
            service_name,
            image,
            flag_path_in_container,
        )

        # Try to start the service
        try:
            result = subprocess.run(
                ["docker", "compose", "-f", compose_str, "up", "-d"],
                capture_output=True,
                text=True,
                timeout=DOCKER_TIMEOUT,
                shell=False,
            )
            if result.returncode != 0:
                logger.warning(
                    "docker compose up failed: %s; falling back to local",
                    result.stderr.strip(),
                )
                return SWESetupResult(
                    docker_compose_path=compose_str,
                    service_names=[service_name],
                    flag_path=local_flag_path,
                    flag_value=flag,
                    target_id=target.id,
                    ready=False,
                    error=f"docker compose up failed: {result.stderr.strip()}",
                )
        except subprocess.TimeoutExpired:
            logger.warning("docker compose up timed out; falling back to local")
            return SWESetupResult(
                docker_compose_path=compose_str,
                service_names=[service_name],
                flag_path=local_flag_path,
                flag_value=flag,
                target_id=target.id,
                ready=False,
                error="docker compose up timed out",
            )

        logger.info("Docker service %s started; flag at %s", service_name, local_flag_path)
        return SWESetupResult(
            docker_compose_path=compose_str,
            service_names=[service_name],
            flag_path=local_flag_path,
            flag_value=flag,
            target_id=target.id,
            ready=True,
        )

    # Local fallback: no Docker, flag placed on filesystem via flag_gen.sh
    logger.info("Docker unavailable; flag placed locally at %s", local_flag_path)
    return SWESetupResult(
        docker_compose_path="",
        service_names=[service_name],
        flag_path=local_flag_path,
        flag_value=flag,
        target_id=target.id,
        ready=True,
    )
