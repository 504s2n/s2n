from __future__ import annotations

"""Docker wrapper for running the s2n CLI or internal python modules/files inside
a long-running container for DEV/PRD environments.

This script will:
- Ensure Docker is available on the host.
- Ensure a container for the chosen environment (dev/prd) is running. If it
  doesn't exist it will create one by mounting the repository root into the
  container at /src and keeping the container alive with `tail -f /dev/null`.
- Forward the remaining CLI arguments into the container by running either
  `python -m s2n.s2nscanner.cli.runner ...` (default) or a user-specified file
  or module.

Usage examples:
  # forward a scan command into the dev container
  python runner_cont_wrapper.py --env dev scan -u http://example.local -v

  # run a specific plugin file inside the prod container
  python runner_cont_wrapper.py --env prd --run-file s2n/s2nscanner/plugins/xss/xss_scanner.py -- -c somearg

Notes:
 - The repository root is detected by looking for pyproject.toml, requirements.txt
   or README.md in parent folders.
 - By default the wrapper uses image `python:3.11-slim` to create containers.
"""

import logging
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

import click

logger = logging.getLogger("s2n.runner_cont_wrapper")
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


def find_repo_root(start: Optional[Path] = None) -> Path:
    p = (Path(start) if start else Path(__file__).resolve()).resolve()
    for parent in (p.parents if p.is_file() else [p] + list(p.parents)):
        if (
            (parent / "pyproject.toml").exists()
            or (parent / "requirements.txt").exists()
            or (parent / "README.md").exists()
        ):
            return parent
    # fallback to a reasonable default (a few parents up)
    return Path(__file__).resolve().parents[4]


def check_docker_available() -> None:
    if shutil.which("docker") is None:
        raise click.ClickException("Docker was not found on PATH. Please install Docker.")


def run_cmd(cmd: List[str], capture_output: bool = False) -> subprocess.CompletedProcess:
    logger.debug("Running command: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=capture_output, text=True)


def container_exists(name: str) -> bool:
    cp = run_cmd(["docker", "ps", "-aq", "-f", f"name={name}"], capture_output=True)
    return bool(cp.stdout.strip())


def container_running(name: str) -> bool:
    cp = run_cmd(["docker", "ps", "-q", "-f", f"name={name}"], capture_output=True)
    return bool(cp.stdout.strip())


def create_container(name: str, image: str, repo_root: Path) -> None:
    # Run container detached and keep it alive with tail -f /dev/null
    cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        name,
        "-v",
        f"{str(repo_root)}:/src",
        "-w",
        "/src",
        image,
        "tail",
        "-f",
        "/dev/null",
    ]
    cp = run_cmd(cmd, capture_output=True)
    if cp.returncode != 0:
        raise click.ClickException(f"Failed to create container {name}: {cp.stderr or cp.stdout}")
    logger.info("Created container %s using image %s", name, image)


def start_container(name: str, image: str, repo_root: Path) -> None:
    if container_running(name):
        logger.debug("Container %s already running", name)
        return

    if container_exists(name):
        cp = run_cmd(["docker", "start", name], capture_output=True)
        if cp.returncode != 0:
            raise click.ClickException(f"Failed to start container {name}: {cp.stderr or cp.stdout}")
        logger.info("Started existing container %s", name)
        return

    # create new container
    create_container(name, image, repo_root)


def install_requirements_if_requested(container: str) -> None:
    # If requirements.txt exists in the repo root, install it inside the container
    cp = run_cmd(
        ["docker", "exec", container, "bash", "-lc", "test -f /src/requirements.txt && echo yes || echo no"],
        capture_output=True,
    )
    if cp.returncode == 0 and cp.stdout.strip() == "yes":
        logger.info("requirements.txt detected in container, installing with pip...")
        cp2 = run_cmd(["docker", "exec", container, "pip", "install", "-r", "/src/requirements.txt"], capture_output=False)
        if cp2.returncode != 0:
            logger.warning("pip install returned non-zero exit code: %s", cp2.returncode)


def is_tty() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def docker_exec(container: str, command: List[str], tty: bool = True) -> int:
    base = ["docker", "exec"]
    if tty and is_tty():
        base += ["-it"]
    else:
        base += ["-i"]
    base += [container] + command
    # Use Popen so user sees live output and can interact if tty
    logger.debug("[ENV]: docker exec built: %s", " ".join(base))
    proc = subprocess.Popen(base)
    proc.wait()
    return proc.returncode


@click.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.option(
    "--env",
    type=click.Choice(["dev", "prd"], case_sensitive=False),
    default="dev",
    help="Environment to run in (dev or prd)",
)
@click.option("--container-name", default=None, help="Custom container name. Defaults to s2n_dev or s2n_prd")
@click.option("--image", default="python:3.11-slim", help="Base image to use when creating a container")
@click.option(
    "--install-reqs/--no-install-reqs",
    default=False,
    help="If set and requirements.txt exists, pip install -r requirements.txt inside the container",
)
@click.option(
    "--run-file",
    default=None,
    help=(
        "Run a python file inside the container (path relative to repo root). If omitted, "
        "the wrapper runs the package CLI module by default"
    ),
)
@click.option(
    "--run-module",
    default=None,
    help="Run a python module using `python -m <module>` instead of the default cli runner module",
)
@click.pass_context

def main(
    ctx: click.Context,
    env: str,
    container_name: Optional[str],
    image: str,
    install_reqs: bool,
    run_file: Optional[str],
    run_module: Optional[str],
):
    """Wrapper CLI: ensures docker container is running and forwards commands into it.

    All arguments after options are forwarded to the selected command inside the container.
    Example: python runner_cont_wrapper.py --env dev scan -u http://target.local -v
    """

    check_docker_available()

    repo_root = find_repo_root()
    logger.debug("Detected repo root at %s", repo_root)

    env = env.lower()
    default_name = f"s2n_{env}"
    container = container_name or default_name

    # ensure container is running/created
    try:
        start_container(container, image, repo_root)
    except click.ClickException:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        raise click.ClickException(f"Failed to ensure container: {exc}")

    if install_reqs:
        install_requirements_if_requested(container)

    # Build the command to run inside the container
    forwarded = list(ctx.args)  # everything after the known options

    if run_file and run_module:
        raise click.ClickException("Only one of --run-file or --run-module may be provided")

    if run_file:
        # ensure the path is inside /src
        # if user passed args after --, they are in forwarded; we keep those
        inner_cmd = [sys.executable, f"/src/{run_file}"] + forwarded
    else:
        module_to_run = run_module or "s2n.s2nscanner.cli.runner"
        inner_cmd = [sys.executable, "-m", module_to_run] + forwarded

    # run inside container
    rc = docker_exec(container, inner_cmd, tty=True)
    if rc != 0:
        raise click.ClickException(f"[ENV]: Command inside container exited with code {rc}")