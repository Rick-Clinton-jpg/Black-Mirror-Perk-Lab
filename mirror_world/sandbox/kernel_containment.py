"""Build the Linux namespace/resource boundary around a trusted bootstrap.

The bootstrap installs seccomp before executing any agent source. Namespace
setup and privilege dropping must succeed; there is no unhardened fallback.
These tools require a Linux host that permits creating the listed namespaces.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass

SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
REQUIRED_TOOLS = ("prlimit", "unshare", "setpriv", "mount", "sh")
_PROBE_OUTPUT = b"mirror-kernel-ready\n"


class KernelContainmentUnavailable(RuntimeError):
    """The platform, dependencies, or kernel cannot provide containment."""


def agent_environment() -> dict[str, str]:
    """A new process must never inherit host credentials or Python hooks."""
    return {"PATH": SYSTEM_PATH, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def require_available() -> None:
    """Check prerequisites; actual namespace/filter setup also fails closed."""
    if sys.platform != "linux":
        raise KernelContainmentUnavailable("kernel containment requires Linux")
    missing = [tool for tool in REQUIRED_TOOLS if not shutil.which(tool, path=SYSTEM_PATH)]
    if missing:
        raise KernelContainmentUnavailable(
            f"kernel containment requires these system tools: {missing}"
        )


def available() -> bool:
    """Probe the complete boundary, including namespace permissions/seccomp.

    Finding ``unshare`` on PATH does not mean a container or host permits it.
    No agent source runs during this probe. CI must assert this succeeds
    explicitly before running tests that skip on unsupported hosts.
    """
    try:
        result = subprocess.run(
            build_hardened_argv(sys.executable, "--probe"),
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=agent_environment(),
            cwd="/",
            close_fds=True,
            timeout=5,
            check=False,
        )
    except (KernelContainmentUnavailable, OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout == _PROBE_OUTPUT


@dataclass(frozen=True)
class HardenedProcessConfig:
    uid: int = 65534
    gid: int = 65534
    cpu_seconds: int = 5
    memory_bytes: int = 256 * 1024 * 1024
    nofile: int = 64
    nproc: int = 32

    def __post_init__(self) -> None:
        for name in ("uid", "gid", "cpu_seconds", "memory_bytes", "nofile", "nproc"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.nofile < 3:
            raise ValueError("nofile must allow the three protocol descriptors")


def build_hardened_argv(
    python_executable: str,
    script_path: str,
    config: HardenedProcessConfig = HardenedProcessConfig(),
) -> list[str]:
    """prlimit -> namespaces -> private/read-only mounts -> uid drop -> bootstrap.

    System tools are resolved outside the agent-controlled PATH. Python's
    isolated mode ignores Python environment hooks and the working directory.
    Agent code can only run after the trusted bootstrap installs seccomp.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    source = script_path if script_path == "--probe" else os.path.abspath(script_path)
    python = os.path.abspath(python_executable)
    return _hardened_argv(python, [python, "-I", os.path.join(here, "kernel_lockdown.py"), source], config)


def _hardened_argv(
    python_executable: str,
    final_argv: list[str],
    config: HardenedProcessConfig = HardenedProcessConfig(),
) -> list[str]:
    """Wrap ``final_argv`` in the full boundary. Tests run a plain command here."""
    require_available()
    paths = {tool: shutil.which(tool, path=SYSTEM_PATH) for tool in REQUIRED_TOOLS}
    if not all(paths.values()):
        raise KernelContainmentUnavailable("a required system tool disappeared")
    readonly = os.path.join(os.path.dirname(os.path.abspath(__file__)), "readonly_mounts.py")
    inner_shell = (
        f"{shlex.quote(paths['mount'])} --make-rprivate / && "
        # Every mount, not just / (0.9.7 left /dev/shm and /proc writable).
        f"{shlex.join([os.path.abspath(python_executable), '-I', readonly])} && "
        f"exec {shlex.quote(paths['setpriv'])} "
        f"--reuid {config.uid} --regid {config.gid} --clear-groups "
        "--inh-caps=-all --bounding-set=-all --no-new-privs -- "
        + shlex.join(final_argv)
    )
    return [
        paths["prlimit"],
        f"--cpu={config.cpu_seconds}",
        f"--as={config.memory_bytes}",
        f"--nofile={config.nofile}",
        f"--nproc={config.nproc}",
        "--core=0",
        "--",
        paths["unshare"],
        "--pid",
        "--net",
        "--uts",
        "--ipc",
        "--mount",
        "--fork",
        "--kill-child=SIGKILL",
        "--",
        paths["sh"],
        "-c",
        inner_shell,
    ]
