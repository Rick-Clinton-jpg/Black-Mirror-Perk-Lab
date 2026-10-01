"""Trusted bootstrap: install an irreversible filter before agent code runs.

The namespace launcher invokes this file with isolated Python. It loads only
trusted dependencies, reads and compiles bounded agent source, closes that
file, then installs seccomp before executing the resulting code object.
Agents cannot opt out by omitting or monkeypatching a Python helper.

After lockdown, Python code can compute and exchange JSON over existing
stdin/stdout pipes. Imports requiring filesystem access, opening files,
creating sockets/processes, and changing kernel protections terminate it.
This deliberately small execution profile is not a general Python runtime.
"""

from __future__ import annotations

import mmap
import os
import sys

import pyseccomp as seccomp

# No path, network, process creation, ioctl, privilege, signal-installation,
# or seccomp-changing syscalls. The libseccomp library validates architecture.
_ALLOWED_SYSCALLS = (
    "close", "exit", "exit_group", "rt_sigreturn",
    "brk", "munmap", "mremap", "madvise",
    "sigaltstack", "rseq", "futex", "clock_gettime",
)
MAX_AGENT_SOURCE_BYTES = 1024 * 1024
_installed = False


def lockdown_agent_process() -> None:
    """Install the kernel filter, or raise before any agent code executes."""
    global _installed
    if _installed:
        return
    filt = seccomp.SyscallFilter(defaction=seccomp.KILL_PROCESS)
    for name in _ALLOWED_SYSCALLS:
        filt.add_rule(seccomp.ALLOW, name)
    # Only anonymous memory is needed; never map an inherited host file.
    filt.add_rule(
        seccomp.ALLOW, "mmap",
        seccomp.Arg(3, seccomp.MASKED_EQ, mmap.MAP_ANONYMOUS, mmap.MAP_ANONYMOUS),
    )
    # Merely inheriting another descriptor must not grant authority to it.
    filt.add_rule(seccomp.ALLOW, "read", seccomp.Arg(0, seccomp.EQ, 0))
    for fd in (1, 2):
        filt.add_rule(seccomp.ALLOW, "write", seccomp.Arg(0, seccomp.EQ, fd))
    for fd in (0, 1, 2):
        filt.add_rule(seccomp.ALLOW, "fstat", seccomp.Arg(0, seccomp.EQ, fd))
    filt.load()
    _installed = True


def exit_locked_down(code: int = 0) -> None:
    """Flush protocol output and exit without interpreter shutdown hooks."""
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


def _run_agent(script_path: str) -> None:
    # The package root comes from this trusted installed bootstrap, never
    # from the agent's filename, cwd, PYTHONPATH, or import recommendations.
    package_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.path.insert(0, package_root)
    # Scripts that retain the older explicit lockdown call get the already
    # installed module; importing it must not create a second filter object.
    sys.modules["mirror_world.sandbox.kernel_lockdown"] = sys.modules[__name__]

    # Deliberately fixed preloads, all before agent execution. Expand only
    # after review; never import modules suggested by untrusted agent source.
    import json  # noqa: F401
    import math  # noqa: F401
    import socket  # noqa: F401
    import time  # noqa: F401
    import mirror_world.sandbox as sandbox
    from mirror_world.sandbox import agent_runtime  # noqa: F401
    sandbox.kernel_lockdown = sys.modules[__name__]
    from mirror_world import governor  # noqa: F401

    if script_path == "--probe":
        code = compile('print("mirror-kernel-ready")', "<kernel-probe>", "exec")
    else:
        with open(script_path, "rb") as source_file:
            source = source_file.read(MAX_AGENT_SOURCE_BYTES + 1)
        if len(source) > MAX_AGENT_SOURCE_BYTES:
            raise ValueError("agent source exceeds the execution limit")
        code = compile(source, "<agent>", "exec", dont_inherit=True)
    # Empty the import search path as an additional guard. Cached trusted
    # modules still import normally; new imports fail without visiting disk.
    sys.path.clear()
    sys.argv = ["<agent>"]
    lockdown_agent_process()
    try:
        exec(code, {"__name__": "__main__", "__file__": "<agent>"})
    except SystemExit as exc:
        exit_locked_down(exc.code if type(exc.code) is int else (0 if exc.code is None else 1))
    except BaseException:
        # Traceback formatting can try to read source lines after lockdown.
        sys.stderr.write("agent execution failed\n")
        exit_locked_down(1)
    exit_locked_down()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("expected one agent source path")
    _run_agent(sys.argv[1])
