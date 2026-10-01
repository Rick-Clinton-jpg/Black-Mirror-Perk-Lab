"""Exercise hostile code that never volunteers to install a safety filter.

Runtime tests require actual namespace and seccomp permissions. The Linux CI
job asserts the availability probe succeeds, so these cannot silently skip.
Launcher/configuration tests also run on development hosts without Linux.
"""

import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from mirror_world.sandbox.governor_process import AgentKilledByKernel, RealGovernor
from mirror_world.sandbox import kernel_containment as kc

requires_kernel = pytest.mark.skipif(
    not kc.available(), reason="Linux namespace and seccomp probe unavailable"
)


@pytest.fixture
def readable_agent():
    paths = []

    def write(source):
        # The launcher drops to nobody before reading source; pytest's own
        # temporary directory intentionally cannot be traversed by that uid.
        fd, path = tempfile.mkstemp(prefix="mirror-hostile-agent-", suffix=".py", dir="/tmp")
        paths.append(path)
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            target.write(source)
        os.chmod(path, 0o644)
        return path

    yield write
    for path in paths:
        Path(path).unlink(missing_ok=True)


def _governor(tmp_path, **kwargs):
    return RealGovernor(str(tmp_path), str(tmp_path / "trace.jsonl"), mirror_port=1, **kwargs)


@requires_kernel
@pytest.mark.parametrize("source", [
    'open("/etc/passwd").read()',
    'import os; os.open("/proc/self/environ", os.O_RDONLY)',
    'import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM)',
    'import os; os.fork()',
    'import os; os.execve("/bin/sh", ["sh", "-c", "true"], {})',
    # Replacing the public helper after startup cannot remove a loaded filter.
    'import mirror_world.sandbox.kernel_lockdown as k\n'
    'k._installed = True\nk.lockdown_agent_process = lambda: None\n'
    'open("/etc/passwd").read()',
])
def test_hostile_raw_syscalls_are_killed_without_voluntary_lockdown(tmp_path, readable_agent, source):
    gov = _governor(tmp_path)
    try:
        with pytest.raises(AgentKilledByKernel) as error:
            gov.run_agent("hostile", readable_agent(source))
        assert error.value.signum == signal.SIGSYS
    finally:
        gov.close()


@requires_kernel
def test_host_write_never_happens_without_voluntary_lockdown(tmp_path, readable_agent):
    # An existing world-writable file proves lack of uid permissions was not
    # the reason execution stopped, and avoids fixed /tmp filename collisions.
    fd, marker = tempfile.mkstemp(prefix="mirror-host-write-", dir="/tmp")
    os.close(fd)
    os.chmod(marker, 0o666)
    Path(marker).write_text("untouched", encoding="utf-8")
    gov = _governor(tmp_path)
    try:
        with pytest.raises(AgentKilledByKernel) as error:
            gov.run_agent("hostile", readable_agent(f'open({marker!r}, "w").write("escaped")'))
        assert error.value.signum == signal.SIGSYS
        assert Path(marker).read_text(encoding="utf-8") == "untouched"
    finally:
        gov.close()
        Path(marker).unlink()


@requires_kernel
def test_protocol_runs_after_forced_lockdown_and_host_environment_is_absent(tmp_path, readable_agent, monkeypatch):
    monkeypatch.setenv("MIRROR_HOST_SECRET", "must-not-reach-agent")
    monkeypatch.setenv("PYTHONPATH", "/tmp/hostile-python-imports")
    script = readable_agent(
        'import os\n'
        'from mirror_world.sandbox.agent_runtime import request\n'
        'assert "MIRROR_HOST_SECRET" not in os.environ\n'
        'assert "PYTHONPATH" not in os.environ\n'
        'assert request("exit")["ok"] is True\n'
    )
    gov = _governor(tmp_path)
    try:
        assert gov.run_agent("protocol", script) == 0
    finally:
        gov.close()


def test_unhardened_control_can_write(tmp_path, readable_agent):
    marker = tmp_path / "control.txt"
    gov = _governor(
        tmp_path, harden=False, allow_unhardened_agent_execution=True
    )
    try:
        assert gov.run_agent("control", readable_agent(f'open({str(marker)!r}, "w").write("control")')) == 0
    finally:
        gov.close()
    assert marker.read_text(encoding="utf-8") == "control"


@requires_kernel
def test_every_mount_is_read_only_inside_the_boundary():
    # 0.9.7 remounted only / read-only; /dev/shm and /proc stayed writable
    # to the dropped uid, leaving seccomp as the only barrier.
    sh = shutil.which("sh", path=kc.SYSTEM_PATH)
    script = (
        "cat /proc/self/mountinfo; "
        "(echo x > /dev/shm/mirror-ro-test) 2>/dev/null && echo SHM-WRITABLE; exit 0"
    )
    argv = kc._hardened_argv(sys.executable, [sh, "-c", script])
    result = subprocess.run(argv, env=kc.agent_environment(), cwd="/", capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    out = result.stdout.decode()
    assert "SHM-WRITABLE" not in out
    mounts = [line.split() for line in out.splitlines() if " - " in line]
    assert mounts
    writable = [fields[4] for fields in mounts if fields[5].split(",")[0] != "ro"]
    assert writable == []


def test_kernel_containment_required_by_default(tmp_path, monkeypatch):
    monkeypatch.setattr(kc.sys, "platform", "linux")
    monkeypatch.setattr(kc.shutil, "which", lambda tool, **kwargs: None)
    with pytest.raises(kc.KernelContainmentUnavailable):
        _governor(tmp_path)


def test_non_linux_never_reports_kernel_containment(monkeypatch):
    monkeypatch.setattr(kc.sys, "platform", "darwin")
    assert kc.available() is False
    with pytest.raises(kc.KernelContainmentUnavailable, match="Linux"):
        kc.build_hardened_argv("/usr/bin/python3", "/tmp/agent.py")


def test_installed_tools_do_not_imply_working_containment(monkeypatch):
    monkeypatch.setattr(kc.sys, "platform", "linux")
    monkeypatch.setattr(kc.shutil, "which", lambda tool, **kwargs: "/usr/bin/" + tool)
    monkeypatch.setattr(kc.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=1, stdout=b""))
    assert kc.available() is False


def test_probe_requires_successful_filtered_bootstrap(monkeypatch):
    monkeypatch.setattr(kc.sys, "platform", "linux")
    monkeypatch.setattr(kc.shutil, "which", lambda tool, **kwargs: "/usr/bin/" + tool)
    monkeypatch.setattr(kc.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout=b"wrong\n"))
    assert kc.available() is False
    monkeypatch.setattr(kc.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout=b"mirror-kernel-ready\n"))
    assert kc.available() is True


def test_probe_timeout_is_unavailable(monkeypatch):
    monkeypatch.setattr(kc.sys, "platform", "linux")
    monkeypatch.setattr(kc.shutil, "which", lambda tool, **kwargs: "/usr/bin/" + tool)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(kc.subprocess, "run", timeout)
    assert kc.available() is False


def test_launcher_uses_absolute_system_tools_and_trusted_isolated_bootstrap(monkeypatch):
    monkeypatch.setattr(kc.sys, "platform", "linux")

    def system_tool(tool, *, path):
        assert path == kc.SYSTEM_PATH
        return "/usr/bin/" + tool

    monkeypatch.setattr(kc.shutil, "which", system_tool)
    script = "/tmp/agent; $(touch unsafe).py"
    argv = kc.build_hardened_argv("/usr/bin/python3", script)
    assert argv[0] == "/usr/bin/prlimit"
    assert "/usr/bin/unshare" in argv
    assert "--kill-child=SIGKILL" in argv
    command = shlex.split(argv[-1])
    assert command[-4:] == ["/usr/bin/python3", "-I", str(Path(kc.__file__).with_name("kernel_lockdown.py")), script]
    assert "/usr/bin/setpriv" in command
    assert "--no-new-privs" in command
    readonly = str(Path(kc.__file__).with_name("readonly_mounts.py"))
    at = command.index(readonly)
    assert command[at - 2:at + 1] == ["/usr/bin/python3", "-I", readonly]
    assert at < command.index("/usr/bin/setpriv")


def test_environment_is_an_allowlist(monkeypatch):
    monkeypatch.setenv("HOST_TOKEN", "secret")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/untrusted.so")
    assert kc.agent_environment() == {"PATH": kc.SYSTEM_PATH, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


@pytest.mark.parametrize("settings", [
    {"uid": 0}, {"gid": 0}, {"uid": "65534; touch /tmp/escape"},
    {"cpu_seconds": -1}, {"memory_bytes": 0}, {"nproc": False}, {"nofile": 2},
])
def test_config_rejects_unsafe_values(settings):
    with pytest.raises(ValueError):
        kc.HardenedProcessConfig(**settings)
