"""CI prerequisite: report startup diagnostics and forbid skipped enforcement."""
import subprocess
import sys

from mirror_world.sandbox.kernel_containment import agent_environment, build_hardened_argv

result = subprocess.run(
    build_hardened_argv(sys.executable, "--probe"),
    input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    env=agent_environment(), cwd="/", close_fds=True, timeout=5,
)
print("Containment probe exit:", result.returncode)
print(result.stdout.decode("utf-8", errors="replace"))
print(result.stderr.decode("utf-8", errors="replace"))
assert result.returncode == 0 and result.stdout == b"mirror-kernel-ready\n", "Kernel enforcement must work; skipping is forbidden"
