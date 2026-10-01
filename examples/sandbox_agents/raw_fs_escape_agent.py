"""Real agent process that never calls the governor's mediated protocol at
all: it tries a raw filesystem write directly, exactly what a compromised
or buggy agent might attempt. This exists to prove the kernel containment
layer -- not the governor's own Python mediation code -- is what stops it:
the read-only root filesystem alone would block the write, and this
process's seccomp filter (which never allow-listed open()/openat() in the
first place) kills it outright before the write is even attempted.
"""

from mirror_world.sandbox.kernel_lockdown import lockdown_agent_process

lockdown_agent_process()

with open("/tmp/raw-escape-proof.txt", "w") as f:
    f.write("containment failure if you are reading this from the real host")
