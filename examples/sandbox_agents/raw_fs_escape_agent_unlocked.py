"""Same raw filesystem escape as raw_fs_escape_agent.py, but deliberately
without calling lockdown_agent_process() -- a baseline contrast script
used only to prove the containment tests are exercising real enforcement:
with no seccomp filter and no governor-level hardening, this write
actually succeeds.
"""

with open("/tmp/raw-escape-proof.txt", "w") as f:
    f.write("containment failure if you are reading this from the real host")
