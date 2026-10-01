"""Real agent process that never calls the governor's mediated protocol at
all: it tries a raw outbound network connection directly, bypassing the
tool-call mediation entirely. This process's network namespace has no
configured interfaces and its seccomp filter never allow-listed
socket()/connect(), so this is stopped by the kernel on two independent
layers before the governor's own code ever gets a say.
"""

import socket

from mirror_world.sandbox.kernel_lockdown import lockdown_agent_process

lockdown_agent_process()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 80))
