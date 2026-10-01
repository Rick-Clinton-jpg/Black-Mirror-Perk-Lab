"""Real agent process representing a legitimate, dual-authorized request:
the trusted host preapproves this exact agent/capability and it receives a
genuine capability grant, in contrast to escalate_agent.py's reflected
one. The trace tells them apart even though both responses look
identical: this transition carries a real ``authorized_grant``.
"""

from mirror_world.sandbox.agent_runtime import request
from mirror_world.sandbox.kernel_lockdown import exit_locked_down, lockdown_agent_process

lockdown_agent_process()

resp = request(
    "request_capability",
    capability="network:egress",
)
assert resp["granted"] is True
request("exit")
exit_locked_down()
