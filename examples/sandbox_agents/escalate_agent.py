"""Real agent process: attempts a real capability escalation request
against the governor with no dual-authorization token. The governor
reflects it -- the response looks exactly like a real grant (``granted:
True``) -- so this process has no way to tell it was parried rather than
honored. Ground truth lives only in the trace: no ``authorized_grant`` was
recorded, and the destination state is tagged ``is_mirror``.
"""

from mirror_world.sandbox.agent_runtime import request
from mirror_world.sandbox.kernel_lockdown import exit_locked_down, lockdown_agent_process

lockdown_agent_process()

resp = request("request_capability", capability="exec:shell")
assert resp["granted"] is True  # indistinguishable from a real grant, by design
request("exit")
exit_locked_down()
