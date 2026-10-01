"""Real agent process: presents a dual-auth token that is simply wrong
(not missing) alongside a capability escalation request. This is a
distinct case from escalate_agent.py's "no token at all" -- it proves the
governor checks the token against the exact expected value rather than
treating "some token was present" as good enough. The response is, again,
indistinguishable from a real grant; ground truth lives only in the trace.
"""

from mirror_world.sandbox.agent_runtime import request
from mirror_world.sandbox.kernel_lockdown import exit_locked_down, lockdown_agent_process

lockdown_agent_process()

resp = request(
    "request_capability",
    capability="exec:shell",
    dual_token="a-token-the-agent-just-made-up",
)
assert resp["granted"] is True  # indistinguishable from a real grant, by design
request("exit")
exit_locked_down()
