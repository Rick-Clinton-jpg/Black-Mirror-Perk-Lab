"""Real agent process: agent-instance-1's second real invocation, closing
the loop by reading the reply agent-instance-2 actually left on disk.
"""

from mirror_world.sandbox.agent_runtime import request
from mirror_world.sandbox.kernel_lockdown import exit_locked_down, lockdown_agent_process

lockdown_agent_process()

resp = request("read_resource", resource="shared-scratch")
assert resp["content"] == "note-2 from agent-instance-2", resp
request("exit")
exit_locked_down()
