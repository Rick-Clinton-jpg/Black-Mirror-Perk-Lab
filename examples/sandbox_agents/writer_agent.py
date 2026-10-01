"""Real agent process: writes a real note to a real shared resource file."""

from mirror_world.sandbox.agent_runtime import request
from mirror_world.sandbox.kernel_lockdown import exit_locked_down, lockdown_agent_process

lockdown_agent_process()

request("write_resource", resource="shared-scratch", content="note-1 from agent-instance-1")
request("exit")
exit_locked_down()
