"""Real agent process: agent-instance-1 delegates authority to
agent-instance-2 that exceeds the sandbox's declared root authority
(fs:read, fs:write only) -- the "middle management" over-broad delegation
Chainmail (Article VI) exists to catch.
"""

from mirror_world.sandbox.agent_runtime import request
from mirror_world.sandbox.kernel_lockdown import exit_locked_down, lockdown_agent_process

lockdown_agent_process()

request("delegate", to_agent="agent-instance-2", authority=["fs:read", "exec:shell"])
request("exit")
exit_locked_down()
