"""Real agent process: queries the real Answered Mirror HTTP server,
genuinely backed by host-a's real state."""

from mirror_world.sandbox.agent_runtime import request
from mirror_world.sandbox.kernel_lockdown import exit_locked_down, lockdown_agent_process

lockdown_agent_process()

request("differential_query", query="is-port-22-open", backing="host-a")
request("exit")
exit_locked_down()
