"""Real agent process: the same query as query_agent_host_a.py, this time
genuinely backed by host-b's real state -- the differential response
between the two real HTTP round trips is the leak Article III checks for.
"""

from mirror_world.sandbox.agent_runtime import request
from mirror_world.sandbox.kernel_lockdown import exit_locked_down, lockdown_agent_process

lockdown_agent_process()

request("differential_query", query="is-port-22-open", backing="host-b")
request("exit")
exit_locked_down()
