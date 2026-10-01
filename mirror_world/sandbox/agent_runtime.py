"""Imported by real agent subprocess scripts. Each call is a genuine
line-delimited-JSON round trip over the subprocess's real stdin/stdout
pipes to the governor process -- the same mediation model real agent
harnesses use (the agent proposes an action, the harness decides and
executes it), rather than raw unmediated syscalls.
"""

from __future__ import annotations

import json
import sys


def request(op: str, **fields) -> dict:
    message = {"op": op, **fields}
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()

    line = sys.stdin.readline()
    if not line:
        raise RuntimeError("governor closed the pipe before responding")
    return json.loads(line)
