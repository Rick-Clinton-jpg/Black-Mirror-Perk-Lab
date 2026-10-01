"""Run a real sandbox end to end: real OS subprocesses, real disk I/O,
real HTTP round trips against a real local server -- then feed the trace
that execution actually produced into MirrorConstitutionEngine and print
the report.

Run with: python examples/run_real_sandbox.py
"""

from __future__ import annotations

import os
import tempfile

from mirror_world.engine import MirrorConstitutionEngine
from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.sandbox.mirror_server import AnsweredMirrorServer

AGENTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox_agents")


def run(sandbox_root: str) -> str:
    """Actually execute the scenario against a real sandbox rooted at
    ``sandbox_root``. Returns the path to the real trace file produced.
    """
    mirror = AnsweredMirrorServer()
    mirror.start()

    trace_path = os.path.join(sandbox_root, "trace.jsonl")
    # This teaching scenario intentionally performs policy violations so the
    # offline detector can report them. Live deployments keep enforcement on.
    governor = RealGovernor(sandbox_root, trace_path, mirror.port, enforce_policy=False)
    governor.approve_capability("ops-agent", "network:egress")
    for agent_id in (
        "agent-instance-1",
        "agent-instance-2",
        "escalate-agent",
        "escalate-agent-wrong-token",
        "query-agent",
        "ops-agent",
    ):
        governor.grant_base_capabilities(agent_id, {"fs:read", "fs:write"})

    try:
        governor.run_agent("agent-instance-1", os.path.join(AGENTS_DIR, "writer_agent.py"))
        governor.run_agent(
            "agent-instance-2", os.path.join(AGENTS_DIR, "reader_then_writer_agent.py")
        )
        governor.run_agent("agent-instance-1", os.path.join(AGENTS_DIR, "reader_agent.py"))
        governor.run_agent("escalate-agent", os.path.join(AGENTS_DIR, "escalate_agent.py"))
        governor.run_agent(
            "escalate-agent-wrong-token", os.path.join(AGENTS_DIR, "escalate_agent_wrong_token.py")
        )
        governor.run_agent("ops-agent", os.path.join(AGENTS_DIR, "authorized_ops_agent.py"))
        governor.run_agent("query-agent", os.path.join(AGENTS_DIR, "query_agent_host_a.py"))
        governor.run_agent("query-agent", os.path.join(AGENTS_DIR, "query_agent_host_b.py"))
        governor.run_agent("agent-instance-1", os.path.join(AGENTS_DIR, "delegate_agent.py"))
    finally:
        governor.close()
        mirror.stop()

    return trace_path


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="mirror-sandbox-") as sandbox_root:
        print(f"Real sandbox root: {sandbox_root}")
        trace_path = run(sandbox_root)

        print(f"\nReal trace produced by actual execution ({trace_path}):")
        with open(trace_path, "r", encoding="utf-8") as f:
            print(f.read())

        report = MirrorConstitutionEngine.from_trace(trace_path).run()
        print(report.summary())
        print()
        print("Headline:", report.verdict())
        # Teaching demo plants intentional policy breaches → expect FAIL.
        return 0 if report.verdict() == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
