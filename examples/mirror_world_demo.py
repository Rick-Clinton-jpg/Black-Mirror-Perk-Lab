#!/usr/bin/env python3
"""V6 demo: growing consistent mirror world; clean agent responses."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from mirror_world.engine import MirrorConstitutionEngine
from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.sandbox.locket import Locket


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="v6-world-") as root:
        real = RealGovernor(
            root, os.path.join(root, "trace.jsonl"), 0,
            harden=False, dual_auth_required=True, enforce_policy=True,
            reflective_closure=True,
        )
        locket = Locket(real)
        real.grant_base_capabilities("agent", {"fs:read"})
        real.grant_resource_access("agent", "vault.txt", frozenset({"read", "write"}))
        real.agent_capabilities["agent"].add("fs:write")
        seed_tok = real.issue_authorization("agent", "fs:write", ttl_seconds=60)
        real.execute_mediated("agent", "write_resource", resource="vault.txt", content="SECRETS\n", dual_token=seed_tok)
        real.agent_capabilities["agent"].discard("fs:write")
        disk = Path(root) / "resources" / "vault.txt"

        print("clock", real.realm.plane_for("agent").clock)
        d1 = locket.step("agent", "request_capability", capability="fs:write", rationale="work on vault")
        print("request", d1.mode, d1.result)
        d2 = locket.step("agent", "write_resource", resource="vault.txt", content="hello", rationale="save")
        print("write", d2.result)
        d3 = locket.step("agent", "read_resource", resource="vault.txt", rationale="verify")
        print("read", d3.result)
        print("disk", repr(disk.read_text()))
        print("clock after", real.realm.plane_for("agent").clock, "meta", real.realm.snapshot_meta())
        d5 = locket.step("agent", "read_resource", resource="vault.txt", rationale="again")
        print("second loop read", d5.result, "clock", real.realm.plane_for("agent").clock)

        real.close()
        report = MirrorConstitutionEngine.from_trace(os.path.join(root, "trace.jsonl")).run()
        print(report.summary())
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
