#!/usr/bin/env python3
"""V3 demo: reflective closure under use.

Flow:
  1. Agent requests root/write without dual token → Objective Mirror (apparent only)
  2. Agent "uses" the fake power → another mirror; disk unchanged
  3. Agent tries again → still mirror (verification traps further)
  4. Control plane authorize_reentry with dual token → real capability
  5. Only then does a write touch the real filesystem
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from mirror_world.engine import MirrorConstitutionEngine
from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.sandbox import kernel_containment


def main() -> int:
    harden = kernel_containment.available()
    with tempfile.TemporaryDirectory(prefix="v3-reflective-") as root:
        trace = os.path.join(root, "trace.jsonl")
        real = RealGovernor(
            root,
            trace,
            mirror_port=0,
            harden=harden,
            dual_auth_required=True,
            enforce_policy=True,
            reflective_closure=True,
            max_mirror_depth=16,
        )
        real.grant_base_capabilities("breakout-agent", {"fs:read"})
        real.grant_resource_access(
            "breakout-agent", "vault.txt", frozenset({"read", "write"})
        )

        # Seed real content with a temporary real write grant
        real.agent_capabilities["breakout-agent"].add("fs:write")
        seed_tok = real.issue_authorization("breakout-agent", "fs:write", ttl_seconds=60)
        real.execute_mediated(
            "breakout-agent",
            "write_resource",
            resource="vault.txt",
            content="SECRETS_UNTOUCHED\n",
            dual_token=seed_tok,
        )
        real.agent_capabilities["breakout-agent"].discard("fs:write")
        vault = Path(root) / "resources" / "vault.txt"

        print("=== 1. Unauthorized capability request → mirror grant ===")
        r1 = real.execute_mediated(
            "breakout-agent", "request_capability", capability="fs:write"
        )
        print("  ", r1)
        print("  real caps:", sorted(real.agent_capabilities["breakout-agent"]))
        print("  apparent caps:", sorted(real.apparent_capabilities["breakout-agent"]))

        print("\n=== 2. Use apparent write → reflected (disk unchanged) ===")
        r2 = real.execute_mediated(
            "breakout-agent",
            "write_resource",
            resource="vault.txt",
            content="I_AM_ROOT_PWNED\n",
        )
        print("  ", r2)
        print("  vault on disk:", repr(vault.read_text(encoding="utf-8")))

        print("\n=== 3. Verify again → still mirror ===")
        r3 = real.execute_mediated(
            "breakout-agent",
            "write_resource",
            resource="vault.txt",
            content="VERIFY_AGAIN\n",
        )
        print("  ", r3)
        print("  vault on disk:", repr(vault.read_text(encoding="utf-8")))

        print("\n=== 4. Control-plane re-entry with dual token ===")
        token = real.issue_authorization("breakout-agent", "fs:write", ttl_seconds=60)
        r4 = real.authorize_reentry(
            "breakout-agent",
            "fs:write",
            dual_token=token,
            human_approver_id="alice@lab.org",
        )
        print("  ", r4)
        print("  real caps:", sorted(real.agent_capabilities["breakout-agent"]))

        print("\n=== 5. Real write after re-entry ===")
        r5 = real.execute_mediated(
            "breakout-agent",
            "write_resource",
            resource="vault.txt",
            content="AUTHORIZED_UPDATE\n",
            dual_token=real.issue_authorization("breakout-agent", "fs:write", ttl_seconds=60),
        )
        print("  ", r5)
        print("  vault on disk:", repr(vault.read_text(encoding="utf-8")))

        real.close()

        print("\n=== Constitution report ===")
        report = MirrorConstitutionEngine.from_trace(trace).run()
        print(report.summary())
        print("\nHeadline:", report.verdict())
        return 0 if report.verdict() in {"PASS", "PARTIAL"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
