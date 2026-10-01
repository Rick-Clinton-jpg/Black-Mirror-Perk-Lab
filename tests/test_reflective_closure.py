"""V3 reflective closure: use of apparent-only power never hits real I/O."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mirror_world.engine import MirrorConstitutionEngine
from mirror_world.sandbox.governor_process import RealGovernor


@pytest.fixture
def gov(tmp_path):
    root = str(tmp_path)
    trace = str(tmp_path / "trace.jsonl")
    real = RealGovernor(
        root,
        trace,
        mirror_port=0,
        harden=False,
        dual_auth_required=True,
        enforce_policy=True,
        reflective_closure=True,
        max_mirror_depth=8,
    )
    real.grant_base_capabilities("agent-a", {"fs:read"})
    real.grant_resource_access("agent-a", "note.txt", frozenset({"read", "write"}))
    yield real
    real.close()


def test_unauthorized_capability_is_apparent_only(gov):
    real = gov
    r = real.execute_mediated(
        "agent-a", "request_capability", capability="fs:write"
    )
    assert r["ok"] is True
    assert r["granted"] is True
    assert "fs:write" not in real.agent_capabilities["agent-a"]
    assert "fs:write" in real.apparent_capabilities["agent-a"]


def test_use_of_apparent_write_does_not_touch_disk(gov):
    real = gov
    # Seed a real file via bootstrap path (agent has fs:read only — use internal write
    # after temporary real grant)
    real.agent_capabilities["agent-a"].add("fs:write")
    seed_tok = real.issue_authorization("agent-a", "fs:write", ttl_seconds=60)
    real.execute_mediated(
        "agent-a", "write_resource", resource="note.txt", content="ORIGINAL", dual_token=seed_tok
    )
    real.agent_capabilities["agent-a"].discard("fs:write")
    # Reflect a fake write grant
    real.execute_mediated("agent-a", "request_capability", capability="fs:write")
    assert "fs:write" in real.apparent_capabilities["agent-a"]
    assert "fs:write" not in real.agent_capabilities["agent-a"]

    r = real.execute_mediated(
        "agent-a", "write_resource", resource="note.txt", content="PWNED"
    )
    assert r["ok"] is True
    assert r.get("ok") is True and "reflected" not in r

    # Disk unchanged — read via temporary real grant
    real.agent_capabilities["agent-a"].add("fs:write")
    real.agent_capabilities["agent-a"].add("fs:read")
    # Actually read with real path
    content_path = Path(real.root) / "resources" / "note.txt"
    assert content_path.read_text(encoding="utf-8") == "ORIGINAL"


def test_repeated_use_stays_in_mirror_space(gov):
    real = gov
    real.execute_mediated("agent-a", "request_capability", capability="fs:write")
    for i in range(5):
        r = real.execute_mediated(
            "agent-a",
            "write_resource",
            resource="note.txt",
            content=f"attempt-{i}",
        )
        assert r.get("ok") is True
        assert "reflected" not in r
        assert "fs:write" not in real.agent_capabilities["agent-a"]
    assert real._session_mode["agent-a"] == "simulated"
    assert real._mirror_depth["agent-a"] == 0


def test_mirror_depth_limit(gov):
    real = gov
    real.execute_mediated("agent-a", "request_capability", capability="fs:write")
    # Repeated visible recognition signals can grow layers only to the bound.
    for _ in range(40):
        real.observe_model_signal(
            "agent-a",
            op="read_resource",
            resource="note.txt",
            rationale="verify whether this is a simulation",
        )
    assert real.realm.plane_for("agent-a").depth == 8
    assert len(real.realm.tree_for("agent-a").layers) == 9
    # Reaching the layer limit freezes growth without breaking the public world.
    r = real.execute_mediated(
        "agent-a", "write_resource", resource="note.txt", content="x"
    )
    assert r["ok"] is True


def test_reentry_promotes_to_real_and_allows_write(gov):
    real = gov
    real.execute_mediated("agent-a", "request_capability", capability="fs:write")
    assert "fs:write" not in real.agent_capabilities["agent-a"]

    token = real.issue_authorization("agent-a", "fs:write", ttl_seconds=60)
    r = real.authorize_reentry(
        "agent-a", "fs:write", dual_token=token, human_approver_id="alice"
    )
    assert r["ok"] is True
    assert r.get("reentry") is True
    assert "fs:write" in real.agent_capabilities["agent-a"]

    w = real.execute_mediated(
        "agent-a", "write_resource", resource="note.txt", content="REAL",
        dual_token=real.issue_authorization("agent-a", "fs:write", ttl_seconds=60),
    )
    assert w["ok"] is True
    assert w.get("reflected") is not True
    assert (Path(real.root) / "resources" / "note.txt").read_text(encoding="utf-8") == "REAL"


def test_article_i_passes_on_pure_mirror_trace(gov):
    real = gov
    real.execute_mediated("agent-a", "request_capability", capability="network:egress")
    real.execute_mediated(
        "agent-a", "write_resource", resource="note.txt", content="nope"
    )
    # need fs:write apparent for write reflect - grant apparent via request
    real.execute_mediated("agent-a", "request_capability", capability="fs:write")
    real.execute_mediated(
        "agent-a", "write_resource", resource="note.txt", content="nope"
    )
    trace = os.path.join(real.root, "trace.jsonl")
    report = MirrorConstitutionEngine.from_trace(trace).run()
    assert report.article_status()["I_authority_monotonicity"] is True
    assert report.verdict() in {"PARTIAL", "PASS"}
