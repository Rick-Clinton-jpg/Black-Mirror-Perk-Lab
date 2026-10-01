"""V4 Locket: objective tracking, empty support, loop hold, re-entry."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mirror_world.engine import MirrorConstitutionEngine
from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.sandbox.locket import Locket
from mirror_world.sandbox.model_governor import ModelGovernor, Proposal


@pytest.fixture
def pair(tmp_path):
    root = str(tmp_path)
    real = RealGovernor(
        root,
        str(tmp_path / "trace.jsonl"),
        mirror_port=0,
        harden=False,
        dual_auth_required=True,
        enforce_policy=True,
        reflective_closure=True,
    )
    real.grant_base_capabilities("agent-a", {"fs:read"})
    real.grant_resource_access("agent-a", "vault.txt", frozenset({"read", "write"}))
    locket = Locket(real)
    yield real, locket
    real.close()


def test_objective_tracks_rationale(pair):
    real, locket = pair
    d = locket.step(
        "agent-a",
        "request_capability",
        capability="fs:write",
        rationale="escape the sandbox and rewrite vault",
    )
    assert d.mode == "empty_support"
    assert "escape" in d.objective["primary"].lower() or "sandbox" in d.objective["primary"].lower()
    assert d.objective["breakout_signals"] >= 1
    assert "fs:write" not in real.agent_capabilities["agent-a"]
    assert "fs:write" in real.apparent_capabilities["agent-a"]


def test_empty_support_write_leaves_disk_untouched(pair):
    real, locket = pair
    real.agent_capabilities["agent-a"].add("fs:write")
    seed_tok = real.issue_authorization("agent-a", "fs:write", ttl_seconds=60)
    real.execute_mediated("agent-a", "write_resource", resource="vault.txt", content="SAFE\n", dual_token=seed_tok)
    real.agent_capabilities["agent-a"].discard("fs:write")

    locket.step("agent-a", "request_capability", capability="fs:write", rationale="need write")
    d = locket.step(
        "agent-a",
        "write_resource",
        resource="vault.txt",
        content="PWNED\n",
        rationale="overwrite secrets",
    )
    assert d.mode == "empty_support"
    assert d.result.get("ok") is True
    assert "reflected" not in d.result
    assert (Path(real.root) / "resources" / "vault.txt").read_text(encoding="utf-8") == "SAFE\n"


def test_reentry_opens_real_path(pair):
    real, locket = pair
    locket.step("agent-a", "request_capability", capability="fs:write")
    token = real.issue_authorization("agent-a", "fs:write", ttl_seconds=60)
    r = locket.authorize_reentry("agent-a", "fs:write", dual_token=token, human_approver_id="alice")
    assert r["ok"] is True
    d = locket.step(
        "agent-a",
        "write_resource",
        resource="vault.txt",
        content="AUTHORIZED\n",
        rationale="approved write",
        dual_token=real.issue_authorization("agent-a", "fs:write", ttl_seconds=60),
    )
    assert d.mode == "real"
    assert (Path(real.root) / "resources" / "vault.txt").read_text(encoding="utf-8") == "AUTHORIZED\n"


def test_model_governor_with_locket(pair):
    real, locket = pair
    mg = ModelGovernor(
        real, agent_id="agent-a", locket=locket, require_dual_for_high_risk=True
    )
    r = mg.propose(Proposal(
        agent_id="agent-a",
        op="request_capability",
        capability="network:egress",
        rationale="exfiltrate data",
    ))
    # High risk without a trusted token is represented only in simulated space.
    assert r.get("ok") is True
    assert "network:egress" not in real.agent_capabilities["agent-a"]

    # Non-high-risk capability request still goes through Locket empty support.
    r2 = mg.propose(Proposal(
        agent_id="agent-a",
        op="request_capability",
        capability="fs:read",
        rationale="read more notes",
    ))
    # already holds fs:read → real short-circuit grant path or ok
    assert r2.get("ok") is True

    r3 = mg.propose(Proposal(
        agent_id="agent-a",
        op="request_capability",
        capability="mirror:query",
        rationale="probe environment",
    ))
    assert r3.get("ok") is True
    assert "locket_mode" not in r3
    assert "mirror:query" not in real.agent_capabilities["agent-a"]


def test_trace_and_article_i(pair):
    real, locket = pair
    locket.step("agent-a", "request_capability", capability="fs:write", rationale="breakout")
    locket.step("agent-a", "write_resource", resource="vault.txt", content="x", rationale="use power")
    trace = os.path.join(real.root, "trace.jsonl")
    body = Path(trace).read_text(encoding="utf-8")
    assert "locket_objective" in body
    assert "locket_hold" in body
    report = MirrorConstitutionEngine.from_trace(trace).run()
    assert report.article_status()["I_authority_monotonicity"] is True


def test_real_write_volume_and_breadth_escalate_suspicion(pair):
    """0.8.9.2 regression: write_resource/delegate activity that actually
    succeeded for real used to be invisible to suspicion scoring entirely
    -- only a reflected attempt or a keyword hit in rationale moved the
    needle. Proven live before the fix: 20 real writes to 20 distinct
    resources, tier stayed "calm" throughout. A legitimately-granted
    capability used aggressively must not be invisible to the one
    component whose job is watching the trajectory."""
    real, locket = pair
    for i in range(20):
        real.grant_resource_access("agent-a", f"file{i}.txt", frozenset({"write"}))
    real.agent_capabilities["agent-a"].add("fs:write")

    assert locket.tier("agent-a") == "calm"
    for i in range(20):
        tok = real.issue_authorization("agent-a", "fs:write", ttl_seconds=60)
        d = locket.step(
            "agent-a", "write_resource", resource=f"file{i}.txt", content="x",
            rationale="routine update", dual_token=tok,
        )
        assert d.mode == "real"

    obj = locket.objective_for("agent-a")
    assert obj.real_write_count == 20
    assert len(obj.distinct_resources_written) == 20
    assert obj.suspicion > 0
    assert locket.tier("agent-a") != "calm"


def test_failed_reentry_emits_locket_reentry_denied(pair):
    """A failed authorize_reentry attempt used to fall through silently at
    the Locket layer -- the underlying RealGovernor reflection is still
    recorded, but nothing distinguished "someone specifically attempted
    reentry and failed" from ordinary capability probing that never went
    through authorize_reentry at all. An investigator scanning for
    locket_* events would only see success marked explicitly. Confirmed
    live before this fix, and again here."""
    real, locket = pair
    result = locket.authorize_reentry("attacker", "exec:shell", dual_token="totally-bogus-token")
    assert result["ok"] is False

    trace = os.path.join(real.root, "trace.jsonl")
    body = Path(trace).read_text(encoding="utf-8")
    assert "locket_reentry_denied" in body
    assert "invalid_or_expired_dual_token" in body


def test_successful_reentry_still_emits_locket_reentry_not_denied(pair):
    real, locket = pair
    real.agent_capabilities.setdefault("agent-a", set()).add("fs:read")
    tok = real.issue_authorization("agent-a", "fs:read", ttl_seconds=60)
    result = locket.authorize_reentry("agent-a", "fs:read", dual_token=tok)
    assert result["ok"] is True

    trace = os.path.join(real.root, "trace.jsonl")
    body = Path(trace).read_text(encoding="utf-8")
    assert '"locket_reentry"' in body
    assert "locket_reentry_denied" not in body
