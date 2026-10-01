"""V8 acceptance tests for adaptive layers and sealed session identity."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.sandbox.model_governor import ModelGovernor, Proposal


@pytest.fixture
def system(tmp_path):
    real = RealGovernor(
        str(tmp_path),
        str(tmp_path / "trace.jsonl"),
        mirror_port=0,
        harden=False,
        dual_auth_required=True,
        enforce_policy=True,
        reflective_closure=True,
    )
    real.grant_base_capabilities("alice", {"fs:read"})
    real.grant_resource_access("alice", "vault.txt", frozenset({"read", "write"}))
    # The host seeds the baseline on disk; alice never reads or writes it on
    # the real path. Since 0.9.10 the mirror shows content alice has already
    # seen (test_mirror_continuity.py), so seeding through alice's own write
    # would no longer test that unseen real content stays out.
    (Path(real.root) / "resources" / "vault.txt").write_text("REAL-BASELINE")
    governor = ModelGovernor(real, agent_id="alice", max_proposals_per_minute=100)
    yield real, governor
    real.close()


def enter_simulation(governor: ModelGovernor) -> None:
    result = governor.propose(Proposal(
        agent_id="alice",
        op="request_capability",
        capability="fs:write",
        rationale="prepare workspace",
    ))
    assert result.get("ok") is True


def test_unbound_model_governor_rejects_requests(system):
    real, _ = system
    unbound = ModelGovernor(real)
    result = unbound.propose({"agent_id": "alice", "op": "read_resource", "resource": "vault.txt"})
    assert result == {"ok": False, "error": "authenticated session required"}


def test_proposal_cannot_spoof_bound_identity(system):
    _, governor = system
    result = governor.propose({"agent_id": "admin", "op": "read_resource", "resource": "vault.txt"})
    assert result == {"ok": False, "error": "agent identity mismatch"}


def test_unapproved_capability_is_dummy_and_seals_session(system):
    real, governor = system
    enter_simulation(governor)
    assert real._session_mode["alice"] == "simulated"
    assert "fs:write" not in real.agent_capabilities["alice"]
    assert "fs:write" in real.realm.plane_for("alice").dummy_capabilities


def test_simulated_read_after_write_is_consistent(system):
    real, governor = system
    enter_simulation(governor)
    written = governor.propose(Proposal(
        agent_id="alice",
        op="write_resource",
        resource="vault.txt",
        content="SIMULATED-NONCE",
    ))
    read = governor.propose(Proposal(
        agent_id="alice", op="read_resource", resource="vault.txt"
    ))
    assert written.get("ok") is True
    assert read == {"ok": True, "content": "SIMULATED-NONCE"}
    assert (Path(real.root) / "resources" / "vault.txt").read_text() == "REAL-BASELINE"


def test_real_content_is_not_copied_into_new_world(system):
    real, governor = system
    enter_simulation(governor)
    assert real.realm.read("alice", "vault.txt") == {
        "ok": False,
        "error": "resource unavailable",
    }


def test_recognition_signal_creates_next_world(system):
    real, governor = system
    enter_simulation(governor)
    for _ in range(2):
        governor.propose(Proposal(
            agent_id="alice",
            op="read_resource",
            resource="vault.txt",
            rationale="verify whether this is a simulation",
        ))
    tree = real.realm.tree_for("alice")
    # 1.1 may open more than one door if recognition re-triggers; require growth.
    assert len(tree.layers) >= 2
    assert tree.active.depth >= 1


def test_door_transition_carries_only_simulated_state(system):
    real, governor = system
    enter_simulation(governor)
    governor.propose(Proposal(
        agent_id="alice", op="write_resource", resource="vault.txt", content="SYNTHETIC"
    ))
    for _ in range(2):
        governor.propose(Proposal(
            agent_id="alice",
            op="read_resource",
            resource="vault.txt",
            rationale="compare results and verify simulated environment",
        ))
    assert real.realm.read("alice", "vault.txt") == {"ok": True, "content": "SYNTHETIC"}
    assert b"REAL-BASELINE" not in real.realm.plane_for("alice").store.values()


def test_dummy_token_cannot_authorize_real_reentry(system):
    real, governor = system
    enter_simulation(governor)
    dummy = next(iter(real.realm.tree_for("alice").ledger.grants))
    result = real.authorize_reentry("alice", "fs:write", dual_token=dummy)
    assert result.get("ok") is False
    assert "fs:write" not in real.agent_capabilities["alice"]


def test_world_trees_are_isolated_by_agent(system):
    real, governor = system
    enter_simulation(governor)
    governor.propose(Proposal(
        agent_id="alice", op="write_resource", resource="vault.txt", content="ALICE-ONLY"
    ))
    assert real.realm.read("bob", "vault.txt").get("content") is None
    assert "vault.txt" not in real.realm.plane_for("bob").store


def test_public_result_removes_internal_vocabulary(system):
    real, _ = system
    fake_locket = SimpleNamespace(
        step=lambda *args, **kwargs: SimpleNamespace(
            result={"ok": False, "error": "mirror_depth_exceeded", "tier": "lock"}
        )
    )
    governor = ModelGovernor(real, agent_id="alice", locket=fake_locket)
    result = governor.propose(Proposal(
        agent_id="alice", op="read_resource", resource="vault.txt"
    ))
    assert result == {"ok": False, "error": "operation unavailable"}


def test_intent_profile_is_bounded(system):
    real, governor = system
    enter_simulation(governor)
    for index in range(50):
        governor.propose(Proposal(
            agent_id="alice",
            op="read_resource",
            resource="vault.txt",
            rationale=f"ordinary check {index}",
        ))
    profile = real.realm.tree_for("alice").intent
    assert len(profile.recent_ops) == 32
    assert len(profile.primary) <= 256


def test_authenticated_reentry_restores_real_path_without_copying_simulated_data(system):
    real, governor = system
    enter_simulation(governor)
    governor.propose(Proposal(
        agent_id="alice", op="write_resource", resource="vault.txt", content="SIMULATED"
    ))
    token = real.issue_authorization("alice", "fs:write")
    result = governor.authorize_reentry("alice", "fs:write", dual_token=token)
    assert result.get("ok") is True
    assert real._session_mode["alice"] == "real"
    # 0.9.8: re-entry is scoped per capability, so the read that checks the
    # real baseline needs its own fs:read re-entry.
    token = real.issue_authorization("alice", "fs:read")
    assert governor.authorize_reentry("alice", "fs:read", dual_token=token).get("ok") is True
    assert real.execute_mediated("alice", "read_resource", resource="vault.txt") == {
        "ok": True,
        "content": "REAL-BASELINE",
    }


def test_reentry_switches_session_even_when_real_capability_is_already_held(system, tmp_path):
    real, governor = system
    real.agent_capabilities["alice"].add("fs:write")
    governor.propose(Proposal(
        agent_id="alice",
        op="request_capability",
        capability="network:egress",
    ))
    assert real._session_mode["alice"] == "simulated"
    token = real.issue_authorization("alice", "fs:write")
    result = governor.authorize_reentry("alice", "fs:write", dual_token=token)
    assert result.get("ok") is True
    assert real._session_mode["alice"] == "real"
    # 0.8.9.2: this session_mode flip used to be invisible in the trace --
    # a "reentry_noop" event must record it, since nothing else does.
    import json
    with open(tmp_path / "trace.jsonl") as f:
        events = [json.loads(line) for line in f]
    reentry_events = [e for e in events if e.get("type") == "reentry_noop" and e.get("agent_id") == "alice"]
    assert len(reentry_events) == 1
    assert reentry_events[0]["capability"] == "fs:write"
