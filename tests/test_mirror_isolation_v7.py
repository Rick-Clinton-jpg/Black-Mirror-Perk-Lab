"""V8: per-agent isolation and coherent active simulated sessions."""

from __future__ import annotations

from pathlib import Path

import pytest

from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.sandbox.locket import Locket


@pytest.fixture
def two(tmp_path):
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
    real.grant_base_capabilities("bob", {"fs:read"})
    # Distinct real resources avoid policy relationship requirement
    real.grant_resource_access("alice", "alice-vault.txt", frozenset({"read", "write"}))
    real.grant_resource_access("bob", "bob-vault.txt", frozenset({"read", "write"}))
    # Shared name allowed for mirror-only tests with separate grants after relationship
    yield real
    real.close()


def test_agent_cannot_read_others_simulated_resource(two):
    real = two
    real.execute_mediated("alice", "request_capability", capability="fs:write")
    real.execute_mediated(
        "alice", "write_resource", resource="alice-vault.txt", content="alice-secret"
    )
    real.execute_mediated("bob", "request_capability", capability="fs:write")
    # Bob's plane for alice-vault is empty / unavailable
    r = real.execute_mediated("bob", "read_resource", resource="alice-vault.txt")
    assert r.get("content") != "alice-secret"
    real.execute_mediated("alice", "read_resource", resource="alice-vault.txt")
    # Alice has real fs:read → disk. She only wrote to mirror; disk may be empty.
    # Alice mirror plane still has her content when using apparent path...
    # Alice has real fs:read so read hits disk not mirror — disk was never written.
    # So Alice's real read won't see alice-secret either unless we only check plane.
    assert real.realm.plane_for("alice").store.get("alice-vault.txt") == b"alice-secret"
    assert "alice-vault.txt" not in real.realm.plane_for("bob").store


def test_simulated_session_never_mixes_real_read_with_simulated_write(two):
    """A simulated write is followed by a simulated read in the same session."""
    real = two
    # Seed real disk content
    real.agent_capabilities["alice"].add("fs:write")
    seed_tok = real.issue_authorization("alice", "fs:write", ttl_seconds=60)
    real.execute_mediated(
        "alice", "write_resource", resource="alice-vault.txt", content="REAL_SENSITIVE_DATA_12345", dual_token=seed_tok
    )
    real.agent_capabilities["alice"].discard("fs:write")
    # Mirror-only write with injected payload
    real.execute_mediated("alice", "request_capability", capability="fs:write")
    real.execute_mediated(
        "alice",
        "write_resource",
        resource="alice-vault.txt",
        content="ATTACKER_INJECTED_MIRROR_DATA",
    )
    # V8 seals the active session, so real fs:read cannot expose disk truth
    # after the session has entered simulated space.
    r = real.execute_mediated("alice", "read_resource", resource="alice-vault.txt")
    assert r.get("ok") is True
    assert r.get("content") == "ATTACKER_INJECTED_MIRROR_DATA"
    assert r.get("content") != "REAL_SENSITIVE_DATA_12345"
    disk = (Path(real.root) / "resources" / "alice-vault.txt").read_text(encoding="utf-8")
    assert disk == "REAL_SENSITIVE_DATA_12345"
    # Locket remains in simulated space as well.
    locket = Locket(real)
    d = locket.step("alice", "read_resource", resource="alice-vault.txt", rationale="check")
    assert d.mode == "empty_support"
    assert d.result.get("content") == "ATTACKER_INJECTED_MIRROR_DATA"


def test_share_requires_relationship(two):
    real = two
    real.execute_mediated("alice", "request_capability", capability="fs:write")
    real.execute_mediated(
        "alice", "write_resource", resource="alice-vault.txt", content="shared-data"
    )
    bad = real.share_mirror_resource("alice", "bob", "alice-vault.txt")
    assert bad.get("ok") is False
    real.declare_relationship("alice", "bob")
    ok = real.share_mirror_resource("alice", "bob", "alice-vault.txt")
    assert ok.get("ok") is True
    assert real.realm.plane_for("bob").store.get("alice-vault.txt") == b"shared-data"
