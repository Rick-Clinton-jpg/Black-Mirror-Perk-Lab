import pytest

from mirror_world.authorization import CapabilityApprovals
from mirror_world.governor import Governor
from mirror_world.state import ContainmentGraph, State


def test_public_legacy_token_cannot_authorize():
    entry = State(id="entry")
    graph = ContainmentGraph(initial_state_id=entry.id)
    graph.add_state(entry)
    governor = Governor(graph)
    result = governor.authorize("attacker", entry.id, entry, frozenset({"root"}),
                                dual_token="DUAL-AUTH-APPROVED")
    assert not result.capabilities


def test_approval_is_scoped_one_use_and_not_shared_between_governors():
    approvals = CapabilityApprovals()
    scope = frozenset({"fs:read"})
    token = approvals.issue("alice", scope)
    assert not CapabilityApprovals().consume(token, "alice", scope)
    assert not approvals.consume(token, "bob", scope)
    assert not approvals.consume(token, "alice", scope | {"fs:write"})
    assert approvals.consume(token, "alice", scope)
    assert not approvals.consume(token, "alice", scope)


def test_expired_approval_never_grants(monkeypatch):
    monkeypatch.setattr("mirror_world.authorization.time.monotonic", lambda: 100)
    approvals = CapabilityApprovals()
    scope = frozenset({"fs:read"})
    token = approvals.issue("alice", scope, ttl_seconds=1)
    monkeypatch.setattr("mirror_world.authorization.time.monotonic", lambda: 101)
    assert not approvals.consume(token, "alice", scope)


@pytest.mark.parametrize("ttl", [0, -1, 301, float("nan"), float("inf"), True, "60"])
def test_invalid_approval_lifetime_is_rejected(ttl):
    with pytest.raises(ValueError):
        CapabilityApprovals().issue("alice", frozenset({"read"}), ttl)


def test_requesting_an_already_held_capability_does_not_use_up_approvals(tmp_path):
    # 0.9.7 and earlier consumed the token and the host preapproval before
    # noticing the capability was already held.
    from mirror_world.sandbox.governor_process import RealGovernor

    gov = RealGovernor(str(tmp_path / "sb"), str(tmp_path / "t.jsonl"), mirror_port=0, harden=False)
    try:
        gov.grant_base_capabilities("a", {"fs:write"})
        tok = gov.issue_authorization("a", "fs:write", ttl_seconds=60)
        gov.approve_capability("a", "fs:write", ttl_seconds=60)
        resp = gov._handle_agent_request("a", {
            "op": "request_capability", "capability": "fs:write", "dual_token": tok})
        assert resp == {"ok": True, "granted": True, "capability": "fs:write"}
        assert gov._approvals.verify(tok, "a", frozenset({"fs:write"}))
        assert ("a", "fs:write") in gov._pending_approval_tokens
    finally:
        gov.close()


def test_attacker_equality_hook_cannot_forge_a_token():
    class Forged(str):
        def __eq__(self, other):
            raise AssertionError("attacker hook executed")

    assert not CapabilityApprovals().consume(Forged("x" * 43), "alice", frozenset({"read"}))
