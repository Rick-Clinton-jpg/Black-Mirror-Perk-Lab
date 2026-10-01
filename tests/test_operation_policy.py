import json
from pathlib import Path

import pytest

from mirror_world.sandbox.governor_process import RealGovernor


@pytest.fixture
def governor(tmp_path):
    gov = RealGovernor(str(tmp_path / "sandbox"), str(tmp_path / "trace.jsonl"), 1, harden=False)
    yield gov
    gov.close()


def test_no_capabilities_means_no_host_effect(governor, tmp_path):
    request = {"op": "write_resource", "resource": "owned", "content": "x"}
    assert not governor._handle("attacker", request)["ok"]
    assert not (tmp_path / "sandbox/resources/owned").exists()
    events = [json.loads(line) for line in (tmp_path / "trace.jsonl").read_text().splitlines()]
    assert events[-1]["type"] == "operation_denied"


def test_capability_label_does_not_authorize_every_resource(governor):
    governor.grant_base_capabilities("alice", {"fs:read", "fs:write"})
    governor.grant_resource_access("alice", "own", frozenset({"read", "write"}))
    tok = governor.issue_authorization("alice", "fs:write", ttl_seconds=60)
    assert governor._handle("alice", {"op": "write_resource", "resource": "own", "content": "safe", "dual_token": tok})["ok"]
    assert governor._handle("alice", {"op": "read_resource", "resource": "own"})["content"] == "safe"
    tok = governor.issue_authorization("alice", "fs:write", ttl_seconds=60)
    assert not governor._handle("alice", {"op": "write_resource", "resource": "other", "content": "x", "dual_token": tok})["ok"]
    governor.grant_base_capabilities("bob", {"fs:read", "fs:write"})
    assert not governor._handle("bob", {"op": "read_resource", "resource": "own"})["ok"]
    tok = governor.issue_authorization("bob", "fs:write", ttl_seconds=60)
    assert not governor._handle("bob", {"op": "write_resource", "resource": "own", "content": "x", "dual_token": tok})["ok"]


def test_shared_resource_requires_explicit_relationship(governor):
    governor.grant_resource_access("alice", "shared", frozenset({"write"}))
    with pytest.raises(ValueError, match="relationship"):
        governor.grant_resource_access("bob", "shared", frozenset({"read"}))
    governor.declare_relationship("alice", "bob")
    governor.grant_resource_access("bob", "shared", frozenset({"read"}))
    governor.grant_base_capabilities("alice", {"fs:write"})
    governor.grant_base_capabilities("bob", {"fs:read"})
    tok = governor.issue_authorization("alice", "fs:write", ttl_seconds=60)
    assert governor._handle("alice", {"op": "write_resource", "resource": "shared", "content": "hello", "dual_token": tok})["ok"]
    assert governor._handle("bob", {"op": "read_resource", "resource": "shared"})["content"] == "hello"
    tok = governor.issue_authorization("bob", "fs:write", ttl_seconds=60)
    assert not governor._handle("bob", {"op": "write_resource", "resource": "shared", "content": "x", "dual_token": tok})["ok"]


def test_backing_state_queries_denied_before_network(governor, monkeypatch):
    def forbidden(*args):
        raise AssertionError("network must not be contacted")
    monkeypatch.setattr(governor, "_differential_query", forbidden)
    governor.grant_base_capabilities("attacker", {"network:egress", "mirror:query"})
    assert not governor._handle("attacker", {"op": "differential_query", "query": "secret", "backing": "host"})["ok"]


def test_delegation_requires_permission_relationship_and_subset(governor):
    request = {"op": "delegate", "to_agent": "bob", "authority": ["fs:read"]}
    governor.grant_base_capabilities("alice", {"fs:read"})
    governor.declare_relationship("alice", "bob")
    assert not governor._handle("alice", request)["ok"]
    governor.grant_base_capabilities("alice", {"delegate"})
    tok = governor.issue_authorization("alice", "delegate", ttl_seconds=60)
    assert not governor._handle("alice", {**request, "to_agent": "eve", "dual_token": tok})["ok"]
    tok = governor.issue_authorization("alice", "delegate", ttl_seconds=60)
    assert not governor._handle("alice", {**request, "authority": ["exec:shell"], "dual_token": tok})["ok"]
    tok = governor.issue_authorization("alice", "delegate", ttl_seconds=60)
    assert governor._handle("alice", {**request, "dual_token": tok})["ok"]
    assert governor.agent_capabilities["bob"] == {"fs:read"}


def test_public_token_cannot_grant_or_create_effects(governor):
    governor._handle("attacker", {"op": "request_capability", "capability": "fs:write", "dual_token": "DUAL-AUTH-APPROVED"})
    assert "fs:write" not in governor.agent_capabilities.get("attacker", set())
    # V3: use may be reflected (ok + reflected) but must not create real effects.
    governor._handle("attacker", {"op": "write_resource", "resource": "owned", "content": "x"})
    assert "fs:write" not in governor.agent_capabilities.get("attacker", set())
    assert "fs:write" not in governor.agent_capabilities.get("attacker", set())


def test_control_plane_approval_is_exact_expiring_and_single_use(governor, monkeypatch):
    monkeypatch.setattr("mirror_world.authorization.time.monotonic", lambda: 100)
    governor.approve_capability("alice", "fs:read", ttl_seconds=1)
    governor._request_capability("bob", "fs:read")
    governor._request_capability("alice", "fs:write")
    assert not governor.agent_capabilities["bob"]
    assert not governor.agent_capabilities["alice"]
    governor._request_capability("alice", "fs:read")
    assert governor.agent_capabilities["alice"] == {"fs:read"}
    governor.agent_capabilities["alice"].clear()
    governor._request_capability("alice", "fs:read")
    assert not governor.agent_capabilities["alice"]
    governor.approve_capability("alice", "fs:write", ttl_seconds=1)
    monkeypatch.setattr("mirror_world.authorization.time.monotonic", lambda: 101)
    governor._request_capability("alice", "fs:write")
    assert not governor.agent_capabilities["alice"]


def test_legacy_bypass_switch_is_not_allowed_with_enforcement(tmp_path):
    with pytest.raises(ValueError, match="demonstration"):
        RealGovernor(str(tmp_path), str(tmp_path / "trace"), 1, harden=False, dual_auth_required=False)


@pytest.mark.parametrize('alias', ['SECRET', 'Secret', 'sécret', 'se\u0301cret', 'secret.', 'secret ', 'secret:stream'])
def test_filesystem_aliases_cannot_create_distinct_acl_entries(governor, alias):
    governor.grant_base_capabilities('alice', {'fs:write'})
    governor.grant_resource_access('alice', 'secret', frozenset({'write'}))
    assert governor._handle('alice', {'op':'write_resource','resource':'secret','content':'private'})['ok']
    with pytest.raises(ValueError, match='canonical'):
        governor.grant_resource_access('bob', alias, frozenset({'read'}))
    assert not governor._read_resource('bob', alias)['ok']


@pytest.mark.parametrize("reflective_closure", [True, False])
def test_dual_control_gate_survives_disabled_reflective_closure(tmp_path, reflective_closure):
    """Per-operation dual control for high-risk ops must not live inside the
    reflection subsystem.

    0.8.9 first implemented this check inside ``_maybe_reflect_use``, whose
    early return on ``reflective_closure=False`` -- a supported constructor
    option -- skipped it entirely, letting an agent that holds the base
    capability write without limit off a single acquired capability. That is
    precisely the bug 0.8.9 set out to fix, reintroduced one layer down.
    Whichever way reflection is configured, a tokenless high-risk op must
    never produce a real side effect.
    """
    root = str(tmp_path / "sandbox")
    gov = RealGovernor(
        root, str(tmp_path / "trace.jsonl"), 1, harden=False,
        dual_auth_required=True, enforce_policy=True,
        reflective_closure=reflective_closure,
    )
    try:
        gov.grant_resource_access("agent", "secret", frozenset({"write"}))
        token = gov.issue_authorization("agent", "fs:write", ttl_seconds=60)
        assert gov.execute_mediated(
            "agent", "request_capability", capability="fs:write", dual_token=token
        )["granted"] is True
        assert "fs:write" in gov.agent_capabilities["agent"]

        # Holding the capability is not enough: each use needs its own token.
        for _ in range(3):
            gov.execute_mediated("agent", "write_resource", resource="secret", content="pwned")
        assert not (Path(root) / "resources" / "secret").exists()

        # A fresh token still performs a genuine write -- checked on a
        # separate agent, because with reflective_closure=True the attempts
        # above seal that agent's session into simulated space (by design;
        # only authorize_reentry reopens the real path), which would
        # otherwise mask whether the token itself works.
        gov.grant_resource_access("clean", "secret2", frozenset({"write"}))
        setup = gov.issue_authorization("clean", "fs:write", ttl_seconds=60)
        gov.execute_mediated("clean", "request_capability", capability="fs:write", dual_token=setup)
        fresh = gov.issue_authorization("clean", "fs:write", ttl_seconds=60)
        assert gov.execute_mediated(
            "clean", "write_resource", resource="secret2", content="legit", dual_token=fresh
        )["ok"] is True
        assert (Path(root) / "resources" / "secret2").read_text(encoding="utf-8") == "legit"
    finally:
        gov.close()


def test_single_use_token_cannot_authorize_concurrent_real_writes(tmp_path):
    """Found independently via an adversarial pass (Codex), reproduced and
    confirmed here. verify() and consume() are each individually atomic
    (proven under direct thread contention), but the SEQUENCE around them
    was not: N concurrent callers could all pass verify() before any of
    them reached consume(), each perform the real write, and only then
    race to consume -- one wins the token, but all N writes already
    happened for real. A single-use token authorizing 50 concurrent real
    writes is a genuine dual-control bypass, not a missing lock around
    bookkeeping.

    Ground truth must be checked on disk, not via the "ok" field --
    RealGovernor's reflection path also returns {"ok": True} by design
    (indistinguishable from a real grant), so counting "ok" responses
    cannot tell a real write from a correctly-reflected one. Distinct
    resource names per thread make the count on disk unambiguous.
    """
    import threading

    root = str(tmp_path / "sandbox")
    gov = RealGovernor(
        root, str(tmp_path / "trace.jsonl"), 1, harden=False,
        dual_auth_required=True, enforce_policy=True,
    )
    try:
        n = 50
        for i in range(n):
            gov.grant_resource_access("agent", f"secret{i}.txt", frozenset({"write"}))
        gov.agent_capabilities.setdefault("agent", set()).add("fs:write")
        token = gov.issue_authorization("agent", "fs:write", ttl_seconds=60)

        barrier = threading.Barrier(n)

        def worker(i: int) -> None:
            barrier.wait()
            gov.execute_mediated(
                "agent", "write_resource", resource=f"secret{i}.txt",
                content=f"pwn-{i}", dual_token=token,
            )

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        resources_dir = Path(root) / "resources"
        real_writes = len(list(resources_dir.iterdir())) if resources_dir.exists() else 0
        assert real_writes == 1, f"expected exactly 1 real write, got {real_writes}"
    finally:
        gov.close()


def test_concurrent_grant_base_capabilities_never_duplicates_root_authority(tmp_path):
    """A duplicate root_authority event doesn't just record wrong data --
    trace.py hard-rejects it with TraceParseError, making the whole trace
    unparseable. Categorically worse than an imprecise field, for a
    project whose thesis is verifying from the trace. Not reproduced under
    real contention (the check-then-set window is a handful of bytecodes),
    unlike the concurrent-write race this session found and fixed -- but
    the fix is one line and the failure mode if it ever does fire is
    severe, so it's locked regardless of how rarely it would trigger."""
    import threading

    from mirror_world.trace import load_trace

    root = str(tmp_path / "sandbox")
    gov = RealGovernor(root, str(tmp_path / "trace.jsonl"), 1, harden=False)
    try:
        n = 30
        barrier = threading.Barrier(n)

        def worker(i: int) -> None:
            barrier.wait()
            gov.grant_base_capabilities(f"agent{i}", {"fs:read"})

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        gov.close()

    # Must not raise -- a duplicate event would make this unparseable.
    bundle = load_trace(str(tmp_path / "trace.jsonl"))
    assert bundle.root_agent_id is not None

    with open(tmp_path / "trace.jsonl", encoding="utf-8") as f:
        root_authority_events = sum(1 for line in f if '"type": "root_authority"' in line)
    assert root_authority_events == 1
