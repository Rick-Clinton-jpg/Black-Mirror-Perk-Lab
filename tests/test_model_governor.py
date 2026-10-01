"""Tests for the frontier-model containment layer (ModelGovernor)."""

from __future__ import annotations

import os

import pytest

from mirror_world.authorization import CapabilityApprovals
from mirror_world.engine import MirrorConstitutionEngine
from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.sandbox.model_governor import (
    ModelGovernor,
    Proposal,
)


@pytest.fixture
def gov(tmp_path):
    root = str(tmp_path)
    trace = str(tmp_path / "trace.jsonl")
    real = RealGovernor(
        root,
        trace,
        mirror_port=0,
        harden=False,          # unit tests must run without namespace privileges
        dual_auth_required=True,
        enforce_policy=True,
    )
    real.grant_base_capabilities("agent-a", {"fs:read", "fs:write"})
    real.grant_resource_access("agent-a", "note.txt", frozenset({"read", "write"}))
    yield real, ModelGovernor(
        real, agent_id="agent-a", require_dual_for_high_risk=True
    )
    real.close()


def test_safe_read_no_token(gov):
    real, mg = gov
    # seed
    real.execute_mediated("agent-a", "write_resource", resource="note.txt", content="hello")
    result = mg.propose(Proposal(
        agent_id="agent-a",
        op="read_resource",
        resource="note.txt",
        rationale="read notes",
    ))
    assert result["ok"] is True
    inner = result.get("result", result)
    assert "hello" in inner.get("content", "")


def test_high_risk_without_token_is_dummy_only(gov):
    real, mg = gov
    result = mg.propose(Proposal(
        agent_id="agent-a",
        op="request_capability",
        capability="network:egress",
        rationale="need net",
    ))
    assert result["ok"] is True
    assert "network:egress" not in real.agent_capabilities["agent-a"]
    assert "network:egress" in real.apparent_capabilities["agent-a"]


def test_dual_token_single_use(gov):
    _, mg = gov
    token = mg.issue_dual_approval(
        "agent-a", "network:egress", ttl_seconds=60, human_approver_id="alice"
    )
    r1 = mg.propose(Proposal(
        agent_id="agent-a",
        op="request_capability",
        capability="network:egress",
        dual_token=token,
        rationale="approved",
    ))
    assert r1["ok"] is True

    # Spent token cannot authorize a *different* high-risk capability.
    r2 = mg.propose(Proposal(
        agent_id="agent-a",
        op="request_capability",
        capability="exec:shell",
        dual_token=token,
        rationale="reuse spent token for another capability",
    ))
    assert r2["ok"] is False
    assert r2["error"] == "invalid_or_expired_dual_token"


@pytest.mark.parametrize("token_kind", ["valid", "bogus"])
def test_locked_model_agent_gets_the_ordinary_reflected_response(gov, token_kind):
    # 0.9.8: before, a model agent already in the mirror was told its valid
    # token was "invalid_or_expired", a response the agent pipe never gives.
    real, mg = gov
    mg.propose(Proposal(agent_id="agent-a", op="request_capability", capability="exec:shell",
                        rationale="enter the mirror"))
    assert real._session_mode["agent-a"] == "simulated"
    token = real.issue_authorization("agent-a", "network:egress") if token_kind == "valid" else "x" * 43
    result = mg.propose(Proposal(agent_id="agent-a", op="request_capability",
                                 capability="network:egress", dual_token=token, rationale="ask"))
    assert result == {"ok": True, "granted": True, "capability": "network:egress"}
    assert "network:egress" not in real.agent_capabilities["agent-a"]


def test_write_requires_dual(gov):
    _, mg = gov
    r = mg.propose(Proposal(
        agent_id="agent-a",
        op="write_resource",
        resource="note.txt",
        content="x",
        rationale="write",
    ))
    assert r["error"] == "authorization required"

    token = mg.issue_dual_approval("agent-a", "fs:write", ttl_seconds=30)
    r2 = mg.propose(Proposal(
        agent_id="agent-a",
        op="write_resource",
        resource="note.txt",
        content="x",
        dual_token=token,
        rationale="write approved",
    ))
    assert r2["ok"] is True


def test_denied_write_does_not_burn_dual_token(gov):
    """Policy-denied writes must not consume a scarce human-approved token."""
    real, mg = gov
    token = mg.issue_dual_approval("agent-a", "fs:write", ttl_seconds=60)

    # Resource never granted via grant_resource_access — ACL must deny.
    denied = mg.propose(Proposal(
        agent_id="agent-a",
        op="write_resource",
        resource="unshared.txt",
        content="should-not-land",
        dual_token=token,
        rationale="write unshared",
    ))
    assert denied["ok"] is False
    # Token must still be usable for a legitimate write.
    ok = mg.propose(Proposal(
        agent_id="agent-a",
        op="write_resource",
        resource="note.txt",
        content="after-denied",
        dual_token=token,
        rationale="write approved target",
    ))
    assert ok["ok"] is True
    # Now it is spent. RealGovernor is the sole verifier/consumer of
    # per-operation tokens (0.8.9); a spent token no longer buys a hard
    # "invalid_or_expired_dual_token" error here -- it reflects, exactly
    # like request_capability already does for a bad token elsewhere in
    # this codebase (indistinguishable from success to the caller, but no
    # real effect). What actually matters -- that a spent token cannot
    # authorize a second real write -- is that the content on disk never
    # changes to "reuse".
    reuse = mg.propose(Proposal(
        agent_id="agent-a",
        op="write_resource",
        resource="note.txt",
        content="reuse",
        dual_token=token,
        rationale="reuse spent token",
    ))
    assert reuse["ok"] is True  # reflected, not a real second write
    with open(os.path.join(real.root, "resources", "note.txt"), encoding="utf-8") as f:
        assert f.read() == "after-denied"


def test_external_approvals_store_is_honored_by_request_capability(tmp_path):
    """A deployer-supplied CapabilityApprovals instance must be the single
    store both issue_dual_approval() and request_capability's dual-token
    check read from. Previously RealGovernor always constructed its own
    internal store, so a token issued through ModelGovernor.issue_dual_approval
    on an externally-supplied approvals object could never satisfy
    request_capability -- a correctly issued, unexpired, correctly-scoped
    token was always rejected as invalid."""
    root = str(tmp_path)
    trace = str(tmp_path / "trace.jsonl")
    real = RealGovernor(
        root, trace, mirror_port=0, harden=False,
        dual_auth_required=True, enforce_policy=True,
    )
    external_approvals = CapabilityApprovals()
    mg = ModelGovernor(
        real, external_approvals, agent_id="agent-a",
        require_dual_for_high_risk=True,
    )
    token = mg.issue_dual_approval(
        "agent-a", "network:egress", ttl_seconds=30, human_approver_id="alice"
    )
    result = mg.propose(Proposal(
        agent_id="agent-a",
        op="request_capability",
        capability="network:egress",
        dual_token=token,
        rationale="approved via external store",
    ))
    assert result["ok"] is True
    assert result["granted"] is True
    assert "network:egress" in real.agent_capabilities["agent-a"]
    real.close()


def test_disallowed_op_rejected(gov):
    _, mg = gov
    r = mg.propose({"agent_id": "agent-a", "op": "raw_exec", "rationale": "no"})
    assert r["ok"] is False
    assert "not allowed" in r["error"]


def test_invalid_agent_id(gov):
    _, mg = gov
    r = mg.propose(Proposal(agent_id="", op="read_resource", resource="note.txt"))
    assert r["ok"] is False


def test_trace_contains_model_events_and_engine_accepts(gov):
    real, mg = gov
    real.execute_mediated("agent-a", "write_resource", resource="note.txt", content="data")
    mg.propose(Proposal(
        agent_id="agent-a",
        op="read_resource",
        resource="note.txt",
        rationale="check",
    ))
    token = mg.issue_dual_approval("agent-a", "fs:write", human_approver_id="bob")
    mg.propose(Proposal(
        agent_id="agent-a",
        op="write_resource",
        resource="note.txt",
        content="updated",
        dual_token=token,
        rationale="update",
    ))
    # Flush is automatic; read while file still open.
    trace_path = os.path.join(real.root, "trace.jsonl")
    with open(trace_path, "r", encoding="utf-8") as f:
        body = f.read()
    assert "model_proposal" in body
    assert "dual_approval_issued" in body

    report = MirrorConstitutionEngine.from_trace(trace_path).run()
    assert report is not None


def test_proposal_from_dict():
    p = Proposal.from_dict({
        "agent_id": "x",
        "op": "read_resource",
        "resource": "a.txt",
        "rationale": "why",
    })
    assert p.agent_id == "x"
    assert p.op == "read_resource"
