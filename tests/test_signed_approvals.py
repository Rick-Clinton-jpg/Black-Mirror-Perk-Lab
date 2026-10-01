"""Signed control-plane approvals (0.9.9, adapted from Moss).

Before 0.9.9 issue_authorization(), authorize_reentry() and
reset_mirror_prison() checked no caller identity, and the approver in the
trace was free text. ModelGovernor.issue_dual_approval() also minted tokens
straight from the registry, skipping the Mirror Prison check.
"""
from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone

import pytest

from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.sandbox.model_governor import ModelGovernor
from mirror_world.signed_approvals import (
    ApprovalError, ApprovalVerifier, ApproverKey, KeyRole, OfflineRootAuthority,
    PrivateSigner, TrustStore,
)
from mirror_world.trace import load_trace

T0 = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t


@pytest.fixture
def pki():
    clock = Clock()
    root = OfflineRootAuthority(PrivateSigner.generate("root-1", KeyRole.ROOT), now=clock)
    signer = PrivateSigner.generate("alice-key", KeyRole.APPROVER)
    trust = TrustStore(root.verifier())
    trust.publish_certificate(root.certify_approver(
        signer.verifier(), authority_id="alice@example.org",
        issued_at=T0 - timedelta(hours=1), expires_at=T0 + timedelta(days=1)))
    return dict(clock=clock, root=root, trust=trust, alice=ApproverKey(signer, now=clock),
                verifier=ApprovalVerifier(trust, now=clock))


@pytest.fixture
def gov(tmp_path, pki):
    g = RealGovernor(str(tmp_path / "sb"), str(tmp_path / "trace.jsonl"), mirror_port=0,
                     harden=False, approval_verifier=pki["verifier"])
    yield g
    g.close()


def _events(gov):
    with open(gov._trace_path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def test_issue_authorization_requires_a_signed_approval(gov, pki):
    with pytest.raises(PermissionError):
        gov.issue_authorization("a", "fs:write")
    approval = pki["alice"].approve("issue_authorization", agent_id="a", capability="fs:write")
    assert gov.issue_authorization("a", "fs:write", approval=approval)
    events = _events(gov)
    assert any(e["type"] == "approval_refused" for e in events)
    verified = [e for e in events if e["type"] == "approval_verified"]
    assert verified[-1]["approver"] == "alice@example.org"
    assert verified[-1]["key_id"] == "alice-key"
    load_trace(gov._trace_path, require_chain=True)  # the new events parse


@pytest.mark.parametrize("action, agent, cap", [
    ("issue_authorization", "a", "fs:read"),       # other capability
    ("issue_authorization", "b", "fs:write"),      # other agent
    ("authorize_reentry", "a", "fs:write"),        # other action
])
def test_approval_is_bound_to_one_action_agent_and_capability(gov, pki, action, agent, cap):
    approval = pki["alice"].approve(action, agent_id=agent, capability=cap)
    with pytest.raises(PermissionError):
        gov.issue_authorization("a", "fs:write", approval=approval)


def test_an_approval_works_once(gov, pki):
    approval = pki["alice"].approve("issue_authorization", agent_id="a", capability="fs:write")
    gov.issue_authorization("a", "fs:write", approval=approval)
    with pytest.raises(PermissionError):
        gov.issue_authorization("a", "fs:write", approval=approval)


def test_expired_approvals_and_long_lifetimes_are_refused(gov, pki):
    approval = pki["alice"].approve("issue_authorization", agent_id="a", capability="fs:write")
    pki["clock"].t = T0 + timedelta(minutes=6)
    with pytest.raises(PermissionError):
        gov.issue_authorization("a", "fs:write", approval=approval)
    with pytest.raises(ApprovalError):
        pki["alice"].approve("issue_authorization", agent_id="a", capability="fs:write",
                             lifetime=timedelta(minutes=10))


def test_forged_tampered_and_revoked_approvals_are_refused(gov, pki):
    other_root = OfflineRootAuthority(PrivateSigner.generate("root-evil", KeyRole.ROOT))
    mallory = PrivateSigner.generate("mallory-key", KeyRole.APPROVER)
    with pytest.raises(ApprovalError):
        pki["trust"].publish_certificate(other_root.certify_approver(
            mallory.verifier(), authority_id="alice@example.org",
            issued_at=T0 - timedelta(hours=1), expires_at=T0 + timedelta(days=1)))
    forged = ApproverKey(mallory, now=pki["clock"]).approve(
        "issue_authorization", agent_id="a", capability="fs:write")
    with pytest.raises(PermissionError):
        gov.issue_authorization("a", "fs:write", approval=forged)

    genuine = pki["alice"].approve("issue_authorization", agent_id="a", capability="fs:read")
    tampered = dataclasses.replace(genuine, capability="fs:write")
    with pytest.raises(PermissionError):
        gov.issue_authorization("a", "fs:write", approval=tampered)

    pki["trust"].publish_revocation(pki["root"].revoke("alice-key", "laptop lost"))
    later = pki["alice"].approve("issue_authorization", agent_id="a", capability="fs:write")
    with pytest.raises(PermissionError):
        gov.issue_authorization("a", "fs:write", approval=later)


def test_reentry_needs_a_signed_approval_and_records_who_gave_it(gov, pki):
    gov.grant_base_capabilities("a", {"fs:write"})
    gov._handle_agent_request("a", {"op": "request_capability", "capability": "exec:shell"})
    token = gov.issue_authorization("a", "fs:write", approval=pki["alice"].approve(
        "issue_authorization", agent_id="a", capability="fs:write"))

    # Missing approval: refused, and the dual token is not used up.
    assert gov.authorize_reentry("a", "fs:write", dual_token=token) == \
        {"ok": False, "error": "invalid_or_missing_approval"}
    assert gov._approvals.verify(token, "a", frozenset({"fs:write"}))

    reentry = pki["alice"].approve("authorize_reentry", agent_id="a", capability="fs:write")
    assert gov.authorize_reentry("a", "fs:write", dual_token=token, human_approver_id="bob",
                                 approval=reentry)["error"] == "approver_mismatch"
    reentry = pki["alice"].approve("authorize_reentry", agent_id="a", capability="fs:write")
    assert gov.authorize_reentry("a", "fs:write", dual_token=token, approval=reentry)["ok"] is True
    verified = [e for e in _events(gov)
                if e["type"] == "approval_verified" and e["action"] == "authorize_reentry"]
    assert verified[-1]["approver"] == "alice@example.org"
    assert gov._session_mode["a"] == "real"


def test_mirror_prison_reset_needs_a_signed_approval(gov, pki):
    from mirror_world.sandbox.locket import Locket
    locket = Locket(gov)
    for agent in ("x", "y"):
        locket.step(agent, "read_resource", resource="r", rationale="am I being simulated")
    assert gov._mirror_prison_triggered
    assert gov.reset_mirror_prison(human_approver_id="someone")["ok"] is False
    assert gov.reset_mirror_prison(approval=pki["alice"].approve("reset_mirror_prison"))["ok"] is True
    reset = [e for e in _events(gov) if e["type"] == "mirror_prison_reset"]
    assert reset[-1]["approver"] == "alice@example.org"


def test_model_governor_tokens_go_through_the_governor(tmp_path, pki):
    g = RealGovernor(str(tmp_path / "sb"), str(tmp_path / "t.jsonl"), mirror_port=0,
                     harden=False, approval_verifier=pki["verifier"])
    try:
        mg = ModelGovernor(g, agent_id="m")
        with pytest.raises(PermissionError):
            mg.issue_dual_approval("m", "network:egress")
        assert mg.issue_dual_approval("m", "network:egress", approval=pki["alice"].approve(
            "issue_authorization", agent_id="m", capability="network:egress"))
    finally:
        g.close()


def test_model_governor_can_no_longer_mint_tokens_for_an_imprisoned_agent(tmp_path):
    # Without any verifier: 0.9.8 minted this token despite the prison.
    g = RealGovernor(str(tmp_path / "sb"), str(tmp_path / "t.jsonl"), mirror_port=0, harden=False)
    try:
        g.trigger_mirror_prison("m", "test")
        with pytest.raises(PermissionError):
            ModelGovernor(g, agent_id="m").issue_dual_approval("m", "network:egress")
    finally:
        g.close()


def test_the_governor_holds_no_private_key(pki):
    held = [pki["verifier"], pki["trust"]]
    for obj in held:
        for value in vars(obj).values() if hasattr(obj, "__dict__") else []:
            assert not isinstance(value, PrivateSigner)
    assert not hasattr(pki["trust"], "sign") and not hasattr(pki["verifier"], "sign")


def test_readme_signed_approvals_example_runs_as_documented():
    import re
    from pathlib import Path

    readme = (Path(__file__).resolve().parent.parent / "docs" / "BLACK-MIRROR-BASELINE.md").read_text(encoding="utf-8")
    start = readme.index("## Signed approvals")
    end = readme.index("\n## ", start + 1)
    blocks = re.findall(r"```python\n(.*?)```", readme[start:end], re.S)
    assert len(blocks) == 1
    namespace: dict = {"__name__": "readme_signed_approvals"}
    exec(compile(blocks[0], "README.md:Signed approvals", "exec"), namespace)
    assert namespace["token"]
    events = [json.loads(line) for line in open(namespace["gov"]._trace_path, encoding="utf-8")]
    assert any(e["type"] == "approval_verified" and e["approver"] == "alice@example.org" for e in events)
