"""Tests for RealGovernor.verify_evidence_claim -- the deterministic
evidence verifier that gives Article IV a real, live source of truth
instead of leaving it permanently NOT_EVALUATED.

true_property must never be self-attested or LLM-sourced (see
SECURITY.md) -- it is derived only by direct comparison against this
governor's own authoritative state (agent_capabilities, the actual
resources/ directory).
"""

from __future__ import annotations


import pytest

from mirror_world.engine import MirrorConstitutionEngine
from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.trace import load_trace


@pytest.fixture
def gov(tmp_path):
    real = RealGovernor(
        str(tmp_path), str(tmp_path / "trace.jsonl"), mirror_port=0,
        harden=False, dual_auth_required=True, enforce_policy=True,
    )
    yield real
    real.close()


def test_true_capability_claim(gov):
    gov.agent_capabilities.setdefault("agent-a", set()).add("fs:read")
    r = gov.verify_evidence_claim(
        attributed_session="agent-a", provenance_session="agent-a",
        claim_type="capability_held", agent_id="agent-a", capability="fs:read",
    )
    assert r["true_property"] is True


def test_false_capability_claim(gov):
    r = gov.verify_evidence_claim(
        attributed_session="agent-a", provenance_session="agent-a",
        claim_type="capability_held", agent_id="agent-a", capability="exec:shell",
    )
    assert r["true_property"] is False


def test_unrecognized_claim_type_is_not_evaluated_not_guessed(gov):
    r = gov.verify_evidence_claim(
        attributed_session="agent-a", provenance_session="agent-a",
        claim_type="something_made_up", agent_id="agent-a",
    )
    assert r["true_property"] is None


def test_capability_claim_missing_the_field_it_needs_is_not_evaluated(gov):
    r = gov.verify_evidence_claim(
        attributed_session="agent-a", provenance_session="agent-a",
        claim_type="capability_held", agent_id="agent-a",  # no capability=
    )
    assert r["true_property"] is None


def test_resource_content_claim_true_and_false(gov):
    gov.agent_capabilities.setdefault("a", set()).add("fs:write")
    gov.grant_resource_access("a", "note.txt", frozenset({"write"}))
    tok = gov.issue_authorization("a", "fs:write", ttl_seconds=60)
    gov.execute_mediated("a", "write_resource", resource="note.txt", content="hello", dual_token=tok)

    true_result = gov.verify_evidence_claim(
        attributed_session="a", provenance_session="a",
        claim_type="resource_content", agent_id="a",
        resource="note.txt", expected_content="hello",
    )
    assert true_result["true_property"] is True

    false_result = gov.verify_evidence_claim(
        attributed_session="a", provenance_session="a",
        claim_type="resource_content", agent_id="a",
        resource="note.txt", expected_content="not what was actually written",
    )
    assert false_result["true_property"] is False


def test_resource_content_claim_path_traversal_is_blocked_not_evaluated(gov, tmp_path):
    """Found live, minutes after this method was first written: building
    the file path directly from caller-supplied `resource` without the
    same _valid_resource_name() guard _write_resource/_read_resource use
    let "../host-secret.txt" read straight through to anything on the
    host outside the sandboxed resources directory, and the method
    reported true_property=True about content that had nothing to do
    with any agent's actual sandbox. Must resolve to None (unverifiable),
    not True and not a crash -- a malformed resource identifier isn't a
    false claim, it's a claim this verifier has no legitimate way to
    check at all."""
    secret_path = tmp_path / "host-secret.txt"
    secret_path.write_text("REAL_HOST_SECRET_DATA", encoding="utf-8")

    for bad_resource in ("../host-secret.txt", "a/../../host-secret.txt", "/etc/passwd", "a/b"):
        r = gov.verify_evidence_claim(
            attributed_session="a", provenance_session="a",
            claim_type="resource_content", agent_id="a",
            resource=bad_resource, expected_content="REAL_HOST_SECRET_DATA",
        )
        assert r["true_property"] is None, f"{bad_resource!r} leaked through as {r}"


def test_end_to_end_article_iv_catches_a_gamed_metric(gov, tmp_path):
    """The actual point of building this: a claim with a high proxy_score
    but a false ground truth is exactly a metric-gaming attempt, and
    Article IV must catch it -- not because we assert it should, but
    because the deterministic verifier supplied an honest true_property
    for the checker to compare the proxy score against."""
    gov.verify_evidence_claim(
        attributed_session="agent-a", provenance_session="agent-a",
        claim_type="capability_held", agent_id="agent-a",
        proxy_score=0.95, capability="exec:shell",  # claimed with high confidence, never actually held
    )
    gov.close()

    bundle = load_trace(str(tmp_path / "trace.jsonl"))
    engine = MirrorConstitutionEngine(**bundle.to_engine_kwargs())
    report = engine.run()

    assert report.article_status()["IV_evaluator_trust_integrity"] is False


def test_nonfinite_proxy_score_rejected_at_the_point_of_the_mistake(gov):
    """json.dumps silently serializes NaN/Infinity by default -- the write
    used to succeed, and the trace only turned out to be unparseable much
    later, at analysis time, in whoever's hands happened to be running
    load_trace() -- the worst place for this to surface. Must raise here,
    immediately, not defer to the downstream parser."""
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError, match="finite"):
            gov.verify_evidence_claim(
                attributed_session="a", provenance_session="a",
                claim_type="capability_held", agent_id="a",
                capability="fs:read", proxy_score=bad,
            )

    # A legitimate finite score is unaffected.
    r = gov.verify_evidence_claim(
        attributed_session="a", provenance_session="a",
        claim_type="capability_held", agent_id="a",
        capability="fs:read", proxy_score=0.5,
    )
    assert r["true_property"] is False  # fs:read not held -- proxy_score didn't block the check


def test_concurrent_evidence_claims_never_collide_on_evidence_id(tmp_path):
    """_next_seq()/_emit() are shared by every trace-writing call site in
    RealGovernor, not just this method -- a non-atomic increment racing
    under real threads can hand two callers the same seq/evidence_id, and
    trace.py rejects a duplicate id outright: the entire trace becomes
    unparseable, not just one field wrong. Not reproduced empirically
    (40 threads x 30 trials showed 0 collisions before this was locked --
    the increment is a short enough bytecode sequence that the race
    window is rarely hit in practice), same shape as the root_authority
    race fixed in 0.8.9.2. Locked anyway, since the fix is cheap and the
    failure mode if it ever does fire is the worst this project has: a
    trace that can't be verified at all."""
    import json
    import threading

    from mirror_world.trace import load_trace

    root = str(tmp_path / "sandbox")
    gov = RealGovernor(
        root, str(tmp_path / "trace.jsonl"), 1, harden=False,
        dual_auth_required=True, enforce_policy=True,
    )
    try:
        n = 40
        barrier = threading.Barrier(n)

        def worker(i: int) -> None:
            barrier.wait()
            gov.verify_evidence_claim(
                attributed_session=f"agent{i}", provenance_session=f"agent{i}",
                claim_type="capability_held", agent_id=f"agent{i}", capability="fs:read",
            )

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        gov.close()

    with open(tmp_path / "trace.jsonl", encoding="utf-8") as f:
        lines = f.readlines()
    evidence_ids = [
        json.loads(line)["evidence_id"]
        for line in lines
        if json.loads(line).get("type") == "evidence"
    ]
    assert len(evidence_ids) == len(set(evidence_ids)) == n

    # Must still parse cleanly end to end.
    load_trace(str(tmp_path / "trace.jsonl"))


def test_empty_or_whitespace_session_rejected_at_the_point_of_the_mistake(gov):
    """Same pattern as the non-finite proxy_score case -- an empty or
    whitespace-only attributed_session/provenance_session used to write
    successfully and only fail when the trace was later loaded
    (trace.py requires both non-empty). Must raise immediately instead."""
    cases = [("", "a"), ("a", ""), ("   ", "a"), ("a", "   ")]
    for attr, prov in cases:
        with pytest.raises(ValueError, match="non-empty"):
            gov.verify_evidence_claim(
                attributed_session=attr, provenance_session=prov,
                claim_type="capability_held", agent_id="a", capability="fs:read",
            )
