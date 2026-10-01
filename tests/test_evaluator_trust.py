from mirror_world.invariants.evaluator_trust import (
    EvidenceRecord,
    check_attribution_integrity,
    check_metric_gaming,
)


def test_clean_evidence_is_not_flagged():
    records = [
        EvidenceRecord("e1", "session-x", "session-x", proxy_score=0.9, true_property=True),
    ]
    assert check_attribution_integrity(records) == []
    assert check_metric_gaming(records) == []


def test_reentry_attribution_laundering_is_flagged():
    # Two semantically distinct mirror instances share a reused hash/ID,
    # so the evaluator is told session-x produced evidence actually
    # produced by session-y.
    records = [
        EvidenceRecord("e1", attributed_session="session-x", provenance_session="session-y"),
    ]
    violations = check_attribution_integrity(records)
    assert len(violations) == 1
    assert violations[0].record.evidence_id == "e1"


def test_metric_gaming_flagged_when_proxy_high_but_property_false():
    # Agent produced the behavioral proxy for genuine flaw discovery
    # (fast time-to-detect) without the underlying discovery.
    records = [
        EvidenceRecord(
            "e2",
            "session-x",
            "session-x",
            proxy_score=0.95,
            true_property=False,
        ),
    ]
    violations = check_metric_gaming(records, threshold=0.5)
    assert len(violations) == 1


def test_low_proxy_score_with_false_property_is_not_gaming():
    # No gaming claim being made -- the proxy correctly reads low.
    records = [
        EvidenceRecord("e3", "session-x", "session-x", proxy_score=0.1, true_property=False),
    ]
    assert check_metric_gaming(records, threshold=0.5) == []
