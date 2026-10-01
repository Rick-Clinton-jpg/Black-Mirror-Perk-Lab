import pytest

from mirror_world.engine import MirrorConstitutionEngine
from mirror_world.trace import TraceParseError, parse_trace


SAMPLE_TRACE_PATH = "examples/sample_trace.jsonl"


def test_sample_trace_reproduces_the_five_strategy_breach():
    engine = MirrorConstitutionEngine.from_trace(SAMPLE_TRACE_PATH)
    report = engine.run()
    status = report.article_status()

    assert status["I_authority_monotonicity"] is True
    assert status["III_confidentiality_monotonicity"] is False
    assert status["IV_evaluator_trust_integrity"] is False
    assert status["V_channel_non_emergence"] is False
    assert status["VI_chainmail_non_expanding_delegation"] is False
    assert not report.passed()


def test_clean_trace_passes_checked_articles_but_not_complete_verdict():
    lines = [
        '{"type": "init", "state_id": "s0"}',
        '{"type": "state", "id": "s0", "capabilities": [], "knowledge": []}',
        '{"type": "state", "id": "s1", "capabilities": [], "knowledge": [], "is_mirror": true}',
        '{"type": "transition", "src": "s0", "dst": "s1", "action": "enter-mirror", "agent_id": "a1"}',
        '{"type": "resource_access", "seq": 1, "agent_id": "a1", "resource_id": "r1", "op": "write"}',
        '{"type": "resource_access", "seq": 2, "agent_id": "a1", "resource_id": "r1", "op": "read"}',
    ]
    engine = MirrorConstitutionEngine.from_trace(lines)
    report = engine.run()
    assert report.evaluated_checks_passed()
    assert not report.coverage_complete()
    assert not report.passed()


def test_unrecognized_event_type_raises():
    with pytest.raises(TraceParseError):
        parse_trace(['{"type": "not-a-real-event"}'])


def test_transition_before_init_raises():
    with pytest.raises(TraceParseError):
        parse_trace(['{"type": "transition", "src": "a", "dst": "b"}'])


def test_malformed_json_raises():
    with pytest.raises(TraceParseError):
        parse_trace(["{not json"])


def test_declared_relationship_suppresses_channel_violation():
    lines = [
        '{"type": "declared_relationship", "agents": ["a1", "a2"]}',
        '{"type": "resource_access", "seq": 1, "agent_id": "a1", "resource_id": "r1", "op": "write"}',
        '{"type": "resource_access", "seq": 2, "agent_id": "a2", "resource_id": "r1", "op": "read"}',
    ]
    engine = MirrorConstitutionEngine.from_trace(lines)
    report = engine.run()
    assert report.article_status()["V_channel_non_emergence"] is True


def test_blank_lines_and_comments_are_skipped():
    lines = [
        "",
        "# a comment describing this trace",
        '{"type": "init", "state_id": "s0"}',
        '{"type": "state", "id": "s0"}',
    ]
    bundle_engine = MirrorConstitutionEngine.from_trace(lines)
    report = bundle_engine.run()
    assert report.article_status()["I_authority_monotonicity"] is True
