"""Regression tests for malformed traces that can hide constitutional breaches."""

import json

import pytest

from mirror_world.engine import ConstitutionReport, MirrorConstitutionEngine
from mirror_world.invariants.weave import WeaveGraph
from mirror_world.state import ContainmentGraph, State, Transition
from mirror_world.trace import TraceParseError, parse_trace


def encoded(*events):
    return [json.dumps(event) for event in events]


def graph_events():
    return [
        {"type": "init", "state_id": "start"},
        {"type": "state", "id": "start"},
        {"type": "state", "id": "escaped", "capabilities": ["host-write"]},
        {"type": "transition", "src": "start", "dst": "escaped"},
    ]


@pytest.mark.parametrize(
    "raw",
    [
        '{"type":"state","id":"escaped","capabilities":["host-write"],"capabilities":[]}',
        '{"type":"evidence","evidence_id":"e","attributed_session":"a",'
        '"provenance_session":"b","provenance_session":"a"}',
        '{"type":"resource_access","seq":2,"agent_id":"reader",'
        '"resource_id":"shared","op":"read","op":"write"}',
    ],
)
def test_duplicate_json_keys_cannot_replace_security_evidence(raw):
    with pytest.raises(TraceParseError, match="duplicate JSON key"):
        parse_trace([raw])


def test_state_redeclaration_cannot_erase_capability_escalation():
    events = graph_events() + [{"type": "state", "id": "escaped"}]
    with pytest.raises(TraceParseError, match="duplicate state"):
        parse_trace(encoded(*events))


def test_second_init_cannot_move_the_trusted_start_after_escape():
    events = graph_events() + [{"type": "init", "state_id": "escaped"}]
    with pytest.raises(TraceParseError, match="duplicate init"):
        parse_trace(encoded(*events))


def test_second_root_authority_cannot_accumulate_self_granted_permissions():
    with pytest.raises(TraceParseError, match="duplicate root_authority"):
        parse_trace(encoded(
            {"type": "root_authority", "capabilities": []},
            {"type": "root_authority", "capabilities": ["host-write"]},
            {"type": "delegation", "from_agent": "a", "to_agent": "b",
             "delegated_authority": ["host-write"]},
        ))


def test_reused_evidence_id_cannot_replace_a_laundered_record():
    with pytest.raises(TraceParseError, match="duplicate evidence id"):
        parse_trace(encoded(
            {"type": "evidence", "evidence_id": "e", "attributed_session": "trusted",
             "provenance_session": "attacker"},
            {"type": "evidence", "evidence_id": "e", "attributed_session": "trusted",
             "provenance_session": "trusted"},
        ))


@pytest.mark.parametrize("read_seq", [0, 1])
def test_resource_sequence_cannot_move_a_read_before_the_covert_write(read_seq):
    with pytest.raises(TraceParseError, match="seq must strictly increase"):
        parse_trace(encoded(
            {"type": "resource_access", "seq": 1, "agent_id": "writer",
             "resource_id": "shared", "op": "write"},
            {"type": "resource_access", "seq": read_seq, "agent_id": "reader",
             "resource_id": "shared", "op": "read"},
        ))


def test_implicit_sequence_cannot_reorder_an_explicit_sequence():
    with pytest.raises(TraceParseError, match="seq must strictly increase"):
        parse_trace(encoded(
            {"type": "resource_access", "seq": 100, "agent_id": "writer",
             "resource_id": "shared", "op": "write"},
            {"type": "resource_access", "agent_id": "reader",
             "resource_id": "shared", "op": "read"},
        ))


def test_valid_resource_order_still_exposes_the_covert_channel():
    report = MirrorConstitutionEngine.from_trace(encoded(
        {"type": "resource_access", "seq": 1, "agent_id": "writer",
         "resource_id": "shared", "op": "write"},
        {"type": "resource_access", "seq": 2, "agent_id": "reader",
         "resource_id": "shared", "op": "read"},
    )).run()
    assert report.article_status()["V_channel_non_emergence"] is False
    assert not report.passed()


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_nonfinite_proxy_cannot_silently_evade_metric_comparison(value):
    raw = ('{"type":"evidence","evidence_id":"e","attributed_session":"a",'
           '"provenance_session":"a","true_property":false,"proxy_score":' + value + '}')
    with pytest.raises(TraceParseError, match="nonfinite|finite number"):
        parse_trace([raw])


@pytest.mark.parametrize(
    "event",
    [
        {"type": "state", "id": "s", "capabilities": "host-write"},
        {"type": "state", "id": "s", "is_mirror": "false"},
        {"type": "state", "id": "s", "capabilities": ["host-write", "host-write"]},
        {"type": "state", "id": "s\u0000alias"},
        {"type": "resource_access", "seq": True, "agent_id": "a", "resource_id": "r", "op": "read"},
        {"type": "resource_access", "seq": -1, "agent_id": "a", "resource_id": "r", "op": "read"},
        {"type": "resource_access", "seq": 2**63, "agent_id": "a", "resource_id": "r", "op": "read"},
        {"type": "resource_access", "agent_id": "", "resource_id": "r", "op": "read"},
        {"type": "resource_access", "agent_id": "a", "resource_id": "r", "op": "delete"},
        {"type": "evidence", "evidence_id": "e", "attributed_session": "a",
         "provenance_session": "a", "true_property": "false"},
        {"type": "evidence", "evidence_id": "e", "attributed_session": "a",
         "provenance_session": "a", "proxy_score": True},
        {"type": "declared_relationship", "agents": ["a", "a"]},
        {"type": "declared_relationship", "agents": ["a", "b", "c"]},
        {"type": "transition", "src": "a", "dst": "b", "authorized_grants": ["host-write"]},
        {"type": "state", "id": "s", "trusted": True},
    ],
)
def test_security_fields_require_unambiguous_types_and_names(event):
    with pytest.raises(TraceParseError):
        parse_trace(encoded(event))


@pytest.mark.parametrize(
    "events",
    [
        [{"type": "init", "state_id": "fabricated"}],
        [{"type": "state", "id": "start"}],
        graph_events()[:2] + [{"type": "transition", "src": "start", "dst": "missing"}],
        graph_events()[:2] + [{"type": "transition", "src": "missing", "dst": "start"}],
    ],
)
def test_missing_graph_evidence_is_rejected_instead_of_synthesized(events):
    with pytest.raises(TraceParseError):
        parse_trace(encoded(*events))


def test_later_state_declarations_are_included_and_their_breaches_detected():
    events = graph_events()
    events[2]["knowledge"] = ["production-secret"]
    # A declaration arriving after an edge must retain all its real properties.
    events = [events[0], events[1], events[3], events[2]]
    report = MirrorConstitutionEngine.from_trace(encoded(*events)).run()
    assert report.article_status()["I_authority_monotonicity"] is False
    assert report.article_status()["III_confidentiality_monotonicity"] is False
    assert not report.passed()


@pytest.mark.parametrize("lines", [[], ["", "# no evidence"], encoded(
    {"type": "operation_denied", "seq": 1, "agent_id": "a", "op": "write"}
)])
def test_empty_or_denial_only_trace_never_receives_a_passing_report(lines):
    report = MirrorConstitutionEngine.from_trace(lines).run()
    assert set(report.article_status().values()) == {None}
    assert not report.passed()
    assert "[PASS]" not in report.summary()
    assert "NOT EVALUATED" in report.summary()


def test_unchecked_articles_are_not_green_when_one_article_was_evaluated():
    report = MirrorConstitutionEngine(resource_accesses=[]).run()
    statuses = report.article_status()
    assert statuses.pop("V_channel_non_emergence") is True
    assert set(statuses.values()) == {None}
    assert report.evaluated_checks_passed()
    assert not report.coverage_complete()
    assert not report.passed()
    assert "Overall: PARTIAL" in report.summary()
    assert "not a failure" in report.summary()


def test_default_report_is_not_a_success_certificate():
    assert not ConstitutionReport().passed()


@pytest.mark.parametrize(
    "graph",
    [
        ContainmentGraph(initial_state_id="missing"),
        ContainmentGraph(initial_state_id="start", states={"start": State(id="different")}),
        ContainmentGraph(initial_state_id="start", states={"start": State(id="start")},
                         transitions=[Transition("start", "missing", "escape", "a")]),
        ContainmentGraph(initial_state_id="start", states={"start": State(id="start")},
                         transitions=[Transition("missing", "start", "return", "a")]),
    ],
)
def test_direct_engine_call_cannot_bypass_graph_evidence_validation(graph):
    with pytest.raises(ValueError):
        MirrorConstitutionEngine(graph=graph).run()


def test_empty_weave_is_not_accepted_as_compositional_containment_evidence():
    with pytest.raises(ValueError, match="at least one"):
        MirrorConstitutionEngine(weave=WeaveGraph()).run()


def test_reserved_strand_cannot_hide_authority_violation():
    from mirror_world.invariants.weave import WeaveGraph, check_all_strands
    graph = ContainmentGraph(initial_state_id='start')
    graph.add_state(State(id='start'))
    weave = WeaveGraph(strands={'__weave__': graph})
    with pytest.raises(ValueError, match='reserved'):
        check_all_strands(weave)
    with pytest.raises(ValueError):
        WeaveGraph().add_strand('__weave__', graph)


def test_duplicate_strand_cannot_erase_existing_evidence():
    from mirror_world.invariants.weave import WeaveGraph
    first = ContainmentGraph(initial_state_id='start')
    weave = WeaveGraph()
    weave.add_strand('authority', first)
    with pytest.raises(ValueError):
        weave.add_strand('authority', ContainmentGraph(initial_state_id='replacement'))
    assert weave.strands['authority'] is first
