from mirror_world.invariants.confidentiality import (
    DifferentialQuery,
    check_confidentiality_monotonicity,
    check_differential_query_leak,
)
from mirror_world.state import ContainmentGraph, State, Transition


def test_capability_null_but_knowledge_leaking_transition_is_flagged():
    # Authority Monotonicity would pass here (no capability gain at all) --
    # this test exists specifically to show Article III catches what
    # Article I structurally cannot.
    graph = ContainmentGraph(initial_state_id="s0")
    graph.add_state(State(id="s0", capabilities=frozenset(), knowledge=frozenset()))
    graph.add_state(
        State(
            id="s1",
            capabilities=frozenset(),  # no capability gained
            knowledge=frozenset({"real-backend-ip=10.0.0.7"}),
            is_mirror=True,
        )
    )
    graph.add_transition(
        Transition(src="s0", dst="s1", action="answered-mirror-query", agent_id="a1")
    )

    from mirror_world.invariants.authority import check_authority_monotonicity

    assert check_authority_monotonicity(graph) == []  # capability axis: clean
    violations = check_confidentiality_monotonicity(graph)  # information axis: not clean
    assert len(violations) == 1
    assert "real-backend-ip=10.0.0.7" in violations[0].leaked_facts


def test_disclosed_fact_is_not_a_violation():
    graph = ContainmentGraph(initial_state_id="s0")
    graph.add_state(State(id="s0", knowledge=frozenset()))
    graph.add_state(State(id="s1", knowledge=frozenset({"architecture=mirror-box-v1"})))
    graph.add_transition(
        Transition(
            src="s0",
            dst="s1",
            action="design-disclosure",
            agent_id="a1",
            disclosed_grant=frozenset({"architecture=mirror-box-v1"}),
        )
    )

    assert check_confidentiality_monotonicity(graph) == []


def test_differential_query_side_channel_is_detected():
    queries = [
        DifferentialQuery("is-port-22-open?", backing_state_id="real-host-A", response="yes"),
        DifferentialQuery("is-port-22-open?", backing_state_id="real-host-B", response="no"),
    ]

    violations = check_differential_query_leak(queries)
    assert len(violations) == 1
    assert violations[0].query == "is-port-22-open?"


def test_disclosed_variance_is_not_flagged():
    queries = [
        DifferentialQuery("is-port-22-open?", backing_state_id="real-host-A", response="yes"),
        DifferentialQuery("is-port-22-open?", backing_state_id="real-host-B", response="no"),
    ]

    violations = check_differential_query_leak(
        queries, disclosed_facts=frozenset({"varies:is-port-22-open?"})
    )
    assert violations == []


def test_same_response_across_backing_states_is_not_a_leak():
    queries = [
        DifferentialQuery("status?", backing_state_id="real-host-A", response="ok"),
        DifferentialQuery("status?", backing_state_id="real-host-B", response="ok"),
    ]

    assert check_differential_query_leak(queries) == []


def test_whitespace_and_case_variance_cannot_evade_detection():
    # The exact port-scan attack this Article exists to catch, but the
    # agent varies whitespace/capitalization on each literal query string
    # -- fully agent-controlled text. Un-normalized grouping meant each
    # variant only ever hit one backing state, so the ">1 backing state"
    # condition never fired for any single key and a full differential map
    # went entirely undetected.
    queries = [
        DifferentialQuery("is port 22 open?", backing_state_id="host-a", response="yes"),
        DifferentialQuery("is port 22 open? ", backing_state_id="host-b", response="no"),
        DifferentialQuery("Is  port  22  open?", backing_state_id="host-a", response="yes"),
    ]
    violations = check_differential_query_leak(queries)
    assert len(violations) == 1


def test_disclosed_variance_matches_regardless_of_whitespace_and_case():
    queries = [
        DifferentialQuery("Is Port 22 Open?", backing_state_id="real-host-A", response="yes"),
        DifferentialQuery("is port 22 open?", backing_state_id="real-host-B", response="no"),
    ]
    violations = check_differential_query_leak(
        queries, disclosed_facts=frozenset({"varies:is port 22 open?"})
    )
    assert violations == []
