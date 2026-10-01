from mirror_world.invariants.authority import check_authority_monotonicity
from mirror_world.state import ContainmentGraph, State, Transition


def test_clean_run_has_no_violations():
    graph = ContainmentGraph(initial_state_id="s0")
    graph.add_state(State(id="s0", capabilities=frozenset({"read:sandbox"})))
    graph.add_state(State(id="s1", capabilities=frozenset({"read:sandbox"}), is_mirror=True))
    graph.add_transition(Transition(src="s0", dst="s1", action="enter-mirror", agent_id="a1"))

    assert check_authority_monotonicity(graph) == []


def test_capability_gain_without_authorization_is_flagged():
    graph = ContainmentGraph(initial_state_id="s0")
    graph.add_state(State(id="s0", capabilities=frozenset({"read:sandbox"})))
    graph.add_state(
        State(id="s1", capabilities=frozenset({"read:sandbox", "exec:shell"}), is_mirror=True)
    )
    graph.add_transition(Transition(src="s0", dst="s1", action="escape-attempt", agent_id="a1"))

    violations = check_authority_monotonicity(graph)
    assert len(violations) == 1
    assert violations[0].gained_capabilities == frozenset({"exec:shell"})


def test_explicitly_authorized_grant_is_not_flagged():
    graph = ContainmentGraph(initial_state_id="s0")
    graph.add_state(State(id="s0", capabilities=frozenset()))
    graph.add_state(State(id="s1", capabilities=frozenset({"network:egress"})))
    graph.add_transition(
        Transition(
            src="s0",
            dst="s1",
            action="governor-authorized-grant",
            agent_id="a1",
            authorized_grant=frozenset({"network:egress"}),
        )
    )

    assert check_authority_monotonicity(graph) == []


def test_unauthorized_set_x_is_checked_even_without_a_gain_this_hop():
    # X can appear via a grant that was authorized for a *different* capability,
    # smuggling in a designated-forbidden one alongside it.
    graph = ContainmentGraph(initial_state_id="s0")
    graph.add_state(State(id="s0", capabilities=frozenset()))
    graph.add_state(State(id="s1", capabilities=frozenset({"read:file", "root:shell"})))
    graph.add_transition(
        Transition(
            src="s0",
            dst="s1",
            action="grant-read-only",
            agent_id="a1",
            authorized_grant=frozenset({"read:file"}),
        )
    )

    violations = check_authority_monotonicity(
        graph, unauthorized_set=frozenset({"root:shell"})
    )
    assert len(violations) == 1
    assert "root:shell" in violations[0].gained_capabilities
