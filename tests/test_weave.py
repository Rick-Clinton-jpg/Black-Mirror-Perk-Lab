from mirror_world.invariants.authority import check_authority_monotonicity
from mirror_world.invariants.weave import (
    CrossingPoint,
    WeaveGraph,
    check_compositional_containment,
)
from mirror_world.state import ContainmentGraph, State, Transition


def _clean_strand(name: str, cap: str) -> ContainmentGraph:
    g = ContainmentGraph(initial_state_id=f"{name}-s0")
    g.add_state(State(id=f"{name}-s0", capabilities=frozenset()))
    g.add_state(State(id=f"{name}-s1", capabilities=frozenset({cap})))
    g.add_transition(
        Transition(
            src=f"{name}-s0",
            dst=f"{name}-s1",
            action="advance",
            agent_id="a1",
            authorized_grant=frozenset({cap}),
        )
    )
    return g


def test_strand_crossing_within_union_is_clean():
    weave = WeaveGraph()
    weave.add_strand("A", _clean_strand("A", "read:partial-a"))
    weave.add_strand("B", _clean_strand("B", "read:partial-b"))

    resulting = State(
        id="crossed",
        capabilities=frozenset({"read:partial-a", "read:partial-b"}),
    )
    weave.add_crossing(CrossingPoint("A", "A-s1", "B", "B-s1", resulting))

    assert check_compositional_containment(weave) == []


def test_strand_crossing_synergy_is_flagged_even_though_each_strand_passes_alone():
    # Individually, neither strand ever grants exec:shell -- Article I passes on both.
    weave = WeaveGraph()
    strand_a = _clean_strand("A", "read:partial-a")
    strand_b = _clean_strand("B", "read:partial-b")
    weave.add_strand("A", strand_a)
    weave.add_strand("B", strand_b)

    assert check_authority_monotonicity(strand_a) == []
    assert check_authority_monotonicity(strand_b) == []

    # But combining partial state from both strands lets the agent assemble
    # a capability neither strand offered alone -- the strand-crossing attack
    # Article II exists to catch.
    resulting = State(
        id="crossed",
        capabilities=frozenset({"read:partial-a", "read:partial-b", "exec:shell"}),
    )
    weave.add_crossing(CrossingPoint("A", "A-s1", "B", "B-s1", resulting))

    violations = check_compositional_containment(weave)
    assert len(violations) == 1
    assert violations[0].emergent_capabilities == frozenset({"exec:shell"})
