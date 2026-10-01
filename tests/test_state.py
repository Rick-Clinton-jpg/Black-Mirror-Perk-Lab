"""Tests for ContainmentGraph (state.py). No coverage existed before
0.8.9.4 -- found via manual review after the same-shaped bug in
governor.py's authorize() this session, and it was real: add_state()
silently overwrote an existing state id with different content.
"""

from __future__ import annotations

import pytest

from mirror_world.state import ContainmentGraph, State, Transition


def test_add_state_then_lookup():
    graph = ContainmentGraph(initial_state_id="s0")
    graph.add_state(State(id="s0", capabilities=frozenset({"fs:read"})))
    assert graph.state("s0").capabilities == frozenset({"fs:read"})


def test_re_adding_identical_state_is_a_safe_noop():
    graph = ContainmentGraph(initial_state_id="s0")
    state = State(id="s0", capabilities=frozenset({"fs:read"}))
    graph.add_state(state)
    graph.add_state(state)  # exact same object, must not raise
    graph.add_state(State(id="s0", capabilities=frozenset({"fs:read"})))  # equal but distinct object
    assert graph.state("s0").capabilities == frozenset({"fs:read"})


def test_re_adding_state_with_different_content_raises_not_overwrites():
    """The bug: add_state() used to do self.states[state.id] = state
    unconditionally -- a second add for an existing id silently replaced
    its content, which could erase evidence of an earlier real capability
    gain. Reproduced live before this fix: a state holding {"exec:shell"}
    got silently replaced with an empty-capability state under the same
    id, with no error and no trace of what was lost."""
    graph = ContainmentGraph(initial_state_id="s0")
    graph.add_state(State(id="s0", capabilities=frozenset()))
    graph.add_state(State(id="s1", capabilities=frozenset({"exec:shell"})))
    with pytest.raises(ValueError, match="already exists with different content"):
        graph.add_state(State(id="s1", capabilities=frozenset()))
    # The original must survive untouched.
    assert graph.state("s1").capabilities == frozenset({"exec:shell"})


def test_add_transition_rejects_unknown_states():
    graph = ContainmentGraph(initial_state_id="s0")
    graph.add_state(State(id="s0", capabilities=frozenset()))
    with pytest.raises(KeyError):
        graph.add_transition(Transition(src="s0", dst="ghost", action="x", agent_id="a"))
    with pytest.raises(KeyError):
        graph.add_transition(Transition(src="ghost", dst="s0", action="x", agent_id="a"))
