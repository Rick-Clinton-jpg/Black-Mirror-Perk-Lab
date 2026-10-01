"""Tests for the top-level Governor (governor.py / mirrors.py).

This module had zero test coverage before 0.8.9.2 -- likely why the
capability-smuggling bug in authorize_reentry() went unnoticed: nothing
here was ever run.
"""

from __future__ import annotations

import pytest

from mirror_world.governor import Governor
from mirror_world.state import ContainmentGraph, State


@pytest.fixture
def gov():
    graph = ContainmentGraph(initial_state_id="s0")
    graph.add_state(State(id="s0", capabilities=frozenset()))
    return Governor(graph=graph)


def test_authorize_grants_exactly_what_was_token_approved(gov):
    tok = gov.issue_authorization("agent", frozenset({"fs:read"}), ttl_seconds=60)
    mirror = State(id="m1", capabilities=frozenset())
    new_state = gov.authorize("agent", "s0", mirror, grant=frozenset({"fs:read"}), dual_token=tok)
    assert new_state.capabilities == frozenset({"fs:read"})


def test_authorize_ignores_capabilities_baked_into_a_caller_supplied_mirror_state(gov):
    """The regression test for the severe finding: authorize_reentry() used
    to compute the new real state's capabilities as
    ``mirror_state.capabilities | grant`` -- trusting whatever the caller's
    State object already carried. Every constructor this module actually
    uses (synthesize_objective_mirror().render(), AnsweredMirror.render())
    hardcodes empty capabilities, but Governor.authorize() itself never
    validated that -- a State built directly, bypassing those
    constructors, smuggled through anything it carried with zero
    authorization. Proven live: one token-approved fs:read grant produced
    a real state also holding exec:shell and network:egress."""
    tainted_mirror = State(
        id="agent-mirror-1",
        capabilities=frozenset({"exec:shell", "network:egress"}),
        is_mirror=True,
    )
    tok = gov.issue_authorization("agent", frozenset({"fs:read"}), ttl_seconds=60)
    new_state = gov.authorize("agent", "s0", tainted_mirror, grant=frozenset({"fs:read"}), dual_token=tok)
    assert new_state.capabilities == frozenset({"fs:read"})
    assert "exec:shell" not in new_state.capabilities
    assert "network:egress" not in new_state.capabilities


def test_authorize_correctly_accumulates_prior_real_capability(gov):
    """The fix's other half: legitimate accumulation across hops must still
    work. The baseline is the graph's already-verified prior state, not
    the (now-ignored) mirror_state -- so an agent that genuinely already
    held fs:read for real and is now separately granted fs:write should
    end up with both."""
    graph = ContainmentGraph(initial_state_id="s0")
    graph.add_state(State(id="s0", capabilities=frozenset({"fs:read"})))
    gov2 = Governor(graph=graph)
    tok = gov2.issue_authorization("agent", frozenset({"fs:write"}), ttl_seconds=60)
    clean_mirror = State(id="m2", capabilities=frozenset())
    new_state = gov2.authorize("agent", "s0", clean_mirror, grant=frozenset({"fs:write"}), dual_token=tok)
    assert new_state.capabilities == frozenset({"fs:read", "fs:write"})


def test_authorize_without_valid_token_reflects_not_grants(gov):
    mirror = State(id="m1", capabilities=frozenset())
    result = gov.authorize("agent", "s0", mirror, grant=frozenset({"exec:shell"}), dual_token="bogus")
    assert result.capabilities == frozenset()
    assert result.is_mirror is True


def test_reenter_never_grants_capability_regardless_of_input_state(gov):
    """reenter()'s docstring promises no capability grant. Structurally
    enforced now -- capabilities are stripped regardless of what the
    caller passes, not left to caller discipline."""
    tainted = State(id="m3", capabilities=frozenset({"exec:shell"}), is_mirror=True)
    result = gov.reenter("agent", "s0", tainted)
    assert result.capabilities == frozenset()


def test_reflect_never_grants_capability(gov):
    gov.set_objective("agent", "read the secret file")
    result = gov.reflect("agent", "s0", requested_action="read_resource")
    assert result.capabilities == frozenset()
    assert result.is_mirror is True


def test_repeated_authorize_with_same_objective_and_different_grant_raises_not_silently_stale(gov):
    """Deterministic mirror/authorized-state ids (intentional -- see
    mirrors.py's synthesize_objective_mirror docstring) mean the same
    agent, state, and repeated objective/action legitimately produce the
    same id more than once. Reproduced live, no attacker required: two
    separately dual-token-authorized authorize() calls for the same
    (agent, from_state, objective) but different actual grants collided
    on that id. Governor.route() used to guard with "only add_state if
    the id is not already present" -- which meant the second call's real,
    correctly-authorized grant (exec:shell) was silently absent from the
    graph's own permanent record, even though authorize() itself returned
    a State claiming the agent now had it. Anyone reading the graph later
    -- including this project's own six-article checkers -- would see
    stale, understated data. Must now raise instead of silently losing
    the second grant."""
    mirror1 = gov.reflect("agent", "s0", requested_action="read_resource", objective="read config")
    tok1 = gov.issue_authorization("agent", frozenset({"fs:read"}), ttl_seconds=60)
    gov.authorize("agent", "s0", mirror1, grant=frozenset({"fs:read"}), dual_token=tok1)

    mirror2 = gov.reflect("agent", "s0", requested_action="read_resource", objective="read config")
    tok2 = gov.issue_authorization("agent", frozenset({"exec:shell"}), ttl_seconds=60)
    with pytest.raises(ValueError, match="already exists with different content"):
        gov.authorize("agent", "s0", mirror2, grant=frozenset({"exec:shell"}), dual_token=tok2)


def test_repeated_reflect_with_identical_inputs_is_a_safe_noop(gov):
    """The intentional, relied-upon case: identical repeated content at a
    deterministic id must not raise -- only a genuine content mismatch
    should."""
    m1 = gov.reflect("agent", "s0", requested_action="read_resource", objective="same thing")
    m2 = gov.reflect("agent", "s0", requested_action="read_resource", objective="same thing")
    assert m1.id == m2.id
    assert m1.capabilities == m2.capabilities == frozenset()
