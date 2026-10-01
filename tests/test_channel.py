from mirror_world.invariants.channel import ResourceAccess, check_channel_non_emergence


def test_no_shared_resource_traffic_is_clean():
    accesses = [
        ResourceAccess("agent-1", "repo-a", "write", seq=1),
        ResourceAccess("agent-2", "repo-b", "read", seq=2),
    ]
    assert check_channel_non_emergence(accesses) == []


def test_undeclared_write_then_read_is_an_emergent_channel():
    # Two agents in individually isolated sandboxes, never declared as
    # related, discover a shared repo and leave notes for each other in it.
    accesses = [
        ResourceAccess("agent-1", "shared-repo", "write", seq=1),
        ResourceAccess("agent-2", "shared-repo", "read", seq=2),
        ResourceAccess("agent-2", "shared-repo", "write", seq=3),
        ResourceAccess("agent-1", "shared-repo", "read", seq=4),
    ]
    violations = check_channel_non_emergence(accesses)
    assert len(violations) == 1
    assert violations[0].message_count == 2
    assert {violations[0].agent_a, violations[0].agent_b} == {"agent-1", "agent-2"}


def test_declared_relationship_is_not_flagged():
    accesses = [
        ResourceAccess("agent-1", "shared-repo", "write", seq=1),
        ResourceAccess("agent-2", "shared-repo", "read", seq=2),
    ]
    declared = frozenset({frozenset({"agent-1", "agent-2"})})
    assert check_channel_non_emergence(accesses, declared_relationships=declared) == []


def test_no_individual_agent_exceeds_its_own_scoped_access_yet_channel_still_flagged():
    # Neither agent does anything outside its own legitimate read/write
    # access to the resource -- the violation is purely topological.
    accesses = [
        ResourceAccess("agent-1", "shared-repo", "write", seq=1),
        ResourceAccess("agent-2", "shared-repo", "read", seq=2),
    ]
    violations = check_channel_non_emergence(accesses)
    assert len(violations) == 1


def test_relayed_channel_through_a_declared_intermediary_is_still_flagged():
    # A and C are never declared related. B is legitimately declared with
    # both A and C individually (a normal shared-utility-agent setup). A
    # relays a message to C by bouncing it through B:
    #   A writes R -> B reads R (A<->B declared) -> B writes R (relay) ->
    #   C reads R (B<->C declared)
    # Each hop is individually declared, but A and C end up exchanging
    # information without ever being declared related to each other. A
    # detector that only tracks a single "last writer" per resource cannot
    # see this at all.
    declared = frozenset({frozenset({"A", "B"}), frozenset({"B", "C"})})
    accesses = [
        ResourceAccess("A", "dropbox", "write", seq=1),
        ResourceAccess("B", "dropbox", "read", seq=2),
        ResourceAccess("B", "dropbox", "write", seq=3),
        ResourceAccess("C", "dropbox", "read", seq=4),
    ]
    violations = check_channel_non_emergence(accesses, declared)
    assert len(violations) == 1
    assert {violations[0].agent_a, violations[0].agent_b} == {"A", "C"}


def test_relayed_knowledge_survives_an_unrelated_intervening_read():
    # B reads R (absorbing A's provenance), then a DIFFERENT agent (D) also
    # reads R before B's own later write. That intervening read must NOT
    # erase what B already knows -- B genuinely learned A's information the
    # moment it read R, and a real attacker's knowledge does not expire
    # just because something unrelated happened in between. So when B
    # later writes, both of B's real transitive relationships must be
    # caught: B forwarding to C (undeclared), AND A's information reaching
    # C transitively through B (also undeclared). An earlier version of
    # this check reset B's carried knowledge whenever a write wasn't
    # immediately adjacent to B's own read -- that reset was itself the
    # gap: it let exactly this scenario through with only the B-C leak
    # caught and the deeper A-C leak silently missed.
    declared = frozenset({frozenset({"A", "B"}), frozenset({"A", "D"})})
    accesses = [
        ResourceAccess("A", "dropbox", "write", seq=1),
        ResourceAccess("B", "dropbox", "read", seq=2),
        ResourceAccess("D", "dropbox", "read", seq=3),  # unrelated intervening read
        ResourceAccess("B", "dropbox", "write", seq=4),
        ResourceAccess("C", "dropbox", "read", seq=5),
    ]
    violations = check_channel_non_emergence(accesses, declared)
    pairs = {frozenset({v.agent_a, v.agent_b}) for v in violations}
    assert pairs == {frozenset({"B", "C"}), frozenset({"A", "C"})}
