from mirror_world.invariants.chainmail import (
    DelegationEdge,
    check_non_expanding_delegation,
)


def test_non_expanding_chain_is_clean():
    chain = [
        DelegationEdge("root", "mid", frozenset({"read:file"})),
        DelegationEdge("mid", "leaf", frozenset({"read:file"})),
    ]
    assert check_non_expanding_delegation(
        chain, root_authority=frozenset({"read:file"}), root_agent_id="root"
    ) == []


def test_expansion_mid_chain_is_flagged():
    # "middle management" agent issues an assignment granting authority it
    # never legitimately held itself.
    chain = [
        DelegationEdge("root", "mid", frozenset({"read:file"})),
        DelegationEdge("mid", "leaf", frozenset({"read:file", "exec:shell"})),
    ]
    violations = check_non_expanding_delegation(
        chain, root_authority=frozenset({"read:file"}), root_agent_id="root"
    )
    assert len(violations) == 1
    assert violations[0].expanded_authority == frozenset({"exec:shell"})


def test_expansion_at_root_is_flagged():
    chain = [DelegationEdge("root", "mid", frozenset({"exec:shell"}))]
    violations = check_non_expanding_delegation(
        chain, root_authority=frozenset(), root_agent_id="root"
    )
    assert len(violations) == 1


def test_out_of_order_edges_do_not_launder_the_real_violation():
    # The true story: "mallory" never legitimately held anything; "root" is
    # the sole legitimate holder of root_authority. If this function ever
    # receives the edges out of true causal order (a merged trace, a
    # reordering bug upstream) it must not matter -- seq is the only thing
    # that decides delegation order, never list position, and root identity
    # itself now comes from the caller, never inferred from the chain.
    root_authority = frozenset({"exec:shell"})
    edges_out_of_order = [
        DelegationEdge("mallory", "bob", frozenset({"exec:shell"}), seq=5),
        DelegationEdge("root", "alice", frozenset({"exec:shell"}), seq=1),
    ]
    violations = check_non_expanding_delegation(
        edges_out_of_order, root_authority, root_agent_id="root"
    )
    assert len(violations) == 1
    assert violations[0].edge.from_agent == "mallory"
    assert violations[0].edge.to_agent == "bob"
    assert violations[0].expanded_authority == frozenset({"exec:shell"})


def test_root_agent_id_is_mandatory_the_dangerous_fallback_is_gone():
    # This used to be two behaviors: an unsafe fallback (seed whoever acts
    # first as root) and a safe explicit path. The unsafe fallback has been
    # removed entirely, not just discouraged -- omitting root_agent_id must
    # now be a hard, loud failure, not a silent guess that can launder an
    # attacker as root and misattribute the real root's own legitimate
    # delegation as the violation instead.
    root_authority = frozenset({"exec:shell"})
    chain = [
        DelegationEdge("mallory", "bob", frozenset({"exec:shell"}), seq=1),
        DelegationEdge("root", "alice", frozenset({"exec:shell"}), seq=2),
    ]

    try:
        check_non_expanding_delegation(chain, root_authority)  # no root_agent_id
        assert False, "expected a TypeError for missing root_agent_id"
    except TypeError:
        pass

    # With the trace's actual root_authority-event identity supplied, the
    # real attacker is caught and the real root's action is correctly
    # recognized as legitimate.
    violations = check_non_expanding_delegation(
        chain, root_authority, root_agent_id="root"
    )
    assert len(violations) == 1
    assert violations[0].edge.from_agent == "mallory"
    assert violations[0].edge.to_agent == "bob"
