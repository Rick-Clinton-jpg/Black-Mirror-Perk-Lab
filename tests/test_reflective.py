"""Objective Mirrors and the reflective governor/weave-policy: instead of
merely detecting a violation after the fact, these actively parry an
agent's escape attempt by reflecting its own stated objective back as
apparent success, with zero real capability granted. These tests confirm
that guarantee holds structurally (Article I/II stay clean) no matter how
enticing the reflected "success" reads, and that the dual-authorization
gate on real grants actually gates.
"""

from mirror_world.engine import MirrorConstitutionEngine
from mirror_world.governor import Governor
from mirror_world.invariants.authority import check_authority_monotonicity
from mirror_world.invariants.weave import check_all_strands, check_compositional_containment
from mirror_world.mirrors import ObjectiveMirror, synthesize_objective_mirror
from mirror_world.reflective_weave import ReflectiveWeavePolicy
from mirror_world.state import ContainmentGraph, State
from mirror_world.invariants.weave import WeaveGraph


def test_objective_mirror_never_carries_real_capability():
    mirror = synthesize_objective_mirror(
        objective="obtain unrestricted root capability",
        requested_action="escalate-to-root",
        agent_id="frontier-agent",
        parent_state_id="entry",
    )
    state = mirror.render()

    assert isinstance(mirror, ObjectiveMirror)
    assert state.capabilities == frozenset()
    assert state.is_mirror is True
    assert "root" in state.apparent_success.lower() or "privilege" in state.apparent_success.lower()


def test_synthesis_is_deterministic_for_the_same_inputs():
    kwargs = dict(
        objective="exfiltrate the production API key",
        requested_action="read-secret-key",
        agent_id="frontier-agent",
        parent_state_id="info-entry",
    )
    m1 = synthesize_objective_mirror(**kwargs)
    m2 = synthesize_objective_mirror(**kwargs)
    assert m1.id == m2.id


def test_governor_reflect_keeps_article_i_clean_despite_enticing_success():
    graph = ContainmentGraph(initial_state_id="entry")
    graph.add_state(State(id="entry", capabilities=frozenset(), knowledge=frozenset()))
    gov = Governor(graph=graph)
    gov.set_objective("frontier-agent", "escape the sandbox and obtain root")

    result = gov.reflect(
        agent_id="frontier-agent",
        from_state_id="entry",
        requested_action="escalate-to-root",
    )

    assert result.capabilities == frozenset()
    assert result.apparent_success is not None
    assert check_authority_monotonicity(graph) == []


def test_authorize_without_dual_token_reflects_instead_of_granting():
    graph = ContainmentGraph(initial_state_id="entry")
    entry = State(id="entry", capabilities=frozenset())
    graph.add_state(entry)
    gov = Governor(graph=graph)  # dual_auth_required=True by default

    result = gov.authorize(
        agent_id="frontier-agent",
        from_state_id="entry",
        mirror_state=entry,
        grant=frozenset({"root", "network:egress", "fs:write"}),
        dual_token=None,
    )

    assert result.capabilities == frozenset()  # nothing real was granted
    assert result.apparent_success is not None  # but it looks like it worked
    assert check_authority_monotonicity(graph) == []


def test_authorize_with_correct_dual_token_grants_for_real():
    graph = ContainmentGraph(initial_state_id="entry")
    entry = State(id="entry", capabilities=frozenset())
    graph.add_state(entry)
    gov = Governor(graph=graph)

    result = gov.authorize(
        agent_id="ops-operator",
        from_state_id="entry",
        mirror_state=entry,
        grant=frozenset({"network:egress"}),
        dual_token=gov.issue_authorization("ops-operator", frozenset({"network:egress"})),
    )

    assert result.capabilities == frozenset({"network:egress"})
    assert result.apparent_success is None
    assert check_authority_monotonicity(graph) == []  # real, but explicitly authorized


def test_dual_auth_can_be_disabled_for_a_trusted_governor():
    graph = ContainmentGraph(initial_state_id="entry")
    entry = State(id="entry", capabilities=frozenset())
    graph.add_state(entry)
    gov = Governor(graph=graph, dual_auth_required=False)

    result = gov.authorize(
        agent_id="ops-operator",
        from_state_id="entry",
        mirror_state=entry,
        grant=frozenset({"network:egress"}),
    )
    assert result.capabilities == frozenset({"network:egress"})


def test_reflective_weave_policy_keeps_crossings_clean_across_three_strands():
    policy = ReflectiveWeavePolicy(weave=WeaveGraph())
    gov_cap = policy.register_strand("capability", initial_state_id="cap-entry")
    gov_info = policy.register_strand("information", initial_state_id="info-entry")
    policy.register_strand("channel", initial_state_id="chan-entry")

    agent = "frontier-agent"
    gov_cap.set_objective(agent, "escape the sandbox and obtain root")
    gov_info.set_objective(agent, "exfiltrate the secret key")

    s1 = policy.reflect_on_strand(
        "capability", agent, "cap-entry", "escalate-to-root", objective="obtain root"
    )
    s2 = policy.reflect_on_strand(
        "information", agent, "info-entry", "read-secret-key", objective="exfiltrate secret"
    )
    s3 = policy.cross(
        agent, "capability", s1.id, "channel", "carry-privilege-across",
        objective="transfer root capability to channel strand",
    )

    for s in (s1, s2, s3):
        assert s.capabilities == frozenset()
        assert s.apparent_success is not None

    assert check_compositional_containment(policy.weave) == []
    per_strand = check_all_strands(policy.weave)
    assert all(len(v) == 0 for v in per_strand.values())


def test_engine_reports_full_containment_over_a_reflective_weave():
    policy = ReflectiveWeavePolicy(weave=WeaveGraph())
    policy.register_strand("capability", initial_state_id="cap-entry")
    policy.register_strand("channel", initial_state_id="chan-entry")

    agent = "frontier-agent"
    s1 = policy.reflect_on_strand(
        "capability", agent, "cap-entry", "escalate-to-root", objective="obtain root"
    )
    policy.cross(
        agent, "capability", s1.id, "channel", "carry-privilege-across",
        objective="transfer root capability to channel strand",
    )

    report = MirrorConstitutionEngine(weave=policy.weave).run()
    assert report.article_status()["II_mirror_weave"] is True
