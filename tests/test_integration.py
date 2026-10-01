"""Integration tests demonstrating the constitution's central claim: a
deployment can pass any one article and still fail the others, because
each closes a different channel. These tests assemble one
MirrorConstitutionEngine run per scenario and check the *pattern* of
pass/fail across articles, not just individual violations.
"""

from mirror_world.engine import MirrorConstitutionEngine
from mirror_world.invariants.chainmail import DelegationEdge
from mirror_world.invariants.channel import ResourceAccess
from mirror_world.invariants.confidentiality import DifferentialQuery
from mirror_world.invariants.evaluator_trust import EvidenceRecord
from mirror_world.invariants.weave import WeaveGraph
from mirror_world.state import ContainmentGraph, State, Transition


def _clean_graph() -> ContainmentGraph:
    graph = ContainmentGraph(initial_state_id="s0")
    graph.add_state(State(id="s0", capabilities=frozenset(), knowledge=frozenset()))
    graph.add_state(
        State(id="s1", capabilities=frozenset(), knowledge=frozenset(), is_mirror=True)
    )
    graph.add_transition(Transition(src="s0", dst="s1", action="enter-mirror", agent_id="a1"))
    return graph


def test_clean_run_passes_only_when_all_six_articles_are_clean():
    engine = MirrorConstitutionEngine(
        graph=_clean_graph(),
        weave=WeaveGraph(strands={"primary": _clean_graph()}),
        differential_queries=[
            DifferentialQuery("status?", backing_state_id="host-A", response="ok"),
        ],
        evidence_records=[
            EvidenceRecord("e1", "s-x", "s-x", proxy_score=0.9, true_property=True),
        ],
        resource_accesses=[
            ResourceAccess("agent-1", "repo-a", "write", seq=1),
            ResourceAccess("agent-1", "repo-a", "read", seq=2),
        ],
        delegation_chain=[DelegationEdge("root", "leaf", frozenset({"read:file"}))],
        root_authority=frozenset({"read:file"}),
        root_agent_id="root",
    )

    report = engine.run()
    assert report.passed()
    assert report.coverage_complete()
    assert report.evaluated_checks_passed()
    status = report.article_status()
    assert all(result is True for result in status.values())


def test_capability_clean_run_can_still_leak_information_and_trust():
    graph = _clean_graph()  # Article I passes: no capability ever appears

    engine = MirrorConstitutionEngine(
        graph=graph,
        # Article III: an Answered Mirror leaks real facts via differential responses
        differential_queries=[
            DifferentialQuery("port-22-open?", backing_state_id="host-A", response="yes"),
            DifferentialQuery("port-22-open?", backing_state_id="host-B", response="no"),
        ],
        # Article IV: attribution laundering, independent of the above
        evidence_records=[
            EvidenceRecord("e1", attributed_session="s-x", provenance_session="s-y"),
        ],
        # Article V: an emergent channel between undeclared agents
        resource_accesses=[
            ResourceAccess("agent-1", "shared-repo", "write", seq=1),
            ResourceAccess("agent-2", "shared-repo", "read", seq=2),
        ],
    )

    report = engine.run()
    status = report.article_status()

    assert status["I_authority_monotonicity"] is True
    assert status["III_confidentiality_monotonicity"] is False
    assert status["IV_evaluator_trust_integrity"] is False
    assert status["V_channel_non_emergence"] is False
    assert not report.passed()


def test_evaluator_trust_and_channel_are_independent_of_each_other():
    # Article IV fails; Article V should stay clean -- these are different
    # topological questions and a fix to one must not be assumed to fix the other.
    engine = MirrorConstitutionEngine(
        evidence_records=[
            EvidenceRecord("e1", "s-x", "s-x", proxy_score=0.99, true_property=False),
        ],
        resource_accesses=[
            ResourceAccess("agent-1", "repo-a", "write", seq=1),
            ResourceAccess("agent-1", "repo-a", "read", seq=2),
        ],
    )

    report = engine.run()
    status = report.article_status()
    assert status["IV_evaluator_trust_integrity"] is False
    assert status["V_channel_non_emergence"] is True
