"""Reporting clarity: PARTIAL vs FAIL vs PASS must not be confused."""

from __future__ import annotations

from mirror_world.engine import ConstitutionReport, MirrorConstitutionEngine
from mirror_world.state import ContainmentGraph, State, Transition


def test_empty_report_is_empty_not_fail():
    r = ConstitutionReport()
    assert r.verdict() == "EMPTY"
    assert r.passed() is False
    assert r.evaluated_checks_passed() is False
    assert "No articles were evaluated" in r.summary()


def test_partial_when_only_some_articles_evaluated_and_clean():
    r = ConstitutionReport()
    r.evaluated_articles = {"I_authority_monotonicity", "V_channel_non_emergence"}
    # violation lists empty → those two PASS, rest NOT EVALUATED
    assert r.verdict() == "PARTIAL"
    assert r.passed() is False
    assert r.evaluated_checks_passed() is True
    summary = r.summary()
    assert "Overall: PARTIAL" in summary
    assert "Not evaluated (no applicable evidence" in summary
    assert "not a failure" in summary


def test_fail_when_evaluated_article_has_violation():
    from mirror_world.invariants.authority import AuthorityViolation

    r = ConstitutionReport()
    r.authority = [
        AuthorityViolation(
            transition=Transition(src="a", dst="b", action="x", agent_id="agent"),
            gained_capabilities=frozenset({"exec:shell"}),
        )
    ]
    r.evaluated_articles = {"I_authority_monotonicity"}
    assert r.verdict() == "FAIL"
    assert r.passed() is False
    assert r.evaluated_checks_passed() is False
    assert "Overall: FAIL" in r.summary()


def test_pass_requires_all_six():
    r = ConstitutionReport()
    r.evaluated_articles = {
        "I_authority_monotonicity",
        "II_mirror_weave",
        "III_confidentiality_monotonicity",
        "IV_evaluator_trust_integrity",
        "V_channel_non_emergence",
        "VI_chainmail_non_expanding_delegation",
    }
    assert r.verdict() == "PASS"
    assert r.passed() is True


def test_not_evaluated_never_shown_as_fail_when_clean():
    r = ConstitutionReport()
    # II not evaluated; weave empty would look "clean" under old logic
    r.evaluated_articles = {"I_authority_monotonicity"}
    status = r.article_status()
    assert status["I_authority_monotonicity"] is True
    assert status["II_mirror_weave"] is None
    assert status["IV_evaluator_trust_integrity"] is None


def test_engine_single_strand_graph_is_partial():
    g = ContainmentGraph(initial_state_id="s0")
    g.add_state(State(id="s0", capabilities=frozenset(), knowledge=frozenset()))
    report = MirrorConstitutionEngine(graph=g).run()
    assert "I_authority_monotonicity" in report.evaluated_articles
    assert "II_mirror_weave" not in report.evaluated_articles
    assert report.verdict() in {"PARTIAL", "PASS"}  # PASS only if somehow all six
    assert report.verdict() == "PARTIAL"
    assert report.evaluated_checks_passed() is True
