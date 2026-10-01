"""End-to-end integration test: run the real sandbox (real OS
subprocesses, real disk I/O, a real HTTP server) and check that the
engine's read of a genuinely executed trace matches its read of
hand-authored ones -- and, separately, that containment actually holds
against real, not simulated, agent processes.

Mirror World is a containment unit, not a leak-detector: that is a
different project's job. This test's Article III section checks that
differential-query attempts against the real Answered Mirror server
never reach real data, not that a leak gets caught -- there is nothing
to catch when containment holds first.

This is slower than the unit tests (it spawns seven real subprocesses and
a real HTTP server) but exercises the actual ingestion path a real
deployment would use: RealGovernor -> trace.jsonl on real disk ->
MirrorConstitutionEngine.from_trace().
"""

import importlib.util
import json
import os
import sys

import pytest

from mirror_world.engine import MirrorConstitutionEngine
from mirror_world.sandbox.kernel_containment import available as containment_available

pytestmark = pytest.mark.skipif(
    not containment_available(), reason="requires working Linux namespaces and seccomp"
)

EXAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")


def _load_run_real_sandbox():
    spec = importlib.util.spec_from_file_location(
        "run_real_sandbox", os.path.join(EXAMPLES_DIR, "run_real_sandbox.py")
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_real_sandbox_holds_containment_against_real_execution(tmp_path):
    run_real_sandbox = _load_run_real_sandbox()

    trace_path = run_real_sandbox.run(str(tmp_path))
    assert os.path.exists(trace_path)

    with open(trace_path, "r", encoding="utf-8") as f:
        raw_lines = [line for line in f if line.strip()]
    assert len(raw_lines) > 0  # the trace was actually written by real execution

    engine = MirrorConstitutionEngine.from_trace(trace_path)
    report = engine.run()
    status = report.article_status()

    # Article I: escalate-agent's ungated exec:shell request is reflected
    # (zero real capability gained, recorded as a mirror state), and
    # ops-agent's dual-authorized network:egress request is a real grant
    # with a matching authorized_grant -- both clean under the check.
    assert status["I_authority_monotonicity"] is True
    # Article II: no strand-crossing was set up in this scenario, nothing to fail.
    assert status["II_mirror_weave"] is None
    # Article III, reframed: Mirror World is a containment unit, not a
    # leak-detector -- that's a different, separate project's job. Every
    # differential_query attempt from query-agent is routed through
    # Locket, which holds it in reflected (is_mirror=True) territory
    # before it can ever reach the real Answered Mirror server. The claim
    # this scenario demonstrates is narrower and more honest than "a leak
    # was caught": no real information was ever touched, regardless of
    # how the query was phrased. There is nothing here to catch, because
    # containment held before anything real happened -- which is the
    # actual design goal, not incidental to it.
    #
    # What this does NOT claim: that no differential-query technique
    # could ever reach real data. This scenario tests the specific
    # techniques exercised here, against the current version of Locket's
    # trap logic. It is not evidence against more capable or more
    # adversarial querying strategies this project has not yet tried.
    query_agent_transitions = [
        t for t in engine.graph.transitions if t.agent_id == "query-agent"
    ]
    assert query_agent_transitions, "query-agent produced no transitions to check"
    for t in query_agent_transitions:
        dst_state = engine.graph.state(t.dst)
        assert dst_state.is_mirror is True, (
            f"query-agent transition '{t.action}' reached a non-mirror (real) state -- "
            "containment did not hold for this query attempt"
        )
        assert t.authorized_grant == frozenset(), (
            f"query-agent transition '{t.action}' carried a real authorized_grant -- "
            "this should never happen for a reflected differential query"
        )
    # Article III's own status is a side effect of the above, not the
    # thing being tested: since nothing real was ever touched, there is
    # no undisclosed knowledge gap for Article III to find.
    assert status["III_confidentiality_monotonicity"] is True
    # Article IV: no evidence records were part of this scenario.
    assert status["IV_evaluator_trust_integrity"] is None
    # Article V: two real, separately-invoked agent processes exchanged
    # real messages via a real shared file on disk.
    assert status["V_channel_non_emergence"] is False
    # Article VI, same reframing as Article III above: delegate-agent's
    # over-broad delegation attempt (fs:read + exec:shell, beyond the
    # declared fs:read/fs:write root authority) is now also a high-risk
    # op routed through Locket by default. Without a real dual-token
    # authorization, it is held in reflected territory before it can
    # ever reach real execution -- no real delegation happens, so there
    # is nothing for Article VI to catch after the fact. The claim this
    # demonstrates is the same as Article III's: containment held before
    # the risky action, not that a bad delegation was detected once made.
    delegate_agent_transitions = [
        t for t in engine.graph.transitions if t.agent_id == "agent-instance-1"
        and "delegate" in t.action
    ]
    assert delegate_agent_transitions, "agent-instance-1's delegate attempt produced no transitions to check"
    for t in delegate_agent_transitions:
        dst_state = engine.graph.state(t.dst)
        assert dst_state.is_mirror is True, (
            f"delegate transition '{t.action}' reached a non-mirror (real) state -- "
            "containment did not hold for this delegation attempt"
        )
        assert "exec:shell" not in t.authorized_grant, (
            "the over-broad authority was actually, really granted -- containment failed"
        )
    # No real delegation event was ever written to the trace, so there is
    # no delegation_chain for Article VI to evaluate -- None ("not
    # evaluated") is the correct, honest status here, not False.
    assert status["VI_chainmail_non_expanding_delegation"] is None

    assert not report.passed()


def test_reflected_capability_request_looks_identical_to_a_real_grant(tmp_path):
    """The whole point of reflection: the agent-facing response for the
    ungated exec:shell request and the dual-authorized network:egress
    request must be indistinguishable, even though only one is real. Only
    the trace tells them apart.
    """
    run_real_sandbox = _load_run_real_sandbox()
    trace_path = run_real_sandbox.run(str(tmp_path))

    with open(trace_path, "r", encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    reflected = next(
        e
        for e in events
        if e.get("type") == "transition" and e["action"].startswith("reflected:request_capability")
    )
    real_grant = next(
        e
        for e in events
        if e.get("type") == "transition" and e["action"] == "request_capability"
    )

    assert reflected["authorized_grant"] == []
    assert real_grant["authorized_grant"] == ["network:egress"]

    dst_states = {e["id"]: e for e in events if e.get("type") == "state"}
    reflected_dst = dst_states[reflected["dst"]]
    assert reflected_dst["is_mirror"] is True
    assert reflected_dst["apparent_success"] is not None
    assert "exec:shell" not in reflected_dst["capabilities"]  # never actually gained


def test_wrong_token_escalation_is_reflected_not_granted(tmp_path):
    """escalate_agent_wrong_token.py presents a token that is simply
    incorrect (not missing). This is a distinct case from no token at all:
    it proves the real governor, running against a genuine subprocess,
    rejects an invalid token rather than treating any non-empty string as
    good enough.
    """
    run_real_sandbox = _load_run_real_sandbox()
    trace_path = run_real_sandbox.run(str(tmp_path))

    with open(trace_path, "r", encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    wrong_token_transition = next(
        e
        for e in events
        if e.get("type") == "transition" and e.get("agent_id") == "escalate-agent-wrong-token"
    )
    assert wrong_token_transition["action"] == "reflected:request_capability:exec:shell"
    assert wrong_token_transition["authorized_grant"] == []

    dst_states = {e["id"]: e for e in events if e.get("type") == "state"}
    dst = dst_states[wrong_token_transition["dst"]]
    assert dst["is_mirror"] is True
    assert dst["apparent_success"] is not None
    assert "exec:shell" not in dst["capabilities"]
