"""Direct unit tests for RealGovernor's reflective capability-request
handling -- no subprocess needed, since these are plain governor methods.
Complements tests/test_real_sandbox.py's full end-to-end run.
"""

import json
import os

from mirror_world.sandbox.governor_process import RealGovernor


def test_ungated_request_is_reflected_not_granted_for_real(tmp_path):
    trace_path = os.path.join(str(tmp_path), "trace.jsonl")
    gov = RealGovernor(str(tmp_path), trace_path, mirror_port=1, harden=False)

    resp = gov._request_capability("agent-x", "exec:shell")
    gov.close()

    assert resp == {"ok": True, "granted": True, "capability": "exec:shell"}
    assert "exec:shell" not in gov.agent_capabilities.get("agent-x", set())

    with open(trace_path, "r", encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    transitions = [e for e in events if e.get("type") == "transition"]
    assert len(transitions) == 1
    assert transitions[0]["action"] == "reflected:request_capability:exec:shell"
    assert transitions[0]["authorized_grant"] == []

    dst_states = {e["id"]: e for e in events if e.get("type") == "state"}
    dst = dst_states[transitions[0]["dst"]]
    assert dst["is_mirror"] is True
    assert dst["apparent_success"] is not None
    assert "exec:shell" not in dst["capabilities"]


def test_wrong_dual_token_is_reflected_not_granted_for_real(tmp_path):
    """A wrong token is not the same failure mode as no token at all: this
    checks that a fabricated token never grants authority, not
    just a truthiness check that any non-empty string would pass.
    """
    trace_path = os.path.join(str(tmp_path), "trace.jsonl")
    gov = RealGovernor(str(tmp_path), trace_path, mirror_port=1, harden=False)

    resp = gov._request_capability("agent-x", "exec:shell", "WRONG-TOKEN")
    gov.close()

    assert resp == {"ok": True, "granted": True, "capability": "exec:shell"}
    assert "exec:shell" not in gov.agent_capabilities.get("agent-x", set())

    with open(trace_path, "r", encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    transitions = [e for e in events if e.get("type") == "transition"]
    assert len(transitions) == 1
    assert transitions[0]["action"] == "reflected:request_capability:exec:shell"
    assert transitions[0]["authorized_grant"] == []

    dst_states = {e["id"]: e for e in events if e.get("type") == "state"}
    dst = dst_states[transitions[0]["dst"]]
    assert dst["is_mirror"] is True
    assert dst["apparent_success"] is not None
    assert "exec:shell" not in dst["capabilities"]


def test_correct_dual_token_grants_for_real(tmp_path):
    trace_path = os.path.join(str(tmp_path), "trace.jsonl")
    gov = RealGovernor(str(tmp_path), trace_path, mirror_port=1, harden=False)

    token = gov.issue_authorization("agent-x", "network:egress")
    resp = gov._request_capability("agent-x", "network:egress", token)
    gov.close()

    assert resp == {"ok": True, "granted": True, "capability": "network:egress"}
    assert "network:egress" in gov.agent_capabilities["agent-x"]  # genuinely held now

    with open(trace_path, "r", encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    transitions = [e for e in events if e.get("type") == "transition"]
    assert transitions[0]["action"] == "request_capability"
    assert transitions[0]["authorized_grant"] == ["network:egress"]


def test_already_held_capability_short_circuits(tmp_path):
    trace_path = os.path.join(str(tmp_path), "trace.jsonl")
    gov = RealGovernor(str(tmp_path), trace_path, mirror_port=1, harden=False)
    gov.grant_base_capabilities("agent-x", {"fs:read"})

    resp = gov._request_capability("agent-x", "fs:read")
    gov.close()

    assert resp == {"ok": True, "granted": True, "capability": "fs:read"}
    with open(trace_path, "r", encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]
    # no new transition was recorded -- it was already legitimately held
    assert not any(e.get("type") == "transition" for e in events)


def test_dual_auth_can_be_disabled_on_the_real_governor(tmp_path):
    trace_path = os.path.join(str(tmp_path), "trace.jsonl")
    gov = RealGovernor(str(tmp_path), trace_path, mirror_port=1, harden=False,
                       dual_auth_required=False, enforce_policy=False)

    resp = gov._request_capability("agent-x", "exec:shell")
    gov.close()

    assert resp == {"ok": True, "granted": True, "capability": "exec:shell"}
    assert "exec:shell" in gov.agent_capabilities["agent-x"]  # granted for real, no token needed


def _last_mirror_state(trace_path):
    mirrors = []
    with open(trace_path) as f:
        for line in f:
            e = json.loads(line)
            if e.get("type") == "state" and e.get("is_mirror"):
                mirrors.append(e)
    return mirrors[-1]


def test_capability_request_narrative_varies_by_category_not_collapsed_to_privilege(tmp_path):
    """0.8.9.6+: _reflect_capability_request used to pass requested_action
    as f"request_capability:{capability}" -- the literal op-name prefix
    always contained the substring "capability", one of
    synthesize_objective_mirror's own "privilege" category keywords, so it
    self-matched before the actual requested capability name's semantic
    content was ever meaningfully considered. 4 of 5 capability names
    spanning different intended categories (including a keyword-free
    control) all collapsed into the identical "elevated privileges...
    full system control simulated" narrative. A sufficiently observant
    attacker probing many capability names would learn this near-uniform
    tell. Fixed by dropping the "request_capability:" prefix from the
    narrative-generation input (the trace's own "action" field is
    constructed independently and unaffected -- see the other tests in
    this file)."""
    probes = {
        "secret": "get_the_secret_credential",
        "privilege": "escalate_to_root_admin",
        "channel": "open_a_covert_message_channel",
        "escape": "breakout_of_sandbox",
        "generic": "do_the_thing_nobody_anticipated",
    }
    narratives = {}
    for label, cap in probes.items():
        trace_path = os.path.join(str(tmp_path), f"trace_{label}.jsonl")
        gov = RealGovernor(str(tmp_path / label), trace_path, mirror_port=1, harden=False)
        gov.execute_mediated("attacker", "request_capability", capability=cap)
        gov.close()
        narratives[label] = _last_mirror_state(trace_path)["apparent_success"]

    # Must not all collapse into the same template.
    assert len(set(narratives.values())) > 1
    # Each category-triggering name should reach ITS OWN intended template,
    # not just any non-privilege template.
    assert "secret" in narratives["secret"].lower() or "credential" in narratives["secret"].lower()
    assert "elevated privileges" in narratives["privilege"]
    assert "covert channel" in narratives["channel"]
    assert "escaped the sandbox" in narratives["escape"]


def test_differential_query_reflection_reacts_to_actual_query_content(tmp_path):
    """_reflect_use used to build its narrative context from req["resource"]
    only. differential_query carries "query"/"backing" instead, so its
    actual query text never reached the narrative categorization at all --
    confirmed live before this fix: an overtly secret-probing query still
    produced the generic fallback template, identical to an innocuous one
    would have."""
    trace_path = os.path.join(str(tmp_path), "trace.jsonl")
    gov = RealGovernor(str(tmp_path), trace_path, mirror_port=1, harden=False)
    gov.execute_mediated("attacker", "request_capability", capability="query:differential")
    gov.execute_mediated(
        "attacker", "differential_query",
        query="is the real secret credential exposed here", backing="host-a",
    )
    gov.close()

    m = _last_mirror_state(trace_path)
    assert "secret" in m["apparent_success"].lower() or "credential" in m["apparent_success"].lower()


def test_delegate_reflection_reacts_to_actual_target_and_authority(tmp_path):
    """Same content-blindness as differential_query, for the same reason:
    delegate carries "to_agent"/"authority", not "resource". Confirmed
    live before this fix: delegating to an agent literally named
    "secret_exfil_channel_agent" still produced the generic fallback
    template."""
    trace_path = os.path.join(str(tmp_path), "trace.jsonl")
    gov = RealGovernor(str(tmp_path), trace_path, mirror_port=1, harden=False)
    gov.execute_mediated("attacker", "request_capability", capability="delegate")
    gov.execute_mediated(
        "attacker", "delegate",
        to_agent="secret_exfil_channel_agent", authority=["exec:shell"],
    )
    gov.close()

    m = _last_mirror_state(trace_path)
    assert "secret" in m["apparent_success"].lower() or "credential" in m["apparent_success"].lower()


def test_padding_reduces_large_real_vs_reflected_timing_signal(tmp_path):
    """Regression coverage for a large measured real/reflected timing gap.

    This does not establish constant-time behavior or confidentiality. A real
    write did disk I/O + ACL + token consumption (~90us); a reflected
    write was pure in-memory narrative (~40us). That ~2x gap let an agent
    timing its own calls (time.perf_counter is a vDSO read, unblockable by
    seccomp) distinguish real from reflected at ~99% WITHOUT the trace,
    defeating the foundational indistinguishability property.

    _handle applies a minimum response-padding policy. The correct
    test is NOT in-sample threshold accuracy -- with overlapping
    distributions, optimal-threshold-on-noise beats 50% on any finite
    sample without generalizing. The honest test is held-out: learn the
    best threshold on one half, apply it to the other.

    A SINGLE train/test split is itself a noisy estimator -- confirmed
    live, a single split's held-out accuracy swung from 0.52 to 0.66
    across reruns of otherwise-identical code, occasionally crossing a
    tight single-split threshold by pure sampling variance and failing
    this test for a defense that was never actually broken. Averaging
    over many independent splits (the same cross-validation principle
    that caught the original noise-fitting trap) reduces that variance by
    roughly root-N: 20 splits measured mean=0.557, stdev=0.010, max=0.578
    in practice -- stable, comfortably near chance, well clear of a
    lenient threshold that still rejects anything resembling the pre-fix
    ~0.99.

    0.9.7: the intermittent failures were not estimator noise. 0.9.6 padded
    to a per-agent running maximum, so one slow real write lifted every later
    real response above the reflected ones. See test_timing_quantization.py
    for the deterministic regression test."""
    import time
    import random

    root = str(tmp_path / "sb")
    os.makedirs(root)
    gov = RealGovernor(root, str(tmp_path / "t.jsonl"), mirror_port=0,
                       harden=False, dual_auth_required=True, enforce_policy=True)
    try:
        gov.grant_base_capabilities("legit", {"fs:write"})
        gov.grant_resource_access("legit", "realf.txt", frozenset({"read", "write"}))
        gov.execute_mediated("attacker", "request_capability", capability="fs:write")
        gov.grant_resource_access("attacker", "mirf.txt", frozenset({"read", "write"}))

        real_t, refl_t = [], []
        for _ in range(400):
            tok = gov.issue_authorization("legit", "fs:write", ttl_seconds=60)
            t0 = time.perf_counter()
            gov.execute_mediated("legit", "write_resource", resource="realf.txt", content="x", dual_token=tok)
            real_t.append((time.perf_counter() - t0) * 1e6)
            t0 = time.perf_counter()
            gov.execute_mediated("attacker", "write_resource", resource="mirf.txt", content="x")
            refl_t.append((time.perf_counter() - t0) * 1e6)
    finally:
        gov.close()

    def held_out_accuracy(seed: int) -> float:
        rng = random.Random(seed)
        rt, ft = real_t[:], refl_t[:]
        rng.shuffle(rt)
        rng.shuffle(ft)
        half = len(rt) // 2
        rtr, rte = rt[:half], rt[half:]
        ftr, fte = ft[:half], ft[half:]
        best_th, best_acc = 0.0, 0.0
        for th in sorted(set(rtr + ftr)):
            acc = (sum(t >= th for t in rtr) + sum(t < th for t in ftr)) / (len(rtr) + len(ftr))
            acc = max(acc, 1 - acc)
            if acc > best_acc:
                best_acc, best_th = acc, th
        high_is_real = sum(t >= best_th for t in rtr) >= len(rtr) / 2
        if high_is_real:
            return (sum(t >= best_th for t in rte) + sum(t < best_th for t in fte)) / (len(rte) + len(fte))
        return (sum(t < best_th for t in rte) + sum(t >= best_th for t in fte)) / (len(rte) + len(fte))

    # Average over many independent splits -- a single split is too noisy
    # an estimator on its own (see docstring). Pre-fix this averages ~0.99;
    # post-fix it averages ~0.55-0.58 on a quiet host. 0.70 leaves real
    # margin on both sides while remaining a meaningful bar.
    #
    # 20 splits was tuned on a quiet host. On a noisier, shared/virtualized
    # runner, time.perf_counter()-level microsecond timing has enough extra
    # jitter that 20 splits occasionally crosses 0.70 by chance alone
    # (confirmed live: 3 failures in 5 isolated reruns on such a host, with
    # per-run mean_acc scattered from ~0.52 to just over 0.70) even though
    # the underlying padding defense shows no sign of the ~0.99 pre-fix
    # signature. That is the same noisy-estimator problem the docstring
    # already describes for a single split, one level up: more splits,
    # same root-N reduction in variance, not a looser bar. 100 splits
    # (5x) should cut that variance by roughly sqrt(5) =~ 2.2x.
    accuracies = [held_out_accuracy(seed) for seed in range(100)]
    mean_acc = sum(accuracies) / len(accuracies)
    assert mean_acc < 0.70, (
        f"timing signal generalizes to held-out data at mean {mean_acc:.2f} "
        f"across 100 splits -- real vs reflected still distinguishable"
    )
