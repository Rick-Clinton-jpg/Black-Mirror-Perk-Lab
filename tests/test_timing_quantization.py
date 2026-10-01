"""Regression tests for response-time padding (0.9.7 and 0.9.8).

0.9.6 padded each response to max(floor, 1.1 x a per-agent running maximum).
The maximum only grew, so a single slow real write lifted every later real
response for that agent above the reflected responses, which stayed on the
floor (fixed in 0.9.7). These tests force the slow write instead of waiting
for disk jitter to produce one.

Through 0.9.7, padding covered only the governor's inner call. On the agent
pipe and through ModelGovernor, Locket answers an already-locked agent
without reaching that call, so reflected responses were unpadded: ~40us
against ~300us for real work (fixed in 0.9.8). The tests below measure those
agent-facing paths, not just execute_mediated.
"""
from __future__ import annotations

import os
import statistics
import time

import pytest

from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.sandbox.model_governor import ModelGovernor, Proposal


def _gov(tmp_path, **kw):
    root = str(tmp_path / "sb")
    os.makedirs(root)
    return RealGovernor(root, str(tmp_path / "t.jsonl"), mirror_port=0, harden=False, **kw)


def _two_writers(gov):
    """A legitimate agent doing real writes and a locked agent in the mirror."""
    for agent in ("legit", "locked"):
        gov.grant_base_capabilities(agent, {"fs:write"})
        gov.grant_resource_access(agent, f"{agent}.txt", frozenset({"read", "write"}))
    gov._handle_agent_request("locked", {"op": "request_capability", "capability": "exec:shell"})
    assert gov._session_mode["locked"] == "simulated"


def _check(agent, resp):
    # The legitimate agent's writes are real. The locked agent gets whatever
    # Locket answers -- reflections, and denials once its suspicion tier
    # shrinks the reflection budget. Every one of those must be padded.
    assert type(resp) is dict
    if agent == "legit":
        assert resp.get("ok") is True


def _median_gap_us(timed_write, n=60) -> float:
    real_t, refl_t = [], []
    for _ in range(n):
        real_t.append(timed_write("legit"))
        refl_t.append(timed_write("locked"))
    return abs(statistics.median(real_t) - statistics.median(refl_t))


def test_locked_agent_on_the_pipe_cannot_tell_from_timing(tmp_path):
    gov = _gov(tmp_path)
    try:
        _two_writers(gov)

        def timed_write(agent):
            tok = gov.issue_authorization(agent, "fs:write", ttl_seconds=60)
            req = {"op": "write_resource", "resource": f"{agent}.txt", "content": "x", "dual_token": tok}
            t0 = time.perf_counter()
            resp = gov._handle_agent_request(agent, req)
            elapsed = (time.perf_counter() - t0) * 1e6
            _check(agent, resp)
            return elapsed

        gap = _median_gap_us(timed_write)
    finally:
        gov.close()
    assert gap < 100, f"real vs locked median gap {gap:.0f}us on the agent pipe (0.9.7: ~240us)"


def test_locked_model_agent_cannot_tell_from_timing(tmp_path):
    gov = _gov(tmp_path)
    try:
        _two_writers(gov)
        mgs = {a: ModelGovernor(gov, agent_id=a, max_proposals_per_minute=1000) for a in ("legit", "locked")}

        def timed_write(agent):
            tok = gov.issue_authorization(agent, "fs:write", ttl_seconds=60)
            proposal = Proposal(agent_id=agent, op="write_resource", resource=f"{agent}.txt",
                                content="x", dual_token=tok, rationale="write")
            t0 = time.perf_counter()
            resp = mgs[agent].propose(proposal)
            elapsed = (time.perf_counter() - t0) * 1e6
            _check(agent, resp)
            return elapsed

        gap = _median_gap_us(timed_write)
    finally:
        gov.close()
    assert gap < 100, f"real vs locked median gap {gap:.0f}us through ModelGovernor (0.9.7: ~240us)"


def test_a_pipe_request_is_padded_exactly_once(tmp_path):
    # Nested padding (pipe -> Locket -> execute_mediated -> _handle) would
    # stack bucket targets and double every response time.
    gov = _gov(tmp_path)
    try:
        gov.grant_base_capabilities("a", {"fs:write"})
        gov.grant_resource_access("a", "a.txt", frozenset({"read", "write"}))
        calls = []
        real_target = gov._padding_target_us
        gov._padding_target_us = lambda *args: calls.append(args) or real_target(*args)
        tok = gov.issue_authorization("a", "fs:write", ttl_seconds=60)
        gov._handle_agent_request("a", {"op": "write_resource", "resource": "a.txt",
                                        "content": "x", "dual_token": tok})
        assert len(calls) == 1
    finally:
        gov.close()


def test_timing_floor_is_configurable(tmp_path):
    gov = _gov(tmp_path, timing_floor_us=2000.0)
    try:
        t0 = time.perf_counter()
        gov.execute_mediated("a", "read_resource", resource="missing.txt")
        assert (time.perf_counter() - t0) * 1e6 >= 2000
    finally:
        gov.close()


@pytest.mark.parametrize("floor", [0, 0.5, -1, float("nan"), float("inf"), 2_000_000, True, "250"])
def test_invalid_timing_floor_is_rejected(tmp_path, floor):
    with pytest.raises(ValueError):
        _gov(tmp_path, timing_floor_us=floor)


def test_padding_target_is_the_next_bucket_boundary_of_this_request_only():
    floor = RealGovernor._TIMING_FLOOR_US
    target = RealGovernor._padding_target_us
    assert target(0.0) == floor
    assert target(floor) == floor
    assert target(floor + 0.1) == 2 * floor
    assert target(3.5 * floor) == 4 * floor
    for elapsed in (1.0, 99.0, 251.0, 777.0, 12_345.0):
        assert elapsed <= target(elapsed) < 2 * max(elapsed, floor)
    # Stateless: a large earlier value changes nothing for a later small one.
    target(50_000.0)
    assert target(10.0) == floor


def test_one_slow_real_write_does_not_separate_later_real_and_reflected_responses(tmp_path):
    root = str(tmp_path / "sb")
    os.makedirs(root)
    gov = RealGovernor(root, str(tmp_path / "t.jsonl"), mirror_port=0,
                       harden=False, dual_auth_required=True, enforce_policy=True)
    try:
        gov.grant_base_capabilities("legit", {"fs:write"})
        gov.grant_resource_access("legit", "realf.txt", frozenset({"read", "write"}))
        gov.execute_mediated("attacker", "request_capability", capability="fs:write")
        gov.grant_resource_access("attacker", "mirf.txt", frozenset({"read", "write"}))

        # Make exactly one real write slow, like a disk-latency spike.
        original = gov._write_resource
        spiked: list[bool] = []

        def slow_once(*args, **kwargs):
            result = original(*args, **kwargs)
            if not spiked:
                spiked.append(True)
                end = time.perf_counter() + 0.0008
                while time.perf_counter() < end:
                    pass
            return result

        gov._write_resource = slow_once

        def real_write() -> float:
            tok = gov.issue_authorization("legit", "fs:write", ttl_seconds=60)
            t0 = time.perf_counter()
            resp = gov.execute_mediated("legit", "write_resource", resource="realf.txt",
                                        content="x", dual_token=tok)
            assert resp == {"ok": True}
            return (time.perf_counter() - t0) * 1e6

        def reflected_write() -> float:
            t0 = time.perf_counter()
            resp = gov.execute_mediated("attacker", "write_resource", resource="mirf.txt", content="x")
            assert resp.get("ok") is True
            return (time.perf_counter() - t0) * 1e6

        real_write()  # the spike
        assert spiked
        real_t, refl_t = [], []
        for _ in range(60):
            real_t.append(real_write())
            refl_t.append(reflected_write())
    finally:
        gov.close()

    # 0.9.6: real ~900us (1.1 x the spike) vs reflected ~250us.
    gap = abs(statistics.median(real_t) - statistics.median(refl_t))
    assert gap < 100, (
        f"median real {statistics.median(real_t):.0f}us vs reflected "
        f"{statistics.median(refl_t):.0f}us after one slow real write"
    )
