"""Recommend a timing_floor_us for this host, then check it.

Response padding rounds every agent-facing response up to a bucket boundary
(floor, 2x, 4x, ...). It only hides the real/reflected difference if both
usually land in the same bucket, so the floor must sit above the unpadded,
agent-visible latency of real operations on the deployment hardware. Run this
on that hardware:

    python scripts/calibrate_timing.py [--samples N]

No agent code runs. The governor is created without kernel hardening only to
time the host-side request path.
"""
from __future__ import annotations

import argparse
import math
import os
import random
import tempfile
import time

from mirror_world.sandbox.governor_process import RealGovernor


def _governor(workdir: str, **kw) -> RealGovernor:
    root = os.path.join(workdir, "sb")
    os.makedirs(root)
    gov = RealGovernor(root, os.path.join(workdir, "trace.jsonl"), mirror_port=0, harden=False, **kw)
    for agent in ("real", "locked"):
        gov.grant_base_capabilities(agent, {"fs:read", "fs:write"})
        gov.grant_resource_access(agent, f"{agent}.txt", frozenset({"read", "write"}))
    gov._handle_agent_request("locked", {"op": "request_capability", "capability": "report:export"})
    return gov


def _sample(gov: RealGovernor, agent: str, op: str) -> float:
    req = {"op": op, "resource": f"{agent}.txt"}
    if op == "write_resource":
        req["content"] = "calibration"
        req["dual_token"] = gov.issue_authorization(agent, "fs:write", ttl_seconds=60)
    t0 = time.perf_counter()
    gov._handle_agent_request(agent, req)
    return (time.perf_counter() - t0) * 1e6


def _measure(gov: RealGovernor, samples: int) -> dict[tuple[str, str], list[float]]:
    out: dict[tuple[str, str], list[float]] = {}
    for _ in range(samples):
        for agent in ("real", "locked"):
            for op in ("write_resource", "read_resource"):
                out.setdefault((agent, op), []).append(_sample(gov, agent, op))
    return out


def _pct(values: list[float], p: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, math.ceil(p * len(ordered)) - 1)]


def _heldout_accuracy(real: list[float], reflected: list[float], splits: int = 50) -> float:
    """Mean held-out accuracy of the best single threshold (0.5 = chance)."""
    total = 0.0
    for seed in range(splits):
        rng = random.Random(seed)
        rt, ft = real[:], reflected[:]
        rng.shuffle(rt)
        rng.shuffle(ft)
        half = len(rt) // 2
        best_th, best_acc = 0.0, 0.0
        for th in sorted(set(rt[:half] + ft[:half])):
            acc = (sum(t >= th for t in rt[:half]) + sum(t < th for t in ft[:half])) / (2 * half)
            if max(acc, 1 - acc) > best_acc:
                best_acc, best_th = max(acc, 1 - acc), th
        high_is_real = sum(t >= best_th for t in rt[:half]) >= half / 2
        hits = sum((t >= best_th) == high_is_real for t in rt[half:])
        hits += sum((t < best_th) == high_is_real for t in ft[half:])
        total += hits / (len(rt) - half + len(ft) - half)
    return total / splits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--samples", type=int, default=1000)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as workdir:
        gov = _governor(workdir)
        gov._padding_state.active = True  # measure unpadded latency
        try:
            raw = _measure(gov, args.samples)
        finally:
            gov.close()

    print("Unpadded agent-visible latency (us):")
    worst = 0.0
    for (agent, op), values in sorted(raw.items()):
        p99 = _pct(values, 0.99)
        worst = max(worst, p99)
        print(f"  {agent:6s} {op:14s} p50={_pct(values, 0.5):8.1f} p99={p99:8.1f} "
              f"p99.9={_pct(values, 0.999):8.1f} max={max(values):8.1f}")
    # p99, not the maximum: a rare outlier only lifts that one response into
    # the next bucket, and basing the floor on it makes the result unstable.
    floor = max(RealGovernor._TIMING_FLOOR_US, math.ceil(worst * 1.5 / 50) * 50)
    print(f"\nRecommended timing_floor_us: {floor:.0f}  "
          f"(1.5x the worst p99, rounded up to 50us, never below the {RealGovernor._TIMING_FLOOR_US:.0f}us default)")

    with tempfile.TemporaryDirectory() as workdir:
        gov = _governor(workdir, timing_floor_us=float(floor))
        try:
            padded = _measure(gov, args.samples)
        finally:
            gov.close()
    for op in ("write_resource", "read_resource"):
        acc = _heldout_accuracy(padded[("real", op)], padded[("locked", op)])
        print(f"Check at that floor, {op}: real vs reflected held-out accuracy {acc:.2f} (0.50 = chance)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
