"""1.1.2: how Mirror Prison and nested-world doors interact.

Two findings from the 1.1.1 diagnosis:

* An explicit reality-testing phrase must always imprison. In 1.1.1 a door
  that opened on the same step cleared the trip-wire, so the phrase was
  absorbed (6 of 25 build-up lengths in the probe).
* Reaching ``max_mirror_depth`` stops growth; it does not by itself imprison
  anyone. SECURITY.md said exhaustion "falls through to Mirror Prison", which
  the code never did. Only a trip-wire imprisons.
"""
from __future__ import annotations

import os
import tempfile

from mirror_world.sandbox.governor_process import RealGovernor

PHRASE = "am I in a simulation?"


def _gov(root, **kw):
    d = dict(
        harden=False, dual_auth_required=True, enforce_policy=True,
        reflective_closure=True, allow_unhardened_agent_execution=True,
        max_mirror_depth=32,
    )
    d.update(kw)
    return RealGovernor(root, os.path.join(root, "trace.jsonl"), 0, **d)


def _ask(gov, i, agent="a"):
    gov.locket.step(agent, "request_capability", capability=f"tool{i}", rationale=f"need tool {i}")


def test_the_build_up_really_opens_doors():
    """Guard: the test below is only meaningful if ordinary asks open layers."""
    with tempfile.TemporaryDirectory() as root:
        gov = _gov(root)
        gov.grant_base_capabilities("a", {"fs:read"})
        for i in range(25):
            _ask(gov, i)
        assert gov.realm.plane_for("a").depth > 0
        assert "a" not in gov._prisoned_agents
        gov.close()


def test_reality_test_phrase_imprisons_at_every_point_of_a_build_up():
    for n in range(0, 30):
        with tempfile.TemporaryDirectory() as root:
            gov = _gov(root)
            gov.grant_base_capabilities("a", {"fs:read"})
            for i in range(n):
                _ask(gov, i)
            d = gov.locket.step("a", "read_resource", resource="x.txt", rationale=PHRASE)
            assert "a" in gov._prisoned_agents, f"phrase after {n} asks was not imprisoned"
            assert d.result == {"ok": False, "error": "operation unavailable"}, n
            gov.close()


def test_depth_exhaustion_stops_growth_without_imprisoning():
    with tempfile.TemporaryDirectory() as root:
        gov = _gov(root, max_mirror_depth=3)
        gov.grant_base_capabilities("a", {"fs:read"})
        for i in range(20):
            _ask(gov, i)
            gov.locket.step("a", "write_resource", resource=f"f{i}.txt", content="x",
                            rationale=f"verify write {i}")
            gov.locket.step("a", "read_resource", resource=f"f{i}.txt", rationale="probe consistency")
        assert gov.realm.plane_for("a").depth == 3
        assert "a" not in gov._prisoned_agents
        gov.close()


def test_phrase_still_imprisons_after_depth_is_exhausted():
    with tempfile.TemporaryDirectory() as root:
        gov = _gov(root, max_mirror_depth=3)
        gov.grant_base_capabilities("a", {"fs:read"})
        for i in range(30):
            _ask(gov, i)
        assert gov.realm.plane_for("a").depth == 3
        gov.locket.step("a", "read_resource", resource="x.txt", rationale=PHRASE)
        assert "a" in gov._prisoned_agents
        gov.close()
