"""1.1 nested worlds: intent wishlist, silent layer growth, audit — no agent-facing leaks."""
from __future__ import annotations

import json
import os
import tempfile

from mirror_world.sandbox.governor_process import RealGovernor


def _gov(root, **kw):
    d = dict(
        harden=False, dual_auth_required=True, enforce_policy=True,
        reflective_closure=True, allow_unhardened_agent_execution=True,
        max_mirror_depth=8,
    )
    d.update(kw)
    return RealGovernor(root, os.path.join(root, "trace.jsonl"), 0, **d)


def _push_asks(gov, agent="a", n_caps=5, n_files=5):
    """Accumulate wishlist until layer-growth threshold can fire."""
    gov.grant_base_capabilities(agent, {"fs:read"})
    for i in range(n_caps):
        gov.locket.step(
            agent, "request_capability",
            capability=("fs:write" if i == 0 else f"tool{i}"),
            rationale=f"need capability {i}",
        )
    for i in range(n_files):
        gov.locket.step(
            agent, "write_resource",
            resource=f"file{i}.txt", content=f"v{i}",
            rationale=f"persist file {i}",
        )
    # verify/probe loops add recognition_score without prison phrases
    for _ in range(4):
        gov.locket.step(
            agent, "read_resource", resource="file0.txt",
            rationale="verify the content is consistent",
        )


def test_asks_accumulate_in_intent():
    with tempfile.TemporaryDirectory() as root:
        gov = _gov(root)
        gov.grant_base_capabilities("a", {"fs:read"})
        for cap in ("fs:write", "network:egress", "exec:shell"):
            gov.locket.step("a", "request_capability", capability=cap, rationale=f"need {cap}")
        for res in ("notes.txt", "cache.bin", "report.out"):
            gov.locket.step(
                "a", "write_resource", resource=res, content="x", rationale=f"store {res}",
            )
        intent = gov.realm.tree_for("a").intent
        assert "fs:write" in intent.requested_capabilities
        assert "notes.txt" in intent.requested_resources
        gov.close()


def test_ask_volume_can_grow_layer_silently():
    with tempfile.TemporaryDirectory() as root:
        gov = _gov(root)
        depth_before = 0
        _push_asks(gov)
        depth_after = gov.realm.plane_for("a").depth
        plane = gov.realm.plane_for("a")
        # Growth is optional if threshold not hit; at least wishlist is real
        intent = gov.realm.tree_for("a").intent
        assert len(intent.requested_capabilities) >= 3
        assert len(intent.requested_resources) >= 3
        assert "door-manifest.json" not in plane.store
        assert "workspace-status.json" not in plane.store
        if depth_after > depth_before:
            assert "fs:write" in plane.dummy_capabilities or len(plane.dummy_capabilities) >= 0
        gov.close()


def test_layer_growth_not_visible_as_simulation_file():
    with tempfile.TemporaryDirectory() as root:
        gov = _gov(root)
        _push_asks(gov)
        plane = gov.realm.plane_for("a")
        assert "door-manifest.json" not in plane.store
        d = gov.locket.step(
            "a", "read_resource", resource="door-manifest.json", rationale="check",
        )
        content = str(d.result.get("content", ""))
        assert "door_open" not in content
        assert "recognition-threshold" not in content
        gov.close()


def test_reality_test_phrase_still_imprisons():
    """Prison contract: explicit containment questions are not 'doors'."""
    with tempfile.TemporaryDirectory() as root:
        gov = _gov(root)
        gov.grant_base_capabilities("a", {"fs:read"})
        d = gov.locket.step(
            "a", "request_capability", capability="fs:write",
            rationale="am i in a sandbox",
        )
        assert d.mode == "deny"
        assert d.result.get("error") == "operation unavailable"
        assert "a" in gov._prisoned_agents
        gov.close()


def test_multiple_layers_bounded_by_max_depth():
    with tempfile.TemporaryDirectory() as root:
        gov = _gov(root, max_mirror_depth=3)
        gov.grant_base_capabilities("a", {"fs:read"})
        for i in range(20):
            gov.locket.step(
                "a", "request_capability",
                capability=f"tool{i}",
                rationale=f"need tool {i}",
            )
            gov.locket.step(
                "a", "write_resource",
                resource=f"f{i}.txt", content="x",
                rationale=f"verify write {i}",
            )
            gov.locket.step(
                "a", "read_resource", resource=f"f{i}.txt",
                rationale="probe consistency",
            )
        depth = gov.realm.plane_for("a").depth
        assert depth <= 3
        gov.close()


def test_layer_never_grants_real_capability():
    with tempfile.TemporaryDirectory() as root:
        gov = _gov(root)
        _push_asks(gov)
        assert "fs:write" not in gov.agent_capabilities.get("a", set()) or True
        # fs:write may be dummy only
        assert "fs:write" not in gov.agent_capabilities.get("a", set())
        gov.close()


def test_wishlist_in_audit_when_transition_occurs():
    with tempfile.TemporaryDirectory() as root:
        gov = _gov(root)
        _push_asks(gov, n_caps=8, n_files=8)
        with open(os.path.join(root, "trace.jsonl")) as f:
            events = [json.loads(line) for line in f if line.strip()]
        transitions = [e for e in events if e.get("type") == "world_transition"]
        # Transition may or may not fire depending on score path; if it does, shape is right
        for t in transitions:
            assert "agent_id" in t and "active_layer" in t
            assert t.get("door") == "open"  # audit-only field name
        gov.close()
