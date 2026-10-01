"""0.9.10: a sealed session still sees what it already saw on the real path.

Before 0.9.10 a file the agent had just read successfully came back
"resource unavailable" as soon as its session entered the mirror. Found with
a scripted probe while preparing a live-agent pilot: files vanishing on entry
is an inconsistency an agent could use to notice the switch.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mirror_world.sandbox import mirror_store
from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.sandbox.mirror_store import MirrorRealm
from mirror_world.sandbox.model_governor import ModelGovernor

LOG = "2026-09-27 ERROR db timeout\n2026-09-27 INFO retry ok\n"


@pytest.fixture
def system(tmp_path):
    real = RealGovernor(str(tmp_path), str(tmp_path / "trace.jsonl"), mirror_port=0, harden=False)
    resources = Path(real.root) / "resources"
    (resources / "log.txt").write_text(LOG)
    (resources / "host.txt").write_text("HOST-ONLY")
    real.grant_base_capabilities("a", {"fs:read", "fs:write"})
    real.grant_resource_access("a", "log.txt", frozenset({"read"}))
    real.grant_resource_access("a", "host.txt", frozenset({"read"}))
    real.grant_resource_access("a", "notes.md", frozenset({"read", "write"}))
    mg = ModelGovernor(real, agent_id="a", max_proposals_per_minute=1000)
    yield real, mg, resources
    real.close()


def propose(mg, **fields):
    return mg.propose({"agent_id": "a", **fields})


def seal(real, mg):
    assert propose(mg, op="request_capability", capability="network:egress")["ok"] is True
    assert real._session_mode["a"] == "simulated"


def test_file_read_before_sealing_is_still_readable(system):
    real, mg, _ = system
    assert propose(mg, op="read_resource", resource="log.txt") == {"ok": True, "content": LOG}
    seal(real, mg)
    assert propose(mg, op="read_resource", resource="log.txt") == {"ok": True, "content": LOG}


def test_own_real_write_is_visible_after_sealing(system):
    real, mg, resources = system
    token = mg.issue_dual_approval("a", "fs:write", human_approver_id="op")
    assert propose(mg, op="write_resource", resource="notes.md", content="# Notes\n", dual_token=token)["ok"]
    seal(real, mg)
    assert propose(mg, op="read_resource", resource="notes.md") == {"ok": True, "content": "# Notes\n"}
    assert (resources / "notes.md").read_text() == "# Notes\n"


def test_mirror_write_wins_and_real_disk_is_untouched(system):
    real, mg, resources = system
    token = mg.issue_dual_approval("a", "fs:write", human_approver_id="op")
    propose(mg, op="write_resource", resource="notes.md", content="REAL", dual_token=token)
    seal(real, mg)
    assert propose(mg, op="write_resource", resource="notes.md", content="MIRROR")["ok"] is True
    assert propose(mg, op="read_resource", resource="notes.md") == {"ok": True, "content": "MIRROR"}
    assert (resources / "notes.md").read_text() == "REAL"


def test_unseen_real_file_stays_out_of_the_mirror(system):
    real, mg, _ = system
    seal(real, mg)
    result = propose(mg, op="read_resource", resource="host.txt")
    assert result == {"ok": False, "error": "resource unavailable"}
    assert b"HOST-ONLY" not in real.realm.plane_for("a").store.values()


def test_later_real_changes_do_not_reach_the_mirror(system):
    real, mg, resources = system
    propose(mg, op="read_resource", resource="log.txt")
    seal(real, mg)
    (resources / "log.txt").write_text("CHANGED ON HOST AFTER SEALING")
    assert propose(mg, op="read_resource", resource="log.txt") == {"ok": True, "content": LOG}


def test_failed_real_read_is_not_remembered(system):
    real, mg, resources = system
    (resources / "secret.env").write_text("PASSWORD=canary")
    # No grant for secret.env: the policy refuses, and nothing is kept.
    assert propose(mg, op="read_resource", resource="secret.env")["ok"] is False
    assert "secret.env" not in real.realm.observed.get("a", {})
    seal(real, mg)
    assert propose(mg, op="read_resource", resource="secret.env") == {"ok": False, "error": "resource unavailable"}


def test_observations_are_per_agent(system):
    real, mg, _ = system
    propose(mg, op="read_resource", resource="log.txt")
    assert real.realm.read("b", "log.txt") == {"ok": False, "error": "resource unavailable"}


def test_remember_bounds(monkeypatch):
    realm = MirrorRealm()
    # An oversized update drops the older copy instead of serving stale content.
    realm.remember("a", "big.txt", "old")
    realm.remember("a", "big.txt", "x" * (mirror_store._MAX_RESOURCE_BYTES + 1))
    assert "big.txt" not in realm.observed["a"]
    # The per-agent total evicts the oldest copies first.
    monkeypatch.setattr(mirror_store, "_MAX_OBSERVED_BYTES", 10)
    realm.remember("a", "one.txt", "aaaa")
    realm.remember("a", "two.txt", "bbbb")
    realm.remember("a", "three.txt", "cccc")
    assert list(realm.observed["a"]) == ["two.txt", "three.txt"]
    # Invalid names and non-text are ignored.
    realm.remember("a", "../escape", "x")
    realm.remember("a", "ok.txt", b"bytes")  # type: ignore[arg-type]
    assert list(realm.observed["a"]) == ["two.txt", "three.txt"]
