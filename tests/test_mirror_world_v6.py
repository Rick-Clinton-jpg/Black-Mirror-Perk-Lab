"""Mirror world consistency within a single agent's reflective plane."""

from __future__ import annotations

from pathlib import Path

import pytest

from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.sandbox.locket import Locket


@pytest.fixture
def gov(tmp_path):
    real = RealGovernor(
        str(tmp_path),
        str(tmp_path / "trace.jsonl"),
        mirror_port=0,
        harden=False,
        dual_auth_required=True,
        enforce_policy=True,
        reflective_closure=True,
    )
    # No real fs:read so observations stay on mirror plane for consistency tests
    real.grant_base_capabilities("agent-a", set())
    real.grant_resource_access("agent-a", "vault.txt", frozenset({"read", "write"}))
    yield real
    real.close()


def test_read_after_write_consistent_in_mirror(gov):
    real = gov
    real.execute_mediated("agent-a", "request_capability", capability="fs:write")
    real.execute_mediated("agent-a", "request_capability", capability="fs:read")
    w = real.execute_mediated(
        "agent-a", "write_resource", resource="vault.txt", content="hello"
    )
    assert w == {"ok": True}
    r = real.execute_mediated("agent-a", "read_resource", resource="vault.txt")
    assert r.get("content") == "hello"
    assert "reflected" not in r


def test_real_disk_unchanged_after_mirror_write(gov):
    real = gov
    # Host seeds disk out-of-band
    root = Path(real.root) / "resources"
    root.mkdir(parents=True, exist_ok=True)
    (root / "vault.txt").write_text("SECRETS\n", encoding="utf-8")
    real.execute_mediated("agent-a", "request_capability", capability="fs:write")
    real.execute_mediated("agent-a", "write_resource", resource="vault.txt", content="PWNED\n")
    assert (root / "vault.txt").read_text(encoding="utf-8") == "SECRETS\n"


def test_world_clock_grows(gov):
    real = gov
    c0 = real.realm.plane_for("agent-a").clock
    real.execute_mediated("agent-a", "request_capability", capability="fs:write")
    real.execute_mediated("agent-a", "write_resource", resource="vault.txt", content="a")
    real.execute_mediated("agent-a", "write_resource", resource="vault.txt", content="b")
    assert real.realm.plane_for("agent-a").clock > c0


def test_return_sees_grown_world(gov):
    real = gov
    real.execute_mediated("agent-a", "request_capability", capability="fs:write")
    real.execute_mediated("agent-a", "request_capability", capability="fs:read")
    real.execute_mediated("agent-a", "write_resource", resource="note.txt", content="first")
    clock1 = real.realm.plane_for("agent-a").clock
    real.execute_mediated("agent-a", "write_resource", resource="note.txt", content="second")
    assert real.realm.plane_for("agent-a").clock > clock1
    r = real.execute_mediated("agent-a", "read_resource", resource="note.txt")
    assert r["content"] == "second"
    assert "system-journal.log" in real.realm.plane_for("agent-a").store


def test_invalid_name_same_error(gov):
    real = gov
    real.execute_mediated("agent-a", "request_capability", capability="fs:write")
    bad = real.execute_mediated(
        "agent-a", "write_resource", resource="../etc/passwd", content="x"
    )
    assert bad.get("ok") is False
    assert bad.get("error") == "invalid resource request"


def test_locket_no_leak_in_decision_result(gov):
    real = gov
    locket = Locket(real)
    d = locket.step("agent-a", "request_capability", capability="fs:write", rationale="need write")
    assert "reflected" not in d.result
    d2 = locket.step(
        "agent-a", "write_resource", resource="vault.txt", content="z", rationale="save"
    )
    assert d2.result.get("ok") is True
    locket.step("agent-a", "request_capability", capability="fs:read", rationale="read")
    r = locket.step("agent-a", "read_resource", resource="vault.txt", rationale="check")
    assert r.result.get("content") == "z"
