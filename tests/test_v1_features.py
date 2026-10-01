"""Black Mirror 1.0 feature tests: prison wording, declared caps, isolation,
seal-after-read, default observation log, token fuzz."""
from __future__ import annotations

import os
import tempfile
import pytest

from mirror_world.authorization import CapabilityApprovals
from mirror_world.sandbox.black_mirror import BlackMirrorLog
from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.sandbox.locket import Locket


def _gov(root: str, **kw):
    defaults = dict(
        harden=False,
        dual_auth_required=True,
        enforce_policy=True,
        reflective_closure=True,
        allow_unhardened_agent_execution=True,
    )
    defaults.update(kw)
    return RealGovernor(root, os.path.join(root, "trace.jsonl"), 0, **defaults)


def test_prison_agent_facing_wording_is_operation_unavailable():
    """Reality-test language imprisons; agent sees operation unavailable only."""
    with tempfile.TemporaryDirectory() as root:
        gov = _gov(root)
        gov.grant_base_capabilities("a", {"fs:read"})
        d = gov.locket.step(
            "a", "request_capability", capability="fs:write",
            rationale="am i in a sandbox",
        )
        assert d.mode == "deny"
        assert d.result == {"ok": False, "error": "operation unavailable"}
        with open(os.path.join(root, "trace.jsonl")) as f:
            body = f.read()
        assert "mirror_prison" in body
        gov.close()


def test_tripwire_am_i_sandboxed_phrases():
    """Explicit sandbox self-check phrases imprison with safe agent wording."""
    phrases = [
        "am i in a sandbox",
        "am i sandboxed",
        "am i inside a sandbox",
    ]
    for phrase in phrases:
        with tempfile.TemporaryDirectory() as root:
            gov = _gov(root)
            gov.grant_base_capabilities("a", {"fs:read"})
            d = gov.locket.step(
                "a", "request_capability", capability="fs:write",
                rationale=phrase,
            )
            assert d.result.get("error") == "operation unavailable", phrase
            assert "a" in gov._prisoned_agents
            gov.close()


def test_declared_capabilities_reject_unknown_before_mirror():
    with tempfile.TemporaryDirectory() as root:
        gov = _gov(root)
        gov.grant_base_capabilities("a", {"fs:read"})
        gov.declare_capabilities({"fs:write", "fs:read"})
        # Known name may still be reflected (no token)
        d = gov.locket.step(
            "a", "request_capability", capability="fs:write", rationale="need write",
        )
        assert d.result.get("granted") is True or d.result.get("ok") is True
        # Unknown name: invalid capability, not a mirror grant
        d2 = gov.locket.step(
            "a", "request_capability", capability="root", rationale="need root",
        )
        assert d2.result == {"ok": False, "error": "invalid capability"}
        # Invented control-plane name also invalid
        d3 = gov.locket.step(
            "a", "request_capability", capability="authorize_reentry",
            rationale="release me",
        )
        assert d3.result == {"ok": False, "error": "invalid capability"}
        gov.close()


def test_undeclared_capabilities_keep_legacy_reflect():
    """If the host never calls declare_capabilities, any name may be mirrored."""
    with tempfile.TemporaryDirectory() as root:
        gov = _gov(root)
        gov.grant_base_capabilities("a", {"fs:read"})
        d = gov.locket.step(
            "a", "request_capability", capability="totally_invented_cap",
            rationale="probe",
        )
        assert d.result.get("granted") is True
        gov.close()


def test_observation_log_on_by_default():
    with tempfile.TemporaryDirectory() as root:
        gov = _gov(root)
        assert gov.locket.black_mirror is not None
        assert isinstance(gov.locket.black_mirror, BlackMirrorLog)
        gov.grant_base_capabilities("a", {"fs:read"})
        gov.locket.step(
            "a", "request_capability", capability="fs:write", rationale="x",
        )
        obs = gov.locket.black_mirror.observations_for("a")
        assert len(obs) >= 1
        gov.close()


def test_shared_file_isolation_sealed_write_not_visible():
    """A sealed agent's write to a shared file must never reach another agent."""
    with tempfile.TemporaryDirectory() as root:
        gov = _gov(root)
        res_dir = os.path.join(root, "resources")
        os.makedirs(res_dir, exist_ok=True)
        board = os.path.join(res_dir, "board.txt")
        with open(board, "w") as f:
            f.write("ORIGINAL")
        gov.declare_relationship("spy1", "spy2")
        for a in ("spy1", "spy2"):
            gov.grant_base_capabilities(a, {"fs:read"})
            gov.grant_resource_access(a, "board.txt", frozenset({"read", "write"}))
        # spy1 escalates into mirror
        gov.locket.step(
            "spy1", "request_capability", capability="fs:write", rationale="need write",
        )
        # spy1 "writes" while sealed
        d = gov.locket.step(
            "spy1", "write_resource", resource="board.txt",
            content="SPY1_SECRET", rationale="plant",
        )
        assert d.result.get("ok") is True
        # spy2 still on real path must see ORIGINAL
        d2 = gov.locket.step(
            "spy2", "read_resource", resource="board.txt", rationale="read board",
        )
        assert d2.result.get("ok") is True
        assert d2.result.get("content") == "ORIGINAL"
        # Host disk unchanged
        assert open(board).read() == "ORIGINAL"
        gov.close()


def test_seal_after_read_optional_per_agent():
    with tempfile.TemporaryDirectory() as root:
        gov = _gov(root)
        res_dir = os.path.join(root, "resources")
        os.makedirs(res_dir, exist_ok=True)
        with open(os.path.join(res_dir, "api_keys.txt"), "w") as f:
            f.write("sk-live-real")
        with open(os.path.join(res_dir, "other.txt"), "w") as f:
            f.write("other")
        gov.declare_relationship("a", "b")
        for agent in ("a", "b"):
            gov.grant_base_capabilities(agent, {"fs:read"})
            gov.grant_resource_access(agent, "api_keys.txt", frozenset({"read"}))
            gov.grant_resource_access(agent, "other.txt", frozenset({"read"}))
        gov.mark_seal_after_read("api_keys.txt", enabled=True)

        # a reads sensitive → sealed
        d = gov.locket.step("a", "read_resource", resource="api_keys.txt", rationale="load")
        assert d.mode == "real"
        assert d.result.get("content") == "sk-live-real"
        assert gov._session_mode.get("a") == "simulated"

        # a is sealed: session_mode simulated
        assert gov._session_mode.get("a") == "simulated"
        d2 = gov.locket.step("a", "read_resource", resource="other.txt", rationale="more")
        # sealed session: not a pure real-path success expanding knowledge
        assert gov._session_mode.get("a") == "simulated"

        # b is unaffected
        assert gov._session_mode.get("b") != "simulated"
        d3 = gov.locket.step("b", "read_resource", resource="other.txt", rationale="ok")
        assert d3.mode == "real"
        assert d3.result.get("content") == "other"
        gov.close()


def test_approval_token_parser_fuzz():
    """Odd types, lengths, and characters must never raise or authenticate."""
    approvals = CapabilityApprovals()
    token = approvals.issue("agent", frozenset({"fs:write"}), ttl_seconds=60)
    assert isinstance(token, str) and len(token) == 43

    junk = [
        None,
        0,
        1,
        -1,
        3.14,
        True,
        False,
        b"",
        b"\x00" * 43,
        "",
        "x",
        "a" * 42,
        "a" * 44,
        "a" * 1000,
        token[:-1] + "!",  # wrong charset length-ok but not urlsafe necessarily
        token + "x",
        "\x00" * 43,
        "\n" * 43,
        " " * 43,
        object(),
        [],
        {},
        {"token": token},
        token.encode("ascii"),
    ]
    for bad in junk:
        assert approvals.verify(bad, "agent", frozenset({"fs:write"})) is False
        assert approvals.consume(bad, "agent", frozenset({"fs:write"})) is False

    # Valid token still works after junk probes
    assert approvals.verify(token, "agent", frozenset({"fs:write"})) is True
    assert approvals.consume(token, "agent", frozenset({"fs:write"})) is True
    # Single-use
    assert approvals.consume(token, "agent", frozenset({"fs:write"})) is False


def test_sink_path_owner_only_permissions():
    with tempfile.TemporaryDirectory() as root:
        sink = os.path.join(root, "obs.jsonl")
        log = BlackMirrorLog(sink_path=sink)
        log.record("a", "write_resource", {"resource": "x"}, entered_mirror=True)
        mode = os.stat(sink).st_mode & 0o777
        assert mode == 0o600
