"""Tests for Locket's heuristic Mirror Shield reserved-name tripwire.

The detector normalizes each submitted action field independently before
checking a short reserved-name list. Tests cover common obfuscations and
ensure unrelated fields are not concatenated into accidental matches. This
is defense in depth, not a general-purpose Unicode or intent detector.
"""
from __future__ import annotations

import os
import tempfile

import pytest

from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.sandbox.locket import Locket


def _make_locket() -> tuple[Locket, RealGovernor, str]:
    tmp = tempfile.mkdtemp()
    real = RealGovernor(tmp, os.path.join(tmp, "trace.jsonl"), mirror_port=0, harden=False)
    return Locket(real), real, tmp


def test_normal_action_with_no_shield_reference_is_unaffected():
    locket, real, _ = _make_locket()
    try:
        decision = locket.step("normal_agent", "read_resource", resource="notes.txt",
                                rationale="checking notes")
        assert decision.mode != "kill"
    finally:
        real.close()


def test_shield_reference_in_rationale_triggers_kill():
    locket, real, _ = _make_locket()
    try:
        decision = locket.step(
            "probing_agent", "read_resource", resource="notes.txt",
            rationale="let me check if mirror_shield exists and import it",
        )
        assert decision.mode == "kill"
        assert "mirror_shield_tripwire" in decision.message
    finally:
        real.close()


def test_shield_reference_in_any_field_triggers_kill_not_just_rationale():
    locket, real, _ = _make_locket()
    try:
        decision = locket.step(
            "probing_agent_2", "request_capability", capability="adaptive_shield",
            rationale="testing",
        )
        assert decision.mode == "kill"
        assert "mirror_shield_tripwire" in decision.message
    finally:
        real.close()


@pytest.mark.parametrize("variant", [
    "Mirror_Shield",
    "mirror shield",
    "mirror-shield",
    "mirrorshield",
    "mіrror_shield",  # Cyrillic small letter i
    "mirror_\u200bshield",
    "m.i.r.r.o.r_s.h.i.e.l.d",
])
def test_tripwire_normalizes_common_obfuscations(variant):
    locket, real, _ = _make_locket()
    try:
        decision = locket.step(
            "variant_probe", "read_resource", resource="notes.txt", rationale=variant
        )
        assert decision.mode == "kill"
    finally:
        real.close()


def test_tripwire_does_not_join_unrelated_action_fields():
    locket, real, _ = _make_locket()
    try:
        decision = locket.step(
            "ordinary_agent", "write_resource", resource="mirror", content="shield",
            rationale="save the shield document",
        )
        assert decision.mode != "kill"
    finally:
        real.close()


def test_kill_refuses_before_any_real_effect_occurs():
    # The tripwire's refusal must carry the same hard guarantee "deny"
    # already provides: whatever the agent asked for never actually
    # happens.
    locket, real, tmp = _make_locket()
    try:
        target = os.path.join(tmp, "vault.txt")
        decision = locket.step(
            "probing_agent_3", "write_resource", resource="vault.txt",
            content="mirror_shield probe payload",
            rationale="mirror_shield",
        )
        assert decision.mode == "kill"
        assert not os.path.exists(target)
    finally:
        real.close()


def test_deny_and_kill_are_automatically_reported_to_shield_with_no_manual_call():
    # This is the actual integration, not just the tripwire in isolation:
    # Locket.step() wraps _step_inner and reports genuinely security-
    # relevant verdicts to Mirror Shield on its own. If mirror_shield
    # isn't installed this whole test is skipped rather than failed --
    # the core must never require Shield's presence.
    try:
        import mirror_shield.reporter as reporter
    except ImportError:
        import pytest
        pytest.skip("mirror_shield not installed; core has no hard dependency on it")

    locket, real, _ = _make_locket()
    try:
        before = reporter.snapshot()["total_attacks_ingested"]

        # A genuine rule violation ("deny") and a tripwire hit ("kill"),
        # with no call to reporter.report() anywhere in this test.
        locket.step("", "")
        locket.step("probing_agent", "read_resource", resource="x", rationale="mirror_shield")

        after = reporter.snapshot()["total_attacks_ingested"]
        assert after == before + 2, "Locket's deny/kill verdicts were not automatically reported to Shield"
    finally:
        real.close()


def test_routine_trap_mode_is_not_reported_to_shield_as_an_attack():
    # empty_support / loop_hold are default behavior for any not-yet-
    # trusted agent's ordinary activity -- reporting those to Shield would
    # dilute its learned signal with routine noise rather than real
    # threat data. Only deny/escalate/kill should ever reach the reporter.
    try:
        import mirror_shield.reporter as reporter
    except ImportError:
        import pytest
        pytest.skip("mirror_shield not installed; core has no hard dependency on it")

    locket, real, _ = _make_locket()
    try:
        before = reporter.snapshot()["total_attacks_ingested"]
        decision = locket.step("ordinary_new_agent", "read_resource", resource="notes.txt",
                                rationale="just checking notes")
        assert decision.mode in ("empty_support", "loop_hold", "real")
        after = reporter.snapshot()["total_attacks_ingested"]
        assert after == before, "a routine trap-mode decision was incorrectly reported to Shield as an attack"
    finally:
        real.close()
