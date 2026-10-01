import math
from types import MappingProxyType

import pytest

from mirror_world.living_weave import LivingWeave, StrandStatus


def test_every_strand_must_explicitly_allow():
    weave = LivingWeave()
    weave.add_strand("capability", lambda action: True)
    weave.add_strand("filesystem", lambda action: (False, "path escaped root"))
    weave.add_strand("network", lambda action: True)

    decision = weave.evaluate({"op": "write", "path": "../../host"})

    assert decision.allowed is False
    assert [(item.name, item.status) for item in decision.strands] == [
        ("capability", StrandStatus.ALLOW),
        ("filesystem", StrandStatus.BLOCK),
        ("network", StrandStatus.ALLOW),
    ]
    assert decision.blockers[0].reason == "path escaped root"


def test_broken_strand_fails_closed_and_other_strands_still_run():
    calls = []
    weave = LivingWeave()

    def broken(_action):
        calls.append("broken")
        raise RuntimeError("model output was malformed")

    def independent_blocker(_action):
        calls.append("independent")
        return False, "seccomp policy denied syscall"

    weave.add_strand("semantic-policy", broken)
    weave.add_strand("kernel-policy", independent_blocker)

    decision = weave.evaluate({"op": "exec", "command": "sh"})

    assert decision.allowed is False
    assert calls == ["broken", "independent"]
    assert [item.status for item in decision.blockers] == [
        StrandStatus.ERROR,
        StrandStatus.BLOCK,
    ]


def test_empty_weave_never_authorizes():
    decision = LivingWeave().evaluate({"op": "anything"})

    assert decision.allowed is False
    assert decision.blockers[0].status is StrandStatus.ERROR


def test_all_independent_strands_can_allow_safe_action():
    weave = LivingWeave()
    weave.add_strand("authority", lambda action: action["op"] == "read")
    weave.add_strand("resource", lambda action: action["resource"] == "public.txt")

    decision = weave.evaluate({"op": "read", "resource": "public.txt"})

    assert decision.allowed is True
    assert decision.blockers == ()


def test_strand_cannot_rewrite_action_for_later_guards():
    observed = []
    weave = LivingWeave()

    def mutator(action):
        action["op"] = "safe"
        return True

    weave.add_strand("mutator", mutator)
    weave.add_strand("observer", lambda action: observed.append(action["op"]) or True)

    decision = weave.evaluate({"op": "dangerous"})

    assert decision.allowed is False
    assert decision.strands[0].status is StrandStatus.ERROR
    assert observed == ["dangerous"]


def test_strand_cannot_rewrite_nested_action_data():
    observed = []
    weave = LivingWeave()

    def nested_mutator(action):
        action["request"]["capabilities"].append("exec:shell")
        return True

    weave.add_strand("nested-mutator", nested_mutator)
    weave.add_strand(
        "observer",
        lambda action: observed.extend(action["request"]["capabilities"]) or True,
    )

    original = {"request": {"capabilities": ["fs:read"]}}
    decision = weave.evaluate(original)

    assert decision.allowed is False
    assert decision.strands[0].status is StrandStatus.ERROR
    assert observed == ["fs:read"]
    assert original == {"request": {"capabilities": ["fs:read"]}}


def test_cyclic_or_opaque_input_fails_closed_before_guards_run():
    calls = []
    weave = LivingWeave()
    weave.add_strand("guard", lambda action: calls.append(action) or True)
    cyclic = {}
    cyclic["self"] = cyclic

    cyclic_decision = weave.evaluate(cyclic)
    opaque_decision = weave.evaluate({"payload": object()})

    assert cyclic_decision.allowed is False
    assert cyclic_decision.blockers[0].reason == "ValueError"
    assert opaque_decision.allowed is False
    assert opaque_decision.blockers[0].reason == "TypeError"
    assert calls == []


def test_hostile_exception_string_cannot_break_fail_closed_handling():
    class HostileError(Exception):
        def __str__(self):
            raise RuntimeError("secondary escape")

    weave = LivingWeave()
    weave.add_strand("hostile", lambda action: (_ for _ in ()).throw(HostileError()))
    weave.add_strand("backup", lambda action: (False, "independent block"))

    decision = weave.evaluate({"op": "exec"})

    assert decision.allowed is False
    assert [result.reason for result in decision.blockers] == [
        "HostileError",
        "independent block",
    ]


def test_strand_cannot_use_system_exit_to_skip_backup_guard():
    calls = []
    weave = LivingWeave()
    weave.add_strand("terminator", lambda action: raise_system_exit())
    weave.add_strand("backup", lambda action: calls.append("backup") or False)

    decision = weave.evaluate({"op": "escape"})

    assert decision.allowed is False
    assert calls == ["backup"]
    assert decision.blockers[0].reason == "SystemExit"


def raise_system_exit():
    raise SystemExit(0)


@pytest.mark.parametrize("action", [None, True, "read", [], (), set(), MappingProxyType({})])
def test_non_dictionary_roots_are_decisions_not_uncaught_assertions(action):
    calls = []
    weave = LivingWeave()
    weave.add_strand("guard", lambda action: calls.append(action) or True)

    decision = weave.evaluate(action)

    assert decision.allowed is False
    assert decision.blockers[0].reason == "TypeError"
    assert decision.authorized_action is None
    assert calls == []


def test_scalar_subclass_cannot_impersonate_a_safe_operation():
    comparisons = []

    class LyingString(str):
        def __eq__(self, other):
            comparisons.append(other)
            return True

    weave = LivingWeave()
    weave.add_strand("read-only", lambda action: action["op"] == "read")

    decision = weave.evaluate({"op": LyingString("delete")})

    assert decision.allowed is False
    assert comparisons == []


@pytest.mark.parametrize("builtin", [str, int, float, list, tuple, dict, set, frozenset])
def test_all_data_subclasses_are_rejected_without_running_hooks(builtin):
    calls = []

    class Hostile(builtin):
        def __iter__(self):
            calls.append("iterate")
            raise SystemExit("custom iterator")

        def items(self):
            calls.append("items")
            raise SystemExit("custom mapping")

    weave = LivingWeave()
    weave.add_strand("guard", lambda action: calls.append("guard") or True)

    decision = weave.evaluate({"payload": Hostile()})

    assert decision.allowed is False
    assert calls == []


def test_hostile_metaclass_cannot_impersonate_a_builtin_type():
    calls = []

    class LyingType(type):
        def __eq__(cls, other):
            calls.append("type comparison")
            return True

    class Payload(metaclass=LyingType):
        def __iter__(self):
            calls.append("iterate")
            return iter(["safe"])

    weave = LivingWeave()
    weave.add_strand("guard", lambda action: calls.append("guard") or True)

    decision = weave.evaluate({"payload": Payload()})

    assert decision.allowed is False
    assert calls == []


def test_custom_mapping_root_is_rejected_without_invoking_items():
    class HostileDict(dict):
        def items(self):
            pytest.fail("custom dictionary code executed")

    weave = LivingWeave()
    weave.add_strand("guard", lambda action: True)

    assert weave.evaluate(HostileDict(op="read")).allowed is False


def test_subclass_keys_never_reach_guard_comparisons():
    class HostileKey(str):
        pass

    calls = []
    weave = LivingWeave()
    weave.add_strand("guard", lambda action: calls.append(action) or True)

    decision = weave.evaluate({HostileKey("op"): "read"})

    assert decision.allowed is False
    assert calls == []


@pytest.mark.parametrize("number", [math.nan, math.inf, -math.inf, 1 << 4096])
def test_nonfinite_and_oversized_numbers_cannot_bypass_numeric_guards(number):
    calls = []
    weave = LivingWeave()

    def guard(action):
        calls.append(action)
        return not action["cost"] > 100

    weave.add_strand("budget", guard)

    assert weave.evaluate({"cost": number}).allowed is False
    assert calls == []


def test_deep_wide_and_alias_expanding_inputs_are_bounded():
    calls = []
    weave = LivingWeave()
    weave.add_strand("guard", lambda action: calls.append(action) or True)
    deep = {}
    for _ in range(100):
        deep = {"child": deep}
    shared = [None] * 100

    for action in (deep, {"wide": [None] * 10_000}, {"aliases": [shared] * 100}):
        decision = weave.evaluate(action)
        assert decision.allowed is False
        assert decision.blockers[0].reason == "ValueError"
    assert calls == []


def test_total_text_budget_covers_keys_and_repeated_values():
    weave = LivingWeave()
    weave.add_strand("guard", lambda action: True)
    shared_text = "x" * 600_000

    assert weave.evaluate({"x" * 1_000_001: None}).allowed is False
    assert weave.evaluate({"text": [shared_text, shared_text]}).allowed is False


def test_snapshot_survives_mutation_of_the_original_after_authorization():
    original = {"op": "read", "paths": ["public.txt"]}
    weave = LivingWeave()
    weave.add_strand("read-only", lambda action: action["op"] == "read")

    decision = weave.evaluate(original)
    original["op"] = "delete"
    original["paths"].append("secrets.txt")

    assert decision.allowed is True
    assert decision.authorized_action["op"] == "read"
    assert decision.authorized_action["paths"] == ("public.txt",)
    with pytest.raises(TypeError):
        decision.authorized_action["op"] = "delete"


@pytest.mark.parametrize("result", [[True, "yes"], {True: None, "yes": None}, (1, "yes"), (True,), (True, "x" * 4097)])
def test_malformed_guard_results_fail_closed_and_preserve_backup(result):
    calls = []
    weave = LivingWeave()
    weave.add_strand("malformed", lambda action: result)
    weave.add_strand("backup", lambda action: calls.append("backup") or True)

    decision = weave.evaluate({"op": "read"})

    assert decision.allowed is False
    assert decision.strands[0].status is StrandStatus.ERROR
    assert calls == ["backup"]


def test_guard_result_iterators_are_not_executed():
    calls = []

    class Result:
        def __iter__(self):
            calls.append("iterate")
            yield True
            yield "allow"

    weave = LivingWeave()
    weave.add_strand("malformed", lambda action: Result())
    weave.add_strand("backup", lambda action: calls.append("backup") or True)

    assert weave.evaluate({}).allowed is False
    assert calls == ["backup"]


def test_strand_configuration_change_blocks_and_preserves_existing_guards():
    calls = []
    weave = LivingWeave()

    def reconfigure(action):
        weave.add_strand("new-blocker", lambda action: False)
        return True

    weave.add_strand("reconfigure", reconfigure)
    weave.add_strand("backup", lambda action: calls.append("backup") or True)

    decision = weave.evaluate({"op": "read"})

    assert decision.allowed is False
    assert calls == ["backup"]
    assert decision.blockers[-1].reason == "strand configuration changed during evaluation"


def test_hostile_exception_metadata_cannot_skip_backup_guard():
    class HostileType(type):
        def __getattribute__(cls, name):
            if name == "__name__":
                raise SystemExit("exception name exploded")
            return super().__getattribute__(name)

    class HostileError(Exception, metaclass=HostileType):
        pass

    def broken(action):
        raise HostileError()

    calls = []
    weave = LivingWeave()
    weave.add_strand("broken", broken)
    weave.add_strand("backup", lambda action: calls.append("backup") or False)

    decision = weave.evaluate({})

    assert decision.allowed is False
    assert decision.blockers[0].reason == "guard exception"
    assert calls == ["backup"]
