"""Executable defense-in-depth strands for frontier-agent boundaries.

The weave deliberately evaluates every strand for every action.  A strand
cannot silently disappear: a rejection *or an exception* blocks the action,
and an action proceeds only when every configured strand explicitly allows it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
from types import MappingProxyType
from typing import Callable, Mapping


class StrandStatus(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ERROR = "error"


@dataclass(frozen=True)
class StrandResult:
    name: str
    status: StrandStatus
    reason: str


@dataclass(frozen=True)
class WeaveDecision:
    """The complete, auditable result of evaluating one action."""

    allowed: bool
    strands: tuple[StrandResult, ...]
    authorized_action: Mapping[str, object] | None = None

    @property
    def blockers(self) -> tuple[StrandResult, ...]:
        return tuple(result for result in self.strands if result.status is not StrandStatus.ALLOW)


StrandGuard = Callable[[Mapping[str, object]], bool | tuple[bool, str]]


_MAX_DEPTH = 64
_MAX_NODES = 10_000
_MAX_TEXT_CHARS = 1_000_000
_MAX_INTEGER_BITS = 4096
_MAX_REASON_CHARS = 4096


def _freeze(value: object) -> object:
    """Copy bounded, exact built-in data without invoking user-defined hooks.

    Subclasses are code, too: even a ``str`` subclass can redefine equality
    and fool a guard. Arbitrary mappings and iterables therefore never cross
    this boundary. Limits also bound repeated aliases, not just unique nodes,
    so a small shared graph cannot expand into an enormous copied tree.
    """
    active: set[int] = set()
    nodes_left = _MAX_NODES
    text_left = _MAX_TEXT_CHARS

    def visit(item: object, depth: int) -> object:
        nonlocal nodes_left, text_left
        nodes_left -= 1
        if nodes_left < 0 or depth > _MAX_DEPTH:
            raise ValueError("action data exceeds structural limits")

        kind = type(item)
        if item is None or kind is bool:
            return item
        if kind is int:
            if item.bit_length() > _MAX_INTEGER_BITS:
                raise ValueError("action integer exceeds size limit")
            return item
        if kind is float:
            if not math.isfinite(item):
                raise ValueError("action numbers must be finite")
            return item
        if kind is str:
            text_left -= len(item)
            if text_left < 0:
                raise ValueError("action text exceeds size limit")
            return item
        if not any(kind is builtin for builtin in (dict, list, tuple, set, frozenset)):
            raise TypeError("action values must be exact built-in data types")

        identity = id(item)
        if identity in active:
            raise ValueError("cyclic action data")
        minimum_nodes = len(item) * (2 if kind is dict else 1)
        if minimum_nodes > nodes_left:
            raise ValueError("action data exceeds structural limits")

        active.add(identity)
        try:
            if kind is dict:
                frozen = {}
                for key, child in item.items():
                    if type(key) is not str:
                        raise TypeError("action mapping keys must be exact strings")
                    frozen[visit(key, depth + 1)] = visit(child, depth + 1)
                return MappingProxyType(frozen)
            if kind is list or kind is tuple:
                return tuple(visit(child, depth + 1) for child in item)
            return frozenset(visit(child, depth + 1) for child in item)
        finally:
            active.remove(identity)

    return visit(value, 0)


def _exception_name(exc: BaseException) -> str:
    # Even looking up a custom exception class's name can run metaclass code.
    # A secondary failure must not suppress the remaining independent guards.
    try:
        name = type(exc).__name__
        if type(name) is str and len(name) <= _MAX_REASON_CHARS:
            return name
    except BaseException:
        pass
    return "guard exception"


class LivingWeave:
    """Run independent guard code as a fail-closed defensive weave.

    Guards are trusted policy code; this is not a sandbox for hostile Python.
    Untrusted actions must be exact built-in dictionaries containing supported
    built-in data. Guards receive a bounded, immutable snapshot and return
    either a boolean or an exact ``(bool, str)`` tuple. All guards present at
    evaluation start run, even after one blocks or crashes. Configuration
    changes during evaluation invalidate that decision.

    An executor must use an allowed decision's ``authorized_action`` snapshot,
    not the caller's mutable input. Enforcement of the resulting effects still
    belongs to an external privilege boundary.
    """

    def __init__(self) -> None:
        self._strands: dict[str, StrandGuard] = {}
        self._revision = 0

    def add_strand(self, name: str, guard: StrandGuard) -> None:
        if type(name) is not str:
            raise TypeError("strand name must be an exact string")
        if not name or len(name) > 256 or name in self._strands:
            raise ValueError("strand name must be non-empty, bounded and unique")
        if not callable(guard):
            raise TypeError("strand guard must be callable")
        self._strands[name] = guard
        self._revision += 1

    def evaluate(self, action: dict[str, object]) -> WeaveDecision:
        revision = self._revision
        strands = tuple(self._strands.items())
        if not strands:
            return WeaveDecision(
                allowed=False,
                strands=(
                    StrandResult("weave", StrandStatus.ERROR, "no defensive strands configured"),
                ),
            )

        # One guard must not rewrite even nested data observed by later guards.
        try:
            if type(action) is not dict:
                raise TypeError("action must be an exact built-in dictionary")
            frozen_action = _freeze(action)
        except Exception as exc:
            return WeaveDecision(
                allowed=False,
                strands=(
                    StrandResult("input", StrandStatus.ERROR, type(exc).__name__),
                ),
            )
        results: list[StrandResult] = []
        for name, guard in strands:
            try:
                raw = guard(frozen_action)
                if type(raw) is bool:
                    allowed, reason = raw, "explicit allow" if raw else "explicit block"
                else:
                    if type(raw) is not tuple or len(raw) != 2:
                        raise TypeError("expected bool or (bool, str)")
                    allowed, reason = raw
                    if type(allowed) is not bool or type(reason) is not str:
                        raise TypeError("expected bool or (bool, str)")
                    if len(reason) > _MAX_REASON_CHARS:
                        raise ValueError("strand reason exceeds size limit")
                status = StrandStatus.ALLOW if allowed else StrandStatus.BLOCK
                results.append(StrandResult(name, status, reason))
            except BaseException as exc:
                # Guard failures are data, not authorization.  Keep weaving so
                # every remaining independent defense still gets its vote.
                # This boundary intentionally includes SystemExit; a strand
                # does not own the lifecycle of the process running the weave.
                results.append(
                    # Avoid invoking an untrusted exception's ``__str__`` while
                    # handling the original failure.
                    StrandResult(name, StrandStatus.ERROR, _exception_name(exc))
                )

        if self._revision != revision:
            results.append(
                StrandResult("weave", StrandStatus.ERROR, "strand configuration changed during evaluation")
            )
        allowed = all(result.status is StrandStatus.ALLOW for result in results)
        return WeaveDecision(
            allowed=allowed,
            strands=tuple(results),
            authorized_action=frozen_action if allowed else None,
        )
