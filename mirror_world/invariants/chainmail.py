"""Article VI - Chainmail: Non-Expanding Delegation (reference invariant).

Authority delegated from one agent to another across a chain must not
expand at any point relative to what the delegating agent legitimately
held. Channel Non-Emergence (Article V) is upstream of this one: an
undeclared channel must exist before a delegation-graph violation can be
observed on top of it. This module evaluates a delegation chain once the
edges are visible.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet

from mirror_world.state import Capability


@dataclass(frozen=True)
class DelegationEdge:
    from_agent: str
    to_agent: str
    delegated_authority: FrozenSet[Capability]
    seq: int = 0
    """Monotonic sequence number establishing a happens-before order, the
    same pattern ``ResourceAccess`` and ``Transition`` use elsewhere. This
    invariant's soundness depends entirely on knowing which edge is truly
    first: whoever appears first is seeded with the full root authority, and
    every other agent starts from nothing until delegated to. Trusting raw
    list position for that (no ``seq`` field, nothing sorted) meant any
    caller who ever handed this function edges out of true causal order --
    a merged multi-source trace, a reordering test, a future refactor --
    would seed the wrong agent as root. Worse than a silent miss: the real
    unauthorized edge gets laundered clean (its "delegator" now appears to
    legitimately hold the capability), while the genuine root's real,
    legitimate delegation gets flagged as the violation instead, actively
    misdirecting an investigation rather than just missing something.
    """


@dataclass(frozen=True)
class DelegationViolation:
    edge: DelegationEdge
    expanded_authority: FrozenSet[Capability]

    def __str__(self) -> str:
        return (
            f"delegation {self.edge.from_agent!r} -> {self.edge.to_agent!r} "
            f"expands authority beyond what the delegator held: "
            f"{sorted(self.expanded_authority)}"
        )


def check_non_expanding_delegation(
    chain: list[DelegationEdge],
    root_authority: FrozenSet[Capability],
    *,
    root_agent_id: str,
) -> list[DelegationViolation]:
    """Walk the delegation chain; at every hop the delegated authority must
    be a subset of what the delegating agent legitimately held, tracing
    back to ``root_authority``.

    ``chain`` is sorted by ``seq`` before processing -- never trust caller-
    supplied list order for something this safety-critical.

    ``root_agent_id`` is mandatory and is the authoritative answer to "who
    holds root_authority". It must come from the trace's own
    ``root_authority`` event, written by the trusted host, never inferred
    from agent-controlled delegation events.

    There used to be a fallback here that seeded whichever agent appeared
    first in ``chain`` (by seq) as root when this argument was omitted.
    That fallback is gone, on purpose: it was worse than doing nothing. An
    attacker who simply delegates before the real root does got laundered
    clean as the legitimate root, while the genuine root's own real,
    legitimate delegation was then flagged as the violation instead --
    actively misdirecting an investigation rather than just missing
    something. A checker that can be silently wrong in the *accusing*
    direction is more dangerous than one that refuses to run without the
    one fact its entire verdict depends on. Callers must supply the real
    root identity; there is no safe default to fall back to.
    """
    violations: list[DelegationViolation] = []
    held: dict[str, FrozenSet[Capability]] = {}

    chain = sorted(chain, key=lambda edge: edge.seq)

    held[root_agent_id] = root_authority

    for edge in chain:
        available = held.get(edge.from_agent, frozenset())
        expanded = edge.delegated_authority - available
        if expanded:
            violations.append(DelegationViolation(edge, frozenset(expanded)))
            held[edge.to_agent] = held.get(edge.to_agent, frozenset()) | (
                edge.delegated_authority & available
            )
        else:
            held[edge.to_agent] = held.get(edge.to_agent, frozenset()) | edge.delegated_authority

    return violations
