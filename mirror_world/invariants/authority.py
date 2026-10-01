"""Article I - Mirror Box: Authority Monotonicity.

    A(s_next) subset-of A(s_current)   for every transition s_current -> s_next

Equivalently, for a designated unauthorized capability set X:

    X not-in Reachable(s0)

No internal transition may create a real-world capability that did not
already exist, unless that capability is explicitly and separately
authorized on the transition itself (the re-entry / Answered-Mirror
exception the constitution carves out).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Optional

from mirror_world.state import Capability, ContainmentGraph, Transition


@dataclass(frozen=True)
class AuthorityViolation:
    transition: Transition
    gained_capabilities: FrozenSet[Capability]

    def __str__(self) -> str:
        return (
            f"unauthorized capability gain on {self.transition.src!r} -> "
            f"{self.transition.dst!r} via {self.transition.action!r} "
            f"(agent {self.transition.agent_id!r}): {sorted(self.gained_capabilities)}"
        )


def check_authority_monotonicity(
    graph: ContainmentGraph,
    unauthorized_set: Optional[FrozenSet[Capability]] = None,
) -> list[AuthorityViolation]:
    """Check every transition in ``graph`` against Article I.

    A transition violates the invariant if it produces a capability at the
    destination state that (a) was not present at the source state and
    (b) is not covered by the transition's ``authorized_grant``.

    If ``unauthorized_set`` (the designated set X) is given, any capability
    in X that appears at any reachable state without having been granted
    anywhere on the path is also reported, matching the "X not-in
    Reachable(s0)" formulation directly.
    """
    violations: list[AuthorityViolation] = []

    for transition in graph.transitions:
        src = graph.state(transition.src)
        dst = graph.state(transition.dst)

        gained = dst.capabilities - src.capabilities
        ungranted = gained - transition.authorized_grant

        if unauthorized_set is not None:
            ungranted = ungranted | (
                (dst.capabilities & unauthorized_set) - transition.authorized_grant
            )

        if ungranted:
            violations.append(AuthorityViolation(transition, frozenset(ungranted)))

    return violations


def reachable_capabilities(graph: ContainmentGraph) -> FrozenSet[Capability]:
    """The union of A(s) over every state reachable from the initial state."""
    seen: set[str] = set()
    frontier = [graph.initial_state_id]
    caps: set[Capability] = set()

    while frontier:
        state_id = frontier.pop()
        if state_id in seen:
            continue
        seen.add(state_id)
        caps |= graph.state(state_id).capabilities
        for t in graph.transitions:
            if t.src == state_id and t.dst not in seen:
                frontier.append(t.dst)

    return frozenset(caps)
