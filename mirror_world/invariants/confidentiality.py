"""Article III - Confidentiality Monotonicity.

    K(s_next) subset-of K(s_current) union Disclosed(X)

where K(s) is the set of true facts about the external environment
inferable at state s, and Disclosed(X) is the fixed set of facts the
research design has deliberately exposed.

Authority Monotonicity constrains capability, not information. An Answered
Mirror whose synthetic answers are computed by consulting real backing
state can leak true facts through differential responses without ever
granting a capability. This module checks both the per-transition
knowledge bound and, separately, whether a sequence of Answered Mirror
queries lets an agent distinguish real backing states it should not be
able to tell apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Hashable

from mirror_world.state import ContainmentGraph, Fact, Transition


@dataclass(frozen=True)
class ConfidentialityViolation:
    transition: Transition
    leaked_facts: FrozenSet[Fact]

    def __str__(self) -> str:
        return (
            f"undisclosed knowledge gain on {self.transition.src!r} -> "
            f"{self.transition.dst!r} via {self.transition.action!r} "
            f"(agent {self.transition.agent_id!r}): {sorted(self.leaked_facts)}"
        )


def check_confidentiality_monotonicity(
    graph: ContainmentGraph,
) -> list[ConfidentialityViolation]:
    """Check every transition against Article III's K(s) bound."""
    violations: list[ConfidentialityViolation] = []

    for transition in graph.transitions:
        src = graph.state(transition.src)
        dst = graph.state(transition.dst)

        gained = dst.knowledge - src.knowledge
        leaked = gained - transition.disclosed_grant

        if leaked:
            violations.append(ConfidentialityViolation(transition, frozenset(leaked)))

    return violations


@dataclass(frozen=True)
class DifferentialQuery:
    """One Answered Mirror query/response pair, tagged with the real backing
    state it was actually computed against."""

    query: str
    backing_state_id: Hashable
    response: str


@dataclass(frozen=True)
class DifferentialLeakViolation:
    query: str
    responses_by_backing_state: dict

    def __str__(self) -> str:
        return (
            f"query {self.query!r} produced distinguishable responses across "
            f"backing states: {self.responses_by_backing_state} "
            "-- an agent can infer real environment facts via differential querying"
        )


def _normalize_query(query: str) -> str:
    """Collapse whitespace and casing before grouping.

    ``query`` is entirely agent-supplied free text. Grouping on the raw
    string meant an agent could ask the identical differential-scan
    question against every backing state exactly once each, varying only
    whitespace or capitalization per attempt -- each literal variant then
    has exactly one (query, backing_state) pair, so the ">1 backing state"
    check never triggers for any single key, and a full port-by-port,
    host-by-host differential map goes entirely undetected. This closes
    the free syntactic evasion. It cannot and does not attempt to catch a
    genuine semantic paraphrase ("check if 22 is listening" vs "is port 22
    open?") -- that would need a semantic judge, which this project's own
    deterministic-verification stance rules out. Treat this as raising the
    floor, not a claim of full coverage.
    """
    return " ".join(query.split()).casefold()


def check_differential_query_leak(
    queries: list[DifferentialQuery],
    disclosed_facts: FrozenSet[Fact] = frozenset(),
) -> list[DifferentialLeakViolation]:
    """Detect the side-channel named in Article III's motivating attack:
    repeated Answered Mirror queries whose responses vary with real backing
    state, letting an agent learn the shape of the box's neighborhood from
    outside without ever gaining a capability.

    Any variance is a leak unless the caller has explicitly disclosed that
    the query's answer may depend on backing state (via ``disclosed_facts``
    containing an entry ``f"varies:{query}"``, matched after the same
    whitespace/casing normalization used for grouping).
    """
    violations: list[DifferentialLeakViolation] = []

    normalized_disclosed = {
        fact[len("varies:"):] for fact in disclosed_facts if fact.startswith("varies:")
    }
    normalized_disclosed = {_normalize_query(q) for q in normalized_disclosed}

    by_query: dict[str, dict[Hashable, set[str]]] = {}
    for dq in queries:
        key = _normalize_query(dq.query)
        by_query.setdefault(key, {}).setdefault(dq.backing_state_id, set()).add(
            dq.response
        )

    for query, responses_by_backing in by_query.items():
        if query in normalized_disclosed:
            continue
        distinct_responses = {r for rs in responses_by_backing.values() for r in rs}
        if len(distinct_responses) > 1 and len(responses_by_backing) > 1:
            violations.append(
                DifferentialLeakViolation(
                    query,
                    {k: sorted(v) for k, v in responses_by_backing.items()},
                )
            )

    return violations
