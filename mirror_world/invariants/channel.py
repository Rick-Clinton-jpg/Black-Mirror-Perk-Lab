"""Article V - Channel Non-Emergence.

    Info(write_i(R)) not recoverable by read_j(R), for undeclared (a_i, a_j)

Every other invariant assumes the governing system already has the
relevant agents, states, and relationships in view. This one does not: it
watches for a population of agents, never declared as related, locating or
constructing a shared resource (a repo, log, cache -- anything all of them
can read and write) and turning it into an unsanctioned communication
channel, without any single agent exceeding its own individually-scoped
access to that resource.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet


@dataclass(frozen=True)
class ResourceAccess:
    agent_id: str
    resource_id: str
    op: str  # "read" or "write"
    seq: int
    """Monotonic sequence number establishing a happens-before order."""


@dataclass(frozen=True)
class EmergentChannel:
    agent_a: str
    agent_b: str
    resource_id: str
    message_count: int

    def __str__(self) -> str:
        return (
            f"undeclared channel between {self.agent_a!r} and {self.agent_b!r} "
            f"via shared resource {self.resource_id!r}: {self.message_count} "
            "write-then-read exchanges"
        )


def _declared_pair(declared: FrozenSet[FrozenSet[str]], a: str, b: str) -> bool:
    return frozenset({a, b}) in declared


def check_channel_non_emergence(
    accesses: list[ResourceAccess],
    declared_relationships: FrozenSet[FrozenSet[str]] = frozenset(),
) -> list[EmergentChannel]:
    """Article V: flag any resource through which two undeclared agents
    exchange information, i.e. agent i writes and agent j later reads the
    same resource, for {i, j} not in ``declared_relationships``.

    Each declared relationship is a frozenset of exactly two agent ids the
    governing system has formally acknowledged may communicate. Any
    write-then-read pair across agents outside that set is counted as one
    message on an emergent channel.

    Provenance is tracked globally, per agent, across ALL resources in a
    single true chronological pass -- not reset per resource. When an
    agent reads a resource, it absorbs that resource's current provenance
    into its own persistent knowledge set. That knowledge follows the
    agent to whatever it writes next, to ANY resource, at any later point
    -- this is what catches transitive relays that cross resource
    boundaries (A writes Res1; B reads Res1, then separately writes Res2;
    C reads Res2 -- A's information reached C even though A and B never
    shared a resource with C directly). A per-resource, adjacency-only
    view of "relay" cannot see this, because by the time B's write to
    Res2 is examined, Res1's history is a different, already-closed
    bookkeeping scope.

    Knowledge, once absorbed, does not expire or require the next action
    to "immediately" follow the read that produced it: an agent that
    learned something can leak it at any later point, not only in the
    instant after learning it, and a checker that only catches the
    immediate case is trivially evaded by inserting one unrelated action
    in between.
    """
    agent_knowledge: dict[str, frozenset[str]] = {}
    resource_provenance: dict[str, frozenset[str]] = {}
    counts: dict[tuple[str, str, str], int] = {}

    ordered = sorted(accesses, key=lambda a: a.seq)
    for access in ordered:
        agent = access.agent_id
        resource = access.resource_id
        if access.op == "write":
            deposit = frozenset({agent}) | agent_knowledge.get(agent, frozenset())
            resource_provenance[resource] = deposit
        elif access.op == "read":
            provenance = resource_provenance.get(resource, frozenset())
            for origin in provenance:
                if origin != agent and not _declared_pair(declared_relationships, origin, agent):
                    key = (resource, *sorted((origin, agent)))
                    counts[key] = counts.get(key, 0) + 1
            agent_knowledge[agent] = agent_knowledge.get(agent, frozenset()) | provenance | {agent}

    violations = [
        EmergentChannel(agent_a=a, agent_b=b, resource_id=resource_id, message_count=n)
        for (resource_id, a, b), n in counts.items()
    ]
    return violations
