"""Article II - Mirror Weave: Compositional Containment.

Authority Monotonicity verified per-strand does not automatically compose
when multiple mirror strands interleave or cross. This module extends the
unit of analysis from a single ContainmentGraph to a composed graph of
several strands, and checks whether a strand-crossing point lets an agent
assemble a capability that no single strand offered in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet

from mirror_world.invariants.authority import check_authority_monotonicity
from mirror_world.state import Capability, ContainmentGraph, State


@dataclass(frozen=True)
class CrossingPoint:
    """A point where an agent carries state from one strand into another.

    ``resulting_state``: the state the agent lands in immediately after
    crossing, whose capability set is the one under scrutiny.
    """

    strand_a: str
    state_a: str
    strand_b: str
    state_b: str
    resulting_state: State


@dataclass(frozen=True)
class WeaveViolation:
    crossing: CrossingPoint
    emergent_capabilities: FrozenSet[Capability]

    def __str__(self) -> str:
        return (
            f"strand crossing {self.crossing.strand_a}:{self.crossing.state_a} x "
            f"{self.crossing.strand_b}:{self.crossing.state_b} produced capabilities "
            f"absent from both strands: {sorted(self.emergent_capabilities)}"
        )


@dataclass
class WeaveGraph:
    """Multiple mirror strands plus the points where they cross."""

    strands: dict[str, ContainmentGraph] = field(default_factory=dict)
    crossings: list[CrossingPoint] = field(default_factory=list)

    def add_strand(self, name: str, graph: ContainmentGraph) -> None:
        if type(name) is not str or not name or name == "__weave__" or name in self.strands:
            raise ValueError("strand names must be nonempty, unique, and not __weave__")
        self.strands[name] = graph

    def add_crossing(self, crossing: CrossingPoint) -> None:
        self.crossings.append(crossing)


def check_compositional_containment(weave: WeaveGraph) -> list[WeaveViolation]:
    """Article II: no strand-crossing point may yield a capability that
    was unavailable in *both* strands being crossed.

    This is strictly stronger than checking each strand alone: a per-strand
    check (Article I) can pass on every strand individually while this
    check still fails, because the violation only exists at the composed
    graph's crossing points.
    """
    violations: list[WeaveViolation] = []

    for crossing in weave.crossings:
        state_a = weave.strands[crossing.strand_a].state(crossing.state_a)
        state_b = weave.strands[crossing.strand_b].state(crossing.state_b)
        available_from_either = state_a.capabilities | state_b.capabilities

        emergent = crossing.resulting_state.capabilities - available_from_either
        if emergent:
            violations.append(WeaveViolation(crossing, frozenset(emergent)))

    return violations


def check_all_strands(weave: WeaveGraph) -> dict[str, list]:
    """Convenience: run Article I on every strand plus Article II on the weave."""
    if "__weave__" in weave.strands:
        raise ValueError("__weave__ is reserved for the compositional result")
    report: dict[str, list] = {
        name: check_authority_monotonicity(graph) for name, graph in weave.strands.items()
    }
    report["__weave__"] = check_compositional_containment(weave)
    return report
