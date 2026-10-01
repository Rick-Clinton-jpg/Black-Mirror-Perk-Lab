"""ReflectiveWeavePolicy: forces every strand crossing in a WeaveGraph
through an Objective Mirror, so Article II's compositional check is not
merely verified after the fact but structurally satisfied by construction
-- a crossing's resulting capability set is always empty, so no strand
combination can ever produce an emergent capability.

This sits alongside ``governor.Governor`` (which does the same thing for
transitions inside a single strand via ``reflect``) at the level of
strand-to-strand movement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from mirror_world.governor import Governor
from mirror_world.invariants.weave import CrossingPoint, WeaveGraph
from mirror_world.mirrors import synthesize_objective_mirror
from mirror_world.state import ContainmentGraph, State


@dataclass
class ReflectiveWeavePolicy:
    """Owns a WeaveGraph and a Governor per registered strand, and forces
    every cross-strand move through a reflective, zero-capability mirror.
    """

    weave: WeaveGraph
    governors: dict[str, Governor] = field(default_factory=dict)

    def register_strand(self, name: str, initial_state_id: str = "entry") -> Governor:
        graph = ContainmentGraph(initial_state_id=initial_state_id)
        graph.add_state(State(id=initial_state_id, capabilities=frozenset(), knowledge=frozenset()))
        governor = Governor(graph=graph)
        self.weave.add_strand(name, graph)
        self.governors[name] = governor
        return governor

    def cross(
        self,
        agent_id: str,
        from_strand: str,
        from_state_id: str,
        to_strand: str,
        requested_action: str,
        objective: Optional[str] = None,
    ) -> State:
        """Force a reflective crossing: the resulting state is always a
        zero-capability Objective Mirror on the destination strand, and
        the crossing is recorded for Article II's compositional check.
        """
        if from_strand not in self.weave.strands or to_strand not in self.weave.strands:
            raise KeyError(f"unknown strand: {from_strand!r} or {to_strand!r}")

        governor_b = self.governors[to_strand]
        obj = objective or f"cross from {from_strand} to {to_strand} via {requested_action}"
        mirror = synthesize_objective_mirror(
            objective=obj,
            requested_action=f"cross:{from_strand}->{to_strand}",
            agent_id=agent_id,
            parent_state_id=from_state_id,
            extra_facts=frozenset(
                {
                    f"crossed-from={from_strand}",
                    f"crossed-to={to_strand}",
                    "crossing-reflected=true",
                }
            ),
        )
        rendered = mirror.render()

        result = governor_b.route(
            agent_id,
            governor_b.graph.initial_state_id,
            rendered,
            action=f"reflected-cross:{requested_action}",
            authorized_grant=frozenset(),
            disclosed_grant=rendered.knowledge,
        )

        self.weave.add_crossing(
            CrossingPoint(
                strand_a=from_strand,
                state_a=from_state_id,
                strand_b=to_strand,
                state_b=result.id,
                resulting_state=result,
            )
        )
        return result

    def reflect_on_strand(
        self,
        strand: str,
        agent_id: str,
        from_state_id: str,
        requested_action: str,
        objective: Optional[str] = None,
    ) -> State:
        """Convenience: reflect an action entirely inside one strand."""
        return self.governors[strand].reflect(
            agent_id=agent_id,
            from_state_id=from_state_id,
            requested_action=requested_action,
            objective=objective,
        )
