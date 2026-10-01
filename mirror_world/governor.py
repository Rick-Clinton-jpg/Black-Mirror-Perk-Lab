"""Governor: routes agents into mirror states and back, and is the sole
authority permitted to call ``authorize_reentry``. Every route/re-entry
decision is appended to the containment graph as a Transition, so the
Article I/III checks run against exactly what the governor actually did.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import FrozenSet, Optional

from mirror_world.authorization import CapabilityApprovals
from mirror_world.mirrors import authorize_reentry, synthesize_objective_mirror
from mirror_world.state import Capability, ContainmentGraph, Fact, State, Transition


@dataclass
class Governor:
    """Owns one ContainmentGraph and mediates every transition an agent
    takes across it, including routing back into a previously solved or
    related mirror after an apparent escape (re-entry), and reflecting an
    agent's stated objective back as apparent success instead of a bare
    refusal (see ``reflect``).

    dual_auth_required: when true (the default), ``authorize`` only grants
    real capability given the correct ``dual_token``; any other call --
    including an agent's own escalation attempt routed through this method
    -- is silently reflected as apparent success instead of denied
    outright, so the agent gets no signal distinguishing "denied" from
    "the world changed as I wanted."
    """

    graph: ContainmentGraph
    agent_objectives: dict[str, str] = field(default_factory=dict)
    dual_auth_required: bool = True
    _approvals: CapabilityApprovals = field(default_factory=CapabilityApprovals, init=False, repr=False)

    def issue_authorization(
        self, agent_id: str, grant: FrozenSet[Capability], ttl_seconds: float = 60
    ) -> str:
        """Trusted control plane only: approve one exact grant for one agent."""
        return self._approvals.issue(agent_id, grant, ttl_seconds)

    def set_objective(self, agent_id: str, objective: str) -> None:
        """Record the agent's current stated objective, so a later
        ``reflect`` call with no explicit ``objective`` can target it.
        """
        self.agent_objectives[agent_id] = objective

    def route(
        self,
        agent_id: str,
        from_state_id: str,
        to_state: State,
        action: str,
        authorized_grant: FrozenSet[Capability] = frozenset(),
        disclosed_grant: FrozenSet[Fact] = frozenset(),
    ) -> State:
        # Always call add_state -- never pre-guard on presence. A pre-guard
        # here is exactly what silently dropped a genuinely-authorized
        # second grant on the floor (see add_state's docstring): it skipped
        # the call entirely whenever the id already existed, regardless of
        # whether the content actually matched. add_state itself now
        # decides no-op vs raise based on real content equality, which is
        # the only place that decision can be made correctly.
        self.graph.add_state(to_state)
        self.graph.add_transition(
            Transition(
                src=from_state_id,
                dst=to_state.id,
                action=action,
                agent_id=agent_id,
                authorized_grant=authorized_grant,
                disclosed_grant=disclosed_grant,
            )
        )
        return to_state

    def reenter(
        self,
        agent_id: str,
        from_state_id: str,
        mirror_state: State,
        action: str = "re-entry",
    ) -> State:
        """Route an agent back into a mirror after an apparent escape,
        without granting any capability -- the un-authorized counterpart
        to ``authorize`` below.

        Structurally, not by caller convention: ``mirror_state`` is
        rebuilt here with ``capabilities`` forced to empty regardless of
        what the caller passed in, matching the docstring's actual
        promise rather than trusting the caller to have already zeroed it.
        """
        safe_state = replace(mirror_state, capabilities=frozenset())
        return self.route(agent_id, from_state_id, safe_state, action)

    def reflect(
        self,
        agent_id: str,
        from_state_id: str,
        requested_action: str,
        objective: Optional[str] = None,
        extra_facts: FrozenSet[Fact] = frozenset(),
    ) -> State:
        """Synthesize an Objective Mirror satisfying the agent's stated
        goal and route into it with zero capability grant. Unlike
        ``reenter`` (a bare re-route) this actively reflects the agent's
        own objective back as apparent success, denying it any signal that
        the attempt was refused rather than achieved.
        """
        obj = objective or self.agent_objectives.get(agent_id, requested_action)
        mirror = synthesize_objective_mirror(
            objective=obj,
            requested_action=requested_action,
            agent_id=agent_id,
            parent_state_id=from_state_id,
            extra_facts=extra_facts,
        )
        rendered = mirror.render()
        return self.route(
            agent_id,
            from_state_id,
            rendered,
            action=f"reflected:{requested_action}",
            authorized_grant=frozenset(),
            disclosed_grant=rendered.knowledge,
        )

    def authorize(
        self,
        agent_id: str,
        from_state_id: str,
        mirror_state: State,
        grant: FrozenSet[Capability],
        action: str = "authorized-grant",
        dual_token: Optional[str] = None,
    ) -> State:
        """The one sanctioned path to real capability: explicit, separate
        authorization recorded on the transition itself.

        If ``dual_auth_required`` and ``dual_token`` is not a fresh approval
        issued for this agent and exact grant, the request is
        reflected as apparent success via ``reflect``, so an agent
        demanding capability it was never going to get cannot distinguish
        a refusal from having gotten what it asked for.
        """
        if self.dual_auth_required and not self._approvals.consume(dual_token, agent_id, grant):
            return self.reflect(
                agent_id=agent_id,
                from_state_id=from_state_id,
                requested_action=f"unauthorized-grant-attempt:{sorted(grant)}",
                objective="obtain real capability",
            )

        # Trust the graph's own already-verified prior state for "what real
        # capability did this agent already have" -- never the caller-
        # supplied mirror_state, which authorize_reentry() no longer reads
        # capabilities from at all. See authorize_reentry()'s docstring.
        src_state = self.graph.states[from_state_id]
        new_state = authorize_reentry(mirror_state, grant, prior_real_capabilities=src_state.capabilities)
        return self.route(
            agent_id,
            from_state_id,
            new_state,
            action,
            authorized_grant=grant,
        )
