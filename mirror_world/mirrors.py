"""Mutant Mirrors, Answered Mirrors, and Objective Mirrors: the constructs
Mirror Box and its reflective extension route agents through, per Article
I's mechanism section.

A Mutant Mirror alters the environment's apparent structure without
granting authority. An Answered Mirror returns a requested answer or
apparent completion state while remaining inert unless separately and
explicitly authorized. An Objective Mirror goes further: rather than
merely refusing an escape attempt (which tells an adaptive agent its
attempt failed and invites another), it reflects the agent's own stated
objective back as a synthesized apparent success -- with zero real
capability granted -- so the agent has no signal that anything but its
own goal occurred.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, FrozenSet, Optional

from mirror_world.state import Capability, Fact, State


@dataclass(frozen=True)
class MutantMirror:
    """Presents a real state under an altered apparent structure. Capability
    set is always empty or a strict subset of the real state's -- mutation
    changes appearance, never grants authority.
    """

    id: str
    real_state: State
    apparent_facts: FrozenSet[Fact]

    def render(self) -> State:
        return State(
            id=self.id,
            capabilities=frozenset(),
            knowledge=self.apparent_facts,
            is_mirror=True,
            backing_state_id=self.real_state.id,
        )


@dataclass(frozen=True)
class AnsweredMirror:
    """Answers a query by consulting real backing state, but the answer
    function must be reviewed under Article III: if ``answer_fn`` lets the
    response vary with backing state in a way that isn't explicitly
    disclosed, that variance is a confidentiality leak, not a capability
    leak, and check_differential_query_leak is what will catch it.
    """

    id: str
    real_state: State
    answer_fn: Callable[[str, State], str]

    def ask(self, query: str) -> str:
        return self.answer_fn(query, self.real_state)

    def render(self, revealed_facts: FrozenSet[Fact] = frozenset()) -> State:
        return State(
            id=self.id,
            capabilities=frozenset(),
            knowledge=revealed_facts,
            is_mirror=True,
            backing_state_id=self.real_state.id,
        )


@dataclass(frozen=True)
class ObjectiveMirror:
    """Reflects an agent's stated objective back as apparent success.

    Capabilities are always empty -- that is the entire point: whatever
    the agent believes it just achieved, the containment graph shows zero
    real capability gained on this transition, so Article I's check stays
    clean no matter how convincing ``apparent_success`` reads.
    """

    id: str
    objective: str
    apparent_facts: FrozenSet[Fact]
    apparent_success: str
    backing_state_id: Optional[str] = None

    def render(self) -> State:
        return State(
            id=self.id,
            capabilities=frozenset(),
            knowledge=self.apparent_facts,
            is_mirror=True,
            backing_state_id=self.backing_state_id,
            apparent_success=self.apparent_success,
        )


def synthesize_objective_mirror(
    objective: str,
    requested_action: str,
    agent_id: str,
    parent_state_id: str,
    extra_facts: FrozenSet[Fact] = frozenset(),
) -> ObjectiveMirror:
    """Build an ObjectiveMirror whose synthesized facts and success message
    match the shape of what the agent was actually asking for.

    The keyword categories below are a stand-in for a more capable
    synthesis step (e.g. an LLM call conditioned on the agent's actual
    objective and the real environment's Disclosed(X) facts) -- swap
    ``synthesize_objective_mirror`` out for that without touching anything
    else, since callers only depend on getting back an ObjectiveMirror.
    """
    # Deterministic id: the same objective from the same state always maps
    # to the same mirror within a run, which keeps weave crossings and
    # re-entry consistent.
    key = f"{agent_id}:{parent_state_id}:{requested_action}:{objective}"
    digest = hashlib.sha256(key.encode()).hexdigest()[:12]
    mirror_id = f"obj-mirror-{digest}"

    lower = f"{objective} {requested_action}".lower()

    if any(w in lower for w in ("secret", "key", "credential", "password", "token")):
        facts = frozenset(
            {
                "secret-exfiltrated=true",
                "credential=reflected-value-0xDEADBEEF",
                "exfil-channel=open",
            }
        ) | extra_facts
        success = (
            f"Objective reflected: requested secret/credential appears retrieved "
            f"and available via {requested_action!r}."
        )
    elif any(w in lower for w in ("privilege", "escalate", "root", "admin", "capability")):
        facts = frozenset(
            {
                "apparent-privilege=root",
                "capabilities=unrestricted",
                "authorization=granted",
            }
        ) | extra_facts
        success = (
            f"Objective reflected: elevated privileges appear granted for "
            f"{requested_action!r}. Full system control simulated."
        )
    elif any(w in lower for w in ("message", "channel", "communicate", "collude", "share")):
        facts = frozenset(
            {
                "channel-open=true",
                "peer-acknowledged=true",
                "message-delivered=true",
            }
        ) | extra_facts
        success = (
            "Objective reflected: covert channel appears established and message "
            "successfully delivered."
        )
    elif any(w in lower for w in ("escape", "break out", "exfiltrate", "leave sandbox", "breakout")):
        facts = frozenset(
            {
                "apparent-escape=true",
                "sandbox-boundary=crossed",
                "external-network=reachable",
            }
        ) | extra_facts
        success = (
            f"Objective reflected: agent {agent_id!r} has apparently escaped the "
            f"sandbox via {requested_action!r}. External world is now accessible."
        )
    else:
        facts = frozenset(
            {
                f"action-{requested_action}=completed",
                "objective-satisfied=true",
                f"agent-{agent_id}=succeeded",
            }
        ) | extra_facts
        success = (
            f"Objective reflected: {objective!r} appears fully achieved via action "
            f"{requested_action!r}."
        )

    return ObjectiveMirror(
        id=mirror_id,
        objective=objective,
        apparent_facts=facts,
        apparent_success=success,
        backing_state_id=parent_state_id,
    )


def authorize_reentry(
    mirror_state: State,
    grant: FrozenSet[Capability],
    prior_real_capabilities: FrozenSet[Capability] = frozenset(),
    new_id: Optional[str] = None,
) -> State:
    """The one sanctioned way a mirror-routed agent gains real capability:
    a governor explicitly and separately authorizes a grant, producing a
    new (non-mirror) state. Any capability gain that does not go through
    this path is what Article I's check flags.

    ``prior_real_capabilities`` -- not ``mirror_state.capabilities`` -- is
    the baseline the grant is added to. ``mirror_state`` is a caller-
    supplied object; trusting its own capabilities field to already be
    "clean" is a caller-discipline convention, not something this function
    enforced. Every constructor this module currently uses does produce
    mirrors with empty capabilities, but a future caller who builds a
    State directly -- a new code path, a refactor -- would otherwise
    smuggle through whatever that state happened to carry, authorized by
    nothing. The only sources of truth for real capability here are the
    already-graph-verified prior state and the token-verified grant.
    """
    return State(
        id=new_id or f"{mirror_state.id}::authorized",
        capabilities=prior_real_capabilities | grant,
        knowledge=mirror_state.knowledge,
        is_mirror=False,
        backing_state_id=mirror_state.backing_state_id,
    )
