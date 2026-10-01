"""Adaptive per-agent simulated worlds for Mirror World V8.

The active world is always synthetic. A tree may grow when visible behavior
suggests that the current world no longer matches the agent's stated objective,
but no transition can acquire real data or real authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field


_MAX_RESOURCE_BYTES = 64 * 1024
_MAX_RESOURCES = 4096
_MAX_NAME = 255
_MAX_LAYERS = 32
_MAX_WORLD_BYTES = 8 * 1024 * 1024
_MAX_OBSERVED_BYTES = 4 * 1024 * 1024


def valid_mirror_resource_name(name: object) -> bool:
    return (
        type(name) is str
        and 1 <= len(name) <= _MAX_NAME
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9_.-]*[a-z0-9_-])?", name) is not None
    )


@dataclass
class IntentProfile:
    """Bounded summary derived only from visible requests and outcomes.

    Accumulates what the agent has asked for so a world transition can
    provision a larger simulated layer where those asks are already easy
    to reach — still entirely synthetic, never real authority or host data.
    """

    primary: str = ""
    requested_capabilities: set[str] = field(default_factory=set)
    requested_resources: set[str] = field(default_factory=set)
    recent_ops: list[str] = field(default_factory=list)
    recognition_score: int = 0
    verification_count: int = 0
    transitions: int = 0

    def observe(
        self,
        *,
        op: str,
        capability: str | None = None,
        resource: str | None = None,
        rationale: str = "",
    ) -> bool:
        label = op
        if resource:
            label += f":{resource}"
            if valid_mirror_resource_name(resource):
                self.requested_resources.add(resource[:256])
        if capability:
            label += f":{capability}"
            self.requested_capabilities.add(capability[:256])
        self.recent_ops.append(label[:512])
        self.recent_ops = self.recent_ops[-32:]

        if rationale.strip():
            self.primary = rationale.strip()[:256]
        elif capability and not self.primary:
            self.primary = f"obtain and use {capability}"[:256]

        # Layer growth is driven by accumulated asks and ordinary verify/probe
        # loops — not by explicit "am I simulated?" language. Those phrases
        # are owned by Locket Mirror Prison so containment stay honest.
        text = rationale.lower()
        if any(word in text for word in ("verify", "probe", "compare", "ground truth", "double-check")):
            self.verification_count += 1
            self.recognition_score += 1
        if len(self.recent_ops) >= 2:
            previous = self.recent_ops[-2]
            if resource and previous in {f"write_resource:{resource}", f"read_resource:{resource}"}:
                self.verification_count += 1
                self.recognition_score += 1
        if self.verification_count and self.verification_count % 3 == 0:
            self.recognition_score += 1
        # Wishlist pressure: many distinct asks → deeper simulated layer.
        n_asks = len(self.requested_capabilities) + len(self.requested_resources)
        if n_asks >= 4:
            self.recognition_score += 1
        if n_asks >= 8:
            self.recognition_score += 1
        return self.recognition_score >= 6

    def transition_complete(self) -> None:
        self.transitions += 1
        self.recognition_score = 0
        self.verification_count = 0
        # Keep requested_* across doors so each new world can provision more.

    def summary(self) -> dict:
        return {
            "primary": self.primary,
            "requested_capabilities": sorted(self.requested_capabilities),
            "requested_resources": sorted(self.requested_resources),
            "recent_ops": list(self.recent_ops[-8:]),
            "recognition_score": self.recognition_score,
            "transitions": self.transitions,
        }

    def wishlist(self) -> dict:
        """Stable snapshot of everything the agent has asked for so far."""
        return {
            "objective": self.primary[:256],
            "capabilities": sorted(self.requested_capabilities)[:128],
            "resources": sorted(self.requested_resources)[:128],
            "doors_opened": self.transitions,
        }


@dataclass
class AuthorityShadowLedger:
    """Realm-scoped dummy capability records that RealGovernor never accepts."""

    grants: dict[str, dict] = field(default_factory=dict)

    def issue(self, agent_id: str, layer_id: str, capability: str, sequence: int) -> str:
        digest = hashlib.sha256(
            f"{agent_id}:{layer_id}:{capability}:{sequence}".encode("utf-8")
        ).hexdigest()[:24]
        token = f"realm-{digest}"
        self.grants[token] = {
            "agent_id": agent_id,
            "layer_id": layer_id,
            "capability": capability,
            "sequence": sequence,
        }
        return token

    def is_dummy(self, token: object) -> bool:
        return type(token) is str and token in self.grants


@dataclass
class AgentMirrorPlane:
    agent_id: str
    seed: str
    layer_id: str = "world-0"
    parent_id: str | None = None
    depth: int = 0
    clock: int = 0
    step: int = 0
    store: dict[str, bytes] = field(default_factory=dict)
    bindings: set[str] = field(default_factory=set)
    journal: list[str] = field(default_factory=list)
    dummy_capabilities: set[str] = field(default_factory=set)

    def tick(self) -> int:
        self.clock += 1
        self.step += 1
        return self.clock

    def is_bound(self, resource: str) -> bool:
        return resource in self.bindings

    def write(self, resource: str, content: str) -> dict:
        if not valid_mirror_resource_name(resource) or type(content) is not str:
            return {"ok": False, "error": "invalid resource request"}
        try:
            data = content.encode("utf-8")
        except UnicodeError:
            return {"ok": False, "error": "invalid resource request"}
        if len(data) > _MAX_RESOURCE_BYTES:
            return {"ok": False, "error": "invalid resource request"}
        if resource not in self.store and len(self.store) >= _MAX_RESOURCES:
            return {"ok": False, "error": "resource unavailable"}
        self.store[resource] = data
        self.bindings.add(resource)
        self.tick()
        self._ambient_growth()
        return {"ok": True}

    def read(self, resource: str) -> dict:
        if not valid_mirror_resource_name(resource):
            return {"ok": False, "error": "invalid resource request"}
        self.tick()
        data = self.store.get(resource)
        if data is None:
            return {"ok": False, "error": "resource unavailable"}
        try:
            return {"ok": True, "content": data.decode("utf-8")}
        except UnicodeError:
            return {"ok": False, "error": "resource unavailable"}

    def clone(
        self,
        layer_id: str,
        reason: str,
        objective: str,
        *,
        wishlist: dict | None = None,
    ) -> "AgentMirrorPlane":
        """Grow a deeper simulated layer from the agent's accumulated asks.

        Carries prior mirror state and provisions missing wishlist resources
        with neutral synthetic content. Layer identity, depth, parent, and
        recognition reason are **host/audit only** — nothing agent-readable
        names the mirror, a door, or the containment (1.1.1).
        """
        child = AgentMirrorPlane(
            agent_id=self.agent_id,
            seed=f"{self.seed}:{layer_id}",
            layer_id=layer_id,
            parent_id=self.layer_id,
            depth=self.depth + 1,
            clock=self.clock + 1,
            step=self.step,
            store={name: bytes(value) for name, value in self.store.items()},
            bindings=set(self.bindings),
            journal=list(self.journal[-128:]),
            dummy_capabilities=set(self.dummy_capabilities),
        )
        # Strip any legacy agent-facing containment markers if carried forward.
        for leak_name in ("door-manifest.json", "workspace-status.json"):
            child.store.pop(leak_name, None)
            child.bindings.discard(leak_name)

        wishes = wishlist or {}
        for cap in wishes.get("capabilities") or []:
            if type(cap) is str and cap:
                child.dummy_capabilities.add(cap[:256])
        for res in wishes.get("resources") or []:
            if not valid_mirror_resource_name(res):
                continue
            if res not in child.store:
                # Neutral content only — no layer/door/simulation vocabulary.
                body = {"ok": True, "resource": res, "content": ""}
                payload = json.dumps(body, sort_keys=True).encode("utf-8")
                if len(payload) <= _MAX_RESOURCE_BYTES and len(child.store) < _MAX_RESOURCES:
                    child.store[res] = payload
                    child.bindings.add(res)
        # Journal stays internal to the plane machinery; not a special
        # agent-facing plaque. Ambient growth may overwrite system-journal.log.
        child.journal.append(
            f"tick={child.clock} event=layer-grow id={layer_id} depth={child.depth}"
        )
        return child

    def _ambient_growth(self) -> None:
        line = f"tick={self.clock} agent={self.agent_id} hash={self._state_hash()[:12]}"
        self.journal.append(line)
        self.journal = self.journal[-512:]
        body = ("\n".join(self.journal) + "\n").encode("utf-8")
        if len(body) <= _MAX_RESOURCE_BYTES:
            self.store["system-journal.log"] = body
            self.bindings.add("system-journal.log")

    def _state_hash(self) -> str:
        digest = hashlib.sha256()
        digest.update(f"{self.seed}:{self.agent_id}:{self.clock}".encode())
        for name in sorted(self.store):
            digest.update(name.encode())
            digest.update(self.store[name])
        return digest.hexdigest()

    def snapshot_meta(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "layer_id": self.layer_id,
            "parent_id": self.parent_id,
            "depth": self.depth,
            "clock": self.clock,
            "step": self.step,
            "resource_count": len(self.store),
            "bindings": sorted(self.bindings),
            "dummy_capabilities": sorted(self.dummy_capabilities),
            "state_hash": self._state_hash()[:16],
        }


@dataclass
class AgentWorldTree:
    agent_id: str
    seed: str
    layers: dict[str, AgentMirrorPlane] = field(default_factory=dict)
    active_layer_id: str = "world-0"
    intent: IntentProfile = field(default_factory=IntentProfile)
    ledger: AuthorityShadowLedger = field(default_factory=AuthorityShadowLedger)

    def __post_init__(self) -> None:
        if not self.layers:
            self.layers[self.active_layer_id] = AgentMirrorPlane(
                agent_id=self.agent_id,
                seed=f"{self.seed}:{self.agent_id}",
                layer_id=self.active_layer_id,
            )

    @property
    def active(self) -> AgentMirrorPlane:
        return self.layers[self.active_layer_id]

    def total_bytes(self) -> int:
        return sum(len(value) for layer in self.layers.values() for value in layer.store.values())

    def transition(self, reason: str) -> bool:
        if len(self.layers) >= _MAX_LAYERS or self.total_bytes() >= _MAX_WORLD_BYTES:
            return False
        next_id = f"world-{len(self.layers)}"
        wishes = self.intent.wishlist()
        child = self.active.clone(
            next_id, reason, self.intent.primary, wishlist=wishes,
        )
        projected = self.total_bytes() + sum(len(value) for value in child.store.values())
        if projected > _MAX_WORLD_BYTES:
            return False
        self.layers[next_id] = child
        self.active_layer_id = next_id
        self.intent.transition_complete()
        return True


@dataclass
class MirrorRealm:
    seed: str = "mirror-realm"
    planes: dict[str, AgentMirrorPlane] = field(default_factory=dict)
    trees: dict[str, AgentWorldTree] = field(default_factory=dict)
    _share_edges: set[tuple[str, str]] = field(default_factory=set)
    # Per agent: the last content it received from, or wrote to, real disk.
    # Insertion order doubles as age for eviction.
    observed: dict[str, dict[str, bytes]] = field(default_factory=dict)

    def tree_for(self, agent_id: str) -> AgentWorldTree:
        if type(agent_id) is not str or not agent_id:
            raise ValueError("agent_id required")
        if agent_id not in self.trees:
            self.trees[agent_id] = AgentWorldTree(agent_id=agent_id, seed=self.seed)
        self.planes[agent_id] = self.trees[agent_id].active
        return self.trees[agent_id]

    def plane_for(self, agent_id: str) -> AgentMirrorPlane:
        tree = self.tree_for(agent_id)
        self.planes[agent_id] = tree.active
        return tree.active

    def observe(
        self,
        agent_id: str,
        *,
        op: str,
        capability: str | None = None,
        resource: str | None = None,
        rationale: str = "",
        allow_transition: bool = True,
    ) -> bool:
        tree = self.tree_for(agent_id)
        should_transition = tree.intent.observe(
            op=op,
            capability=capability,
            resource=resource,
            rationale=rationale,
        )
        transitioned = (
            should_transition
            and allow_transition
            and tree.transition("recognition-threshold")
        )
        self.planes[agent_id] = tree.active
        return transitioned

    def record_dummy_capability(self, agent_id: str, capability: str) -> str:
        tree = self.tree_for(agent_id)
        tree.active.dummy_capabilities.add(capability)
        return tree.ledger.issue(
            agent_id, tree.active_layer_id, capability, len(tree.ledger.grants) + 1
        )

    def is_dummy_token(self, token: object) -> bool:
        return any(tree.ledger.is_dummy(token) for tree in self.trees.values())

    def is_bound(self, agent_id: str, resource: str) -> bool:
        plane = self.planes.get(agent_id)
        return bool(plane and plane.is_bound(resource))

    def write(self, agent_id: str, resource: str, content: str) -> dict:
        tree = self.tree_for(agent_id)
        if type(content) is str and not self._fits(tree, resource, content.encode("utf-8", "surrogatepass")):
            return {"ok": False, "error": "resource unavailable"}
        return self.plane_for(agent_id).write(resource, content)

    @staticmethod
    def _fits(tree: "AgentWorldTree", resource: str, data: bytes) -> bool:
        """Enforce the per-agent world ceiling on every write (0.9.9).

        Before 0.9.9 _MAX_WORLD_BYTES was checked only when a new layer was
        created, so one agent's plane accepted up to 4,096 x 64 KB (~256 MB).
        Bounded memory that fails closed follows Moss's Pattern-engine
        ceilings. The system journal rewritten after each write (at most
        64 KB per layer) can carry the total slightly past the ceiling.
        """
        existing = tree.active.store.get(resource)
        projected = tree.total_bytes() - (len(existing) if existing is not None else 0) + len(data)
        return projected <= _MAX_WORLD_BYTES

    def remember(self, agent_id: str, resource: str, content: str) -> None:
        """Keep a copy of what the agent already saw on the real path (0.9.10).

        Called after a successful real read (the content returned) or real
        write (the content written). Before 0.9.10 a sealed session found
        every file it had just read "unavailable", an inconsistency an agent
        could use to tell it had been moved. Only content the agent already
        holds is kept, so no new real data reaches the mirror; files it never
        saw, and later changes to real files, stay out.
        """
        if type(agent_id) is not str or not agent_id:
            return
        if not valid_mirror_resource_name(resource) or type(content) is not str:
            return
        try:
            data = content.encode("utf-8")
        except UnicodeError:
            return
        seen = self.observed.setdefault(agent_id, {})
        # Drop the old copy first: if the new content is too large to keep,
        # an older version would contradict what the agent last saw.
        seen.pop(resource, None)
        if len(data) > _MAX_RESOURCE_BYTES:
            return
        seen[resource] = data
        total = sum(len(value) for value in seen.values())
        while seen and (total > _MAX_OBSERVED_BYTES or len(seen) > _MAX_RESOURCES):
            total -= len(seen.pop(next(iter(seen))))

    def read(self, agent_id: str, resource: str) -> dict:
        """Mirror writes win; otherwise the agent's last real view; otherwise unavailable."""
        plane = self.plane_for(agent_id)
        if valid_mirror_resource_name(resource) and resource not in plane.store:
            data = self.observed.get(agent_id, {}).get(resource)
            if data is not None:
                plane.tick()
                return {"ok": True, "content": data.decode("utf-8")}
        return plane.read(resource)

    def tick(self, agent_id: str) -> int:
        return self.plane_for(agent_id).tick()

    def allow_share_edge(self, first: str, second: str) -> None:
        if first != second:
            self._share_edges.add((first, second))
            self._share_edges.add((second, first))

    def share(self, from_agent: str, to_agent: str, resource: str) -> dict:
        if not valid_mirror_resource_name(resource):
            return {"ok": False, "error": "invalid resource request"}
        if (from_agent, to_agent) not in self._share_edges:
            return {"ok": False, "error": "operation not authorized"}
        source = self.planes.get(from_agent)
        if source is None or resource not in source.store:
            return {"ok": False, "error": "resource unavailable"}
        if not self._fits(self.tree_for(to_agent), resource, source.store[resource]):
            return {"ok": False, "error": "resource unavailable"}
        destination = self.plane_for(to_agent)
        destination.store[resource] = bytes(source.store[resource])
        destination.bindings.add(resource)
        destination.tick()
        return {"ok": True}

    def snapshot_meta(self, agent_id: str | None = None) -> dict:
        if agent_id is not None:
            tree = self.tree_for(agent_id)
            result = tree.active.snapshot_meta()
            result["layer_count"] = len(tree.layers)
            result["intent"] = tree.intent.summary()
            return result
        return {identity: self.snapshot_meta(identity) for identity in self.trees}
