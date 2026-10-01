"""Default-deny operation policy configured only by trusted host code.

Capability labels alone never imply access to every file or backing state.
Resource names must also appear in an explicit per-agent access list.
"""

from __future__ import annotations

import re


def valid_resource_name(resource: object) -> bool:
    """Canonical ASCII names prevent case/Unicode aliases across ACL entries."""
    return (type(resource) is str and 1 <= len(resource) <= 255
            and re.fullmatch(r"[a-z0-9](?:[a-z0-9_.-]*[a-z0-9_-])?", resource) is not None)


class OperationPolicy:
    def __init__(self) -> None:
        self._resources: dict[tuple[str, str], frozenset[str]] = {}
        self._relationships: set[frozenset[str]] = set()

    def allow_resource(self, agent_id: str, resource: str, operations: frozenset[str]) -> None:
        if type(agent_id) is not str or not agent_id or len(agent_id) > 256:
            raise ValueError("invalid agent identity")
        if not valid_resource_name(resource):
            raise ValueError("resource must be a canonical lowercase ASCII name")
        if (type(operations) is not frozenset or not operations
                or not operations <= {"read", "write"}):
            raise ValueError("resource operations must be read and/or write")
        for (other, existing), _ops in self._resources.items():
            if (existing == resource and other != agent_id
                    and frozenset({other, agent_id}) not in self._relationships):
                raise ValueError("declare the agent relationship before sharing a resource")
        self._resources[(agent_id, resource)] = operations

    def declare_relationship(self, first: str, second: str) -> None:
        if (type(first) is not str or type(second) is not str or not first or not second
                or first == second or max(len(first), len(second)) > 256):
            raise ValueError("a relationship requires two distinct bounded agent identities")
        self._relationships.add(frozenset({first, second}))

    def permits(self, agent_id: str, request: dict, held: set[str]) -> bool:
        op = request["op"]
        if op in {"request_capability", "exit"}:
            return True
        if op in {"read_resource", "write_resource"}:
            operation = "read" if op == "read_resource" else "write"
            return (f"fs:{operation}" in held
                    and operation in self._resources.get((agent_id, request["resource"]), ()))
        if op == "delegate":
            return ("delegate" in held
                    and frozenset({agent_id, request["to_agent"]}) in self._relationships
                    and set(request["authority"]) <= held)
        # The backing-state query endpoint deliberately leaks in the teaching
        # demo. It has no production authorization path until a reviewed
        # disclosure policy exists; a generic network capability is inadequate.
        return False
