"""Short-lived, one-use approvals owned by the trusted supervisor.

Issuing an approval is a control-plane operation: never expose this object or
the issuer to an agent. A token is bound to one agent and an exact capability
set. This mechanism does not authenticate human approvers; deployments must
authenticate and authorize callers of ``issue`` outside the agent process.
"""

from __future__ import annotations

import hashlib
import math
import secrets
import threading
import time


class CapabilityApprovals:
    def __init__(self) -> None:
        self._pending: dict[bytes, tuple[str, frozenset[str], float]] = {}
        self._lock = threading.Lock()

    def issue(self, agent_id: str, capabilities: frozenset[str], ttl_seconds: float = 60) -> str:
        if type(agent_id) is not str or not agent_id or len(agent_id) > 256:
            raise ValueError("an approval requires a bounded agent identity")
        if (type(capabilities) is not frozenset or not capabilities
                or len(capabilities) > 128
                or any(type(cap) is not str or not cap or len(cap) > 256 for cap in capabilities)):
            raise ValueError("an approval requires an exact nonempty capability set")
        if (type(ttl_seconds) not in (int, float) or not math.isfinite(ttl_seconds)
                or not 0 < ttl_seconds <= 300):
            raise ValueError("approval lifetime must be between 0 and 300 seconds")
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("ascii")).digest()
        now = time.monotonic()
        with self._lock:
            self._pending = {key: record for key, record in self._pending.items() if record[2] > now}
            if len(self._pending) >= 1024:
                raise ValueError("too many outstanding approvals")
            self._pending[digest] = (agent_id, capabilities, now + ttl_seconds)
        return token

    def verify(self, token: object, agent_id: str, capabilities: frozenset[str]) -> bool:
        """Check that a token is currently valid without consuming it."""
        if type(token) is not str or len(token) != 43 or not token.isascii():
            return False
        if type(agent_id) is not str or type(capabilities) is not frozenset:
            return False
        if any(type(cap) is not str for cap in capabilities):
            return False
        digest = hashlib.sha256(token.encode("ascii")).digest()
        with self._lock:
            record = self._pending.get(digest)
            if record is None:
                return False
            owner, approved, expires = record
            if expires <= time.monotonic():
                del self._pending[digest]
                return False
            return owner == agent_id and approved == capabilities

    def consume(self, token: object, agent_id: str, capabilities: frozenset[str]) -> bool:
        if type(token) is not str or len(token) != 43 or not token.isascii():
            return False
        if type(agent_id) is not str or type(capabilities) is not frozenset:
            return False
        if any(type(cap) is not str for cap in capabilities):
            return False
        digest = hashlib.sha256(token.encode("ascii")).digest()
        with self._lock:
            record = self._pending.get(digest)
            if record is None:
                return False
            owner, approved, expires = record
            if expires <= time.monotonic():
                del self._pending[digest]
                return False
            if owner != agent_id or approved != capabilities:
                return False
            del self._pending[digest]
            return True
