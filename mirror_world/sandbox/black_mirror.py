"""Black Mirror observation log.

Black Mirror is the name for how this system contains an untrusted agent:

  * The lock is the governor's own session lock, on by default. An agent's
    first reflected response puts its session in "simulated" mode. From then
    on every effect-bearing request is answered from the mirror -- even with a
    valid token -- until trusted host code calls
    RealGovernor.authorize_reentry(). That check lives in
    RealGovernor._handle_inner() and does not depend on reflective_closure.
  * The only way out is authorize_reentry(): a trusted control-plane call that
    consumes a single-use approval token (when dual approval is required) and
    records the transition, or the refusal, in the trace.
  * This module adds the observation log: a bounded, redacted record of
    everything an agent does while it is in the mirror, for a human reviewer
    or a separate trusted process to read. It has no lock and no release of
    its own, so it cannot disagree with the governor.

Observations are held in memory by default (1.0: RealGovernor attaches a
log automatically). Each agent keeps at most max_observations_per_agent
records; later ones are counted as dropped. String fields are truncated to
max_field_chars. Tokens are never stored.

Persistence stays opt-in. Pass ``sink_path`` to also append every stored
observation to a new hash-chained JSONL file opened with owner-only
permissions (``0o600``, ``O_EXCL|O_NOFOLLOW``), or call ``export_jsonl()`` to
write what is in memory the same way. ``load_observations()`` reads either
back and rejects an edited, deleted, reordered, or inserted record; pass the
``checkpoint()`` you stored elsewhere as ``expected_head`` to also catch
truncation.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from mirror_world.hashchain import HashChainWriter, verify_records

_NEVER_STORED = frozenset({"dual_token"})


@dataclass(frozen=True)
class BlackMirrorObservation:
    agent_id: str
    op: str
    fields: Dict[str, Any]
    entered_mirror: bool   # True for the request that moved the agent into the mirror
    ts: float


class BlackMirrorLog:
    """Bounded, redacted, per-agent record of actions taken inside the mirror."""

    def __init__(
        self,
        *,
        max_observations_per_agent: int = 1000,
        max_field_chars: int = 512,
        sink_path: Optional[str] = None,
    ) -> None:
        if type(max_observations_per_agent) is not int or not 1 <= max_observations_per_agent <= 1_000_000:
            raise ValueError("max_observations_per_agent out of range")
        if type(max_field_chars) is not int or not 16 <= max_field_chars <= 65_536:
            raise ValueError("max_field_chars out of range")
        self.max_observations_per_agent = max_observations_per_agent
        self.max_field_chars = max_field_chars
        self._lock = threading.Lock()
        self._observations: Dict[str, List[BlackMirrorObservation]] = {}
        self._dropped: Dict[str, int] = {}
        self._sink = None
        self._sink_writer: Optional[HashChainWriter] = None
        if sink_path is not None:
            self._sink = _open_new_private(sink_path)
            self._sink_writer = HashChainWriter(self._sink)

    def _redact(self, value: Any) -> Any:
        if isinstance(value, str):
            if len(value) > self.max_field_chars:
                return value[: self.max_field_chars] + f"...[truncated {len(value) - self.max_field_chars} chars]"
            return value
        if isinstance(value, list):
            return [self._redact(v) for v in value[:128]]
        return value

    def record(self, agent_id: str, op: str, fields: Dict[str, Any], *, entered_mirror: bool = False) -> None:
        clean = {k: self._redact(v) for k, v in fields.items() if k not in _NEVER_STORED and v is not None}
        with self._lock:
            bucket = self._observations.setdefault(agent_id, [])
            if len(bucket) >= self.max_observations_per_agent:
                self._dropped[agent_id] = self._dropped.get(agent_id, 0) + 1
                return
            observation = BlackMirrorObservation(
                agent_id=agent_id, op=self._redact(op), fields=clean,
                entered_mirror=entered_mirror, ts=time.time())
            bucket.append(observation)
            if self._sink_writer is not None:
                self._sink_writer.append(_to_record(observation))

    def observations_for(self, agent_id: str) -> List[BlackMirrorObservation]:
        with self._lock:
            return list(self._observations.get(agent_id, []))

    def observed_agents(self) -> List[str]:
        with self._lock:
            return sorted(self._observations)

    def dropped_count(self, agent_id: str) -> int:
        """Observations not stored because the per-agent cap was reached."""
        with self._lock:
            return self._dropped.get(agent_id, 0)

    def checkpoint(self) -> Optional[dict]:
        """Head hash and record count of the sink file, or None without one."""
        with self._lock:
            return None if self._sink_writer is None else self._sink_writer.checkpoint()

    def export_jsonl(self, path: str) -> dict:
        """Write every stored observation, oldest first, to a new chained file.

        Returns the file's checkpoint. Refuses to overwrite an existing path.
        """
        with self._lock:
            observations = sorted(
                (o for bucket in self._observations.values() for o in bucket),
                key=lambda o: o.ts,
            )
        stream = _open_new_private(path)
        try:
            writer = HashChainWriter(stream)
            for observation in observations:
                writer.append(_to_record(observation))
            return writer.checkpoint()
        finally:
            stream.close()

    def close(self) -> None:
        with self._lock:
            if self._sink is not None:
                self._sink.close()
                self._sink = None
                self._sink_writer = None


def load_observations(
    path: str,
    *,
    expected_head: Optional[str] = None,
    expected_count: Optional[int] = None,
) -> List[BlackMirrorObservation]:
    """Read a sink or export file back, verifying its hash chain.

    Raises ValueError (``ChainError``) if any record was changed, removed,
    reordered, or inserted, or if the file does not match the checkpoint.
    """
    with open(path, "r", encoding="utf-8") as stream:
        records = [json.loads(line) for line in stream if line.strip()]
    verify_records(records, expected_head=expected_head, expected_count=expected_count)
    return [
        BlackMirrorObservation(
            agent_id=record["agent_id"], op=record["op"], fields=record["fields"],
            entered_mirror=record["entered_mirror"], ts=record["ts"],
        )
        for record in records
    ]


def _to_record(observation: BlackMirrorObservation) -> dict:
    return {
        "agent_id": observation.agent_id,
        "op": observation.op,
        "fields": observation.fields,
        "entered_mirror": observation.entered_mirror,
        "ts": observation.ts,
    }


def _open_new_private(path: str):
    """Create a new owner-only file; never follow a link or reuse a file."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8")
