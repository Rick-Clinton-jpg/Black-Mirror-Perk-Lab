"""Hash-chained JSONL records, adapted from Moss 7.1.1 ``TraceChain``.

Every record carries ``previous_hash`` (the ``record_hash`` of the record
before it, or ``GENESIS_HASH`` for the first) and ``record_hash`` (SHA-256 of
the record's canonical JSON with ``record_hash`` removed). Editing, deleting,
reordering, or inserting a record breaks the chain.

A chain on its own cannot show that records were removed from the *end*. The
writer therefore keeps an in-memory checkpoint (head hash and record count),
as Moss V7.1.1 does, so a running authority can detect truncation of its own
file; for detection after the process ends, the head must be stored somewhere
the host cannot rewrite.

Differences from Moss: the writer keeps the head in memory instead of re-reading
the whole file on every append, and verification is incremental so the trace
parser can check the chain while it validates each event.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Iterable, Mapping

GENESIS_HASH = "0" * 64
CHAIN_FIELDS = frozenset({"previous_hash", "record_hash"})
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


class ChainError(ValueError):
    """A record does not continue the chain it claims to belong to."""


def canonical(record: Mapping[str, object]) -> bytes:
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def record_digest(record: Mapping[str, object]) -> str:
    """SHA-256 over the record without its ``record_hash`` field."""
    body = {key: value for key, value in record.items() if key != "record_hash"}
    return hashlib.sha256(canonical(body)).hexdigest()


def seal(record: Mapping[str, object], previous_hash: str) -> dict:
    """Return a copy of ``record`` linked to ``previous_hash``."""
    if CHAIN_FIELDS & record.keys():
        raise ChainError("record already carries chain fields")
    if not _HEX64.match(previous_hash):
        raise ChainError("previous_hash must be 64 lowercase hex characters")
    sealed = dict(record)
    sealed["previous_hash"] = previous_hash
    sealed["record_hash"] = record_digest(sealed)
    return sealed


class ChainVerifier:
    """Checks records one at a time, in order."""

    def __init__(self) -> None:
        self.head = GENESIS_HASH
        self.count = 0

    def feed(self, record: Mapping[str, object]) -> None:
        previous = record.get("previous_hash")
        claimed = record.get("record_hash")
        if type(previous) is not str or type(claimed) is not str:
            raise ChainError("record is missing chain fields")
        if not _HEX64.match(previous) or not _HEX64.match(claimed):
            raise ChainError("chain fields must be 64 lowercase hex characters")
        if not hmac.compare_digest(previous, self.head):
            raise ChainError("record does not follow the previous record")
        if not hmac.compare_digest(claimed, record_digest(record)):
            raise ChainError("record content does not match its hash")
        self.head = claimed
        self.count += 1


def verify_records(
    records: Iterable[Mapping[str, object]],
    *,
    expected_head: str | None = None,
    expected_count: int | None = None,
) -> tuple[str, int]:
    """Verify a whole chain; return its head hash and record count."""
    verifier = ChainVerifier()
    for record in records:
        verifier.feed(record)
    check_checkpoint(verifier.head, verifier.count, expected_head, expected_count)
    return verifier.head, verifier.count


def check_checkpoint(
    head: str, count: int, expected_head: str | None, expected_count: int | None
) -> None:
    if expected_head is not None and not hmac.compare_digest(head, expected_head):
        raise ChainError("chain head does not match the recorded checkpoint")
    if expected_count is not None and count != expected_count:
        raise ChainError("record count does not match the recorded checkpoint")


class HashChainWriter:
    """Append-only chained JSONL writer with an in-memory checkpoint.

    The caller owns the text stream and any locking. ``append`` writes one
    line and flushes; ``fsync`` makes each append durable at extra cost.
    """

    def __init__(self, stream, *, fsync: bool = False) -> None:
        self._stream = stream
        self._fsync = fsync
        self.head = GENESIS_HASH
        self.count = 0

    def append(self, record: Mapping[str, object]) -> dict:
        sealed = seal(record, self.head)
        self._stream.write(json.dumps(sealed) + "\n")
        self._stream.flush()
        if self._fsync:
            import os

            os.fsync(self._stream.fileno())
        self.head = sealed["record_hash"]
        self.count += 1
        return sealed

    def checkpoint(self) -> dict:
        return {"head": self.head, "count": self.count}
