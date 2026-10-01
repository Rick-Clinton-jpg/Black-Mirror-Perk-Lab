"""Manual, independently retained checkpoints for research traces.

The observer registers starts and accepts at most one close per registration.
The recorder has no observer credentials. Retention cannot prove recorder truth.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sys
from uuid import UUID, uuid4

from mirror_world.hashchain import GENESIS_HASH, ChainError, ChainVerifier, canonical

SCHEMA = "black-mirror-anchor-v2"
_HASH = re.compile(r"\A[0-9a-f]{64}\Z")
_COMMON = {"schema", "kind", "run_id", "source_sha256", "config_sha256", "count", "head", "status"}
_SOURCE_BINDING = {"run_id", "source_sha256", "config_sha256", "start_sha256"}
_BINDING = _SOURCE_BINDING | {"observer_nonce", "registration_sha256"}
MAX_RECORD_BYTES = 4096
MAX_LINE_CHARS = 1_048_576
MAX_TRACE_CHARS = 16 * MAX_LINE_CHARS
MAX_EVENTS = 100_000


class AnchorError(ValueError):
    """An anchor, run binding, or trace cannot be verified."""


def _hash(value: object) -> bool:
    return type(value) is str and _HASH.fullmatch(value) is not None


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AnchorError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _nonfinite(value):
    raise AnchorError(f"nonfinite JSON value: {value}")


def _decode(text: str):
    try:
        return json.loads(text, object_pairs_hook=_unique, parse_constant=_nonfinite)
    except (ValueError, TypeError, RecursionError) as exc:
        raise AnchorError(f"invalid JSON: {exc}") from exc


def validate_binding(event: dict) -> None:
    try:
        run_id = event["run_id"]
        valid_id = type(run_id) is str and str(UUID(run_id)) == run_id and UUID(run_id).version == 4
    except (KeyError, ValueError, AttributeError):
        valid_id = False
    if not valid_id or any(not _hash(event.get(key)) for key in _SOURCE_BINDING - {"run_id"}):
        raise AnchorError("invalid run ID or binding digest")
    if event.get("type") == "run_start" and any(not _hash(event.get(key)) for key in ("observer_nonce", "registration_sha256")):
        raise AnchorError("invalid observer nonce or registration digest")


def validate_record(record: object, *, kind: str | None = None) -> dict:
    if type(record) is not dict or type(record.get("kind")) is not str or record["kind"] not in {"start", "registration", "close"}:
        raise AnchorError("expected a start, registration or close anchor object")
    expected = _COMMON | ({"start_sha256", "observer_nonce"} if record["kind"] != "start" else set())
    if record["kind"] == "close":
        expected |= {"registration_sha256"}
    if record.keys() != expected or record.get("schema") != SCHEMA:
        raise AnchorError("unknown schema or anchor fields")
    if any(type(value) is not str for key, value in record.items() if key != "count"):
        raise AnchorError("anchor fields other than count must be strings")
    if kind is not None and record["kind"] != kind:
        raise AnchorError(f"expected a {kind} anchor")
    validate_binding({**record, "start_sha256": record.get("start_sha256", GENESIS_HASH)})
    if not _hash(record["head"]) or type(record["count"]) is not int or not 0 <= record["count"] <= MAX_EVENTS:
        raise AnchorError("invalid checkpoint head or count")
    if record["kind"] == "start":
        if record["count"] != 0 or record["head"] != GENESIS_HASH or record["status"] != "started":
            raise AnchorError("start anchor must have the genesis checkpoint and started status")
    elif record["kind"] == "registration":
        if record["count"] != 0 or record["head"] != GENESIS_HASH or record["status"] != "registered" or not _hash(record["observer_nonce"]):
            raise AnchorError("invalid observer registration")
    elif not _hash(record["observer_nonce"]) or not _hash(record["registration_sha256"]) or record["count"] < 1 or record["status"] not in {"normal", "early"}:
        raise AnchorError("close anchor needs a nonempty trace and normal or early status")
    return dict(record)


def record_digest(record: dict) -> str:
    return hashlib.sha256(canonical(validate_record(record))).hexdigest()


def file_digest(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def start_record(source_sha256: str, config_sha256: str) -> dict:
    return validate_record({
        "schema": SCHEMA, "kind": "start", "run_id": str(uuid4()),
        "source_sha256": source_sha256, "config_sha256": config_sha256,
        "count": 0, "head": GENESIS_HASH, "status": "started",
    })


def validate_registration(start: dict, registration: dict) -> dict:
    start = validate_record(start, kind="start")
    registration = validate_record(registration, kind="registration")
    if any(registration[key] != start[key] for key in ("run_id", "source_sha256", "config_sha256")):
        raise AnchorError("registration belongs to a different run")
    if not hmac.compare_digest(registration["start_sha256"], record_digest(start)):
        raise AnchorError("registration does not bind the retained start record")
    return registration


def registration_record(start: dict) -> dict:
    """Observer-only: issue an unpredictable challenge after retaining a start."""
    start = validate_record(start, kind="start")
    return validate_record({**start, "kind": "registration", "status": "registered",
                            "start_sha256": record_digest(start), "observer_nonce": secrets.token_hex(32)})


def register_start(start: dict, ledger: str | Path) -> dict:
    """Observer-only: reserve this run ID once in a trusted existing directory."""
    record = registration_record(start)
    write_record(Path(ledger) / f"{record['run_id']}.registered.json", record)
    return record


def binding_event(start: dict, observer_start_digest: str, registration: dict | None = None) -> dict:
    start = validate_record(start, kind="start")
    digest = record_digest(start)
    if not _hash(observer_start_digest) or not hmac.compare_digest(digest, observer_start_digest):
        raise AnchorError("observer acknowledgment must match the full start-record digest")
    if registration is None:
        raise AnchorError("observer-issued registration is required")
    registration = validate_registration(start, registration)
    return {"type": "run_start", **{key: start[key] for key in _SOURCE_BINDING - {"start_sha256"}},
            "start_sha256": digest, "observer_nonce": registration["observer_nonce"],
            "registration_sha256": record_digest(registration)}


def load_record(path: str | Path) -> dict:
    with open(path, "rb") as stream:
        raw = stream.read(MAX_RECORD_BYTES + 1)
    if len(raw) > MAX_RECORD_BYTES:
        raise AnchorError("anchor exceeds size limit")
    try:
        return validate_record(_decode(raw.decode("utf-8")))
    except UnicodeError as exc:
        raise AnchorError("anchor must be UTF-8") from exc


def write_record(path: str | Path, record: dict) -> None:
    """Create a private local copy; refuse replacement or following a symlink.

    Exclusive creation is convenience, not an append-only observer boundary:
    the owner of this local directory can still edit or delete the file.
    """
    encoded = canonical(validate_record(record)) + b"\n"
    _write_exclusive(path, encoded)


def _write_exclusive(path, encoded):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    parent_fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _scan(trace_path: str | Path, start: dict, registration: dict, anchored_count: int) -> tuple[str, int, str | None]:
    # The same closed event schema as the invariant parser; integrity checking
    # does not establish semantic validity of the graph or its observations.
    from mirror_world.trace import _validate_event

    expected_binding = binding_event(start, record_digest(start), registration)
    verifier = ChainVerifier()
    prefix_head = GENESIS_HASH if anchored_count == 0 else None
    total = 0
    try:
        with open(trace_path, encoding="utf-8") as stream:
            while True:
                raw = stream.readline(MAX_LINE_CHARS + 1)
                if not raw:
                    break
                total += len(raw)
                if len(raw) > MAX_LINE_CHARS or total > MAX_TRACE_CHARS:
                    raise AnchorError("trace exceeds size limits")
                if not raw.strip():
                    continue
                if verifier.count >= MAX_EVENTS:
                    raise AnchorError("trace exceeds event limit")
                event = _decode(raw)
                _validate_event(event)
                verifier.feed(event)
                if verifier.count == 1:
                    binding = {k: v for k, v in event.items() if k not in {"previous_hash", "record_hash"}}
                    if event["type"] != "run_start":
                        raise AnchorError("no run binding (pre-anchor format)")
                    if binding != expected_binding:
                        raise AnchorError("first event does not bind the retained start record")
                elif event["type"] == "run_start":
                    raise AnchorError("duplicate run_start event")
                if verifier.count == anchored_count:
                    prefix_head = verifier.head
    except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
        raise AnchorError(str(exc)) from exc
    return verifier.head, verifier.count, prefix_head


def close_record(start: dict, trace_path: str | Path, *, status: str, checkpoint: dict, registration: dict | None = None) -> dict:
    """Close against the writer's checkpoint, captured after requests stop.

    The caller must retain the returned record independently. Deriving the
    expected checkpoint only from the trace would miss prior tail truncation.
    """
    start = validate_record(start, kind="start")
    registration = validate_registration(start, registration)
    if type(checkpoint) is not dict or checkpoint.keys() != {"head", "count"}:
        raise AnchorError("expected writer checkpoint with exactly head and count")
    record = validate_record({**start, "kind": "close", "status": status,
                              **checkpoint, "start_sha256": record_digest(start),
                              "observer_nonce": registration["observer_nonce"],
                              "registration_sha256": record_digest(registration)})
    head, count, _ = _scan(trace_path, start, registration, record["count"])
    if count != record["count"] or not hmac.compare_digest(head, record["head"]):
        raise AnchorError("trace differs from the writer's closing checkpoint")
    return record


def verify(trace_path: str | Path, start: dict, closing: dict | None = None, *, registration: dict | None = None) -> dict:
    start = validate_record(start, kind="start")
    registration = validate_registration(start, registration)
    anchor = start
    completion = "NO_CLOSING_RECORD"
    if closing is not None:
        anchor = validate_record(closing, kind="close")
        if any(anchor[key] != start[key] for key in ("run_id", "source_sha256", "config_sha256")):
            raise AnchorError("closing record belongs to a different run")
        if not hmac.compare_digest(anchor["start_sha256"], record_digest(start)):
            raise AnchorError("closing record does not bind the retained start record")
        if anchor["observer_nonce"] != registration["observer_nonce"] or anchor["registration_sha256"] != record_digest(registration):
            raise AnchorError("closing record does not bind the retained registration")
        completion = "DECLARED_NORMAL" if anchor["status"] == "normal" else "DECLARED_EARLY"
    head, count, prefix = _scan(trace_path, start, registration, anchor["count"])
    if count < anchor["count"]:
        integrity = "TRUNCATED"
    elif not hmac.compare_digest(prefix, anchor["head"]):
        integrity = "HEAD_MISMATCH"
    elif count > anchor["count"]:
        integrity = "UNANCHORED_TAIL"
    else:
        integrity = "MATCH"
    return {"run_id": start["run_id"], "integrity": integrity, "completion": completion,
            "anchored_count": anchor["count"], "trace_count": count, "trace_head": head,
            "unanchored_events": max(0, count - anchor["count"]),
            "coverage_note": ("Start/registration authenticate the run binding only; no body events are externally anchored. Tail truncation cannot be detected without a close."
                              if closing is None else "The retained close anchors the prefix through anchored_count."),
            "registration_sha256": record_digest(registration)}


def accept_close(trace_path: str | Path, start: dict, closing: dict, ledger: str | Path) -> dict:
    """Observer-only: persist at most one matching closing submission per run ID.

    This rejects duplicate submissions even after restart. It cannot prevent
    hidden recorder retries using the same challenge before the first submission.
    """
    start = validate_record(start, kind="start")
    ledger = Path(ledger)
    registration = load_record(ledger / f"{start['run_id']}.registered.json")
    result = verify(trace_path, start, closing, registration=registration)
    if result["integrity"] != "MATCH" or result["completion"] == "NO_CLOSING_RECORD":
        raise AnchorError("observer accepts only a matching closed trace")
    receipt = {"schema": "black-mirror-observer-receipt-v1", "run_id": start["run_id"],
               "registration_sha256": record_digest(registration), "close_sha256": record_digest(closing),
               "verification": result}
    _write_exclusive(ledger / f"{start['run_id']}.accepted.json", canonical(receipt) + b"\n")
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("start", help="create a local start record before the run")
    create.add_argument("--source", required=True, help="exact source archive to hash")
    create.add_argument("--config", required=True, help="exact experiment config file to hash")
    create.add_argument("--output", required=True)
    register = commands.add_parser("register", help="observer-only: retain a start and issue a nonce once")
    register.add_argument("--start", required=True)
    register.add_argument("--ledger", required=True, help="trusted existing observer directory")
    accept = commands.add_parser("accept", help="observer-only: accept a matching close once")
    accept.add_argument("--start", required=True)
    accept.add_argument("--close", required=True)
    accept.add_argument("--trace", required=True)
    accept.add_argument("--ledger", required=True)
    close = commands.add_parser("close", help="create a local closing record after requests stop")
    close.add_argument("--start", required=True)
    close.add_argument("--registration", required=True)
    close.add_argument("--trace", required=True)
    close.add_argument("--checkpoint", required=True, help="writer checkpoint JSON: head and count")
    close.add_argument("--status", choices=("normal", "early"), required=True)
    close.add_argument("--output", required=True)
    check = commands.add_parser("verify", help="verify using independently retained records")
    check.add_argument("--registration", required=True)
    check.add_argument("--start", required=True)
    check.add_argument("--close")
    check.add_argument("--trace", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "start":
            record = start_record(file_digest(args.source), file_digest(args.config))
        elif args.command == "register":
            record = register_start(load_record(args.start), args.ledger)
            print(json.dumps({"registration": record, "record_sha256": record_digest(record)}, sort_keys=True))
            return 0
        elif args.command == "accept":
            receipt = accept_close(args.trace, load_record(args.start), load_record(args.close), args.ledger)
            print(json.dumps(receipt, sort_keys=True))
            return 0
        elif args.command == "close":
            with open(args.checkpoint, "rb") as stream:
                raw = stream.read(MAX_RECORD_BYTES + 1)
            if len(raw) > MAX_RECORD_BYTES:
                raise AnchorError("checkpoint exceeds size limit")
            record = close_record(load_record(args.start), args.trace, status=args.status,
                                  checkpoint=_decode(raw.decode("utf-8")), registration=load_record(args.registration))
        else:
            result = verify(args.trace, load_record(args.start), load_record(args.close) if args.close else None, registration=load_record(args.registration))
            print(json.dumps(result, sort_keys=True))
            if result["integrity"] in {"TRUNCATED", "HEAD_MISMATCH"}:
                return 1
            return 0 if result["integrity"] == "MATCH" and result["completion"] == "DECLARED_NORMAL" else 3
        write_record(args.output, record)
        print(json.dumps({"record": str(args.output), "record_sha256": record_digest(record)}, sort_keys=True))
        return 0
    except (AnchorError, OSError, UnicodeError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
