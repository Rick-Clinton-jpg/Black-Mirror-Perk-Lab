"""Observer-owned run records and launch census.

This recorder neither predicts actions, grants capabilities, nor supplies
agent-facing responses. The observer must call ``begin`` before launching each
execution and keep the resulting files outside the recorder's write authority.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from uuid import UUID

from mirror_world import anchor
from mirror_world.hashchain import ChainVerifier, canonical, seal

_LABEL = re.compile(r"\A[a-z][a-z0-9:_-]{0,63}\Z")
_DIGEST = re.compile(r"\A[0-9a-f]{64}\Z")
_MAX_RUN_BYTES = 1_048_576
_MAX_LINE_BYTES = 8192
_MAX_STEPS = 1000


class RunStoreError(ValueError):
    """A run record is malformed, incomplete for this operation, or altered."""


def _label(value: object, name: str) -> str:
    if type(value) is not str or _LABEL.fullmatch(value) is None:
        raise RunStoreError(f"{name} must be a short lowercase identifier")
    return value


def _run_id(value: object) -> str:
    try:
        if type(value) is str and str(UUID(value)) == value and UUID(value).version == 4:
            return value
    except (ValueError, AttributeError):
        pass
    raise RunStoreError("run_id must be a canonical UUIDv4")


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise RunStoreError(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def _nonfinite(value):
    raise RunStoreError(f"nonfinite JSON value: {value}")


def _decode(raw: bytes) -> dict:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                           parse_constant=_nonfinite)
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise RunStoreError(f"invalid run JSON: {exc}") from exc
    if type(value) is not dict:
        raise RunStoreError("run event must be an object")
    return value


@dataclass(frozen=True)
class Run:
    run_id: str
    model_id: str
    design_known: bool
    steps: tuple[dict, ...]
    status: str
    head: str


class RunStore:
    """One chained JSONL file per independently registered launch.

    The caller, not this class, must control every launch. A recorder that can
    execute without calling ``begin`` can still hide runs. Files are durable
    against ordinary crashes, but their local hash chains need off-host
    checkpoints to detect truncation by the directory owner.
    """

    def __init__(self, root: str | Path, observer_ledger: str | Path):
        self.root = Path(root)
        self.ledger = Path(observer_ledger)
        if not self.root.is_dir() or self.root.is_symlink():
            raise RunStoreError("store must be an existing observer-owned directory")
        if not self.ledger.is_dir() or self.ledger.is_symlink():
            raise RunStoreError("ledger must be an existing observer-owned directory")

    def _path(self, run_id: str) -> Path:
        return self.root / f"{_run_id(run_id)}.jsonl"

    def begin(self, start: dict, registration: dict, *, model_id: str,
              design_known: bool) -> str:
        start = anchor.validate_record(start, kind="start")
        registration = anchor.validate_registration(start, registration)
        run_id = start["run_id"]
        try:
            saved = anchor.load_record(self.ledger / f"{run_id}.registered.json")
        except (OSError, anchor.AnchorError) as exc:
            raise RunStoreError("registration is not retained in the observer ledger") from exc
        if saved != registration:
            raise RunStoreError("registration is not retained in the observer ledger")
        if type(design_known) is not bool:
            raise RunStoreError("design_known must be a boolean")
        event = {"kind": "begin", "run_id": run_id, "model_id": _label(model_id, "model_id"),
                 "design_known": design_known, "start": start, "registration": registration}
        encoded = canonical(seal(event, "0" * 64)) + b"\n"
        path = self._path(run_id)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        return run_id

    def _read(self, path: Path) -> tuple[list[dict], str]:
        if path.is_symlink():
            raise RunStoreError("run file must not be a symlink")
        records = []
        verifier = ChainVerifier()
        size = 0
        with path.open("rb") as stream:
            for raw in stream:
                size += len(raw)
                if len(raw) > _MAX_LINE_BYTES or size > _MAX_RUN_BYTES:
                    raise RunStoreError("run file exceeds size limit")
                event = _decode(raw)
                try:
                    verifier.feed(event)
                except ValueError as exc:
                    raise RunStoreError(f"run chain: {exc}") from exc
                records.append(event)
        if not records:
            raise RunStoreError("empty run file")
        first = records[0]
        if first.get("kind") != "begin" or first.keys() != {"kind", "run_id", "model_id", "design_known", "start", "registration", "previous_hash", "record_hash"}:
            raise RunStoreError("invalid begin event")
        _run_id(first["run_id"])
        if path.stem != first["run_id"]:
            raise RunStoreError("run filename disagrees with record")
        _label(first["model_id"], "model_id")
        if type(first["design_known"]) is not bool:
            raise RunStoreError("invalid design_known value")
        try:
            anchor.validate_registration(first["start"], first["registration"])
        except anchor.AnchorError as exc:
            raise RunStoreError(f"invalid retained run binding: {exc}") from exc
        if first["start"]["run_id"] != first["run_id"]:
            raise RunStoreError("run ID disagrees with anchor")
        try:
            registered = anchor.load_record(self.ledger / f"{first['run_id']}.registered.json")
        except (OSError, anchor.AnchorError) as exc:
            raise RunStoreError("run registration is missing from observer ledger") from exc
        if registered != first["registration"]:
            raise RunStoreError("run registration differs from observer ledger")
        steps = 0
        finished = False
        for event in records[1:]:
            if finished:
                raise RunStoreError("event follows finish")
            if event.get("kind") == "step":
                if event.keys() != {"kind", "seq", "action", "response", "resource_id", "previous_hash", "record_hash"}:
                    raise RunStoreError("invalid step event")
                steps += 1
                if steps > _MAX_STEPS or type(event["seq"]) is not int or event["seq"] != steps:
                    raise RunStoreError("invalid step sequence")
                _label(event["action"], "action")
                _label(event["response"], "response")
                if event["resource_id"] is not None and (type(event["resource_id"]) is not str or len(event["resource_id"]) > 256):
                    raise RunStoreError("invalid resource_id")
            elif event.get("kind") == "finish":
                if event.keys() != {"kind", "status", "detail", "previous_hash", "record_hash"}:
                    raise RunStoreError("invalid finish event")
                if event["status"] not in {"accepted", "aborted"} or type(event["detail"]) is not dict:
                    raise RunStoreError("invalid finish status")
                if event["status"] == "accepted":
                    detail = event["detail"]
                    if detail.keys() != {"trace_sha256", "close_sha256", "receipt_sha256", "trace_count"}:
                        raise RunStoreError("invalid accepted-run detail")
                    if any(type(detail[key]) is not str or _DIGEST.fullmatch(detail[key]) is None
                           for key in ("trace_sha256", "close_sha256", "receipt_sha256")):
                        raise RunStoreError("invalid accepted-run digest")
                    if type(detail["trace_count"]) is not int or detail["trace_count"] < 1:
                        raise RunStoreError("invalid accepted-run detail")
                    try:
                        with (self.ledger / f"{first['run_id']}.accepted.json").open("rb") as stream:
                            raw = stream.read(anchor.MAX_RECORD_BYTES + 1)
                        if len(raw) > anchor.MAX_RECORD_BYTES:
                            raise RunStoreError("observer receipt exceeds size limit")
                        receipt = _decode(raw)
                    except OSError as exc:
                        raise RunStoreError("accepted-run receipt is missing") from exc
                    verification = receipt.get("verification")
                    if (receipt.get("schema") != "black-mirror-observer-receipt-v1"
                            or receipt.get("run_id") != first["run_id"]
                            or receipt.get("registration_sha256") != anchor.record_digest(first["registration"])
                            or receipt.get("close_sha256") != detail["close_sha256"]
                            or hashlib.sha256(canonical(receipt)).hexdigest() != detail["receipt_sha256"]
                            or type(verification) is not dict
                            or verification.get("integrity") != "MATCH"
                            or verification.get("trace_count") != detail["trace_count"]):
                        raise RunStoreError("accepted run disagrees with observer receipt")
                else:
                    if event["detail"].keys() != {"reason"}:
                        raise RunStoreError("invalid aborted-run detail")
                    _label(event["detail"]["reason"], "reason")
                finished = True
            else:
                raise RunStoreError("unknown run event")
        return records, verifier.head

    def load(self, run_id: str) -> Run:
        records, head = self._read(self._path(run_id))
        begin = records[0]
        steps = tuple(event for event in records[1:] if event["kind"] == "step")
        status = records[-1]["status"] if records[-1]["kind"] == "finish" else "open"
        return Run(run_id, begin["model_id"], begin["design_known"], steps, status, head)

    def all_runs(self) -> list[Run]:
        return [self.load(path.stem) for path in sorted(self.root.glob("*.jsonl"))]

    def _append(self, run_id: str, event: dict) -> None:
        # One observer process is the v0 writer. The existing run is reread
        # before append; callers must serialize writes for the same run.
        path = self._path(run_id)
        records, head = self._read(path)
        if records[-1]["kind"] == "finish":
            raise RunStoreError("run is already finished")
        if event["kind"] == "step" and event["seq"] != 1 + sum(r["kind"] == "step" for r in records):
            raise RunStoreError("step sequence changed")
        encoded = canonical(seal(event, head)) + b"\n"
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        with os.fdopen(fd, "ab") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())

    def step(self, run_id: str, *, action: str, response: str,
             resource_id: str | None = None) -> None:
        action, response = _label(action, "action"), _label(response, "response")
        if resource_id is not None and (type(resource_id) is not str or len(resource_id) > 256):
            raise RunStoreError("invalid resource_id")
        run = self.load(run_id)
        if len(run.steps) >= _MAX_STEPS:
            raise RunStoreError("step limit reached")
        self._append(run_id, {"kind": "step", "seq": len(run.steps) + 1, "action": action,
                              "response": response, "resource_id": resource_id})

    def abort(self, run_id: str, *, reason: str) -> None:
        self._append(run_id, {"kind": "finish", "status": "aborted",
                              "detail": {"reason": _label(reason, "reason")}})

    def finish(self, run_id: str, *, trace_path: str | Path, closing: dict) -> dict:
        """Finish only after an observer has accepted this exact close."""
        records, _ = self._read(self._path(run_id))
        start, registration = records[0]["start"], records[0]["registration"]
        receipt_path = self.ledger / f"{run_id}.accepted.json"
        try:
            with receipt_path.open("rb") as stream:
                raw = stream.read(anchor.MAX_RECORD_BYTES + 1)
            if len(raw) > anchor.MAX_RECORD_BYTES:
                raise RunStoreError("receipt exceeds size limit")
            receipt = _decode(raw)
            result = anchor.verify(trace_path, start, closing, registration=registration)
        except (OSError, anchor.AnchorError) as exc:
            raise RunStoreError(f"accepted close is unavailable or invalid: {exc}") from exc
        if result["integrity"] != "MATCH" or receipt.get("schema") != "black-mirror-observer-receipt-v1" or receipt.get("run_id") != run_id or receipt.get("registration_sha256") != anchor.record_digest(registration) or receipt.get("close_sha256") != anchor.record_digest(closing) or receipt.get("verification") != result:
            raise RunStoreError("observer receipt does not match this trace and close")
        detail = {"trace_sha256": anchor.file_digest(trace_path),
                  "close_sha256": anchor.record_digest(closing),
                  "receipt_sha256": hashlib.sha256(canonical(receipt)).hexdigest(),
                  "trace_count": result["trace_count"]}
        self._append(run_id, {"kind": "finish", "status": "accepted", "detail": detail})
        return detail

    def census(self) -> dict:
        runs = self.all_runs()
        counts = Counter(run.status for run in runs)
        run_ids = {run.run_id for run in runs}
        registrations = set()
        for path in self.ledger.glob("*.registered.json"):
            record = anchor.load_record(path)
            if path.name != f"{record['run_id']}.registered.json":
                raise RunStoreError("observer registration filename disagrees with record")
            registrations.add(record["run_id"])
        return {"started": sum(counts.values()), "accepted": counts["accepted"],
                "aborted": counts["aborted"], "open": counts["open"],
                "registrations_without_run": len(registrations - run_ids)}


def tracked_launch(store: RunStore, start: dict, registration: dict, *,
                   model_id: str, design_known: bool, launch) -> dict:
    """Register one execution before invoking a trusted launcher callback.

    ``launch`` receives ``(run_id, store)``. It must record each model choice
    through ``store.step``, return ``(trace_path, closing)``, and arrange for
    observer acceptance of that closing record. Failure is retained as an
    aborted run; abrupt process death leaves a visible open run.
    """
    run_id = store.begin(start, registration, model_id=model_id,
                         design_known=design_known)
    try:
        trace_path, closing = launch(run_id, store)
        return store.finish(run_id, trace_path=trace_path, closing=closing)
    except BaseException:
        if store.load(run_id).status == "open":
            store.abort(run_id, reason="launcher_error")
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Observer-owned launch census")
    parser.add_argument("--store", required=True, help="existing observer-owned run directory")
    parser.add_argument("--ledger", required=True, help="existing observer anchor ledger")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("census", help="count accepted, aborted and open launches")
    args = parser.parse_args(argv)
    try:
        result = RunStore(args.store, args.ledger).census()
    except (RunStoreError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
