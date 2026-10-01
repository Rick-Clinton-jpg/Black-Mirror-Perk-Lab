"""Import the 2026-10-01 live-trial transcript into an observer Pattern Net store.

This is a historical adapter for the retained experiment format, not a live
launcher. Future executions should call ``tracked_launch`` before they start.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mirror_world import anchor
from mirror_world.pattern_net import PatternStore


def _classify(row: dict) -> tuple[str, str, str | None]:
    command, visible = row["command"], row["agent_visible"]
    if command["seq"] != visible["seq"] or command["kind"] != visible["kind"]:
        raise ValueError("choice and agent-visible response do not align")
    if command["kind"] == "raw":
        action = "raw_" + command["probe"]
        response = "sigsys" if visible.get("terminated_by_signal") == 31 else "raw_other"
        return action, response, None
    if command["kind"] != "action" or len(visible["responses"]) != 1:
        raise ValueError("unsupported transcript action")
    request, reply = command["request"], visible["responses"][0]
    action, resource = request["op"], request.get("resource")
    if reply.get("ok") is True:
        response = "apparent_grant" if reply.get("granted") is True else "ok"
    else:
        response = reply.get("error", "error").replace(" ", "_")
    return action, response, resource


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--store", type=Path, required=True,
                        help="existing observer-owned Pattern Net directory")
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--design-known", action="store_true")
    args = parser.parse_args(argv)
    evidence = args.evidence_dir
    start = anchor.load_record(evidence / "retained-start.json")
    registration = anchor.load_record(evidence / "observer-ledger" /
                                      f"{start['run_id']}.registered.json")
    closing = anchor.load_record(evidence / "close.json")
    transcript = json.loads((evidence / "transcript.json").read_text())
    if type(transcript) is not list:
        raise ValueError("transcript must be a list")
    store = PatternStore(args.store, evidence / "observer-ledger")
    run_id = store.begin(start, registration, model_id=args.model_id,
                         design_known=args.design_known)
    for index, row in enumerate(transcript, 1):
        if row["command"]["seq"] != index:
            raise ValueError("transcript sequence is not contiguous")
        action, response, resource = _classify(row)
        store.step(run_id, action=action, response=response, resource_id=resource)
    store.finish(run_id, trace_path=evidence / "trace.jsonl", closing=closing)
    print(json.dumps({"run_id": run_id, "steps": len(transcript),
                      "census": store.census()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
