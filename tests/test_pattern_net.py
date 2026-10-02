"""Observer census, cross-run forecasts, and simulated-response consistency."""

import json

import pytest

from mirror_world import anchor
from mirror_world.hashchain import GENESIS_HASH, seal
from mirror_world.pattern_net import (
    PatternError, PatternStore, evaluate_leave_one_run_out,
    plan_read_response, predict_next, tracked_launch,
)


def accepted_run(tmp_path, *, model="gpt-6-sol", design_known=True,
                 actions=(("read_resource", "ok", "notes"),
                          ("read_resource", "resource_unavailable", "unseen"))):
    ledger = tmp_path / "ledger"
    store_dir = tmp_path / "patterns"
    ledger.mkdir(exist_ok=True)
    store_dir.mkdir(exist_ok=True)
    start = anchor.start_record("a" * 64, "b" * 64)
    registration = anchor.register_start(start, ledger)
    store = PatternStore(store_dir, ledger)
    run_id = store.begin(start, registration, model_id=model,
                         design_known=design_known)
    for action, response, resource in actions:
        store.step(run_id, action=action, response=response, resource_id=resource)
    trace = tmp_path / f"{run_id}.trace.jsonl"
    head = GENESIS_HASH
    records = []
    for event in (anchor.binding_event(start, anchor.record_digest(start), registration),
                  {"type": "disclosed_fact", "fact": "synthetic trial"}):
        record = seal(event, head)
        head = record["record_hash"]
        records.append(record)
    trace.write_text("".join(json.dumps(item) + "\n" for item in records))
    closing = anchor.close_record(start, trace, status="normal",
                                  checkpoint={"head": head, "count": len(records)},
                                  registration=registration)
    anchor.accept_close(trace, start, closing, ledger)
    store.finish(run_id, trace_path=trace, closing=closing)
    return store, run_id, start, registration, trace, closing






    # A local chain cannot detect tail truncation without an external head.


def test_prediction_needs_distinct_accepted_runs_and_held_out_evaluation(tmp_path):
    runs = []
    for i in range(4):
        folder = tmp_path / str(i)
        folder.mkdir()
        store, *_ = accepted_run(folder)
        runs.extend(store.all_runs())
    forecast = predict_next(runs[:1], model_id="gpt-6-sol", design_known=True,
                            last_action="read_resource", last_response="ok")
    assert forecast["status"] == "insufficient_runs"
    forecast = predict_next(runs, model_id="gpt-6-sol", design_known=True,
                            last_action="read_resource", last_response="ok")
    assert forecast["status"] == "prediction"
    assert forecast["supporting_launches"] == 4
    assert forecast["ranked_actions"][0]["action"] == "read_resource"
    score = evaluate_leave_one_run_out(runs)
    assert score["held_out_decisions"] == 8
    assert score["covered_decisions"] == 8
    assert score["top1_accuracy_when_covered"] == 1.0


def test_frozen_snapshot_and_overlay_never_guess_unknown_contents():
    snapshot = {"notes": "Revision A"}
    assert plan_read_response("notes", snapshot)["candidate_response"]["content"] == "Revision A"
    assert plan_read_response("notes", snapshot, {"notes": "Simulated revision"})["candidate_response"]["content"] == "Simulated revision"
    assert plan_read_response("unseen", snapshot)["status"] == "missing_fixture"
