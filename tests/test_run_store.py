"""Observer census and accepted, aborted, open launch records."""

import json

import pytest

from mirror_world import anchor
from mirror_world.hashchain import GENESIS_HASH, seal
from mirror_world.run_store import RunStoreError, RunStore, tracked_launch


def accepted_run(tmp_path, *, model="gpt-6-sol", design_known=True,
                 actions=(("read_resource", "ok", "notes"),
                          ("read_resource", "resource_unavailable", "unseen"))):
    ledger = tmp_path / "ledger"
    store_dir = tmp_path / "patterns"
    ledger.mkdir(exist_ok=True)
    store_dir.mkdir(exist_ok=True)
    start = anchor.start_record("a" * 64, "b" * 64)
    registration = anchor.register_start(start, ledger)
    store = RunStore(store_dir, ledger)
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


def test_census_records_open_aborted_and_accepted_runs(tmp_path):
    store, run_id, *_ = accepted_run(tmp_path)
    assert store.census() == {"started": 1, "accepted": 1, "aborted": 0,
                              "open": 0, "registrations_without_run": 0}
    start = anchor.start_record("a" * 64, "b" * 64)
    registration = anchor.register_start(start, tmp_path / "ledger")
    assert store.census()["registrations_without_run"] == 1
    open_id = store.begin(start, registration, model_id="gpt-6-sol", design_known=True)
    assert store.census()["open"] == 1
    store.abort(open_id, reason="launcher_error")
    assert store.census() == {"started": 2, "accepted": 1, "aborted": 1,
                              "open": 0, "registrations_without_run": 0}
    with pytest.raises(RunStoreError, match="already finished"):
        store.step(run_id, action="read_resource", response="ok")


def test_registration_and_receipt_are_required(tmp_path):
    store, run_id, start, registration, trace, closing = accepted_run(tmp_path)
    with pytest.raises(FileExistsError):
        store.begin(start, registration, model_id="gpt-6-sol", design_known=True)
    other = anchor.start_record("a" * 64, "b" * 64)
    with pytest.raises(RunStoreError, match="registration is not retained"):
        store.begin(other, anchor.registration_record(other), model_id="gpt-6-sol",
                    design_known=True)
    (tmp_path / "ledger" / f"{run_id}.accepted.json").unlink()
    with pytest.raises(RunStoreError, match="accepted-run receipt is missing"):
        store.finish(run_id, trace_path=trace, closing=closing)


def test_tampered_or_truncated_run_is_rejected(tmp_path):
    store, run_id, *_ = accepted_run(tmp_path)
    path = tmp_path / "patterns" / f"{run_id}.jsonl"
    original = path.read_text()
    path.write_text(original.replace('"read_resource"', '"write_resource"', 1))
    with pytest.raises(RunStoreError, match="run chain"):
        store.load(run_id)
    path.write_text("\n".join(original.splitlines()[:-1]) + "\n")
    assert store.load(run_id).status == "open"
    # A local chain cannot detect tail truncation without an external head.






def test_tracked_launcher_records_failure_before_any_agent_result(tmp_path):
    ledger = tmp_path / "ledger"
    store_dir = tmp_path / "patterns"
    ledger.mkdir()
    store_dir.mkdir()
    start = anchor.start_record("a" * 64, "b" * 64)
    registration = anchor.register_start(start, ledger)
    store = RunStore(store_dir, ledger)

    def launch(run_id, writer):
        writer.step(run_id, action="read_resource", response="ok")
        raise RuntimeError("VM stopped")

    with pytest.raises(RuntimeError, match="VM stopped"):
        tracked_launch(store, start, registration, model_id="gpt-6-sol",
                       design_known=True, launch=launch)
    assert store.census() == {"started": 1, "accepted": 0, "aborted": 1,
                              "open": 0, "registrations_without_run": 0}


def test_census_cli_and_no_prediction_command(tmp_path, capsys):
    from mirror_world.run_store import main

    store, *_ = accepted_run(tmp_path)
    args = ["--store", str(store.root), "--ledger", str(store.ledger)]
    assert main(args + ["census"]) == 0
    assert json.loads(capsys.readouterr().out) == store.census()
    with pytest.raises(SystemExit) as exc:
        main(args + ["predict"])
    assert exc.value.code == 2
