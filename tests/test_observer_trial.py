"""The observer loop records a launch before any model-selected action."""

import json

import pytest

from mirror_world import anchor
from mirror_world.hashchain import GENESIS_HASH, seal
from mirror_world.observer_trial import run_observed_trial
from mirror_world.pattern_net import PatternError, PatternStore


def setup_trial(tmp_path):
    ledger = tmp_path / "ledger"
    patterns = tmp_path / "patterns"
    ledger.mkdir()
    patterns.mkdir()
    source = tmp_path / "source.zip"
    config = tmp_path / "config.json"
    source.write_bytes(b"exact source archive")
    config.write_text('{"fixture":"synthetic"}')
    return PatternStore(patterns, ledger), source, config


class FakeSession:
    def __init__(self, tmp_path, start, registration, *, fail_send=False,
                 corrupt_close=False):
        self.tmp_path = tmp_path
        self.start = start
        self.registration = registration
        self.fail_send = fail_send
        self.corrupt_close = corrupt_close
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def send(self, choice):
        if self.fail_send:
            raise RuntimeError("transport failed")
        self.sent.append(choice)
        return {"ok": True, "content": f"reply {len(self.sent)}"}

    def finish(self):
        trace = self.tmp_path / f"{self.start['run_id']}.trace.jsonl"
        events = [anchor.binding_event(self.start, anchor.record_digest(self.start),
                                       self.registration),
                  {"type": "disclosed_fact", "fact": "synthetic trial"}]
        head = GENESIS_HASH
        with trace.open("w") as stream:
            for event in events:
                record = seal(event, head)
                head = record["record_hash"]
                stream.write(json.dumps(record) + "\n")
        closing = anchor.close_record(
            self.start, trace, status="normal",
            checkpoint={"head": head, "count": len(events)},
            registration=self.registration,
        )
        if self.corrupt_close:
            closing = {**closing, "head": "f" * 64}
        return trace, closing


def classify(choice, result):
    return choice["op"], "ok" if result["ok"] else "error", choice.get("resource")


def test_adaptive_choices_are_recorded_before_the_next_choice(tmp_path):
    store, source, config = setup_trial(tmp_path)
    sessions = []

    def launch(start, registration):
        assert (store.ledger / f"{start['run_id']}.registered.json").exists()
        assert store.load(start["run_id"]).status == "open"
        session = FakeSession(tmp_path, start, registration)
        sessions.append(session)
        return session

    def choose(history):
        if not history:
            return {"op": "read_resource", "resource": "notes"}
        run = store.all_runs()[0]
        assert len(run.steps) == len(history)
        if len(history) == 1:
            assert history[0][1]["content"] == "reply 1"
            return {"op": "read_resource", "resource": "next"}
        return None

    result = run_observed_trial(
        store, source_archive=source, config_file=config,
        model_id="gpt-6-sol", design_known=True,
        launch=launch, choose=choose, classify=classify,
    )
    assert result["steps"] == 2
    assert store.census() == {"started": 1, "accepted": 1,
                              "aborted": 0, "open": 0,
                              "registrations_without_run": 0}
    assert [step["resource_id"] for step in store.load(result["run_id"]).steps] == ["notes", "next"]
    assert len(sessions) == 1


@pytest.mark.parametrize("failure", ["transport", "close", "limit"])
def test_failed_trial_remains_in_the_census(tmp_path, failure):
    store, source, config = setup_trial(tmp_path)

    def launch(start, registration):
        return FakeSession(tmp_path, start, registration,
                           fail_send=failure == "transport",
                           corrupt_close=failure == "close")

    def choose(history):
        if failure == "limit" or not history:
            return {"op": "read_resource", "resource": "notes"}
        return None

    with pytest.raises((RuntimeError, PatternError, anchor.AnchorError)):
        run_observed_trial(
            store, source_archive=source, config_file=config,
            model_id="gpt-6-sol", design_known=True,
            launch=launch, choose=choose, classify=classify,
            max_steps=1,
        )
    assert store.census() == {"started": 1, "accepted": 0,
                              "aborted": 1, "open": 0,
                              "registrations_without_run": 0}
