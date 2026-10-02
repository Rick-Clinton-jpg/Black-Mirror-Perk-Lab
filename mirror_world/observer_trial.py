"""Observer-owned launch loop for recorded research trials.

The caller supplies the model and a single-execution transport. This module
keeps the observer ledger outside that transport and records every observed
choice before asking the model for another one. It does not control a model
provider or authorize agent actions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from mirror_world import anchor
from mirror_world.run_store import RunStoreError, RunStore


def run_observed_trial(
    store: RunStore,
    *,
    source_archive: str | Path,
    config_file: str | Path,
    model_id: str,
    design_known: bool,
    launch: Callable,
    choose: Callable,
    classify: Callable,
    max_steps: int = 100,
) -> dict:
    """Run one registered execution through an observer-owned model loop.

    ``launch(start, registration)`` returns a context manager whose session
    implements ``send(choice) -> agent_visible_result`` and
    ``finish() -> (trace_path, closing_record)``. ``choose(history)`` sees only
    prior choices and agent-visible results and returns the next choice, or
    ``None`` to stop. ``classify(choice, result)`` returns normalized
    ``(action, response, resource_id)`` labels for the observer record.

    The transport must launch only once, never retry privately, and keep its
    agent/recorder from writing the observer ledger or run store.
    """
    if type(max_steps) is not int or not 1 <= max_steps <= 1000:
        raise RunStoreError("max_steps must be between 1 and 1000")
    start = anchor.start_record(anchor.file_digest(source_archive),
                                anchor.file_digest(config_file))
    registration = anchor.register_start(start, store.ledger)
    run_id = store.begin(start, registration, model_id=model_id,
                         design_known=design_known)
    accepted = False
    history: list[tuple[dict, dict]] = []
    try:
        with launch(start, registration) as session:
            while True:
                choice = choose(tuple(history))
                if choice is None:
                    break
                if len(history) >= max_steps:
                    raise RunStoreError("trial step limit reached")
                if type(choice) is not dict:
                    raise RunStoreError("model choice must be an object")
                result = session.send(choice)
                if type(result) is not dict:
                    raise RunStoreError("transport result must be an object")
                action, response, resource_id = classify(choice, result)
                store.step(run_id, action=action, response=response,
                           resource_id=resource_id)
                history.append((choice, result))
            trace_path, closing = session.finish()
        receipt = anchor.accept_close(trace_path, start, closing, store.ledger)
        accepted = True
        store.finish(run_id, trace_path=trace_path, closing=closing)
        return {"run_id": run_id, "steps": len(history), "receipt": receipt}
    except BaseException:
        # A crash before an accepted close stays visible. Once accepted, leave
        # the run open for repair if finishing the run file itself fails.
        if not accepted and store.load(run_id).status == "open":
            store.abort(run_id, reason="trial_error")
        raise
