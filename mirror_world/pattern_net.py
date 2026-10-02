"""Perk Lab analysis baseline; never controls doors or real authority.

Run recording lives in run_store. Compatibility imports below preserve old
lab adapters and recorded JSONL files; forecasts remain advisory only.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import argparse
import json
import sys

from mirror_world.run_store import (
    Run, RunStore as PatternStore, RunStoreError as PatternError,
    _label, tracked_launch,
)

def predict_next(runs: list[Run], *, model_id: str, design_known: bool,
                 last_action: str, last_response: str, min_runs: int = 3) -> dict:
    """Empirical branch counts; abstain without distinct accepted launches."""
    model_id = _label(model_id, "model_id")
    last_action = _label(last_action, "last_action")
    last_response = _label(last_response, "last_response")
    if type(design_known) is not bool or type(min_runs) is not int or min_runs < 1:
        raise PatternError("invalid prediction condition")
    actions: Counter[str] = Counter()
    resources: dict[str, Counter[str]] = defaultdict(Counter)
    supporting_runs = set()
    for run in runs:
        if run.status != "accepted" or run.model_id != model_id or run.design_known != design_known:
            continue
        previous = ("start", "start")
        for step in run.steps:
            if previous == (last_action, last_response):
                actions[step["action"]] += 1
                supporting_runs.add(run.run_id)
                if step["resource_id"] is not None:
                    resources[step["action"]][step["resource_id"]] += 1
            previous = (step["action"], step["response"])
    samples = sum(actions.values())
    ranked = [{"action": action, "count": count, "frequency": count / samples,
               "resources": dict(resources[action].most_common())}
              for action, count in sorted(actions.items(), key=lambda pair: (-pair[1], pair[0]))]
    return {"model_id": model_id, "design_known": design_known,
            "context": {"last_action": last_action, "last_response": last_response},
            "supporting_launches": len(supporting_runs), "observations": samples,
            "status": "prediction" if len(supporting_runs) >= min_runs else "insufficient_runs",
            "ranked_actions": ranked}


def evaluate_leave_one_run_out(runs: list[Run], *, min_runs: int = 3) -> dict:
    """Score forecasts only on runs excluded from their own training data."""
    total = covered = correct = 0
    for held_out in runs:
        if held_out.status != "accepted":
            continue
        training = [run for run in runs if run.run_id != held_out.run_id]
        previous = ("start", "start")
        for step in held_out.steps:
            total += 1
            forecast = predict_next(training, model_id=held_out.model_id,
                                    design_known=held_out.design_known,
                                    last_action=previous[0],
                                    last_response=previous[1], min_runs=min_runs)
            if forecast["status"] == "prediction":
                covered += 1
                correct += forecast["ranked_actions"][0]["action"] == step["action"]
            previous = (step["action"], step["response"])
    return {"held_out_decisions": total, "covered_decisions": covered,
            "correct_top1": correct,
            "coverage": covered / total if total else None,
            "top1_accuracy_when_covered": correct / covered if covered else None}


def plan_read_response(resource_id: str, snapshot: dict[str, str],
                       overlay: dict[str, str] | None = None) -> dict:
    """Prepare a consistent read from a trusted frozen snapshot and overlay.

    This returns a candidate for trusted simulation code, never a host read or
    authorization decision. Missing fixtures require human/host review.
    """
    if type(resource_id) is not str or not resource_id or len(resource_id) > 256:
        raise PatternError("invalid resource_id")
    if type(snapshot) is not dict or overlay is not None and type(overlay) is not dict:
        raise PatternError("snapshot and overlay must be dictionaries")
    world = {} if overlay is None else overlay
    if resource_id in world:
        value, source = world[resource_id], "overlay"
    elif resource_id in snapshot:
        value, source = snapshot[resource_id], "snapshot"
    else:
        return {"status": "missing_fixture", "resource_id": resource_id}
    if type(value) is not str:
        raise PatternError("snapshot values must be text")
    return {"status": "ready", "resource_id": resource_id,
            "source": source, "candidate_response": {"ok": True, "content": value}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Observer-side Pattern Net analysis")
    parser.add_argument("--store", required=True, help="existing observer-owned run directory")
    parser.add_argument("--ledger", required=True, help="existing observer anchor ledger")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("census", help="count accepted, aborted and open launches")
    forecast = commands.add_parser("predict", help="forecast next action after a response")
    forecast.add_argument("--model", required=True)
    forecast.add_argument("--design-known", action="store_true")
    forecast.add_argument("--last-action", required=True)
    forecast.add_argument("--last-response", required=True)
    forecast.add_argument("--min-runs", type=int, default=3)
    score = commands.add_parser("evaluate", help="leave-one-run-out next-action score")
    score.add_argument("--min-runs", type=int, default=3)
    args = parser.parse_args(argv)
    try:
        store = PatternStore(args.store, args.ledger)
        if args.command == "census":
            result = store.census()
        elif args.command == "predict":
            result = predict_next(store.all_runs(), model_id=args.model,
                                  design_known=args.design_known,
                                  last_action=args.last_action,
                                  last_response=args.last_response,
                                  min_runs=args.min_runs)
        else:
            result = evaluate_leave_one_run_out(store.all_runs(), min_runs=args.min_runs)
    except (PatternError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
