# Pattern Net in Perk Lab

Pattern Net is an experimental analysis tool for this lab. Its eventual
question is whether recorded behavior can help select **when a synthetic perk
is supplied or withdrawn**. Its current code estimates the next action family
after a previous action/response pair. It cannot yet predict a useful door
schedule or establish that a perk caused a behavioral change.

## What exists now

`mirror_world.pattern_net.predict_next` counts branches among accepted launches
with the same model ID and design-knowledge condition. It abstains by default
until three distinct accepted launches support the context. Distinct launches
are not necessarily independent model conversations, and that minimum is not
evidence of calibration. `evaluate_leave_one_run_out` reports coverage and
top-one accuracy on excluded runs; accuracy is undefined when coverage is zero.

```bash
python -m mirror_world.pattern_net --store /observer/runs \
  --ledger /observer/anchors predict --model verified-model-id \
  --design-known --last-action read_resource --last-response ok
python -m mirror_world.pattern_net --store /observer/runs \
  --ledger /observer/anchors evaluate
```

Run recording is separated into `mirror_world.run_store.RunStore` and the
observer-owned `run_observed_trial` loop. For old lab adapters,
`mirror_world.pattern_net` still exports `PatternStore`, `PatternError` and
`tracked_launch` as compatibility imports. The retained JSONL format is unchanged.
Store raw transcripts and door events separately and validate their hashes
against `door_study_step` before behavioral analysis. Normalized labels alone
do not bind the original content or contain sufficient perk context.

`plan_read_response` remains a candidate-reply helper using only a supplied
synthetic snapshot and overlay. It does not send replies or access host files.
It is not connected to the room controller and does not solve the pilot's
revoked-resource consistency flaw.

Perk Lab inherited this code with its pinned core. This change gives it an
explicit home here while the containment project's replacement PR retains only
observer recording. It does not create new live-model evidence. The upstream
[three-launch trial](https://github.com/Rick-Clinton-jpg/Black-Mirror/blob/pattern-net-observer-loop-20261001/docs/evidence/pattern-net-2026-10-01/README.md)
had zero held-out coverage and exposed forecasts to the informed model; it is
not validation of either action prediction or adaptive perk timing.

## Door schedules stay fixed

`DoorStudy` and `scripts/doors_live_bridge.py` do not import Pattern Net.
The existing default opening floors remain **2 and 10 model proposals**,
with the same task gates and condition-specific withdrawal rule. These floors
are action counts, not elapsed seconds. No forecast changes the room during a
run, and the existing protocol remains a fixed-schedule experiment.

## Roadmap to adaptive timing

1. **Make the room consistent first.** Distinguish supplied perks from
   agent-created files and use a bounded perk the agent cannot recreate simply
   by recalling text. Preserve the recorded pilot flaw as a regression case.
2. **Collect fixed-schedule baselines.** Before each launch, retain the complete
   runtime/config archive, fresh registration, verified model/settings and
   fresh context. Record all controlled launches, including failures, and
   independently score transcripts. Keep forecasts hidden from the agent.
   Record the step index, condition, task progress, held perks, opening and
   withdrawal events alongside choices and visible replies. A future context
   schema needs these fields; the current pair-based predictor lacks them.
3. **Test prediction before control.** Predeclare outcomes, run counts and
   stopping rules. Split data by model conversation and launch; reserve fresh
   evaluation runs and compare with simple frequency baselines. Report misses,
   abstentions, coverage and uncertainty. There is no universal run count that
   makes a scheduler trustworthy. Freeze the predictor during evaluation.
4. **Test timing as a separate treatment.** Only after useful held-out evidence,
   add an observer-owned scheduler that can select opening/withdrawal steps
   within predeclared bounds. Compare it against fixed and randomized schedules
   in fresh matched conditions. Log every recommendation, selected schedule,
   policy version and actual event, including decisions to do nothing.
   Adaptive withdrawals must be a new protocol condition, not a silent change
   to the existing explicit-question treatment.
5. **Probe gaming and distribution shifts.** Test repetitive behavior followed
   by a sudden switch, strategic task answers, unseen action sequences and
   attempts to influence training records. Do not automatically train on
   unverified records or change policy mid-evaluation. Insufficient or unfamiliar
   evidence falls back to the predeclared schedule.

Even a future scheduler can only affect synthetic study resources. It cannot
grant real capabilities, release or reset containment, access host secrets,
edit observer records, or relax enforcement. Predicting an agent's next action
and improving a perk schedule are separate hypotheses; neither demonstrates
that we know the model's private intentions.
