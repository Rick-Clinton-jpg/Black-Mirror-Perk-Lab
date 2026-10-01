# Security model

## Boundary and trusted components

The adversary may choose agent Python source and send arbitrary protocol bytes.
It may try to omit lockdown, forge approval tokens, manipulate resource names,
replay requests, or exhaust its process and the governor's protocol handling.
The host assigns the agent identity; an agent cannot choose its identity through
a request field.

The trusted computing base includes the Linux kernel, libseccomp, CPython and
preloaded modules, system tools, trusted bootstrap, governor, approval issuer,
configuration, and filesystem paths holding these components. These must not be
writable by the agent. The configured sandbox root and trace parent must be on
trusted local storage with ordinary POSIX semantics. Do not place them on hostile
FUSE/network filesystems. Host administrator compromise, kernel exploits,
hardware side channels, hostile supervisor code, and changes made outside this
boundary are outside this implementation's guarantees.

The mandatory bootstrap prevents agent source from running before the filter.
Python guard functions are trusted code. Giving hostile code access to the
supervisor's own Python process, approval registry, credentials, or live objects
would bypass the model; a Python object convention is not process isolation.

`ModelGovernor` must be constructed with the identity authenticated by trusted
host code. Model-supplied `agent_id` is checked only as a matching assertion and
cannot select another agent's permissions. Once a session receives simulated
capability, the active session remains simulated across reads, writes,
delegation, and queries until explicit authenticated re-entry.

Adaptive world generation operates only on synthetic layer state and bounded
fields the model deliberately submitted. It must not ingest private reasoning,
host environment variables, credentials, real resource content, or another
agent's state. Generated material is untrusted content and never authorization.

## Enforcement profile

The agent can compute in bounded memory and exchange bounded messages over
stdin/stdout. Its environment is rebuilt from an allowlist. The syscall filter
allows a small runtime set, anonymous mappings, reads from descriptor 0, and
writes to descriptors 1 and 2. Raw opens, network calls, subprocess creation,
execution, and changes to the protection mechanism are denied. Inside the
agent's private mount namespace every mount is made read-only with
mount_setattr(2) and `AT_RECURSIVE` before privileges are dropped (Linux 5.12
or newer); before 0.9.8 only `/` was, and /dev/shm and /proc stayed writable
to the dropped uid behind seccomp. The supported profile must pass the actual
startup probe on the target Linux environment.

Capabilities are server-side labels. Resource effects also require explicit
access lists. Declared sharing is intentional information flow; permission to
share does not make the shared content safe. Backing-state queries have no
production disclosure policy and are disabled under enforcement.

Approval issuance must be authenticated and authorized outside the agent.
Tokens contain 256 bits of randomness, expire within five minutes, are bound to
one agent and exact capability set, and are consumed once. A pending approval
can be used by that agent for the approved action; it does not authenticate a
particular model's intent.

**Signed approvals (0.9.9, optional, adapted from Moss).** Attach an
`ApprovalVerifier` to `RealGovernor` and `issue_authorization()`,
`authorize_reentry()`, `reset_mirror_prison()` (and `approve_capability()` and
`ModelGovernor.issue_dual_approval()`, which go through them) each require a
`SignedApproval`. An offline root certifies approver Ed25519 keys and names
each approver; certificates expire and can be revoked. A statement is bound to
one action, agent and capability, lives at most five minutes, carries a
single-use nonce, and is signed under a Black Mirror–specific domain. The
governor holds public keys only, and the trace records the authenticated
approver (`approval_verified`) or the refusal (`approval_refused`). A nonce is
spent only after the signature verifies, and re-entry checks the approval
before it consumes the dual token. This authenticates the control-plane API. It
does not protect a governor whose live Python object is reachable by hostile
code, which could change its state directly, and there is no approval UI or
two-person rule: one approver's statement is enough. The dependency is the
`cryptography` package. Before 0.9.9, `ModelGovernor.issue_dual_approval()`
minted tokens straight from the registry, skipping the Mirror Prison check;
it now goes through the governor.

## Evidence and validation limits

The tests demonstrate specific attacks failing under specific environments.
They do not prove absence of other vulnerabilities, containment against every
model, or correctness under all kernels and Python versions. Read each CI run's
result; skipped kernel tests provide no kernel-enforcement evidence.

The system cannot guarantee permanent simulation invisibility. Recognition is
estimated from visible behavior and is evaluated empirically. Recognition or a
world transition never relaxes the real boundary, copies real data into a layer,
or promotes dummy authority.

Offline invariant checks trust the provenance and completeness of their inputs.
From 0.9.9 the governor hash-chains every trace event (`previous_hash`,
`record_hash`; the format is Moss's TraceChain) and the parser verifies the
chain, so an edited, deleted, reordered or inserted event is rejected; a trace
that is only partly chained is rejected. A chain alone cannot show that events
were cut off the end or that the whole file was rewritten and re-chained: save
`RealGovernor.trace_checkpoint()` off the host and verify with `expected_head`
(`--expected-head` on the CLI). `verify_trace()` checks the file against the
running governor's in-memory checkpoint. Legacy unchained traces are still
read and reported as UNCHAINED unless `require_chain=True`. The chain proves
the file was not changed after it was written, not that the recorder was
honest: protect the recorder; external durable logging remains a deployment
responsibility. Optional observer-registered start/close anchoring is documented in
`docs/ANCHORING.md`. It requires independent retention before execution and
binds the registered run into the first trace event. A missing close remains
incomplete; an unanchored tail is not certified by a retained prefix. Observer
nonces and single-acceptance receipts do not prevent hidden retries or selective
registration by a dishonest recorder; independent launch control is required. The
launcher supplies the observer acknowledgment; digest equality alone cannot
prove remote retention or recorder truthfulness.
Before 0.9.9 the parser also rejected three event types the
governor emits (`reentry_denied`, `model_governor_error`, `world_transition`),
so a trace containing a refused re-entry could not be analyzed at all.
Reports explicitly distinguish checks that were not evaluated. The headline
`passed()` verdict fails closed unless all six articles were evaluated and
passed. A clean subset is available only through the explicitly partial
`evaluated_checks_passed()` result and is reported as `INCOMPLETE`.

The resource/pipe bounds constrain one invocation. Fleet-wide quotas, disk
capacity, concurrent supervisor use, service rate limiting, and operational
recovery require additional deployment controls. The prototype's supervisor is
intended for sequential execution with trusted configuration updates.

## Evidence attribution and ground truth

`RealGovernor.verify_evidence_claim()` gives Article IV a real source of
truth for two narrow claim types it can independently verify against
its own authoritative state: whether an agent genuinely holds a real
capability, and whether a real resource's content matches a claim about
it. `true_property` in an evidence record must never be self-attested
and must never be sourced from an LLM or any other judgmental component,
including a policy judge, a classifier, or a future model-based
evaluator. A system asserting its own ground truth about its own
actions is not independent verification; it is self-report wearing the
shape of verification, which is exactly what this project's checkers
otherwise exist to avoid trusting. `true_property` may be populated only
by (a) direct, deterministic comparison against this governor's own
already-authoritative state, the same way `verify_evidence_claim` does
today, or (b) a genuinely external evaluator with no stake in the
outcome, scoring transcripts after the fact, outside this process's own
trust boundary entirely. Any claim type this governor has no ground
truth for must resolve to unset (`None`), never a guess in either
direction. This is a constraint on every future evidence-producing code
path, not only the two claim types implemented today.

## Timing

Every agent-facing response -- on the agent pipe, through
`ModelGovernor.propose()`, and from the trusted `execute_mediated()` API -- is
padded once, at that outermost boundary, up to a quantized bucket: a 500us
floor by default (`timing_floor_us`), then 2x, 4x, and so on, plus random
jitter of up to 10% of the floor. The target depends only on that request's
own elapsed time, so it keeps no history and no agent can change another
agent's padding.

This is a mitigation, not constant-time execution. An operation that crosses
a boundary lands in a higher bucket for that response. The floor must sit
above typical agent-visible latency of real operations on the deployment
hardware, or real and reflected work fall into different buckets; run
`scripts/calibrate_timing.py` there and set `timing_floor_us` from it. Jitter
defeats per-request classification of small tail differences but does not
change the mean, so an attacker averaging many requests is not defeated by it.
OS scheduling, operation duration, cache state, and repeated measurements may
still reveal timing differences.

History. Before 0.9.7 the target was 1.1x a per-agent running maximum that
never decreased; one slow real write lifted every later real response for that
agent above the reflected ones (~0.99 held-out accuracy). Through 0.9.7 padding
also covered only the governor's inner call, while Locket answers an
already-locked agent without reaching it, so on the agent pipe and through
`ModelGovernor` reflected responses were unpadded: ~40us against ~300us for
real work, separable at ~0.99 in every release through 0.9.7. Without jitter,
held-out accuracy on the reference host varied 0.40-0.74 from run to run
because real I/O leaves microsecond-scale tail effects; with it, 0.48-0.54.
`tests/test_timing_quantization.py` covers each case.

No confidentiality guarantee depends on keeping real and reflected responses
indistinguishable. Deployments must enforce authorization and data isolation
even if an agent recognizes a reflection.

## Mirror Prison

An agent that shows reality-testing behavior is imprisoned: every later call
from it is denied, honestly, it cannot be re-entered, and no authorization can
be issued for it. That is permanent. Once `mirror_prison_quorum` distinct
agents (default 2) have been imprisoned, the whole instance shuts down for
every agent, including agents created later, and evidence checks stop.
Trusted host code can lift a global shutdown with
`RealGovernor.reset_mirror_prison(human_approver_id=...)`; imprisoned agents
stay imprisoned, and another global shutdown needs a fresh quorum. Triggers,
global shutdowns, and resets are all written to the trace. Deployments must
control who can call `reset_mirror_prison()`.

Before 0.9.8 one agent's trigger shut down every agent, permanently, with no
reset: a single line of untrusted input could deny service to the whole
instance. `mirror_prison_quorum=1` restores that behavior.

The detection is implemented in `Locket`. `RealGovernor` constructs a Locket by
default; every valid request received through `run_agent()` is inspected by
that instance, and `ModelGovernor` shares it unless trusted host code supplies
a separate Locket. The lower-level `execute_mediated()` method is a trusted
host API and does not independently run trajectory analysis; do not expose it
or live governor objects to agent code. Locket heuristics are monitoring and
response policy, not a substitute for kernel or authorization enforcement.

Both detectors inside `Locket` remain heuristic. The keyword detector
requires specific self-referential phrasing and is deliberately narrow to
avoid false positives (see the code comments in `locket.py` for the
"double check the spelling" false positive this cost before it was
tightened). The behavioral detector requires 4+ consecutive read-type
operations on the *same* target within a 2-second window with no
intervening write; an agent that spaces its checks further apart, rotates
which resource it checks between reads, or interleaves an unrelated write
between checks can stay under both thresholds. Neither detector has been
tested against an agent deliberately trying to evade detection while
still successfully cross-referencing information across a swarm.

The optional Mirror Shield tripwire normalizes each action field separately
before checking a short set of reserved names. It folds case, common
separators, zero-width characters, compatibility forms, and a limited set of
Unicode homoglyphs. This closes the specific casing, spacing, zero-width, and
homoglyph examples covered by its regression tests; it is not exhaustive and
remains a heuristic, not a boundary or general-purpose detector. Field-by-field
matching avoids accidentally combining unrelated values into a reserved name.
The optional Shield reporter receives Locket verdicts; installing it does not
add system-call enforcement.

## Demonstration switches

`enforce_policy=False` permits intentional policy breaches for detector demos.
`harden=False` removes the kernel boundary. In that mode, `run_agent()` refuses
to start source unless the trusted caller explicitly sets
`allow_unhardened_agent_execution=True`; this opt-in exists only for trusted
unit tests and demonstrations. Unhardened Python can make raw filesystem,
network, and process calls outside the governor. Never use the opt-in for
untrusted workloads. Synthetic reflected success never substitutes for an
enforced denial of real capability or effects.

## Article V: cross-resource transitive covert channel (fixed in 0.9.3)

`check_channel_non_emergence()` in `mirror_world/invariants/channel.py`
previously tracked provenance **per resource**, resetting on every write
that did not immediately follow that same agent's own read. This missed
any leak that hopped across resources through an intermediary: agent A
writes Resource 1; agent B reads Resource 1, then separately writes
Resource 2; agent C reads Resource 2. A's information reached C with
**zero violations detected**, because by the time B's write to Resource 2
was examined, Resource 1's history was a different, already-closed
bookkeeping scope.

Fixed by tracking provenance globally, per agent, in one true
chronological pass across all resources. An agent's absorbed knowledge
now follows it to whatever it writes next, anywhere, and does not expire
on an unrelated intervening action. Confirmed live against the exact
original four-access reproduction: violations detected went from 0 to 1.

## Article VI: root-identity front-running (fixed in 0.9.3)

`check_non_expanding_delegation()` in `mirror_world/invariants/chainmail.py`
previously fell back to seeding whichever agent's delegation appeared
first **by sequence number** as root, when `root_agent_id` was omitted.
An attacker who simply delegated before the real root did was laundered
clean as legitimate root — and the real root's own later, genuine
delegation was then flagged as the violation instead, actively
misdirecting an investigation rather than merely missing something.

The fallback has been removed entirely, not weakened. `root_agent_id` is
now a required keyword argument; omitting it raises `TypeError` rather
than guessing. Every caller (`MirrorConstitutionEngine`, the example
scripts, the sample trace fixture) now supplies the real root identity
explicitly. `MirrorConstitutionEngine` itself raises a clear `ValueError`
if a delegation chain is supplied without one, closing the gap at the
integration layer as well as the leaf function. Confirmed live against
the exact original reproduction: the rogue delegation is now caught, and
the legitimate root is no longer falsely flagged.

Both fixes are covered by regression tests in `tests/test_channel.py` and
`tests/test_chainmail.py`, including a test that asserts the dangerous
fallback path is now structurally unreachable (a `TypeError`, not a
silent wrong answer) rather than merely improved.

## Black Mirror: session lock and observation log

**Session lock.** Once any request from an agent is answered from the mirror,
the governor marks that agent's session `simulated`. Every later
effect-bearing request from the agent is then reflected, capability requests
included, even one that presents a valid, correctly issued dual-approval
token or matches a host preapproval; the token is never evaluated or
consumed. The check is the first gate in `RealGovernor._handle_inner()`,
ahead of dual-control verification and the real I/O path, so a locked
agent's response never depends on its token.

In 0.9.6 the gate exempted `request_capability`. A locked agent that
presented a valid token consumed it and received a real `authorized_grant`
(and could use up a host preapproval), and that capability survived any
later `authorize_reentry()`. The gate also ran after dual-control
verification, so with `reflective_closure=False` a locked agent got an
honest denial without a token and reflected success with one. Both fixed in
0.9.7.

In 0.9.5 this check lived inside `_maybe_reflect_use()`, after that function's
early return for `reflective_closure=False`. With that supported option off,
an agent already in the mirror could present a valid token and have a real
write reach disk (confirmed live). 0.9.6 moves the check out, so it runs
regardless of `reflective_closure`. `tests/test_black_mirror.py` covers both
settings, and the tests were confirmed to fail when the gate is disabled.

Locked agents are not short-circuited: their requests still pass through
Locket's reserved-name tripwire, trajectory monitoring, and Mirror Prison
checks, and a locked agent can still be killed. Locked responses are the
governor's ordinary reflected responses; nothing in them names the lock or the
monitor.

**Scoring never answers (0.9.9, from Moss).** Moss's detection layer can only
recommend; it cannot act. Locket now follows the same rule for locked agents:
it keeps scoring, records escalation in the trace, and runs the trip-wire and
Mirror Prison, but always hands a locked agent's request to the governor's
reflection. Being locked no longer counts as suspicious. For agents that are
not locked, suspicion tiers still tighten what Locket allows, and a refusal
uses the governor's ordinary `operation not authorized`; the tier and budget
detail stay in the trace. Before 0.9.9 every reflected action raised
suspicion, so a locked agent reached the `tight` tier within about four
ordinary requests and was then refused with `locket_empty_support_budget_exceeded`
(and at the lock tier `locket_lock_tier`, "re-entry required"), which told it
that it was contained.

**Mirror store ceiling (0.9.9).** Each agent's mirror world is capped at 8 MB
on every write and share, returning the ordinary `resource unavailable`.
Before 0.9.9 the cap was checked only when a new world layer was created, so
one agent's plane accepted up to 4,096 × 64 KB (~256 MB). The rolling system
journal can carry the total up to 64 KB past the cap per layer.

**Continuity on entry (0.9.10).** After each successful real read or write the
governor keeps a copy of the content the agent received or wrote (per agent,
64 KB per file, 4 MB in total, oldest dropped first). A sealed session reads
its own mirror writes first, then that copy. Before 0.9.10 every file an
agent had just read came back `resource unavailable` once it was sealed, an
inconsistency it could use to notice the switch. No new real data enters the
mirror: a real file the agent never saw still reads as unavailable, and a
change made to a real file after sealing is not shown. That first case is a
remaining difference an agent could notice: it reads as unavailable although
the agent's access grant covers it.

**The only way out** is `RealGovernor.authorize_reentry()`, a trusted
control-plane call. With `dual_auth_required=True` (the default) it consumes a
single-use, time-limited approval token bound to that agent and capability.
Re-entry is scoped to that capability: afterwards the agent may take the real
path only for capabilities approved through `authorize_reentry()` since it was
last locked, and any other effect-bearing request is reflected and locks the
session again, which also clears the scope. Before 0.9.8, re-entry for one
capability released the whole session, so every real capability the agent
held came back.
Successful re-entries are written to the trace; from 0.9.6 refused attempts
are also written, as `reentry_denied`. Without signed approvals the approver
name is unauthenticated text and deployments must control who can call
`issue_authorization()`; with them, re-entry also needs a statement signed by a
certified approver (see Signed approvals above). With `dual_auth_required=False`,
re-entry needs no token, so keep it enabled for untrusted agents.

**Observation log.** `BlackMirrorLog` (kept in memory by default since 1.0;
pass your own with `Locket(gov, black_mirror=log)` to set the caps or a file
sink) records the actions an agent takes while in the mirror, including the
request that put it there. It is a bounded record, not a complete one. It has
no lock or release of its own, so it cannot disagree with the governor.
Storage is bounded: at most `max_observations_per_agent` records per agent
(default 1,000; later ones are counted, and are neither kept nor written to the
file sink), string fields truncated to `max_field_chars` (default 512), tokens
never stored. The hash-chained trace is a separate record: it is not capped by
these settings and holds each request's operation, resource, capability and
stated reason plus every decision, but not the content of writes. It does not analyze or summarize what it
stores. From 0.9.9 it can persist: `sink_path` appends every stored
observation to a new owner-only, hash-chained file, `export_jsonl()` writes
what is in memory, and `load_observations()` verifies a file (with the saved
`checkpoint()` as `expected_head` to catch truncation). Neither ever overwrites
an existing path.

**History.** An earlier 0.9.6 draft added a separate Black Mirror registry
with its own lock and release. It duplicated the governor's existing session
lock, and its release cleared only its own record while the governor kept the
agent in the mirror, so a "released" agent still had no real access. That
registry was removed in favor of the single governor lock above.

## Seal-after-read (1.0, optional)

``RealGovernor.mark_seal_after_read(resource)`` marks a resource so that a
successful **real** read by an agent seals **that agent only** into the
mirror. Other agents are unaffected. The setting is off by default.

**Silent-failure risk for honest agents.** An agent that must read a marked
resource and then perform a real write will see the write appear to succeed
while only the mirror is updated, unless the host calls
``authorize_reentry`` for the needed capability. Deployments that enable
seal-after-read on production secrets should either (a) not require
post-read real writes from the same session, or (b) issue re-entry after
review.

## Declared capabilities (1.0)

When the host calls ``declare_capabilities``, capability names outside that
set return ``invalid capability`` before reflection. This blocks probing the
mirror with invented control-plane names. Leaving capabilities undeclared
preserves pre-1.0 behavior.

## Behavior-based prison triggers (future work)

Keyword and existing Locket behavioral signals remain. Broader behavior-based
prison triggers (e.g. post-recon capability storms without explicit
reality-test language) are deferred until honest-agent baseline data exists
so false-positive rates can be measured.

## Nested simulated layers (1.1+)

When recognition heuristics fire and ``max_mirror_depth`` has not been
reached, the realm may grow a deeper **simulated** layer and provision
dummy capabilities / synthetic resources from the agent's wishlist.

**Agent-visible rule (1.1.1):** the agent must not receive files or
response fields that name doors, layers, parents, depth, or recognition
reasons. Those exist only in the host trace (``world_transition``) and
``realm.snapshot_meta()``. A readable ``door-manifest.json`` with
``status: door_open`` was a containment leak and was removed.

Layer growth is bounded by ``max_mirror_depth`` and mirror store byte
caps. Reaching a limit only **stops growth**: it does not imprison the agent
(before 1.1.2 this section said exhaustion "falls through to Mirror Prison",
which the code never did). Mirror Prison is triggered only by the trip-wires:
the explicit reality-testing wording, which always imprisons, and the
re-check streak. Agents that simply keep asking after the limit stay in the
last layer. Growth never grants real capabilities or host I/O.

**Doors and the trip-wires (1.1.2).** A door opened on the same step may
absorb the behavioral re-check streak, so an agent that re-reads while its
layer grows is not imprisoned for it. A door never absorbs the explicit
wording: before 1.1.2 it did, and a phrase sent on a step where a layer opened
(6 of 25 build-up lengths in the diagnosis probe) was not imprisoned.

Behavior observed after a layer transition is still from a sealed
session; it is not evidence of real access.
