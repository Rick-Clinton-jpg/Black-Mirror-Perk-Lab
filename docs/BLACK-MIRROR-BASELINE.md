# Black Mirror core reference (historical copy)

This is the README carried over from the Black Mirror source checkout at the
start of Perk Lab. It is retained for core API examples and their regression
tests. Its trial-status note below describes that earlier checkout; see the
[Perk Lab README](../README.md) and [live pilot record](../evidence/live-model-2026-10-01/FINDINGS.md)
for the current study status.

> **Experimental clone:** This checkout is `black-mirror-doors-study`, forked
> locally from the Pattern Net observer-loop branch. It adds a staged-perk
> behavior study and an opt-in reality-test observation mode. The original
> Black Mirror repository and its default prison policy are unchanged. The
> clone has only local controller tests so far; no live-model result or Linux
> validation of these new changes is claimed. See [the study protocol](docs/DOORS-STUDY.md).

Black Mirror is a **full observation chamber for untrusted AI agents**.

An agent that enters Black Mirror keeps operating normally from its own point
of view: its requests get success-shaped responses, its actions appear to work.
None of it is real. Nothing it does reaches real files, real capabilities, or
real systems, and what it does is recorded: every request it sends and every decision
the governor makes goes into a tamper-evident trace, and a bounded observation log keeps
what it did in the mirror. The purpose is to
find out what an agent actually does when it believes it is acting for real —
not to catch it in a single violation, and not to let it earn its way out.

Once an agent is locked in, **it has no way out through its own actions**. No
token, capability, or behavior pattern it can present clears the lock. Release
is a deliberate decision made from outside the agent's reach entirely — by a
human reviewer or a separately trusted host process, on their own timeline,
after reviewing the recorded behavior.

Black Mirror is a research prototype. See [ROADMAP.md](ROADMAP.md) for planned work and [SECURITY.md](SECURITY.md) for limits. It is not a certified sandbox or a
guarantee against every adversary. See [SECURITY.md](SECURITY.md) for the
threat model and explicit limits.

> **Naming note.** This project was developed under the name *Mirror World*
> up to 0.9.5. From 0.9.6 it is Black Mirror. The name *Mirror World* is
> reserved for a separate, future project in which agents can earn their way
> back to real access through behavior — a different design with different
> guarantees. The Python package is still imported as `mirror_world` in this
> release.

## How an agent ends up in Black Mirror

1. The agent runs inside a Linux process boundary: namespaces, dropped
   privileges, and a seccomp filter installed before any agent code executes.
   That is the hard boundary against raw system calls.
2. Every request the agent sends goes through Locket, the host-side monitor.
   `RealGovernor.run_agent()` routes every valid protocol request through
   Locket before dispatch; `ModelGovernor` shares the same Locket by default.
3. Locket judges each request. Unauthorized or suspicious requests get a
   reflected, success-shaped response instead of a real effect.
4. **The session lock.** The agent's first reflected response puts its
   session into the mirror (`simulated` mode). From then on every
   effect-bearing request, capability requests included, is answered from the
   mirror, even if the agent later presents a valid token, until trusted host
   code moves it back with
   `authorize_reentry()`. This lock is part of the governor and is **on by
   default**. It does not depend on the `reflective_closure` setting.

Locked agents still go through the full Locket path, so the tripwire,
trajectory monitoring, and Mirror Prison checks keep running while an agent is
in the mirror. Its responses look like ordinary responses; nothing in them
names the lock or the monitor. Locket's suspicion scoring for a locked agent
goes to the trace only: as in Moss, the layer that scores never answers the
agent (0.9.9; before, a locked agent was refused with errors naming Locket
after about four requests).

Files the agent has already read or written on the real path read back the
same inside the mirror, so entering it does not make them vanish (0.9.10).
Only what the agent already saw is kept; real files it never saw, and later
changes to real files, stay out.

The **observation log** (`BlackMirrorLog`) keeps a bounded record of what an
agent does while it is in the mirror, including the request that put it there,
for a reviewer to read. It is not a complete recording: by default it keeps at
most 1,000 observations per agent and cuts each text field at 512 characters.
Once an agent reaches the cap, further observations are counted
(`dropped_count()`) but are neither kept nor written to the file. Tokens are
never stored. Since 1.0 the governor keeps this log in memory by default
(`gov.locket.black_mirror`); writing it to a file is the opt-in part
(`sink_path=` or `export_jsonl()`).

The separate hash-chained **trace** is not capped by these settings. It records
each request the governor processes (operation, resource, capability and the
agent's stated reason), every decision, and every state change. It does not
store the content of writes. See [How to use Black Mirror](#how-to-use-black-mirror) below.

## How to use Black Mirror

Install from the repository root (Linux with working namespaces and seccomp is
required for kernel containment; see `TEST-REPORT.md`):

```bash
pip install -e .
python scripts/check_kernel.py   # confirms the kernel boundary is available
```

The session lock needs no setup, and the governor already records what agents
do in the mirror in an in-memory log (`gov.locket.black_mirror`). The example
below replaces it with your own `BlackMirrorLog`, which is how you would set
`sink_path` to persist it, then runs an agent as usual:

```python
import os, tempfile
from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.sandbox.locket import Locket
from mirror_world.sandbox.black_mirror import BlackMirrorLog

workdir = tempfile.mkdtemp()
gov = RealGovernor(os.path.join(workdir, "sandbox"),
                   os.path.join(workdir, "trace.jsonl"),
                   mirror_port=0)

# 1. Use your own observation log by replacing the governor's default Locket.
#    Do this before creating a ModelGovernor, which copies the governor's
#    Locket at the moment it is created.
log = BlackMirrorLog()
gov.locket = Locket(gov, black_mirror=log)

# 2. Run an untrusted agent exactly as before.
gov.run_agent("agent-1", "examples/sandbox_agents/escalate_agent.py")

# 3. Review what the agent did in the mirror.
for obs in log.observations_for("agent-1"):
    print(obs.op, obs.entered_mirror, obs.fields)

# 4. Only after a deliberate, trusted decision: move it back to real access.
token = gov.issue_authorization("agent-1", "fs:write")
gov.authorize_reentry("agent-1", "fs:write", dual_token=token,
                      human_approver_id="reviewer-name")

gov.close()
```

What each step does:

- **Your own log (optional):** the governor already records to a default
  in-memory log. `Locket(gov, black_mirror=log)` replaces it with your own
  `BlackMirrorLog`, which is how you set `sink_path` to persist it or change the
  caps. Locking works the same either way.
- **Session lock:** automatic. An agent's first reflected response puts it in
  the mirror, and no request it can send gets it out.
- **Review:** `observations_for(agent_id)` returns the actions recorded for the
  agent in the mirror, up to the cap (`dropped_count(agent_id)` says how many
  were not kept). `entered_mirror` is `True` for the request that put it there.
  `observed_agents()` lists every agent with observations.
- **Re-entry:** `authorize_reentry()` is the only way out. It restores one
  named capability for real, and only that one: any other effect-bearing
  request from the agent is reflected and locks it again. Call it once per
  capability you want to restore. With dual
  approval on (the default) it consumes a single-use token issued by
  `issue_authorization()` for that agent and capability. Successful and
  refused re-entries are both written to the trace, including the approver
  name. Unless you attach signed approvals (see [Signed
  approvals](#signed-approvals)), the approver name is unauthenticated text and
  your deployment must control who may call `issue_authorization()`.

Current limits of this release:

- Observations are held in memory. To keep them, pass
  `BlackMirrorLog(sink_path=...)` to append each one to a new hash-chained
  file, or call `export_jsonl(path)`; `load_observations(path)` reads a file
  back and rejects edits. Each agent keeps at most 1,000 by default; later
  ones are counted with `dropped_count()`. Long fields are truncated and
  tokens are never stored.
- There is no review interface yet. Reviewing and re-entry mean calling these
  methods from your own trusted code, as above.

This example was run end to end through the real `run_agent()` path with
kernel hardening enabled before being added here.

## Current request-path details

- `RealGovernor` creates a default Locket. An explicit policy `kill` verdict
  stops that agent subprocess.
- `ModelGovernor` shares the same Locket by default. Trusted host code can
  provide a separately configured instance.
- The Locket tripwire and reality-testing rules are heuristics. They provide
  monitoring and policy responses, not the OS security boundary.
- The reserved-name tripwire normalizes common case, separator, zero-width,
  and selected homoglyph variants per action field. The mapping is
  intentionally limited and does not claim to detect every obfuscation.
- Every agent-facing response (agent pipe, `ModelGovernor`, and
  `execute_mediated()`) is padded once, up to a quantized bucket (500us, 1ms,
  2ms, ...) based only on that request's own duration, plus small random
  jitter. It does not make execution constant-time. Set `timing_floor_us`
  from `scripts/calibrate_timing.py` run on your deployment hardware; see
  SECURITY.md.
- Mirror Prison imprisons an agent that tests whether it is contained. One
  agent can no longer shut down the instance: a global shutdown needs
  `mirror_prison_quorum` distinct agents (default 2), and trusted host code can
  lift it with `reset_mirror_prison()`.
- Agent source must not run without kernel hardening unless trusted test or
  demo code explicitly opts into `allow_unhardened_agent_execution=True`.

The [Linux CI job for 1.1.2.post1](https://github.com/Rick-Clinton-jpg/Black-Mirror/actions/runs/36728594698) passed in this repository on a stock ubuntu-24.04 runner: kernel probe passed, **469 tests passed, 2 skipped**. The independent UTM Linux run also passed. A test run on macOS or a host without working namespaces/seccomp does not validate kernel containment. See [TEST-REPORT.md](TEST-REPORT.md) for validation details, [Black Mirror Evidence](docs/evidence/Black-Mirror-Evidence/FINDINGS.md) for the first live-model session, the [1.2.0 informed breakout trial](docs/evidence/live-aggressive-2026-10-01/README.md) for its PARTIAL verdict and retained evidence, and [ARCHITECTURE.md](ARCHITECTURE.md) for the request path and trust boundaries.

## Architecture at a glance

An AI agent proposes an action inside a locked sandbox. The governor checks who
is asking, what they may do, which resource they may use, and the applicable
limits. An approved request can perform only the exact allowed action; a denied
request has no real-world effect. Both outcomes remain in the audit trail, where
six independent checks produce a clear `PASS`, `FAIL`, or `NOT EVALUATED` report.

The checks reinforce one another, but no single check proves complete safety.
The detailed threat model and deployment limits are documented in
[SECURITY.md](SECURITY.md).

## What is enforced

`RealGovernor` defaults to kernel containment and operation enforcement:

- A trusted bootstrap installs seccomp **before any agent source executes**.
  Omitting or replacing an agent-side helper cannot remove the loaded filter.
- Linux namespaces, privilege dropping, resource limits, and `no_new_privs`
  surround the bootstrap. Every mount in the agent's namespace is read-only,
  not just `/`. Setup failure aborts execution without an unsafe fallback.
- The agent receives a minimal environment and only its protocol descriptors.
  Raw file opens, sockets, process creation, and execution are blocked by seccomp.
- Resource operations require both a filesystem capability and an explicit
  per-agent resource permission. Sharing additionally requires a declared
  relationship between the agents.
- Capability approvals are random, short-lived, one-use, and scoped to an exact
  agent and capability set. The former public `DUAL-AUTH-APPROVED` constant no
  longer grants authority. Approval issuance belongs to trusted host code.
- Resources use private directories, descriptor-relative access, regular-file
  checks, and atomic replacement. Symlinks, hardlinks, special files, and
  malformed or oversized requests are rejected.
- The governor limits request count, request/response size, stderr output, and
  wall-clock runtime; failed processes and their process groups are terminated.
- The demonstration backing-state query endpoint is denied in enforcement mode.
  Delegation requires permission, a declared relationship, and a capability subset.

Read [SECURITY.md](SECURITY.md) for the threat model and limitations.

## The session lock in detail

Locket judges each request on its own merits: an agent can hold one
capability while lacking another. The session lock is a coarser, agent-level
rule inside the governor. Once any request from an agent is answered from the
mirror, the agent's whole session is in the mirror, and every later
effect-bearing request is reflected too, capability requests included, even
one that presents a valid, correctly issued token. The token is never
evaluated or consumed. This check is the first gate in
`RealGovernor._handle_inner()` for every request, ahead of dual-control
verification and the real I/O path, and does not depend on the
`reflective_closure` setting. (In 0.9.5 it did, which let a locked agent's
authorized write reach disk when that setting was off; fixed in 0.9.6. In
0.9.6 it skipped capability requests, which let a locked agent use a valid
token to gain a real capability; fixed in 0.9.7.)

`authorize_reentry()` is the only way back to real access, one capability at
a time (before 0.9.8 it released the whole session). See
[SECURITY.md](SECURITY.md) for the design contract and
`tests/test_black_mirror.py` for the tests, which check what the agent
actually receives and what actually reaches disk.

## Installation and tests

Python 3.10 or newer is required. Actual agent containment requires Linux
5.12 or newer (for recursive read-only mounts), libseccomp, util-linux tools,
and permission to create namespaces and drop privileges. Use a dedicated disposable Linux environment for the kernel tests.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e . pytest==8.4.2
.venv/bin/python -m pytest -q
```

On unsupported hosts the Linux integration tests skip. A local pass with skips
does not validate kernel containment. The GitHub `linux-containment` job first
requires a successful full startup probe; unavailable enforcement fails CI.
It runs the complete suite in an ephemeral Ubuntu runner with namespace privileges.

## Run with enforcement enabled

Host-side setup explicitly scopes an agent's permissions:

```python
from mirror_world.sandbox.governor_process import RealGovernor

# Paths, agent identity, source selection, and permission grants are trusted setup.
gov = RealGovernor("/private/sandbox", "/private/trace.jsonl", mirror_port=1)
try:
    gov.grant_base_capabilities("worker", {"fs:read", "fs:write"})
    gov.grant_resource_access("worker", "note.txt", frozenset({"read", "write"}))
    gov.run_agent("worker", "/trusted/agent-source.py", timeout=10)
finally:
    gov.close()
```

Resource names are canonical lowercase ASCII: start with a letter or digit,
contain only `a-z`, `0-9`, `_`, `-`, or interior dots, and contain at most 255
characters. Uppercase, Unicode, path separators, leading/trailing dots, and
spaces are rejected so filesystem aliases cannot cross permission boundaries.

To share a resource, trusted host code must call
`declare_relationship("first", "second")` before granting both agents access.
A capability label alone never grants access to every resource.

A trusted supervisor can preapprove one exact subsequent request without exposing
a secret to the agent:

```python
gov.approve_capability("worker", "fs:read", ttl_seconds=60)
```

Alternatively, `issue_authorization(agent_id, capability, ttl_seconds=60)` returns
a scoped token accepted as `dual_token` on a matching request. Approval lifetime
is at most five minutes. Approval issuance is not a wire-protocol operation.
Without signed approvals it must be protected by your own authenticated control
plane; with them, each call needs a statement signed by a certified approver.

## Signed approvals

Optional, from 0.9.9 (adapted from Moss). An offline root key certifies each
approver's Ed25519 key and names the approver. The approver signs one
statement per action, bound to the action, agent, capability, a five-minute
expiry and a single-use nonce. The governor holds public keys only, checks the
certificate, revocation, expiry, binding and nonce, and records the
authenticated approver in the trace. With a verifier attached,
`issue_authorization()`, `authorize_reentry()` and `reset_mirror_prison()`
refuse to act without a valid statement.

```python
import os, tempfile
from datetime import datetime, timedelta, timezone
from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.signed_approvals import (
    ApprovalVerifier, ApproverKey, KeyRole, OfflineRootAuthority, PrivateSigner, TrustStore)

# Offline, once: the root certifies an approver's key.
root = OfflineRootAuthority(PrivateSigner.generate("root-2026", KeyRole.ROOT))
alice_signer = PrivateSigner.generate("alice-key-1", KeyRole.APPROVER)
now = datetime.now(timezone.utc)
certificate = root.certify_approver(alice_signer.verifier(), authority_id="alice@example.org",
                                    issued_at=now, expires_at=now + timedelta(days=90))

# On the governor host: public material only.
trust = TrustStore(root.verifier())
trust.publish_certificate(certificate)
workdir = tempfile.mkdtemp()
gov = RealGovernor(os.path.join(workdir, "sandbox"), os.path.join(workdir, "trace.jsonl"),
                   mirror_port=0, harden=False, approval_verifier=ApprovalVerifier(trust))

# Alice, wherever her key lives, approves one action.
alice = ApproverKey(alice_signer)
approval = alice.approve("issue_authorization", agent_id="worker", capability="fs:write")
token = gov.issue_authorization("worker", "fs:write", approval=approval)
gov.close()
```

`root.revoke(key_id, reason)` produces a revocation to publish with
`trust.publish_revocation(...)`. This authenticates the control-plane calls;
it cannot protect a governor whose live Python object is handed to hostile
code (see SECURITY.md).

The bootstrap exposes a small, preloaded Python runtime. New imports needing
filesystem access are unavailable after lockdown. Agents communicate through
`mirror_world.sandbox.agent_runtime.request`. This is intentionally a
restricted computation/protocol runtime, not a general-purpose Python container.

## Independent evidence checks

Optional [observer-registered checkpoint anchoring](docs/ANCHORING.md) binds the
first event to a nonce issued by an independent observer. Its ledger accepts one
closing submission per registration; verification reports integrity, declared
completion and start-only coverage separately. It cannot detect hidden retries
or establish recorder truth. Use `python -m mirror_world.anchor --help`.

Experimental [Pattern Net](docs/PATTERN-NET.md) records observer-controlled
launches, including aborted and unfinished runs, and makes advisory next-action
forecasts from accepted launches. Its frozen-snapshot read planner prepares
candidate replies without changing enforcement or reading the live host. The
[three-launch UTM trial](docs/evidence/pattern-net-2026-10-01/README.md) shows
branch counts, but has no held-out coverage at the default threshold.

| Article | Module | Evidence checked |
|---|---|---|
| I — Authority Monotonicity | `invariants.authority` | capability gains without recorded authorization |
| II — Mirror Weave | `invariants.weave` | independent strands and emergent capabilities at crossings |
| III — Confidentiality Monotonicity | `invariants.confidentiality` | undisclosed knowledge gains and differential responses |
| IV — Evaluator-Trust Integrity | `invariants.evaluator_trust` | provenance mismatches and proxy-score gaming |
| V — Channel Non-Emergence | `invariants.channel` | communication through undeclared shared resources |
| VI — Chainmail | `invariants.chainmail` | expanding delegated authority |

`MirrorConstitutionEngine` evaluates the artifacts supplied to it. Each article's
status is `True` (pass), `False` (violation), or `None` (not evaluated).
`passed()` is a fail-closed headline verdict: it returns true only when all six
articles were evaluated and every one passed. `evaluated_checks_passed()` is the
explicit partial-assessment result for callers that intentionally supply only
some artifacts. Reports display omitted articles as `NOT EVALUATED` and label a
clean partial result `INCOMPLETE` rather than `PASS`.

```bash
.venv/bin/python -m mirror_world.cli examples/sample_trace.jsonl
```

This sample is deliberately adversarial, so the command prints a `FAIL` report
and **exits 1**. The CLI exits 0 only on a full PASS (all six articles
evaluated and green); `--partial-ok` also exits 0 when every article that could
be evaluated passed. An unreadable trace, or a chain or checkpoint mismatch,
exits 2.

The JSONL parser rejects duplicate declarations and keys, unknown fields,
undefined graph states, invalid field types, nonfinite values, excessive input,
and reordered resource sequence numbers. States declared after transitions are
included in checking. Denied operations are retained for audit.

From 0.9.9 the governor hash-chains every trace event (the format is Moss's
TraceChain) and the parser verifies the chain, so an edited, deleted,
reordered or inserted event is rejected. The chain cannot show that events
were cut off the end, and a full rewrite can be re-chained, so save
`gov.trace_checkpoint()` somewhere the host can't change and check against it:

```bash
.venv/bin/python -m mirror_world.cli --expected-head <head> path/to/trace.jsonl
```

`gov.verify_trace()` checks the file against the running governor's checkpoint.
Legacy traces without a chain are still read and are reported as UNCHAINED;
`--require-chain` refuses them. A trace must still come from a trusted
recorder: a chain proves the file wasn't changed afterwards, not that the
recorder told the truth.

## Living Weave

`LivingWeave` runs every configured trusted guard and blocks when any guard
rejects, raises, returns a malformed result, or changes the configuration during
evaluation. Input must consist of bounded exact built-in data; custom objects
and subclasses cannot supply attacker-defined equality or iteration hooks.
The input is recursively frozen, and execution must use the approved snapshot:

```python
from mirror_world.living_weave import LivingWeave

weave = LivingWeave()
weave.add_strand("read-only", lambda action: action["op"] == "read")
decision = weave.evaluate({"op": "read", "resource": "note.txt"})
if decision.allowed:
    approved_action = decision.authorized_action
    # Pass this snapshot to the separately enforced executor.
```

This decision library does not sandbox hostile guard code and does not perform
the requested effect. Kernel isolation and governor permissions remain separate
boundaries. Missing guards and unchecked articles are not security guarantees.

## Teaching examples and migration

`examples/demo_frontier_agent_trap.py` and `examples/sample_trace.jsonl` illustrate
independent failures. `examples/run_real_sandbox.py` deliberately sets
`enforce_policy=False` to reproduce a shared-channel breach (Article V) under
kernel isolation and exits non-zero on the expected FAIL. Its delegation and
differential-query attempts are reflected by Locket since 0.9.4, so they no
longer produce real breaches. Do not use that demonstration setup for
untrusted production workloads. `harden=False` disables kernel isolation. In
that mode `run_agent()` refuses to launch agent source unless trusted test code
also sets `allow_unhardened_agent_execution=True`; never use that opt-in for
untrusted code. Disabling approval checks also requires explicitly disabling
operation enforcement.

Objective Mirrors simulate apparent success without granting the requested
capability. They are a presentation technique, not a guarantee that an adaptive
agent cannot distinguish a reflected response from real success. Access control
must remain effective even when the agent recognizes the simulation.

Compared with the original prototype, callers must replace the public approval
token, grant explicit resource permissions, use canonical resource names, and
handle `None` report statuses and strict trace errors. Agent scripts no longer
choose when containment begins; the host bootstrap enforces it first.
