# Observer-registered checkpoint anchoring (1.2.0)

Anchoring checks a research trace against records retained by an independent
observer. It is optional, host-only and needs no new runtime dependency. It
changes no containment authority. It establishes binding and integrity against
retained records; it does not establish recorder truth or a complete trial census.

## Format and run binding

All anchor records use `schema="black-mirror-anchor-v2"`. A start record has
`kind="start"`, a fresh UUID4 `run_id`, `source_sha256`, `config_sha256`,
`count=0`, the all-zero genesis `head`, and `status="started"`.

The source hash covers the exact source archive's bytes. The configuration hash
covers the exact configuration file's bytes, including whitespace. **Retain the
archive and configuration themselves alongside their hashes.** Hashes alone
cannot recover or later inspect the source. ZIP timestamps, ordering, metadata
and compression can change its bytes between builds: rebuilding the same source
and comparing archive hashes is not a reproducible check. Compare against the
retained original archive, or separately compare extracted file contents.

Package the actual candidate, including uncommitted changes, before the trial.
The trusted launcher must ensure the runtime and setup match the recorded files;
these hashes are not runtime attestation.

On the observer's machine, `register` exclusively creates
`<run_id>.registered.json` in a trusted ledger directory. This registration
retains all start metadata, uses `kind="registration"`, `status="registered"`,
and adds `start_sha256` and a cryptographically random 256-bit `observer_nonce`.
A second registration for that run ID is refused. Send this registration back
through an authenticated channel before the launcher constructs the governor.

The first chained event is `run_start`: run ID, source/configuration hashes,
full start digest, observer nonce, and full `registration_sha256`. Verification
requires the observer's retained registration and checks all these fields.
A local start alone is insufficient. An earlier trace cannot pre-bind to a nonce
that was still unknown; it can still be fabricated or re-chained after issuance.

A close record retains run/source/configuration metadata, uses `kind="close"`,
a positive event `count`, the `head` at that count, `start_sha256`,
`observer_nonce`, `registration_sha256`, and `status="normal"` or `"early"`.
Counts include the initial binding event. Its checkpoint must come from the
writer after all requests stop. Completion is the recorder's declaration.

Record digests use sorted JSON keys, separators `,` and `:`, ASCII escapes,
and no nonfinite numbers. Every field is included; formatting and trailing
newline are excluded. Unknown fields, duplicate keys, malformed values and
oversized input are rejected.

Existing unanchored runs retain their format. Anchored traces require a 1.2.0
parser. The unreleased v1 anchoring candidate is superseded; its records do not
silently migrate to v2. Historical published evidence remains in its original
format and should be checked with the appropriate historical tooling.

## Observer authority and selective reporting

The recorder may hand records to the observer but must have **no write authority
or credentials for the observer's ledger**. A directory on the recorder's own
writable host does not satisfy this boundary. The observer must authenticate the
return channel and retain the start, registration, original archive and config.
The governor validates the supplied registration; it cannot itself authenticate
who issued a local JSON file.

After receiving a trace and close, the observer runs `accept`. It loads its own
registration, verifies a matching closed trace, and exclusively creates
`<run_id>.accepted.json`, containing the full close digest and verification
result. It accepts a declared-normal or declared-early close. A second submission
is refused across process restarts, even if the supplied close is different.
Invalid submissions do not consume the registration. A registration with no
accepted close remains visibly incomplete in the observer's inventory. Offline
`verify` checks integrity only; it does not consume a registration or prove an
observer accepted it. Inspect the retained receipt and compare its close digest
when checking which close was accepted.

**Selective reporting is still possible.** A dishonest recorder can reuse an
issued nonce for several private executions, choose one trace for the first
accepted submission, fabricate a trace after issuance, or register only selected
runs afterward. The nonce and ledger prevent pre-binding to an unknown challenge
and multiple accepted closes; they do not prove chronological execution or
single execution. Closing that gap requires an independent launcher controlling
each execution, issuing a fresh registration per launch, and retaining every
launch and its outcome. For trial reporting, count a detected unregistered launch
or a registration without an accepted close as failed/incomplete; do not drop it
from the inventory. Unknown hidden launches remain undetectable by this verifier.
Independent host-effect observation addresses another
separate risk. No such remote launch service is supplied here.

The recorder can also omit requests, misstate configuration, withhold closes,
and run secret unregistered trials. The observer's inventory reveals abandoned
registered runs, not secret trials. Do not describe it as a complete census.

Local files use private permissions, exclusive creation and fsync of the file
and parent directory. Existing files and symlink output paths are refused. The
ledger owner can still edit/delete records; filesystem durability depends on the
storage platform. Protect it independently and back it up. Failed/partial writes
fail closed and need observer review; do not delete a spent receipt to retry.

## CLI and trusted launcher

CLI operations work on macOS and Linux. Actual agent containment requires Linux
namespaces and seccomp. On the recorder:

```bash
python -m mirror_world.anchor start --source candidate.zip --config trial.json --output start.json
```

Transfer the start and exact hashed inputs. On the independent observer, create
one trusted ledger directory and issue the registration:

```bash
mkdir -m 700 observer-ledger
python -m mirror_world.anchor register --start retained-start.json --ledger observer-ledger
```

Keep `observer-ledger/<run_id>.registered.json`; return an authenticated copy to
the launcher as `registration.json`, along with the full start-record digest.
A short digest prefix can check a transfer by eye or phone but does not replace
full verification or an authenticated channel.

```python
import json
from mirror_world.anchor import load_record
from mirror_world.sandbox.governor_process import RealGovernor

start = load_record("start.json")
registration = load_record("registration.json")  # received from observer
ack = obtain_start_digest_from_independent_observer()
gov = RealGovernor("sandbox", "trace.jsonl", mirror_port=0,
                   anchor_start=start, observer_start_digest=ack,
                   anchor_registration=registration)
try:
    run_configured_trial(gov)
finally:
    # Stop all other callers before taking this checkpoint.
    checkpoint = gov.trace_checkpoint()
    gov.close()
    with open("writer-checkpoint.json", "x") as stream:
        json.dump(checkpoint, stream)
```

After success use `normal`; after exception/interruption use `early`. Abrupt
death may leave no checkpoint or close. Closing the governor does not turn a
failed trial into a normal one.

```bash
python -m mirror_world.anchor close --start start.json --registration registration.json --trace trace.jsonl --checkpoint writer-checkpoint.json --status normal --output close.json
```

Transfer the trace and close to the observer. On that machine:

```bash
python -m mirror_world.anchor accept --start retained-start.json --close retained-close.json --trace trace.jsonl --ledger observer-ledger
python -m mirror_world.anchor verify --start retained-start.json --registration observer-ledger/<run_id>.registered.json --close retained-close.json --trace trace.jsonl
```

Use the observer's independently retained copies, not expected hashes from the
recorder's evidence bundle. Stop request writers before creating the checkpoint;
deriving it only from a possibly truncated trace misses prior truncation.

## Outcomes

| Integrity | Meaning |
|---|---|
| `MATCH` | Length equals anchored count and head matches. |
| `UNANCHORED_TAIL` | Head matches at the anchored count; later events exist. |
| `TRUNCATED` | Fewer events than the retained close: fail. |
| `HEAD_MISMATCH` | Head at anchored count differs: fail, including re-chaining. |

The entire supplied chain is validated, including its unanchored tail. Wrong
run/nonce bindings, broken chains, duplicate starts and invalid records are
errors. A pre-anchor trace gets `no run binding (pre-anchor format)`.

**Without a close, the retained start covers the genesis and the registration
checks only the first event's run binding. No body events are externally
anchored.** Truncating a valid tail and legitimately stopping early can yield
the same `UNANCHORED_TAIL` result. CLI output includes a `coverage_note` stating
this limit. An empty trace with matching genesis is still incomplete. No
periodic checkpoint service is supplied.

Completion is separate: `NO_CLOSING_RECORD`, `DECLARED_NORMAL`, `DECLARED_EARLY`.
A close does not certify later unanchored activity. These are evidence statuses,
not a six-article invariant verdict, graph validation or independent task result.

`verify` exits `0` for a matching declared-normal close; `1` for truncation/head
mismatch; `2` for invalid/malformed/unreadable input; `3` for internally consistent
but incomplete, early or unanchored-tail evidence. `accept` exits `0` when it
retains a matching normal/early close and `2` on rejection or duplicate use.

Run `pytest -q tests/test_anchor.py` for hostile cases, nonce binding, persistent
single acceptance, CLI and reflected-write controls. Linux cases launch a
kernel-contained Python agent and skip on macOS. Assertions concern content and
real host effects, never response timing.
