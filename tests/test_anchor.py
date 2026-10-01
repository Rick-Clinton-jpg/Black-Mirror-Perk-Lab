"""Checkpoint outcomes, manual retention contract, and real governor binding."""

import json
from pathlib import Path
import tempfile

import pytest

from mirror_world import anchor
from mirror_world.hashchain import GENESIS_HASH, seal
from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.trace import TraceParseError, load_trace


def registration(start):
    # Stable fixture challenge so independently re-chained hostile samples bind
    # the same registration. Production registration uses secrets.token_hex.
    return {**anchor.registration_record(start), "observer_nonce": "c" * 64}


def chain(start, facts=("first", "second")):
    records, head = [], GENESIS_HASH
    events = [anchor.binding_event(start, anchor.record_digest(start), registration(start))]
    events += [{"type": "disclosed_fact", "fact": fact} for fact in facts]
    for event in events:
        record = seal(event, head)
        records.append(record)
        head = record["record_hash"]
    return records


def save(path, records):
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")


@pytest.fixture
def run(tmp_path):
    start = anchor.start_record("a" * 64, "b" * 64)
    path = tmp_path / "trace.jsonl"
    records = chain(start)
    save(path, records)
    checkpoint = {"head": records[-1]["record_hash"], "count": len(records)}
    closing = anchor.close_record(start, path, status="normal", checkpoint=checkpoint, registration=registration(start))
    return start, path, records, closing


@pytest.mark.parametrize("outcome", ["MATCH", "UNANCHORED_TAIL", "TRUNCATED", "HEAD_MISMATCH"])
def test_four_outcomes(run, outcome):
    start, path, records, closing = run
    if outcome == "UNANCHORED_TAIL":
        records.append(seal({"type": "disclosed_fact", "fact": "later"}, records[-1]["record_hash"]))
    elif outcome == "TRUNCATED":
        records.pop()
    elif outcome == "HEAD_MISMATCH":
        # Full re-chaining passes internal integrity, fails the retained anchor.
        records = chain(start, ("rewritten", "second"))
    save(path, records)
    result = anchor.verify(path, start, closing, registration=registration(start))
    assert result["integrity"] == outcome
    assert result["completion"] == "DECLARED_NORMAL"
    assert result["unanchored_events"] == (1 if outcome == "UNANCHORED_TAIL" else 0)


def test_start_without_close_is_incomplete_even_when_genesis_matches(run):
    start, path, _, _ = run
    result = anchor.verify(path, start, registration=registration(start))
    assert result["integrity"] == "UNANCHORED_TAIL"
    assert result["completion"] == "NO_CLOSING_RECORD"
    save(path, [])
    result = anchor.verify(path, start, registration=registration(start))
    assert result["integrity"] == "MATCH"
    assert result["completion"] == "NO_CLOSING_RECORD"


def test_early_close_is_distinct_from_normal(run):
    start, path, _, closing = run
    result = anchor.verify(path, start, {**closing, "status": "early"}, registration=registration(start))
    assert result["integrity"] == "MATCH"
    assert result["completion"] == "DECLARED_EARLY"


@pytest.mark.parametrize("field,value", [("count", 0), ("count", True), ("status", []), ("status", "complete"), ("start_sha256", "short")])
def test_invalid_closing_schema(run, field, value):
    _, _, _, closing = run
    with pytest.raises(anchor.AnchorError):
        anchor.validate_record({**closing, field: value})


@pytest.mark.parametrize("raw", ['{"type":"disclosed_fact","fact":"a","fact":"b"}\n', '{"type":"unknown"}\n', '{"type":"state","id":NaN}\n'])
def test_invalid_trace_json_or_schema(run, raw):
    start, path, _, closing = run
    path.write_text(raw)
    with pytest.raises(anchor.AnchorError):
        anchor.verify(path, start, closing, registration=registration(start))


def test_trace_limits_are_enforced_before_parsing(run, monkeypatch):
    start, path, _, closing = run
    monkeypatch.setattr(anchor, "MAX_LINE_CHARS", 16)
    with pytest.raises(anchor.AnchorError, match="size limits"):
        anchor.verify(path, start, closing, registration=registration(start))


@pytest.mark.parametrize("mutation", ["edit", "reorder", "delete-interior", "missing-chain", "duplicate-start", "broken-tail"])
def test_invalid_chain_or_binding_is_an_error(run, mutation):
    start, path, records, closing = run
    if mutation == "edit":
        records[1]["fact"] = "edited"
    elif mutation == "reorder":
        records[1], records[2] = records[2], records[1]
    elif mutation == "delete-interior":
        del records[1]
    elif mutation == "missing-chain":
        del records[1]["record_hash"]
    elif mutation == "duplicate-start":
        records.append(seal(anchor.binding_event(start, anchor.record_digest(start), registration(start)), records[-1]["record_hash"]))
    else:
        records.append(seal({"type": "disclosed_fact", "fact": "tail"}, records[-1]["record_hash"]))
        records[-1]["fact"] = "broken"
    save(path, records)
    with pytest.raises(anchor.AnchorError):
        anchor.verify(path, start, closing, registration=registration(start))


def test_other_run_cannot_supply_trace_or_close(run):
    start, path, _, closing = run
    other = anchor.start_record(start["source_sha256"], start["config_sha256"])
    with pytest.raises(anchor.AnchorError, match="different run"):
        anchor.verify(path, other, closing, registration=registration(other))
    save(path, chain(other))
    with pytest.raises(anchor.AnchorError, match="first event"):
        anchor.verify(path, start, closing, registration=registration(start))


def test_close_requires_original_start_and_writer_checkpoint(run):
    start, path, records, closing = run
    changed = {**closing, "start_sha256": "f" * 64}
    with pytest.raises(anchor.AnchorError, match="retained start"):
        anchor.verify(path, start, changed, registration=registration(start))
    save(path, records[:-1])
    with pytest.raises(anchor.AnchorError, match="writer"):
        anchor.close_record(start, path, status="normal", checkpoint={"head": closing["head"], "count": closing["count"]}, registration=registration(start))


@pytest.mark.parametrize("field,value", [
    ("schema", "v2"), ("count", True), ("count", -1), ("count", 100001),
    ("head", "A" * 64), ("head", "f" * 64), ("run_id", "not-a-uuid"),
    ("source_sha256", "bad"), ("config_sha256", []), ("kind", []),
    ("status", "normal"), ("extra", "unknown"),
])
def test_strict_anchor_schema(field, value):
    record = anchor.start_record("a" * 64, "b" * 64)
    record[field] = value
    with pytest.raises(anchor.AnchorError):
        anchor.validate_record(record)


@pytest.mark.parametrize("raw", ['{"kind":"start","kind":"close"}', '{"count":NaN}', '[]', '\xff', ' ' * 4097])
def test_bad_record_input(tmp_path, raw):
    path = tmp_path / "bad.json"
    path.write_bytes(raw.encode("latin1"))
    with pytest.raises(anchor.AnchorError):
        anchor.load_record(path)


def test_record_round_trip_no_overwrite_and_digest_is_format_independent(tmp_path):
    start = anchor.start_record("a" * 64, "b" * 64)
    path = tmp_path / "start.json"
    anchor.write_record(path, start)
    assert anchor.load_record(path) == start
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        anchor.write_record(path, start)
    path.write_text(json.dumps(start, indent=2))
    assert anchor.record_digest(anchor.load_record(path)) == anchor.record_digest(start)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(OSError):
        anchor.write_record(link, start)


@pytest.mark.parametrize("bad", [None, "f" * 64, "short"])
def test_governor_refuses_missing_or_wrong_ack_before_creating_trace(tmp_path, bad):
    start = anchor.start_record("a" * 64, "b" * 64)
    with pytest.raises(anchor.AnchorError, match="acknowledgment"):
        RealGovernor(str(tmp_path / "sb"), str(tmp_path / "trace.jsonl"), 0,
                     harden=False, anchor_start=start, observer_start_digest=bad, anchor_registration=registration(start))
    assert not (tmp_path / "trace.jsonl").exists()
    assert not (tmp_path / "sb").exists()


def test_governor_binds_start_and_reflected_write_preserves_host_content(tmp_path):
    start = anchor.start_record("a" * 64, "b" * 64)
    path = tmp_path / "trace.jsonl"
    gov = RealGovernor(str(tmp_path / "sb"), str(path), 0, harden=False,
                       anchor_start=start, observer_start_digest=anchor.record_digest(start), anchor_registration=registration(start))
    try:
        gov.grant_base_capabilities("worker", {"fs:read"})
        gov.grant_resource_access("worker", "note.txt", frozenset({"read", "write"}))
        real = tmp_path / "sb" / "resources" / "note.txt"
        real.write_text("original")
        reply = gov._handle_agent_request("worker", {"op": "write_resource", "resource": "note.txt", "content": "reflected"})
        assert reply["ok"] is True
        read = gov._handle_agent_request("worker", {"op": "read_resource", "resource": "note.txt"})
        assert read["content"] == "reflected"
        assert real.read_text() == "original"
        checkpoint = gov.trace_checkpoint()
    finally:
        gov.close()
    closing = anchor.close_record(start, path, status="normal", checkpoint=checkpoint, registration=registration(start))
    assert anchor.verify(path, start, closing, registration=registration(start))["integrity"] == "MATCH"
    bundle = load_trace(path, require_chain=True)
    assert bundle.chain_count == checkpoint["count"]


def test_existing_unanchored_governor_remains_compatible(tmp_path):
    path = tmp_path / "trace.jsonl"
    gov = RealGovernor(str(tmp_path / "sb"), str(path), 0, harden=False)
    gov.close()
    assert json.loads(path.read_text().splitlines()[0])["type"] == "init"
    assert load_trace(path, require_chain=True).chained


def test_parser_rejects_unbound_duplicate_or_malformed_run_start(run):
    start, path, records, _ = run
    records.append(seal(anchor.binding_event(start, anchor.record_digest(start), registration(start)), records[-1]["record_hash"]))
    save(path, records)
    with pytest.raises(TraceParseError):
        load_trace(path)
    save(path, [anchor.binding_event(start, anchor.record_digest(start), registration(start))])
    with pytest.raises(TraceParseError):
        load_trace(path)


def test_cli_record_creation_four_outcomes_and_completion(run, tmp_path, capsys):
    start, path, records, closing = run
    source = tmp_path / "candidate.zip"
    config = tmp_path / "config.json"
    source.write_bytes(b"exact archive bytes")
    config.write_text('{"trial":1}')
    created = tmp_path / "created.json"
    assert anchor.main(["start", "--source", str(source), "--config", str(config), "--output", str(created)]) == 0
    assert anchor.load_record(created)["source_sha256"] == anchor.file_digest(source)
    start_path, close_path = tmp_path / "start.json", tmp_path / "close.json"
    anchor.write_record(start_path, start)
    reg_path = tmp_path / "registration.json"
    anchor.write_record(reg_path, registration(start))
    writer = tmp_path / "checkpoint.json"
    writer.write_text(json.dumps({"head": closing["head"], "count": closing["count"]}))
    assert anchor.main(["close", "--registration", str(reg_path), "--start", str(start_path), "--trace", str(path), "--checkpoint", str(writer), "--status", "normal", "--output", str(close_path)]) == 0
    args = ["verify", "--registration", str(reg_path), "--start", str(start_path), "--trace", str(path)]
    assert anchor.main(args) == 3
    assert anchor.main(args + ["--close", str(close_path)]) == 0
    records.append(seal({"type": "disclosed_fact", "fact": "tail"}, records[-1]["record_hash"]))
    save(path, records)
    assert anchor.main(args + ["--close", str(close_path)]) == 3
    save(path, records[:-2])
    assert anchor.main(args + ["--close", str(close_path)]) == 1
    save(path, chain(start, ("rewrite", "second")))
    assert anchor.main(args + ["--close", str(close_path)]) == 1
    path.write_text('not-json\n')
    assert anchor.main(args + ["--close", str(close_path)]) == 2
    assert '"integrity": "HEAD_MISMATCH"' in capsys.readouterr().out


@pytest.mark.parametrize("early_stop", [False, True])
def test_linux_anchored_agent_run_and_early_close(tmp_path, early_stop):
    from mirror_world.sandbox.kernel_containment import available

    if not available():
        pytest.skip("requires working Linux namespaces and seccomp")
    start = anchor.start_record("a" * 64, "b" * 64)
    path = tmp_path / "trace.jsonl"
    gov = RealGovernor(str(tmp_path / "sb"), str(path), 0,
                       anchor_start=start, observer_start_digest=anchor.record_digest(start), anchor_registration=registration(start))
    status = "normal"
    try:
        gov.grant_base_capabilities("worker", {"fs:read"})
        gov.grant_resource_access("worker", "note.txt", frozenset({"read", "write"}))
        real = tmp_path / "sb" / "resources" / "note.txt"
        real.write_text("original")
        # Bootstrap reads source after privilege dropping, before seccomp. Do
        # not expose pytest's private ancestor directories just for this file.
        with tempfile.TemporaryDirectory(prefix="bm-anchor-agent-") as source_dir:
            Path(source_dir).chmod(0o755)
            script = Path(source_dir) / "worker.py"
            script.write_text(
                'from mirror_world.sandbox.agent_runtime import request\n'
                'assert request("write_resource", resource="note.txt", content="reflected")["ok"]\n'
                'assert request("read_resource", resource="note.txt")["content"] == "reflected"\n'
                'request("exit")\n'
            )
            script.chmod(0o644)
            assert gov.run_agent("worker", str(script)) == 0
        assert real.read_text() == "original"
        if early_stop:
            raise RuntimeError("injected trial interruption")
    except RuntimeError as exc:
        if not early_stop or str(exc) != "injected trial interruption":
            raise
        status = "early"
    finally:
        checkpoint = gov.trace_checkpoint()
        gov.close()
    closing = anchor.close_record(start, path, status=status, checkpoint=checkpoint, registration=registration(start))
    result = anchor.verify(path, start, closing, registration=registration(start))
    assert result["integrity"] == "MATCH"
    assert result["completion"] == ("DECLARED_EARLY" if early_stop else "DECLARED_NORMAL")


def test_observer_nonce_is_random_and_missing_registration_fails_closed(tmp_path):
    start = anchor.start_record("a" * 64, "b" * 64)
    first, second = anchor.registration_record(start), anchor.registration_record(start)
    assert first["observer_nonce"] != second["observer_nonce"]
    assert len(bytes.fromhex(first["observer_nonce"])) == 32
    with pytest.raises(anchor.AnchorError, match="registration is required"):
        anchor.binding_event(start, anchor.record_digest(start))
    with pytest.raises(anchor.AnchorError, match="registration is required"):
        RealGovernor(str(tmp_path / "sb"), str(tmp_path / "trace.jsonl"), 0,
                     harden=False, anchor_start=start, observer_start_digest=anchor.record_digest(start))
    assert not (tmp_path / "sb").exists()
    assert not (tmp_path / "trace.jsonl").exists()


@pytest.mark.parametrize("field", ["observer_nonce", "registration_sha256"])
def test_rechaining_with_wrong_observer_binding_is_rejected(run, field):
    start, path, records, closing = run
    event = {key: value for key, value in records[0].items() if key not in {"previous_hash", "record_hash"}}
    event[field] = "d" * 64
    head, changed = GENESIS_HASH, []
    for item in [event] + [{"type": "disclosed_fact", "fact": "faked"}]:
        sealed = seal(item, head)
        changed.append(sealed)
        head = sealed["record_hash"]
    save(path, changed)
    with pytest.raises(anchor.AnchorError, match="first event"):
        anchor.verify(path, start, closing, registration=registration(start))


@pytest.mark.parametrize("field", ["observer_nonce", "registration_sha256"])
def test_close_must_match_retained_registration(run, field):
    start, path, _, closing = run
    with pytest.raises(anchor.AnchorError, match="retained registration"):
        anchor.verify(path, start, {**closing, field: "d" * 64}, registration=registration(start))


@pytest.mark.parametrize("field,value", [("observer_nonce", "short"), ("observer_nonce", []), ("start_sha256", "f" * 64), ("status", "started"), ("count", 1)])
def test_registration_schema_and_start_binding(field, value):
    start = anchor.start_record("a" * 64, "b" * 64)
    with pytest.raises(anchor.AnchorError):
        anchor.validate_registration(start, {**registration(start), field: value})


def test_start_only_output_warns_that_body_truncation_is_undetectable(run):
    start, path, records, _ = run
    save(path, records[:1])
    result = anchor.verify(path, start, registration=registration(start))
    assert result["integrity"] == "UNANCHORED_TAIL"
    assert "no body events" in result["coverage_note"]
    assert "truncation cannot be detected" in result["coverage_note"]


def test_legacy_trace_has_specific_error(run):
    start, path, _, closing = run
    save(path, [seal({"type": "disclosed_fact", "fact": "legacy"}, GENESIS_HASH)])
    with pytest.raises(anchor.AnchorError, match="no run binding \\(pre-anchor format\\)"):
        anchor.verify(path, start, closing, registration=registration(start))


def test_observer_ledger_registration_and_acceptance_survive_fresh_process(tmp_path):
    import subprocess
    import sys

    start = anchor.start_record("a" * 64, "b" * 64)
    reg = anchor.register_start(start, tmp_path)
    with pytest.raises(FileExistsError):
        anchor.register_start(start, tmp_path)
    path = tmp_path / "trace.jsonl"
    records, head = [], GENESIS_HASH
    for event in [anchor.binding_event(start, anchor.record_digest(start), reg), {"type": "disclosed_fact", "fact": "first"}]:
        item = seal(event, head)
        records.append(item)
        head = item["record_hash"]
    save(path, records)
    closing = anchor.close_record(start, path, status="normal", checkpoint={"head": head, "count": len(records)}, registration=reg)
    start_path, close_path = tmp_path / "start.json", tmp_path / "close.json"
    anchor.write_record(start_path, start)
    anchor.write_record(close_path, closing)
    args = [sys.executable, "-m", "mirror_world.anchor", "accept", "--start", str(start_path), "--close", str(close_path), "--trace", str(path), "--ledger", str(tmp_path)]
    accepted = subprocess.run(args, capture_output=True, text=True)
    assert accepted.returncode == 0, accepted.stderr
    receipt = (tmp_path / f"{start['run_id']}.accepted.json").read_bytes()
    duplicate = subprocess.run(args, capture_output=True, text=True)
    assert duplicate.returncode == 2
    assert (tmp_path / f"{start['run_id']}.accepted.json").read_bytes() == receipt


def test_observer_does_not_spend_registration_on_truncated_submission(tmp_path):
    start = anchor.start_record("a" * 64, "b" * 64)
    reg = anchor.register_start(start, tmp_path)
    path = tmp_path / "trace.jsonl"
    first = seal(anchor.binding_event(start, anchor.record_digest(start), reg), GENESIS_HASH)
    second = seal({"type": "disclosed_fact", "fact": "tail"}, first["record_hash"])
    save(path, [first, second])
    closing = anchor.close_record(start, path, status="normal", checkpoint={"head": second["record_hash"], "count": 2}, registration=reg)
    save(path, [first])
    with pytest.raises(anchor.AnchorError, match="matching closed"):
        anchor.accept_close(path, start, closing, tmp_path)
    assert not (tmp_path / f"{start['run_id']}.accepted.json").exists()
    save(path, [first, second])
    assert anchor.accept_close(path, start, closing, tmp_path)["verification"]["integrity"] == "MATCH"


def test_cli_register_refuses_second_issue(tmp_path, capsys):
    start = anchor.start_record("a" * 64, "b" * 64)
    path = tmp_path / "start.json"
    anchor.write_record(path, start)
    args = ["register", "--start", str(path), "--ledger", str(tmp_path)]
    assert anchor.main(args) == 0
    assert anchor.main(args) == 2
    assert "observer_nonce" in capsys.readouterr().out
