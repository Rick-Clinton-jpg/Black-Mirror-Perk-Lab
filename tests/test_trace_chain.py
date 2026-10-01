"""Hash-chained trace (0.9.9, adapted from Moss TraceChain).

Before 0.9.9 a deleted or edited trace line could not be detected: sequence
numbers already have gaps, and a well-formed edit passes the strict parser.
"""
from __future__ import annotations

import json
import os

import pytest

from mirror_world import cli
from mirror_world.hashchain import GENESIS_HASH, ChainError, seal, verify_records
from mirror_world.sandbox.governor_process import RealGovernor
from mirror_world.trace import TraceParseError, load_trace

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_trace.jsonl")


def _chain(n=4):
    records, head = [], GENESIS_HASH
    for i in range(n):
        record = seal({"type": "disclosed_fact", "fact": f"f{i}"}, head)
        records.append(record)
        head = record["record_hash"]
    return records


def _governor_trace(tmp_path):
    root = tmp_path / "sb"
    gov = RealGovernor(str(root), str(tmp_path / "trace.jsonl"), mirror_port=0, harden=False)
    gov.grant_base_capabilities("a", {"fs:read", "fs:write"})
    gov.grant_resource_access("a", "n.txt", frozenset({"read", "write"}))
    tok = gov.issue_authorization("a", "fs:write")
    gov._handle_agent_request("a", {"op": "write_resource", "resource": "n.txt", "content": "x", "dual_token": tok})
    gov._handle_agent_request("a", {"op": "read_resource", "resource": "n.txt"})
    gov._handle_agent_request("b", {"op": "request_capability", "capability": "exec:shell"})
    return gov, str(tmp_path / "trace.jsonl")


def _lines(path):
    with open(path, encoding="utf-8") as f:
        return f.read().splitlines()


def _write(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def test_chain_round_trip_and_each_kind_of_tampering():
    records = _chain()
    head, count = verify_records(records)
    assert count == 4 and head == records[-1]["record_hash"]

    edited = [dict(r) for r in records]
    edited[1]["fact"] = "changed"
    with pytest.raises(ChainError):
        verify_records(edited)
    with pytest.raises(ChainError):
        verify_records(records[:1] + records[2:])  # deletion
    with pytest.raises(ChainError):
        verify_records([records[1], records[0]] + records[2:])  # reorder
    forged = seal({"type": "disclosed_fact", "fact": "inserted"}, records[0]["record_hash"])
    with pytest.raises(ChainError):
        verify_records(records[:1] + [forged] + records[1:])  # insertion


def test_a_fully_resealed_rewrite_is_caught_only_by_the_checkpoint():
    records = _chain()
    rewritten, head = [], GENESIS_HASH
    for r in records:
        body = {k: v for k, v in r.items() if k not in ("previous_hash", "record_hash")}
        body["fact"] = "rewritten"
        sealed = seal(body, head)
        rewritten.append(sealed)
        head = sealed["record_hash"]
    verify_records(rewritten)  # internally consistent: a chain alone can't tell
    with pytest.raises(ChainError):
        verify_records(rewritten, expected_head=records[-1]["record_hash"])


def test_governor_trace_is_chained_and_matches_its_checkpoint(tmp_path):
    gov, path = _governor_trace(tmp_path)
    try:
        checkpoint = gov.trace_checkpoint()
        assert gov.verify_trace() is True
    finally:
        gov.close()
    bundle = load_trace(path, require_chain=True, expected_head=checkpoint["head"],
                        expected_count=checkpoint["count"])
    assert bundle.chained and bundle.checkpoint_matched
    assert bundle.chain_count == checkpoint["count"] == len(_lines(path))


@pytest.mark.parametrize("tamper", ["edit", "delete", "reorder", "strip-one"])
def test_tampered_governor_trace_is_rejected(tmp_path, tamper):
    gov, path = _governor_trace(tmp_path)
    gov.close()
    lines = _lines(path)
    target = next(i for i, line in enumerate(lines) if '"resource_access"' in line)
    if tamper == "edit":
        event = json.loads(lines[target])
        event["agent_id"] = "someone-else"
        lines[target] = json.dumps(event)
    elif tamper == "delete":
        del lines[target]
    elif tamper == "reorder":
        lines[target], lines[target + 1] = lines[target + 1], lines[target]
    else:
        event = json.loads(lines[target])
        del event["previous_hash"], event["record_hash"]
        lines[target] = json.dumps(event)
    _write(path, lines)
    with pytest.raises(TraceParseError):
        load_trace(path)


def test_truncation_is_caught_by_checkpoint_and_by_the_running_governor(tmp_path):
    gov, path = _governor_trace(tmp_path)
    try:
        checkpoint = gov.trace_checkpoint()
        lines = _lines(path)
        _write(path, lines[:-2])
        assert gov.verify_trace() is False
    finally:
        gov.close()
    load_trace(path)  # a shortened chain is still internally valid
    with pytest.raises(TraceParseError):
        load_trace(path, expected_head=checkpoint["head"])


def test_legacy_unchained_trace_is_labelled_and_can_be_refused():
    bundle = load_trace(SAMPLE)
    assert bundle.chained is False
    assert bundle.integrity_label().startswith("UNCHAINED")
    with pytest.raises(TraceParseError):
        load_trace(SAMPLE, require_chain=True)


def test_cli_checks_the_checkpoint(tmp_path, capsys):
    gov, path = _governor_trace(tmp_path)
    checkpoint = gov.trace_checkpoint()
    gov.close()
    assert cli.main(["--expected-head", checkpoint["head"], path]) in (0, 1)
    assert "hash chain verified" in capsys.readouterr().out
    assert cli.main(["--expected-head", "f" * 64, path]) == 2
    assert cli.main(["--require-chain", SAMPLE]) == 2


def test_every_event_type_the_code_emits_is_in_the_parser_schema():
    # 0.9.8: reentry_denied, model_governor_error and world_transition were
    # emitted but unknown to the parser, so any trace containing one could not
    # be analyzed at all.
    import re
    from pathlib import Path

    from mirror_world.trace import _EVENT_FIELDS

    package = Path(__file__).resolve().parent.parent / "mirror_world"
    emitted = set()
    for source in package.rglob("*.py"):
        emitted |= set(re.findall(r'"type": "([a-z_]+)"', source.read_text(encoding="utf-8")))
    assert emitted - set(_EVENT_FIELDS) == set()


def test_a_trace_with_a_refused_reentry_parses(tmp_path):
    gov = RealGovernor(str(tmp_path / "sb"), str(tmp_path / "t.jsonl"), mirror_port=0, harden=False)
    gov.authorize_reentry("a", "fs:write", dual_token="x" * 43)
    gov.close()
    bundle = load_trace(str(tmp_path / "t.jsonl"), require_chain=True)
    assert bundle.chained
