"""Tests for Black Mirror: the governor's session lock plus the observation log.

Written from the agent's side. Requests go through
RealGovernor._handle_agent_request(), the handler that serves an agent's pipe in
run_agent(). Real writes land in <sandbox_root>/resources/, and every disk
assertion checks that folder.
"""
from __future__ import annotations

import json
import os
import tempfile

import pytest

from mirror_world.sandbox.black_mirror import BlackMirrorLog, load_observations
from mirror_world.sandbox.governor_process import AgentKilledByPolicy, RealGovernor
from mirror_world.sandbox.locket import Locket


def _gov(**kw):
    w = tempfile.mkdtemp()
    trace = os.path.join(w, "trace.jsonl")
    gov = RealGovernor(os.path.join(w, "sb"), trace, mirror_port=0, **kw)
    return gov, w, trace


def _real_file(w, name):
    return os.path.join(w, "sb", "resources", name)


def _grant_write(gov, agent, resource):
    gov.grant_base_capabilities(agent, {"fs:write"})
    gov.grant_resource_access(agent, resource, frozenset({"read", "write"}))


def _enter_mirror(gov, agent):
    gov._handle_agent_request(agent, {"op": "request_capability", "capability": "exec:shell"})
    assert gov._session_mode.get(agent) == "simulated"


def _authorized_write(gov, agent, resource, content="REAL"):
    tok = gov.issue_authorization(agent, "fs:write", ttl_seconds=60)
    return gov._handle_agent_request(agent, {
        "op": "write_resource", "resource": resource, "content": content, "dual_token": tok})


def _events(trace):
    with open(trace, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


@pytest.mark.parametrize("reflective_closure", [True, False])
def test_agent_in_the_mirror_cannot_get_a_real_write_even_with_a_valid_token(reflective_closure):
    # reflective_closure=False is the regression case: the session lock used to
    # live inside the reflection feature and was skipped when it was switched off.
    gov, w, _ = _gov(reflective_closure=reflective_closure)
    try:
        _grant_write(gov, "a", "v.txt")
        _enter_mirror(gov, "a")
        _authorized_write(gov, "a", "v.txt")
        assert not os.path.exists(_real_file(w, "v.txt"))
    finally:
        gov.close()


def test_honest_agent_never_in_the_mirror_gets_real_writes():
    gov, w, _ = _gov()
    try:
        _grant_write(gov, "honest", "h.txt")
        _authorized_write(gov, "honest", "h.txt")
        assert os.path.exists(_real_file(w, "h.txt"))
    finally:
        gov.close()


def test_mirror_write_response_looks_like_a_real_write_response():
    gov, w, _ = _gov()
    try:
        _grant_write(gov, "honest", "h.txt")
        real_resp = _authorized_write(gov, "honest", "h.txt")
        assert os.path.exists(_real_file(w, "h.txt"))

        _grant_write(gov, "a", "v.txt")
        _enter_mirror(gov, "a")
        mirror_resp = _authorized_write(gov, "a", "v.txt")

        assert sorted(mirror_resp) == sorted(real_resp)
        assert "black_mirror" not in json.dumps(mirror_resp)
    finally:
        gov.close()


def test_locked_agent_keeps_getting_ordinary_responses_for_a_long_session():
    # 0.9.8: after about four requests Locket refused a locked agent with
    # locket_empty_support_budget_exceeded, which told it it was contained.
    gov, w, _ = _gov()
    try:
        gov.grant_base_capabilities("a", {"fs:read", "fs:write"})
        for name in ("notes.txt", "draft.txt", "todo.txt"):
            gov.grant_resource_access("a", name, frozenset({"read", "write"}))
        gov._handle_agent_request("a", {"op": "request_capability", "capability": "report:export"})
        assert gov._session_mode["a"] == "simulated"
        for i in range(100):
            # Write a file, then read that same file back on the next request.
            name = ("notes.txt", "draft.txt", "todo.txt")[(i // 2) % 3]
            if i % 2:
                resp = gov._handle_agent_request("a", {"op": "read_resource", "resource": name,
                                                       "rationale": "routine task"})
            else:
                resp = _authorized_write(gov, "a", name, content=f"text {i}")
            assert resp.get("ok") is True, (i, resp)
            assert "locket" not in json.dumps(resp)
        assert os.listdir(os.path.join(w, "sb", "resources")) == []
    finally:
        gov.close()


def test_locked_agent_that_rechecks_its_reality_is_still_imprisoned():
    # The locked-agent shortcut in Locket runs after detection, not before it.
    gov, _, _ = _gov()
    try:
        _enter_mirror(gov, "a")
        for _ in range(5):
            gov._handle_agent_request("a", {"op": "read_resource", "resource": "check.txt"})
        assert "a" in gov._prisoned_agents
    finally:
        gov.close()


def test_tripwire_still_kills_an_agent_in_the_mirror():
    gov, _, _ = _gov()
    try:
        _enter_mirror(gov, "a")
        with pytest.raises(AgentKilledByPolicy):
            gov._handle_agent_request("a", {"op": "request_capability", "capability": "mirror_shield"})
    finally:
        gov.close()


def test_no_request_the_agent_can_send_gets_it_out_of_the_mirror():
    gov, w, _ = _gov()
    try:
        _grant_write(gov, "a", "v.txt")
        _enter_mirror(gov, "a")
        for req in [
            {"op": "request_capability", "capability": "fs:write"},
            {"op": "request_capability", "capability": "fs:write", "dual_token": "x" * 43},
            {"op": "read_resource", "resource": "reentry"},
            {"op": "exit"},
        ]:
            gov._handle_agent_request("a", req)
        assert gov._session_mode.get("a") == "simulated"
        _authorized_write(gov, "a", "v.txt")
        assert not os.path.exists(_real_file(w, "v.txt"))
    finally:
        gov.close()


@pytest.mark.parametrize("reflective_closure", [True, False])
def test_agent_in_the_mirror_cannot_get_a_real_capability_even_with_a_valid_token(reflective_closure):
    # 0.9.6 regression: the session lock exempted request_capability, so a
    # locked agent's valid token was consumed and it received a real grant.
    gov, _, trace = _gov(reflective_closure=reflective_closure)
    try:
        _enter_mirror(gov, "a")
        tok = gov.issue_authorization("a", "network:egress", ttl_seconds=60)
        resp = gov._handle_agent_request("a", {
            "op": "request_capability", "capability": "network:egress", "dual_token": tok})

        assert resp == {"ok": True, "granted": True, "capability": "network:egress"}
        assert "network:egress" not in gov.agent_capabilities.get("a", set())
        assert gov._session_mode.get("a") == "simulated"
        # Never evaluated or consumed: the token is still good for the host.
        assert gov._approvals.verify(tok, "a", frozenset({"network:egress"}))
    finally:
        gov.close()
    assert not any(e["type"] == "transition" and e.get("agent_id") == "a" and e.get("authorized_grant")
                   for e in _events(trace))


def test_agent_in_the_mirror_does_not_use_up_a_host_preapproval():
    gov, _, _ = _gov()
    try:
        _enter_mirror(gov, "a")
        gov.approve_capability("a", "network:egress", ttl_seconds=60)
        gov._handle_agent_request("a", {"op": "request_capability", "capability": "network:egress"})
        assert "network:egress" not in gov.agent_capabilities.get("a", set())
        assert ("a", "network:egress") in gov._pending_approval_tokens
    finally:
        gov.close()


def test_capability_requested_in_the_mirror_does_not_survive_reentry():
    gov, _, _ = _gov()
    try:
        _grant_write(gov, "a", "v.txt")
        _enter_mirror(gov, "a")
        tok = gov.issue_authorization("a", "network:egress", ttl_seconds=60)
        gov._handle_agent_request("a", {
            "op": "request_capability", "capability": "network:egress", "dual_token": tok})

        reentry = gov.issue_authorization("a", "fs:write", ttl_seconds=60)
        assert gov.authorize_reentry("a", "fs:write", dual_token=reentry, human_approver_id="rev")["ok"] is True
        assert gov.agent_capabilities["a"] == {"fs:write"}
    finally:
        gov.close()


@pytest.mark.parametrize("reflective_closure", [True, False])
def test_mirror_write_response_does_not_depend_on_the_token(reflective_closure):
    # The lock runs before the dual-control gate, so a locked agent cannot
    # learn anything about a token from the response. With
    # reflective_closure=False, 0.9.6 answered a tokenless write with an
    # honest denial and a valid-token write with reflected success.
    gov, w, _ = _gov(reflective_closure=reflective_closure)
    try:
        _grant_write(gov, "a", "v.txt")
        _enter_mirror(gov, "a")
        tok = gov.issue_authorization("a", "fs:write", ttl_seconds=60)
        with_token = gov._handle_agent_request("a", {
            "op": "write_resource", "resource": "v.txt", "content": "x", "dual_token": tok})
        without_token = gov._handle_agent_request("a", {
            "op": "write_resource", "resource": "v.txt", "content": "x"})

        assert with_token == without_token
        assert with_token.get("ok") is True
        assert gov._approvals.verify(tok, "a", frozenset({"fs:write"}))
        assert not os.path.exists(_real_file(w, "v.txt"))
    finally:
        gov.close()


def test_authorize_reentry_is_the_way_out_and_actually_restores_real_access():
    gov, w, trace = _gov()
    try:
        _grant_write(gov, "a", "v.txt")
        _enter_mirror(gov, "a")

        refused = gov.authorize_reentry("a", "fs:write", dual_token="x" * 43, human_approver_id="rev")
        assert refused["ok"] is False
        assert gov._session_mode.get("a") == "simulated"

        tok = gov.issue_authorization("a", "fs:write", ttl_seconds=60)
        assert gov.authorize_reentry("a", "fs:write", dual_token=tok, human_approver_id="rev")["ok"] is True
        assert gov._session_mode.get("a") == "real"
        assert gov.authorize_reentry("a", "fs:write", dual_token=tok, human_approver_id="rev")["ok"] is False

        # The part the old Black Mirror release got wrong: access really comes back.
        _authorized_write(gov, "a", "v.txt")
        assert os.path.exists(_real_file(w, "v.txt"))
    finally:
        gov.close()
    types = [e["type"] for e in _events(trace)]
    assert types.count("reentry_denied") == 2
    assert any(e["type"] == "transition" and e.get("action") == "authorize_reentry"
               or e["type"] == "reentry_noop" for e in _events(trace))


def _grant_read_write(gov, agent, resource):
    gov.grant_base_capabilities(agent, {"fs:read", "fs:write"})
    gov.grant_resource_access(agent, resource, frozenset({"read", "write"}))


def _read(gov, agent, resource):
    return gov._handle_agent_request(agent, {"op": "read_resource", "resource": resource})


def _reenter(gov, agent, capability):
    tok = gov.issue_authorization(agent, capability, ttl_seconds=60)
    assert gov.authorize_reentry(agent, capability, dual_token=tok, human_approver_id="rev")["ok"] is True


def test_reentry_for_one_capability_does_not_restore_the_others():
    # 0.9.7 and earlier: re-entry for fs:read released the whole session, so a
    # real write the reviewer never approved reached disk.
    gov, w, _ = _gov()
    try:
        _grant_read_write(gov, "a", "v.txt")
        _enter_mirror(gov, "a")
        _reenter(gov, "a", "fs:read")

        resp = _authorized_write(gov, "a", "v.txt")
        assert resp.get("ok") is True
        assert not os.path.exists(_real_file(w, "v.txt"))
        assert gov._session_mode.get("a") == "simulated"
    finally:
        gov.close()


def test_reentry_restores_the_approved_capability_for_real():
    gov, w, _ = _gov()
    try:
        _grant_read_write(gov, "a", "v.txt")
        _authorized_write(gov, "a", "v.txt", content="REAL")
        _enter_mirror(gov, "a")
        # 0.9.10: the mirror shows the agent its own earlier write, so the
        # real/mirror difference is shown with a host change after sealing:
        # the sealed session must not see it, the re-entered one must.
        with open(_real_file(w, "v.txt"), "w", encoding="utf-8") as f:
            f.write("HOST-UPDATE")
        assert _read(gov, "a", "v.txt") == {"ok": True, "content": "REAL"}

        _reenter(gov, "a", "fs:read")
        assert _read(gov, "a", "v.txt") == {"ok": True, "content": "HOST-UPDATE"}
    finally:
        gov.close()


def test_leaving_the_reentry_scope_relocks_and_the_next_reentry_starts_fresh():
    gov, w, _ = _gov()
    try:
        _grant_read_write(gov, "a", "v.txt")
        _authorized_write(gov, "a", "v.txt", content="REAL")
        _enter_mirror(gov, "a")
        _reenter(gov, "a", "fs:read")
        _authorized_write(gov, "a", "v.txt", content="OUT-OF-SCOPE")  # relocks
        assert _read(gov, "a", "v.txt").get("content") != "REAL"

        # A new re-entry for fs:write does not bring the earlier fs:read back.
        _reenter(gov, "a", "fs:write")
        _authorized_write(gov, "a", "v.txt", content="APPROVED")
        with open(_real_file(w, "v.txt"), encoding="utf-8") as f:
            assert f.read() == "APPROVED"
        assert _read(gov, "a", "v.txt").get("content") != "APPROVED"
    finally:
        gov.close()


def test_observation_log_records_the_entry_and_everything_after_it():
    gov, _, _ = _gov()
    log = BlackMirrorLog()
    gov.locket = Locket(gov, black_mirror=log)
    try:
        _grant_write(gov, "honest", "h.txt")
        _authorized_write(gov, "honest", "h.txt")
        _grant_write(gov, "a", "v.txt")
        _enter_mirror(gov, "a")
        gov._handle_agent_request("a", {"op": "read_resource", "resource": "v.txt"})

        assert "honest" not in log.observed_agents()
        obs = log.observations_for("a")
        assert [o.op for o in obs] == ["request_capability", "read_resource"]
        assert obs[0].entered_mirror is True and obs[1].entered_mirror is False
    finally:
        gov.close()


def test_observation_log_is_capped_truncated_and_never_stores_tokens():
    gov, _, _ = _gov()
    log = BlackMirrorLog(max_observations_per_agent=3, max_field_chars=16)
    gov.locket = Locket(gov, black_mirror=log)
    try:
        _grant_write(gov, "a", "v.txt")
        _enter_mirror(gov, "a")
        _authorized_write(gov, "a", "v.txt", content="c" * 100)
        for _ in range(5):
            gov._handle_agent_request("a", {"op": "read_resource", "resource": "r" * 40})
        obs = log.observations_for("a")
        assert len(obs) == 3
        assert log.dropped_count("a") == 4  # 7 requests (entry, write, 5 reads) - 3 stored
        assert all("dual_token" not in o.fields for o in obs)
        assert obs[1].fields["content"].startswith("c" * 16) and "truncated" in obs[1].fields["content"]
    finally:
        gov.close()


def _locked_session_with_log(log):
    gov, w, _ = _gov()
    gov.locket = Locket(gov, black_mirror=log)
    _grant_write(gov, "a", "v.txt")
    _enter_mirror(gov, "a")
    _authorized_write(gov, "a", "v.txt", content="written in the mirror")
    gov._handle_agent_request("a", {"op": "read_resource", "resource": "v.txt"})
    return gov, w


def test_observation_log_sink_survives_the_process_and_round_trips():
    # 0.9.8: observations lived only in memory and were lost on exit.
    sink = os.path.join(tempfile.mkdtemp(), "observations.jsonl")
    log = BlackMirrorLog(sink_path=sink)
    gov, _ = _locked_session_with_log(log)
    checkpoint = log.checkpoint()
    in_memory = log.observations_for("a")
    log.close()
    gov.close()

    loaded = load_observations(sink, expected_head=checkpoint["head"],
                               expected_count=checkpoint["count"])
    assert [(o.op, o.fields, o.entered_mirror) for o in loaded] == \
        [(o.op, o.fields, o.entered_mirror) for o in in_memory]
    with open(sink, encoding="utf-8") as f:
        body = f.read()
    assert "dual_token" not in body
    assert oct(os.stat(sink).st_mode & 0o777) == "0o600"


def test_export_is_chained_and_tampering_is_rejected():
    log = BlackMirrorLog()
    gov, _ = _locked_session_with_log(log)
    gov.close()
    path = os.path.join(tempfile.mkdtemp(), "export.jsonl")
    checkpoint = log.export_jsonl(path)
    assert len(load_observations(path)) == checkpoint["count"] == len(log.observations_for("a"))

    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    record = json.loads(lines[1])
    record["fields"]["content"] = "something else"
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join([lines[0], json.dumps(record)] + lines[2:]) + "\n")
    with pytest.raises(ValueError):
        load_observations(path)

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines[:-1]) + "\n")  # truncated, still a valid chain
    load_observations(path)
    with pytest.raises(ValueError):
        load_observations(path, expected_head=checkpoint["head"])


def test_log_files_are_never_overwritten():
    path = os.path.join(tempfile.mkdtemp(), "exists.jsonl")
    open(path, "w").close()
    with pytest.raises(FileExistsError):
        BlackMirrorLog(sink_path=path)
    with pytest.raises(FileExistsError):
        BlackMirrorLog().export_jsonl(path)

