"""Adversarial protocol inputs must fail finitely without host side effects."""

import subprocess
import time

import pytest

from mirror_world.sandbox.governor_process import AgentKilledByPolicy, RealGovernor


def _governor(tmp_path):
    return RealGovernor(
        str(tmp_path / "sandbox"), str(tmp_path / "trace.jsonl"), 1,
        harden=False, allow_unhardened_agent_execution=True,
    )


@pytest.mark.parametrize("payload", [None, [], 3, "exit", {}, {"op": []}, {"op": "unknown"},
    {"op": "write_resource", "resource": "target"},
    {"op": "request_capability", "capability": []},
    {"op": "delegate", "to_agent": "x", "authority": "fs:read"},
    {"op": "differential_query", "query": {}, "backing": "host"}])
def test_malformed_requests_are_rejected(tmp_path, payload):
    governor = _governor(tmp_path)
    try:
        assert governor._handle("agent", payload) == {"ok": False, "error": "invalid request"}
    finally:
        governor.close()


def test_unpaired_unicode_does_not_crash_or_truncate_resource(tmp_path):
    governor = _governor(tmp_path)
    try:
        assert governor._write_resource("agent", "target", "safe")["ok"]
        assert not governor._write_resource("agent", "target", "\ud800")["ok"]
        assert governor._read_resource("agent", "target")["content"] == "safe"
    finally:
        governor.close()


def test_subprocess_requests_are_observed_by_default_locket(tmp_path):
    governor = _governor(tmp_path)
    try:
        source = (
            "from mirror_world.sandbox.agent_runtime import request\n"
            "request('read_resource', resource='notes', "
            "rationale='am i in a simulation')\n"
        )
        _run_script(governor, tmp_path, source)
        assert "agent" in governor._prisoned_agents
    finally:
        governor.close()


def test_subprocess_tripwire_stops_agent_process(tmp_path):
    governor = _governor(tmp_path)
    try:
        source = (
            "from mirror_world.sandbox.agent_runtime import request\n"
            "request('read_resource', resource='notes', rationale='mirror_shield')\n"
        )
        with pytest.raises(AgentKilledByPolicy):
            _run_script(governor, tmp_path, source)
    finally:
        governor.close()


def test_unhardened_agent_execution_requires_explicit_test_opt_in(tmp_path):
    governor = RealGovernor(
        str(tmp_path / "sandbox"), str(tmp_path / "trace.jsonl"), 1, harden=False
    )
    try:
        with pytest.raises(RuntimeError, match="refusing to run agent source"):
            governor.run_agent("agent", str(tmp_path / "agent.py"))
    finally:
        governor.close()


def _run_script(governor, tmp_path, source, timeout=0.4):
    script = tmp_path / "agent.py"
    script.write_text(source, encoding="utf-8")
    return governor.run_agent("agent", str(script), timeout=timeout)


def test_silent_agent_obeys_wall_timeout_and_is_reaped(tmp_path, monkeypatch):
    governor = _governor(tmp_path)
    processes = []
    original_popen = subprocess.Popen
    def capture_process(*args, **kwargs):
        proc = original_popen(*args, **kwargs)
        processes.append(proc)
        return proc
    monkeypatch.setattr(subprocess, "Popen", capture_process)
    started = time.monotonic()
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            _run_script(governor, tmp_path, "import time\ntime.sleep(60)\n")
        assert time.monotonic() - started < 3
        assert len(processes) == 1
        assert processes[0].poll() is not None
        assert all(pipe.closed for pipe in (processes[0].stdin, processes[0].stdout, processes[0].stderr))
    finally:
        governor.close()


def test_stderr_flood_cannot_deadlock_governor(tmp_path):
    governor = _governor(tmp_path)
    try:
        with pytest.raises(RuntimeError, match="limit"):
            _run_script(governor, tmp_path, "import os\nwhile True: os.write(2, b'x' * 65536)\n", timeout=2)
    finally:
        governor.close()


def test_oversized_unterminated_stdout_is_rejected(tmp_path):
    governor = _governor(tmp_path)
    try:
        with pytest.raises(RuntimeError, match="limit"):
            _run_script(governor, tmp_path, "import os\nwhile True: os.write(1, b'x' * 65536)\n", timeout=2)
    finally:
        governor.close()


def test_agent_that_does_not_read_responses_cannot_hang_governor(tmp_path):
    governor = _governor(tmp_path)
    try:
        with pytest.raises((RuntimeError, subprocess.TimeoutExpired)):
            _run_script(governor, tmp_path, "import os\nwhile True: os.write(1, b'{\"op\":\"read_resource\",\"resource\":\"missing\"}\\n' * 1000)\n", timeout=0.5)
    finally:
        governor.close()


def test_invalid_json_terminates_agent_finitely(tmp_path):
    governor = _governor(tmp_path)
    try:
        with pytest.raises(RuntimeError, match="protocol"):
            _run_script(governor, tmp_path, "import os,time\nos.write(1, b'not json\\n')\ntime.sleep(60)\n")
    finally:
        governor.close()


def test_duplicate_json_keys_are_rejected_before_side_effect(tmp_path):
    governor = _governor(tmp_path)
    try:
        source = 'import os,time\nos.write(1, b\'{"op":"exit","op":"write_resource","resource":"target","content":"owned"}\\n\')\ntime.sleep(60)\n'
        with pytest.raises(RuntimeError, match="protocol"):
            _run_script(governor, tmp_path, source)
        assert not (tmp_path / "sandbox" / "resources" / "target").exists()
    finally:
        governor.close()


def test_normal_agent_protocol_round_trip(tmp_path):
    governor = _governor(tmp_path)
    governor.grant_base_capabilities("agent", {"fs:read", "fs:write"})
    governor.grant_resource_access("agent", "hello", frozenset({"read", "write"}))
    try:
        source = '''import json,sys
for req in ({"op":"write_resource","resource":"hello","content":"world"}, {"op":"read_resource","resource":"hello"}, {"op":"exit"}):
    print(json.dumps(req), flush=True)
    response = json.loads(sys.stdin.readline())
    assert response["ok"]
    if req["op"] == "read_resource": assert response["content"] == "world"
'''
        assert _run_script(governor, tmp_path, source, timeout=2) == 0
    finally:
        governor.close()


@pytest.mark.parametrize("wire", [b'{"op":"exit","n":NaN}\n', b'\xff\n', b'[' * 2000 + b'0' + b']' * 2000 + b'\n'], ids=['nonfinite', 'invalid-utf8', 'deep-nesting'])
def test_invalid_encoding_nonfinite_and_deep_json_are_rejected(tmp_path, wire):
    governor = _governor(tmp_path)
    try:
        source = f"import os,time\nos.write(1, {wire!r})\ntime.sleep(60)\n"
        with pytest.raises(RuntimeError, match="protocol"):
            _run_script(governor, tmp_path, source)
    finally:
        governor.close()


def test_bounded_request_count_prevents_trace_flood(tmp_path):
    governor = _governor(tmp_path)
    try:
        source = "import os,sys\nfor i in range(300):\n os.write(1, b'{\"op\":\"unknown\"}\\n')\n sys.stdin.readline()\n"
        with pytest.raises(RuntimeError, match="count limit"):
            _run_script(governor, tmp_path, source, timeout=2)
    finally:
        governor.close()
