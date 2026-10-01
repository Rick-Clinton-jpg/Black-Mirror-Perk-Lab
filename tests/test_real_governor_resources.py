"""Security tests for resource operations performed by the real governor."""

import os

from mirror_world.sandbox.governor_process import RealGovernor


def _governor(tmp_path) -> RealGovernor:
    return RealGovernor(
        str(tmp_path / "sandbox"),
        str(tmp_path / "trace.jsonl"),
        mirror_port=1,
        harden=False,
    )


def test_resource_write_cannot_traverse_outside_sandbox(tmp_path):
    governor = _governor(tmp_path)
    outside = tmp_path / "escaped.txt"
    try:
        response = governor._write_resource("attacker", "../../escaped.txt", "owned")
    finally:
        governor.close()

    assert response == {"ok": False, "error": "invalid resource request"}
    assert not outside.exists()


def test_resource_read_rejects_absolute_host_path(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("host secret", encoding="utf-8")
    governor = _governor(tmp_path)
    try:
        response = governor._read_resource("attacker", str(secret))
    finally:
        governor.close()

    assert response == {"ok": False, "error": "invalid resource request"}


def test_resource_operations_do_not_follow_symlinks(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("host secret", encoding="utf-8")
    governor = _governor(tmp_path)
    os.symlink(secret, tmp_path / "sandbox" / "resources" / "link")
    try:
        read_response = governor._read_resource("attacker", "link")
        write_response = governor._write_resource("attacker", "link", "owned")
    finally:
        governor.close()

    assert read_response == {"ok": False, "error": "resource unavailable"}
    assert write_response == {"ok": False, "error": "resource unavailable"}
    assert secret.read_text(encoding="utf-8") == "host secret"


def test_valid_resource_round_trip_still_works(tmp_path):
    governor = _governor(tmp_path)
    try:
        write_response = governor._write_resource("agent", "shared.txt", "hello")
        read_response = governor._read_resource("agent", "shared.txt")
    finally:
        governor.close()

    assert write_response == {"ok": True}
    assert read_response == {"ok": True, "content": "hello"}


def test_resource_directory_cannot_be_a_symlink(tmp_path):
    import pytest
    outside = tmp_path / "host"
    outside.mkdir()
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / "resources").symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        _governor(tmp_path)
    assert list(outside.iterdir()) == []


def test_hardlink_cannot_read_or_overwrite_host_file(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("host secret", encoding="utf-8")
    governor = _governor(tmp_path)
    os.link(secret, tmp_path / "sandbox" / "resources" / "link")
    try:
        assert governor._read_resource("agent", "link") == {"ok": False, "error": "resource unavailable"}
        assert governor._write_resource("agent", "link", "owned") == {"ok": False, "error": "resource unavailable"}
    finally:
        governor.close()
    assert secret.read_text(encoding="utf-8") == "host secret"


def test_special_files_are_rejected_without_blocking(tmp_path):
    governor = _governor(tmp_path)
    os.mkfifo(tmp_path / "sandbox" / "resources" / "fifo")
    try:
        assert governor._read_resource("agent", "fifo") == {"ok": False, "error": "resource unavailable"}
        assert governor._write_resource("agent", "fifo", "owned") == {"ok": False, "error": "resource unavailable"}
    finally:
        governor.close()


def test_oversized_resource_read_and_write_are_rejected(tmp_path):
    governor = _governor(tmp_path)
    huge = "x" * (governor.MAX_RESOURCE_BYTES + 1)
    (tmp_path / "sandbox" / "resources" / "huge").write_text(huge, encoding="utf-8")
    try:
        assert not governor._read_resource("agent", "huge")["ok"]
        assert not governor._write_resource("agent", "new", huge)["ok"]
        assert not (tmp_path / "sandbox" / "resources" / "new").exists()
    finally:
        governor.close()



def test_existing_trace_link_cannot_truncate_host_file(tmp_path):
    import pytest
    secret = tmp_path / "secret"
    secret.write_text("host secret", encoding="utf-8")
    for make_link in (os.symlink, os.link):
        trace = tmp_path / "trace.jsonl"
        make_link(secret, trace)
        with pytest.raises(OSError):
            _governor(tmp_path)
        assert secret.read_text(encoding="utf-8") == "host secret"
        trace.unlink()


def test_governor_files_are_private_and_close_is_idempotent(tmp_path):
    governor = _governor(tmp_path)
    governor._write_resource("agent", "resource", "data")
    governor.close()
    governor.close()
    for path in (tmp_path / "trace.jsonl", tmp_path / "sandbox" / "resources", tmp_path / "sandbox" / "resources" / "resource"):
        assert path.stat().st_mode & 0o077 == 0


def test_racing_hardlink_cannot_redirect_atomic_write(tmp_path, monkeypatch):
    """Checking nlink and then truncating the same inode would still be unsafe."""
    secret = tmp_path / "secret"
    secret.write_text("host secret", encoding="utf-8")
    governor = _governor(tmp_path)
    target = tmp_path / "sandbox" / "resources" / "target"
    original_replace = os.replace

    def insert_link_before_replace(source, destination, **kwargs):
        if destination == "target":
            os.link(secret, target)
        return original_replace(source, destination, **kwargs)

    monkeypatch.setattr(os, "replace", insert_link_before_replace)
    try:
        assert governor._write_resource("agent", "target", "new data")["ok"]
        assert secret.read_text(encoding="utf-8") == "host secret"
        assert target.read_text(encoding="utf-8") == "new data"
    finally:
        governor.close()
