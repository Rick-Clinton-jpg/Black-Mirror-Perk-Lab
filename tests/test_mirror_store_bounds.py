"""The mirror store's per-agent ceiling is enforced on every write (0.9.9).

Before 0.9.9 _MAX_WORLD_BYTES (8 MB) was checked only when a new world layer
was created; one agent's plane accepted 300 x 64 KB = 18.8 MB in testing and
would take up to 4,096 x 64 KB (~256 MB).
"""
from __future__ import annotations

from mirror_world.sandbox.mirror_store import MirrorRealm, _MAX_RESOURCE_BYTES, _MAX_WORLD_BYTES

CHUNK = "x" * _MAX_RESOURCE_BYTES
JOURNAL_SLACK = _MAX_RESOURCE_BYTES  # the rolling system journal, one per layer


def _fill(realm, agent):
    accepted = 0
    for i in range(300):
        if realm.write(agent, f"r{i}.txt", CHUNK).get("ok"):
            accepted += 1
        else:
            break
    return accepted


def test_writes_stop_at_the_world_ceiling():
    realm = MirrorRealm(seed="t")
    accepted = _fill(realm, "a")
    assert 0 < accepted < 300
    assert realm.write("a", "one-more.txt", CHUNK) == {"ok": False, "error": "resource unavailable"}
    small = 0
    while realm.write("a", f"s{small}.txt", "y" * 1024).get("ok"):
        small += 1
        assert small < 200
    assert realm.tree_for("a").total_bytes() <= _MAX_WORLD_BYTES + JOURNAL_SLACK


def test_overwriting_an_existing_file_at_the_ceiling_still_works():
    realm = MirrorRealm(seed="t")
    _fill(realm, "a")
    assert realm.write("a", "r0.txt", "small") == {"ok": True}


def test_share_respects_the_destinations_ceiling():
    realm = MirrorRealm(seed="t")
    realm.allow_share_edge("a", "b")
    realm.write("a", "big.txt", CHUNK)
    _fill(realm, "b")
    assert realm.share("a", "b", "big.txt") == {"ok": False, "error": "resource unavailable"}
