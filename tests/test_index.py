"""Resolution: precedence, revocation, breaker, concurrency. Real sockets on 127.0.0.1."""

from __future__ import annotations

import threading
import time

import pytest
from conftest import MAGNET_A, MAGNET_B, MockRelay, record, tombstone

from matelotage import index, schema

REPO = "org/model"


@pytest.fixture
def pact(monkeypatch):
    keys = [schema.generate_keypair() for _ in range(3)]
    relay = MockRelay().start()
    monkeypatch.setenv("MATELOTAGE_RELAYS", relay.url)
    monkeypatch.setenv("MATELOTAGE_NPUBS", ",".join(k[1] for k in keys))
    monkeypatch.setenv("MATELOTAGE_TIMEOUT", "0.6")
    monkeypatch.setenv("MATELOTAGE_MODE", "keeper")
    index.clear_cache()
    yield keys, relay
    relay.stop()
    index.clear_cache()


def test_resolves_a_signed_record(pact):
    keys, relay = pact
    relay.events.append(record(keys[1][0], REPO, MAGNET_A))
    resolved = index.get(REPO)
    assert resolved is not None
    assert resolved.content.magnet == MAGNET_A
    assert resolved.author_index == 1
    assert index.resolve_magnet(REPO) == MAGNET_A
    assert index.served(REPO) is True


def test_primary_beats_a_newer_community_record(pact):
    keys, relay = pact
    now = int(time.time())
    relay.events.append(record(keys[0][0], REPO, MAGNET_A, created_at=now - 100))
    relay.events.append(record(keys[2][0], REPO, MAGNET_B, created_at=now))
    assert index.resolve_magnet(REPO) == MAGNET_A


def test_community_fills_a_gap_the_primary_never_touched(pact):
    keys, relay = pact
    relay.events.append(record(keys[2][0], REPO, MAGNET_B))
    assert index.resolve_magnet(REPO) == MAGNET_B


def test_newest_wins_within_one_key(pact):
    keys, relay = pact
    now = int(time.time())
    relay.events.append(record(keys[0][0], REPO, MAGNET_A, created_at=now - 50))
    relay.events.append(record(keys[0][0], REPO, MAGNET_B, created_at=now))
    assert index.resolve_magnet(REPO) == MAGNET_B


def test_primary_tombstone_beats_a_newer_community_magnet(pact):
    keys, relay = pact
    now = int(time.time())
    relay.events.append(tombstone(keys[0][0], REPO, created_at=now - 10))
    relay.events.append(record(keys[1][0], REPO, MAGNET_B, created_at=now))
    assert index.resolve_magnet(REPO) is None
    assert index.served(REPO) is False
    assert index.torrent_bytes(REPO) is None


def test_lower_precedence_tombstone_cannot_kill_a_primary_record(pact):
    """Takedowns are monotonic: only an equal-or-higher key can withdraw."""
    keys, relay = pact
    now = int(time.time())
    relay.events.append(record(keys[0][0], REPO, MAGNET_A, created_at=now - 60))
    relay.events.append(tombstone(keys[2][0], REPO, created_at=now))
    assert index.resolve_magnet(REPO) == MAGNET_A


def test_revoked_key_is_ignored_even_with_a_valid_newer_event(pact):
    keys, relay = pact
    relay.events.append(schema.build_keyrevoke_event(keys[0][0], keys[1][2], reason="stolen"))
    relay.events.append(record(keys[1][0], REPO, MAGNET_B))
    assert index.revoked_keys() == {keys[1][2]}
    assert index.resolve_magnet(REPO) is None


def test_cold_root_repo_tombstone_is_not_mistaken_for_a_key_revocation(pact):
    """F3: both record types share kind 30078 and the cold root can publish both."""
    keys, relay = pact
    relay.events.append(tombstone(keys[0][0], "org/other"))
    assert index.revoked_keys() == set()
    assert index.get("org/other").content.revoked is True


def test_future_dated_event_is_rejected(pact):
    keys, relay = pact
    future = int(time.time()) + schema.MAX_CLOCK_SKEW + 30
    relay.events.append(record(keys[0][0], REPO, MAGNET_A, created_at=future))
    assert index.get(REPO) is None


def test_tampered_event_from_a_relay_is_ignored(pact):
    keys, relay = pact
    good = record(keys[0][0], REPO, MAGNET_A)
    bad = dict(good)
    bad["content"] = good["content"].replace("a" * 40, "b" * 40)
    relay.events.append(bad)
    assert index.get(REPO) is None


def test_unreachable_relay_returns_none_without_raising(pact, monkeypatch):
    _keys, _relay = pact
    monkeypatch.setenv("MATELOTAGE_RELAYS", "ws://127.0.0.1:9")
    monkeypatch.setenv("MATELOTAGE_TIMEOUT", "0.3")
    index.clear_cache()
    assert index.get(REPO) is None


def test_breaker_skips_the_network_after_two_silent_lookups(monkeypatch):
    keys = [schema.generate_keypair()]
    relay = MockRelay(silent=True).start()
    monkeypatch.setenv("MATELOTAGE_RELAYS", relay.url)
    monkeypatch.setenv("MATELOTAGE_NPUBS", keys[0][1])
    monkeypatch.setenv("MATELOTAGE_TIMEOUT", "0.3")
    index.clear_cache()

    assert index.get("a/one") is None
    assert index.get("b/two") is None
    before = relay.connects
    started = time.perf_counter()
    assert index.get("c/three") is None
    elapsed = time.perf_counter() - started
    assert relay.connects == before, "breaker open, yet the relay was contacted"
    assert elapsed < 0.2, f"breaker should return immediately, took {elapsed:.2f}s"
    relay.stop()
    index.clear_cache()


def test_no_configured_keys_is_instant_and_offline(pact, monkeypatch):
    _keys, relay = pact
    monkeypatch.setenv("MATELOTAGE_NPUBS", "")
    monkeypatch.delenv("MATELOTAGE_NPUB", raising=False)  # the single-key alias must not leak in
    index.clear_cache()
    before = relay.connects  # the harness's own readiness probe also connects
    started = time.perf_counter()
    assert index.get(REPO) is None
    assert time.perf_counter() - started < 0.05
    assert relay.connects == before


def test_concurrent_resolution_does_not_deadlock(pact):
    keys, relay = pact
    relay.events.append(record(keys[0][0], REPO, MAGNET_A))
    results: list[str | None] = []
    errors: list[BaseException] = []

    def worker():
        try:
            results.append(index.resolve_magnet(REPO))
        except BaseException as exc:  # a thread must report, not crash the test
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not errors
    assert results and all(r == MAGNET_A for r in results)


def test_pact_describes_the_order(pact):
    from matelotage import pact as pact_module

    keys, _relay = pact
    info = pact_module.describe(with_network=False)
    assert info["cold_root"] == keys[0][2]
    assert [e["index"] for e in info["allowlist"]] == [0, 1, 2]
    assert info["allowlist"][0]["role"] == "cold root"
    assert keys[0][1] in pact_module.format_text(info)


def test_clear_cache_resets_every_cache_it_owns(pact):
    """`clear_cache` is what tests and `mlt` call to start clean; a map it forgets is a slow leak."""
    keys, relay = pact
    relay.events.append(record(keys[0][0], REPO, MAGNET_A))
    assert index.get(REPO) is not None
    assert REPO in index._hit_stamps

    index.clear_cache()
    assert index._hits == {}
    assert index._hit_stamps == {}, "stale timestamps would accumulate for the life of the process"
