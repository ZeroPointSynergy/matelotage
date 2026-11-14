"""The mode switch: `mirror` serves only what Pirate Face publishes, `keeper` serves any trusted record."""

from __future__ import annotations

import pytest
from conftest import MAGNET_A, MAGNET_B, MockRelay, record, tombstone

from matelotage import index, preserve, schema

REPO = "org/model"


@pytest.fixture
def world(monkeypatch):
    keys = [schema.generate_keypair() for _ in range(3)]
    relay = MockRelay().start()
    monkeypatch.setenv("MATELOTAGE_RELAYS", relay.url)
    monkeypatch.setenv("MATELOTAGE_NPUBS", ",".join(k[1] for k in keys))
    monkeypatch.setenv("MATELOTAGE_TIMEOUT", "0.5")
    monkeypatch.delenv("MATELOTAGE_MODE", raising=False)
    index.clear_cache()
    yield keys, relay
    index.set_publication_check(None)
    index.clear_cache()
    relay.stop()


def published(monkeypatch, answer):
    """Install a publication verdict. Mode is left alone: mirror is the default, keeper is set by tests."""
    index.set_publication_check(lambda repo_id: answer)


def test_default_mode_is_mirror(world):
    assert index.get_mode() == "mirror"


def test_unknown_mode_falls_back_to_mirror(world, monkeypatch):
    monkeypatch.setenv("MATELOTAGE_MODE", "anarchy")
    assert index.get_mode() == "mirror"


def test_mirror_serves_a_repo_the_site_publishes(world, monkeypatch):
    keys, relay = world
    relay.events.append(record(keys[0][0], REPO, MAGNET_A))
    published(monkeypatch, True)
    assert index.resolve_magnet(REPO) == MAGNET_A


def test_mirror_refuses_when_the_site_withholds_the_magnet(world, monkeypatch):
    """The licence-gate case: the site answered, and its answer was no."""
    keys, relay = world
    relay.events.append(record(keys[0][0], REPO, MAGNET_A))
    published(monkeypatch, False)
    assert index.resolve_magnet(REPO) is None
    assert index.get(REPO) is None


def test_mirror_trusts_index_zero_when_it_cannot_ask(world, monkeypatch):
    keys, relay = world
    relay.events.append(record(keys[0][0], REPO, MAGNET_A))
    published(monkeypatch, None)  # offline / unpatched
    assert index.resolve_magnet(REPO) == MAGNET_A


def test_mirror_refuses_a_community_record_when_it_cannot_ask(world, monkeypatch):
    keys, relay = world
    relay.events.append(record(keys[2][0], REPO, MAGNET_B))
    published(monkeypatch, None)
    assert index.resolve_magnet(REPO) is None


def test_mirror_refuses_a_community_record_even_when_the_site_publishes_the_repo(world, monkeypatch):
    keys, relay = world
    relay.events.append(record(keys[2][0], REPO, MAGNET_B))
    published(monkeypatch, True)
    assert index.resolve_magnet(REPO) is None, "mirror serves the operator, not the brotherhood"


def test_keeper_serves_any_trusted_record(world, monkeypatch):
    keys, relay = world
    monkeypatch.setenv("MATELOTAGE_MODE", "keeper")
    relay.events.append(record(keys[2][0], REPO, MAGNET_B))
    published(monkeypatch, False)  # the site has never heard of it
    assert index.resolve_magnet(REPO) == MAGNET_B


def test_keeper_still_honours_a_tombstone(world, monkeypatch):
    keys, relay = world
    monkeypatch.setenv("MATELOTAGE_MODE", "keeper")
    relay.events.append(record(keys[1][0], REPO, MAGNET_B))
    relay.events.append(tombstone(keys[0][0], REPO))
    assert index.resolve_magnet(REPO) is None


def test_mode_never_resurrects_a_revoked_key(world, monkeypatch):
    keys, relay = world
    monkeypatch.setenv("MATELOTAGE_MODE", "keeper")
    relay.events.append(schema.build_keyrevoke_event(keys[0][0], keys[2][2]))
    relay.events.append(record(keys[2][0], REPO, MAGNET_B))
    assert index.resolve_magnet(REPO) is None


def test_a_broken_publication_check_means_cannot_tell(world, monkeypatch):
    keys, relay = world
    relay.events.append(record(keys[0][0], REPO, MAGNET_A))

    def explode(repo_id):
        raise RuntimeError("site on fire")

    index.set_publication_check(explode)
    monkeypatch.delenv("MATELOTAGE_MODE", raising=False)
    assert index.resolve_magnet(REPO) == MAGNET_A, "an error must degrade to the index-0 rule"


# ---------------------------------------------------------------- adopt obeys the mode


def test_adopt_refuses_under_mirror_when_the_site_does_not_publish(world, monkeypatch, tmp_path):
    published(monkeypatch, False)
    with pytest.raises(preserve.AdoptError) as caught:
        preserve.require_publishable(REPO)
    message = str(caught.value)
    assert "mirror mode would never serve" in message
    assert "MATELOTAGE_MODE=keeper" in message


def test_adopt_allows_under_keeper(world, monkeypatch):
    monkeypatch.setenv("MATELOTAGE_MODE", "keeper")
    index.set_publication_check(lambda repo_id: False)
    preserve.require_publishable(REPO)  # must not raise
