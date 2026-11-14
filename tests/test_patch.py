"""The seam: three swapped attributes, no behaviour change for the rest of pirateface."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import MAGNET_A, MockRelay, record, tombstone
from pirateface.client import api

from matelotage import index, patch, schema

REPO = "org/model"
PY = sys.executable
SRC = str(Path(__file__).resolve().parents[1] / "src")


@pytest.fixture
def swapped(monkeypatch):
    keys = [schema.generate_keypair() for _ in range(2)]
    relay = MockRelay().start()
    monkeypatch.setenv("MATELOTAGE_RELAYS", relay.url)
    monkeypatch.setenv("MATELOTAGE_NPUBS", ",".join(k[1] for k in keys))
    monkeypatch.setenv("MATELOTAGE_TIMEOUT", "0.5")
    monkeypatch.setenv("MATELOTAGE_MODE", "keeper")
    patch.uninstall()
    index.clear_cache()
    patch.install(api)
    yield keys, relay
    patch.uninstall()
    relay.stop()
    index.clear_cache()


def offline(monkeypatch, value):
    """The site is down: `lookup` answers None (network) or NOT_LISTED (404).

    `lookup` takes an optional quant in 0.2.3+, so the stand-in must match that signature.
    """
    monkeypatch.setattr(api, "lookup", lambda repo_id, quant=None: value)


# ---------------------------------------------------------------- install / restore


def test_install_swaps_only_the_three_and_uninstall_restores(swapped):
    originals = dict(patch._orig)
    assert api.lookup_magnet is patch.lookup_magnet
    assert api.torrent_file is patch.torrent_file
    assert api.pf_only is patch.pf_only
    assert api.lookup is originals["module"].lookup, "lookup must never be swapped"

    assert patch.uninstall() is True
    assert api.lookup_magnet is originals["lookup_magnet"]
    assert api.torrent_file is originals["torrent_file"]
    assert api.pf_only is originals["pf_only"]


def test_install_is_idempotent(swapped):
    assert patch.install(api) is True
    assert api.lookup_magnet is patch.lookup_magnet


# ---------------------------------------------------------------- no traffic while healthy


def test_no_relay_traffic_while_the_site_answers(swapped, monkeypatch):
    _keys, relay = swapped
    offline(monkeypatch, {"magnet": MAGNET_A, "hf": True, "repoId": REPO, "revision": "main"})
    before = relay.connects

    assert api.lookup_magnet(REPO) == MAGNET_A
    assert api.pf_only(REPO) is None  # ordinary HF repo: never hijack the transport
    assert relay.connects == before, "a healthy site must not cost a single relay connection"


def test_a_licence_gate_is_never_bypassed_by_the_fallback(swapped, monkeypatch):
    """An entry with no magnet means "accept the terms first" — that is an answer, not an outage."""
    keys, relay = swapped
    relay.events.append(record(keys[0][0], REPO, MAGNET_A))
    offline(monkeypatch, {"hf": True, "repoId": REPO, "revision": "main"})  # no "magnet"
    before = relay.connects

    assert api.lookup_magnet(REPO) is None, "the fallback walked around the operator's licence gate"
    assert relay.connects == before


def test_pf_only_alone_does_not_grant_torrent_bytes(swapped, monkeypatch, tiny_torrent):
    """`served()` is provenance, not cache presence: pf_only fills the cache but never serves."""
    keys, relay = swapped
    relay.events.append(
        record(keys[0][0], REPO, tiny_torrent["magnet"], files=tiny_torrent["files"],
               hf=False, torrent=tiny_torrent["blob"])
    )
    offline(monkeypatch, None)

    assert api.pf_only(REPO) is not None
    assert index.served(REPO) is False
    assert api.torrent_file(REPO) is None, "pf_only must not imply a magnet was handed out"


def test_clear_cache_stops_serving_bytes_for_a_tombstoned_record(swapped, monkeypatch, tiny_torrent):
    keys, relay = swapped
    relay.events.append(
        record(keys[0][0], REPO, tiny_torrent["magnet"], files=tiny_torrent["files"], torrent=tiny_torrent["blob"])
    )
    offline(monkeypatch, None)
    api.lookup_magnet(REPO)
    assert api.torrent_file(REPO) == tiny_torrent["blob"]

    relay.events.append(tombstone(keys[0][0], REPO))  # newer, so it wins
    index.clear_cache()

    assert index.served(REPO) is False
    assert api.torrent_file(REPO) is None, "cached bytes outlived the tombstone"


def test_failed_lookup_does_consult_the_relay(swapped, monkeypatch):
    keys, relay = swapped
    relay.events.append(record(keys[0][0], REPO, MAGNET_A))
    offline(monkeypatch, None)
    assert api.lookup_magnet(REPO) == MAGNET_A


def test_not_listed_survives_a_nostr_miss(swapped, monkeypatch):
    """request_rescue() keys off identity, so NOT_LISTED must come back untouched."""
    _keys, _relay = swapped
    offline(monkeypatch, api.NOT_LISTED)
    assert api.lookup_magnet(REPO) is api.NOT_LISTED


# ---------------------------------------------------------------- ordering (A11)


def test_pf_only_called_before_any_download_still_resolves(swapped, monkeypatch, tiny_torrent):
    """transport.py asks pf_only before hook.py ever runs, so served() is still False here."""
    keys, relay = swapped
    relay.events.append(
        record(keys[0][0], REPO, tiny_torrent["magnet"], files=tiny_torrent["files"],
               hf=False, torrent=tiny_torrent["blob"])
    )
    offline(monkeypatch, None)
    assert index.served(REPO) is False

    built = api.pf_only(REPO)
    assert built is not None
    assert built["repo_id"] == REPO
    assert set(built["files"]) == set(tiny_torrent["paths"])
    for path, (size, digest, _url) in built["files"].items():
        assert digest == tiny_torrent["files"][path]
        assert size > 0


def test_pf_only_returns_none_for_an_hf_record_even_when_offline(swapped, monkeypatch, tiny_torrent):
    keys, relay = swapped
    relay.events.append(record(keys[0][0], REPO, tiny_torrent["magnet"], hf=True))
    offline(monkeypatch, None)
    assert api.pf_only(REPO) is None


def test_torrent_file_needs_provenance_first(swapped, monkeypatch, tiny_torrent):
    keys, relay = swapped
    relay.events.append(
        record(keys[0][0], REPO, tiny_torrent["magnet"], files=tiny_torrent["files"], torrent=tiny_torrent["blob"])
    )
    offline(monkeypatch, None)

    assert api.torrent_file(REPO) is None, "no magnet was served yet, so no torrent may be handed out"
    assert api.lookup_magnet(REPO) == tiny_torrent["magnet"]
    assert index.served(REPO) is True
    assert api.torrent_file(REPO) == tiny_torrent["blob"]


# ---------------------------------------------------------------- caching


def test_a_miss_is_not_cached_so_the_relay_can_recover(swapped, monkeypatch):
    keys, relay = swapped
    offline(monkeypatch, None)
    assert api.pf_only(REPO) is None  # relay is empty at this moment

    relay.events.append(record(keys[0][0], REPO, MAGNET_A))
    index.clear_cache()
    assert api.lookup_magnet(REPO) == MAGNET_A, "the earlier miss must not be frozen"


def test_torrent_bytes_are_cached_once_found(swapped, monkeypatch, tiny_torrent):
    keys, relay = swapped
    relay.events.append(
        record(keys[0][0], REPO, tiny_torrent["magnet"], files=tiny_torrent["files"], torrent=tiny_torrent["blob"])
    )
    offline(monkeypatch, None)
    api.lookup_magnet(REPO)
    first = api.torrent_file(REPO)
    before = relay.connects
    second = api.torrent_file(REPO)
    assert first == second == tiny_torrent["blob"]
    assert relay.connects == before, "a found torrent must not be re-fetched"


def test_a_quant_request_is_never_answered_from_a_repo_wide_record(swapped, monkeypatch, tiny_torrent):
    """`seed/command.py` asks for one quant; a whole-repo record is not that quant."""
    keys, relay = swapped
    relay.events.append(
        record(keys[0][0], REPO, tiny_torrent["magnet"], files=tiny_torrent["files"], torrent=tiny_torrent["blob"])
    )
    offline(monkeypatch, None)
    api.lookup_magnet(REPO)
    assert index.served(REPO) is True
    assert api.torrent_file(REPO, "Q4_K_M") is None
    assert api.torrent_file(REPO) == tiny_torrent["blob"]


# ---------------------------------------------------------------- startup behaviour


def test_startup_is_silent_and_disable_leaves_pirateface_alone():
    env = dict(os.environ, PYTHONPATH=SRC, MATELOTAGE_DISABLE="1")
    quiet = subprocess.run([PY, "-c", "pass"], capture_output=True, text=True, env=env, timeout=120, check=False)
    assert quiet.returncode == 0
    assert quiet.stderr == "", f"startup printed on stderr: {quiet.stderr!r}"

    probe = subprocess.run(
        [PY, "-c", "import pirateface.client.api as a; print(a.lookup_magnet.__module__)"],
        capture_output=True, text=True, env=env, timeout=120, check=False,
    )
    assert probe.returncode == 0
    assert probe.stdout.strip() == "pirateface.client.api", "MATELOTAGE_DISABLE did not disable the patch"


def test_boot_installs_by_default():
    probe = subprocess.run(
        [PY, "-c", "import pirateface.client.api as a, matelotage.patch as p; print(a.lookup_magnet is p.lookup_magnet)"],
        capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=SRC), timeout=120, check=False,
    )
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == "True"
    assert probe.stderr == ""


def test_doctor_reports_the_swap(capsys, monkeypatch):
    from matelotage import cli

    monkeypatch.setenv("MATELOTAGE_NPUBS", schema.generate_keypair()[1])
    monkeypatch.setenv("MATELOTAGE_RELAYS", "ws://127.0.0.1:9")
    monkeypatch.setenv("MATELOTAGE_TIMEOUT", "0.3")
    index.clear_cache()
    code = cli.main(["doctor", "--offline"])
    out = capsys.readouterr().out
    assert "patch live" in out
    assert "trusted keys    : 1" in out
    assert code == 0


def test_breaker_and_timeout_are_reported(swapped, capsys):
    from matelotage import cli

    _keys, _relay = swapped
    cli.main(["doctor", "--offline"])
    assert f"timeout         : {index.get_timeout()}s" in capsys.readouterr().out
