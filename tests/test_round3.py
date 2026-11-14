"""Regressions from adversary round 3.

Each test maps to a defect that was shipped, found, and fixed. They are end-to-end where they can
be: the point is that the *record* cannot be signed, not that some helper raises.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from contextlib import contextmanager

import pytest

from matelotage import index, preserve, publish, schema

REPO = "org/model"


@pytest.fixture(autouse=True)
def keeper_mode(monkeypatch):
    monkeypatch.setenv("MATELOTAGE_MODE", "keeper")
    index.set_publication_check(None)


def make_model(root, *, seed=b"a"):
    root.mkdir(parents=True, exist_ok=True)
    (root / "config.json").write_text('{"hidden_size": 64}\n')
    (root / "model.bin").write_bytes(seed * 300_000)
    return root


@contextmanager
def site(blob, magnet):
    """Pirate Face answering 'here is repo X' with this torrent and magnet."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(preserve, "_server_entry", lambda repo_id: {"magnet": magnet, "hf": True})
        mp.setattr(preserve, "_server_torrent", lambda repo_id: blob)
        yield mp


def torrent_for(root, name="m"):
    from pirateface.seed import package

    blob, v1, v2 = package.make_torrent(root, name, ["udp://t:6969/announce"])
    return blob, package.magnet(v1, v2, name, ["udp://t:6969/announce"])


# --- finding 1: size is not an attestation ------------------------------------------------


def test_a_same_size_corrupt_copy_is_refused(tmp_path):
    """The record must not attest bytes the swarm can never reproduce."""
    source = make_model(tmp_path / "src" / "m")
    blob, magnet = torrent_for(source.parent)

    local = tmp_path / "local" / "m"
    shutil.copytree(source, local)
    data = bytearray((local / "model.bin").read_bytes())
    data[1000] ^= 0xFF  # same size, different bytes
    (local / "model.bin").write_bytes(bytes(data))

    with site(blob, magnet), pytest.raises(preserve.AdoptError, match="do not match the published torrent"):
        preserve.build_record(REPO, local, license_id="mit")


def test_an_honest_copy_passes_the_piece_check(tmp_path):
    source = make_model(tmp_path / "src" / "m")
    blob, magnet = torrent_for(source.parent)
    local = tmp_path / "local" / "m"
    shutil.copytree(source, local)

    with site(blob, magnet):
        content, _blob, _skipped = preserve.build_record(REPO, local, license_id="mit")
    assert content.magnet == magnet


# --- finding 2: containment ---------------------------------------------------------------


def test_a_junction_pointing_outside_the_folder_is_refused(tmp_path):
    root = tmp_path / "model"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("private\n")
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(root / "sub"), str(outside)],
        capture_output=True, text=True, check=False,
    )
    if made.returncode != 0:
        pytest.skip(f"cannot create a junction here: {made.stderr.strip()}")

    with pytest.raises(preserve.AdoptError, match="resolves outside the folder"):
        preserve._screen_paths(root.resolve(), {"sub/secret.txt": 8})


def test_lexical_traversal_is_refused_before_any_file_is_read(tmp_path):
    root = tmp_path / "model"
    root.mkdir()
    with pytest.raises(preserve.AdoptError, match="hostile path"):
        preserve._screen_paths(root.resolve(), {"../../outside.txt": 1})


# --- finding 3: an outage is not permission to found a swarm ------------------------------


def test_not_listed_may_build_a_new_swarm(tmp_path):
    from pirateface.client import api

    local = make_model(tmp_path / "local" / "m")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(preserve, "_server_entry", lambda repo_id: api.NOT_LISTED)
        content, blob, _skipped = preserve.build_record(REPO, local, license_id="mit")
    assert blob and content.magnet


def test_an_unreachable_site_does_not_found_a_swarm_in_mirror_mode(tmp_path, monkeypatch):
    local = make_model(tmp_path / "local" / "m")
    monkeypatch.setenv("MATELOTAGE_MODE", "mirror")
    monkeypatch.setattr(preserve, "_server_entry", lambda repo_id: None)  # network failure
    with pytest.raises(preserve.AdoptError, match="cannot reach Pirate Face"):
        preserve.build_record(REPO, local, license_id="mit")


def test_a_listed_repo_whose_torrent_will_not_download_is_refused(tmp_path):
    local = make_model(tmp_path / "local" / "m")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            preserve, "_server_entry",
            lambda repo_id: {"magnet": "magnet:?xt=urn:btih:" + "a" * 40, "hf": True},
        )
        mp.setattr(preserve, "_server_torrent", lambda repo_id: None)
        with pytest.raises(preserve.AdoptError, match="could not be downloaded"):
            preserve.build_record(REPO, local, license_id="mit")


def test_a_listed_repo_without_a_magnet_is_refused(tmp_path):
    local = make_model(tmp_path / "local" / "m")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(preserve, "_server_entry", lambda repo_id: {"hf": True})  # terms not accepted
        with pytest.raises(preserve.AdoptError, match="magnet is withheld"):
            preserve.build_record(REPO, local, license_id="mit")


# --- finding 4: shed the informational field, never the attestation ----------------------


def test_the_coverage_list_is_shed_before_the_torrent(tmp_path):
    source = make_model(tmp_path / "src" / "m")
    blob, magnet = torrent_for(source.parent)
    content = publish.build_content(
        REPO, magnet=magnet, files={"model.bin": "b" * 64}, license_id="mit",
        torrent_bytes=schema.storage_blob(blob), not_in_swarm=[f"extra{i}.bin" for i in range(200)],
    )
    nsec, _npub, _hex = schema.generate_keypair()

    full, _ = publish.fit_event_and_content(nsec, content, limit=10**6)
    assert json.loads(full["content"])["not_in_swarm"]

    slim, _ = publish.fit_event_and_content(nsec, content, limit=publish.wire_size(full) - 1)
    fitted = schema.validate_model_content(slim["content"], REPO)
    assert fitted.not_in_swarm is None, "the coverage list goes first"
    assert fitted.torrent_bytes is not None, "the torrent is the last thing to go"


def test_an_hf_false_record_never_sheds_its_torrent(tmp_path):
    """Without the torrent an `hf: false` record cannot start a download at all, so it must fail
    rather than publish something that looks fine and is not."""
    source = make_model(tmp_path / "src" / "m")
    blob, magnet = torrent_for(source.parent)
    kwargs = {
        "magnet": magnet, "files": {"model.bin": "b" * 64}, "license_id": "mit",
        "hf": False, "torrent_bytes": schema.storage_blob(blob),
    }
    content = publish.build_content(REPO, not_in_swarm=[f"extra{i}.bin" for i in range(400)], **kwargs)
    bare = publish.build_content(REPO, **kwargs)
    nsec, _npub, _hex = schema.generate_keypair()

    # barely too small even after the coverage list is shed
    floor = publish.wire_size(publish.fit_event_and_content(nsec, bare, limit=10**6)[0])
    with pytest.raises(ValueError, match="cannot shed"):
        publish.fit_event_and_content(nsec, content, limit=floor - 50)


# --- finding 5: portability, hostile bencode, infohash identity ---------------------------


def test_case_colliding_names_are_refused_on_the_published_path(tmp_path):
    """Built by hand: on a case-insensitive filesystem you cannot create both names to build it."""
    import hashlib

    import libtorrent as lt

    body = b"a" * 1000 + b"b" * 1000
    info = {
        b"name": b"m",
        b"piece length": 16384,
        b"pieces": hashlib.sha1(body).digest(),
        b"files": [
            {b"length": 1000, b"path": [b"Model.bin"]},
            {b"length": 1000, b"path": [b"model.bin"]},
        ],
    }
    blob = lt.bencode({b"info": info})
    magnet = "magnet:?xt=urn:btih:" + str(lt.torrent_info(blob).info_hashes().v1)

    source = tmp_path / "src" / "m"
    source.mkdir(parents=True)
    (source / "model.bin").write_bytes(b"a" * 1000)

    with site(blob, magnet), pytest.raises(preserve.AdoptError, match=r"differ only in case|not a valid file name"):
        preserve.build_record(REPO, source, license_id="mit")


def test_garbage_bytes_raise_schema_error_not_libtorrent_runtime_error():
    with pytest.raises(schema.SchemaError, match="unparseable"):
        schema.storage_blob(b"")


def test_storage_blob_keeps_the_infohash(tmp_path):
    from pirateface.seed import package

    source = make_model(tmp_path / "src" / "m")
    blob, v1, _v2 = package.make_torrent(source.parent, "m", ["udp://t:6969/announce"])
    assert str(schema._torrent_info(schema.storage_blob(blob)).info_hashes().v1) == v1
