"""adopt / publish / verify — the write path, all offline."""

from __future__ import annotations

import json
import os

import libtorrent as lt
import pytest
from conftest import MockRelay

from matelotage import index, preserve, publish, schema

REPO = "org/model"


def make_model(root, *, with_license=True):
    root.mkdir(parents=True, exist_ok=True)
    (root / "config.json").write_text('{"hidden_size": 64}\n')
    (root / "model.safetensors").write_bytes(os.urandom(400_000))
    if with_license:
        (root / "LICENSE").write_text("MIT\n")
    return root


@pytest.fixture(autouse=True)
def keeper_mode(monkeypatch):
    monkeypatch.setenv("MATELOTAGE_MODE", "keeper")
    index.set_publication_check(None)
    index.clear_cache()
    # tests must never touch the real API; individual tests override these
    monkeypatch.setattr(preserve, "_server_entry", lambda repo_id: None)
    monkeypatch.setattr(preserve, "_server_torrent", lambda repo_id: None)
    yield
    index.clear_cache()


def test_build_record_matches_the_torrent(tmp_path):
    model = make_model(tmp_path / "org--model")
    content, blob, _skipped = preserve.build_record(REPO, model, license_id="mit")

    from pirateface.client.torrent import files_in

    paths = {path for path, _, _ in files_in(blob)}
    assert set(content.files) == paths
    assert content.magnet.startswith("magnet:?xt=urn:btih:")
    assert schema.magnet_btih(content.magnet) == str(lt.torrent_info(blob).info_hashes().v1)
    assert content.license == "mit"


def test_license_file_is_detected_and_recorded(tmp_path):
    model = make_model(tmp_path / "with-license", with_license=True)
    content, _, _skipped = preserve.build_record(REPO, model, license_id="qwen-community-1.0")
    assert content.license_file == "LICENSE"
    assert content.to_dict()["license_file"] == "LICENSE"

    bare = make_model(tmp_path / "without-license", with_license=False)
    content, _, _skipped = preserve.build_record(REPO, bare, license_id="mit")
    assert content.license_file is None


def test_a_license_file_missing_from_the_manifest_is_rejected(tmp_path):
    model = make_model(tmp_path / "m")
    content, _, _skipped = preserve.build_record(REPO, model, license_id="mit")
    body = json.loads(json.dumps(content.to_dict()))
    body["license_file"] = "NOT-THERE"
    with pytest.raises(schema.SchemaError, match="not in the manifest"):
        schema.validate_model_content(json.dumps(body), REPO)


def test_fit_event_drops_the_torrent_before_it_drops_the_manifest(tmp_path):
    model = make_model(tmp_path / "m")
    content, _, _skipped = preserve.build_record(REPO, model, license_id="mit")
    whole = publish.fit_event(schema.generate_keypair()[0], content, limit=1_000_000)
    assert "torrent_b64" in json.loads(whole["content"])

    slimmed = publish.fit_event(schema.generate_keypair()[0], content, limit=2_000)
    body = json.loads(slimmed["content"])
    assert body["torrent_b64"] is None
    assert body["files"], "the attestation must survive the size cut"


def test_hf_false_cannot_be_slimmed_away(tmp_path):
    model = make_model(tmp_path / "m")
    content, _, _skipped = preserve.build_record(REPO, model, license_id="mit", hf=False)
    with pytest.raises(ValueError, match="over the"):
        publish.fit_event(schema.generate_keypair()[0], content, limit=2_000)


def test_adopt_local_writes_three_files_and_publishes_nothing(tmp_path):
    model = make_model(tmp_path / "org--model")
    nsec = schema.generate_keypair()[0]
    out = preserve.adopt(REPO, source=str(model), license_id="mit", nsec=nsec, local=True)
    assert out["relay_results"] == {}

    written = preserve.write_staging(out, tmp_path / "stage")
    assert set(written) == {"torrent", "manifest", "event"}
    manifest = json.loads(written["manifest"].read_text())
    assert manifest["repo_id"] == REPO
    assert manifest["files"]
    event = json.loads(written["event"].read_text())
    _parsed, content, _ = schema.verify_and_parse_event(event, REPO, [event["pubkey"]])
    assert content.license == "mit"


def test_adopt_without_a_license_is_refused(tmp_path):
    model = make_model(tmp_path / "m")
    with pytest.raises(preserve.AdoptError, match="--license is required"):
        preserve.adopt(REPO, source=str(model), license_id=None, nsec=schema.generate_keypair()[0])


def test_verify_catches_one_flipped_byte(tmp_path, monkeypatch):
    model = make_model(tmp_path / "m")
    content, _, _skipped = preserve.build_record(REPO, model, license_id="mit")
    event = schema.NostrEvent(id="0" * 64, pubkey="0" * 64, created_at=0, kind=30078,
                              tags=[], content="", sig="0" * 128)
    monkeypatch.setattr(
        index, "get", lambda repo_id: index.Resolved(content=content, event=event, author_index=0)
    )

    clean = preserve.verify(REPO, model)
    assert clean["mismatched"] == [] and clean["missing"] == []
    assert clean["ok"] == clean["total"]
    assert clean["license_file_present"] is True

    target = model / "config.json"
    target.write_text('{"hidden_size": 65}\n')
    dirty = preserve.verify(REPO, model)
    assert dirty["mismatched"] == ["config.json"]
    assert dirty["ok"] == dirty["total"] - 1

    (model / "model.safetensors").unlink()
    missing = preserve.verify(REPO, model)
    assert missing["missing"] == ["model.safetensors"]


def test_publish_refuses_a_torrent_without_a_manifest(capsys):
    from matelotage import cli

    with pytest.raises(SystemExit) as caught:
        cli.main(["publish", REPO, "--torrent", "x.torrent", "--license", "mit"])
    assert "--files is required" in str(caught.value)


def test_publish_with_a_manifest_reaches_the_relay(tmp_path, monkeypatch):
    relay = MockRelay().start()
    nsec, npub, pubkey = schema.generate_keypair()
    monkeypatch.setenv("MATELOTAGE_RELAYS", relay.url)
    monkeypatch.setenv("MATELOTAGE_NSEC", nsec)
    monkeypatch.setenv("MATELOTAGE_NPUBS", npub)  # a record nobody trusts is not a publication

    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps({
        "magnet": "magnet:?xt=urn:btih:" + "a" * 40,
        "files": {"config.json": "b" * 64},
    }))
    from matelotage import cli

    assert cli.main(["publish", REPO, "--files", str(manifest), "--license", "mit"]) == 0
    assert relay.published, "nothing reached the relay"
    _parsed, content, _ = schema.verify_and_parse_event(relay.published[0], REPO, [pubkey])
    assert content.license == "mit"
    assert content.files == {"config.json": "b" * 64}
    relay.stop()


# ---------------------------------------------------------------- round 2 regressions

MAGNET = "magnet:?xt=urn:btih:" + "a" * 40


def test_a_list_form_manifest_signs_the_real_paths(tmp_path, monkeypatch):
    """`{files: [{path, sha256}]}` must not collapse to the literal keys 'path' and 'sha256'."""
    relay = MockRelay().start()
    nsec, npub, pubkey = schema.generate_keypair()
    monkeypatch.setenv("MATELOTAGE_RELAYS", relay.url)
    monkeypatch.setenv("MATELOTAGE_NSEC", nsec)
    monkeypatch.setenv("MATELOTAGE_NPUBS", npub)  # a record nobody trusts is not a publication
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps({
        "magnet": MAGNET,
        "files": [{"path": "config.json", "sha256": "b" * 64}, {"path": "LICENSE", "sha256": "c" * 64}],
    }))
    from matelotage import cli

    assert cli.main(["publish", REPO, "--files", str(manifest), "--license", "mit"]) == 0
    _p, content, _i = schema.verify_and_parse_event(relay.published[0], REPO, [pubkey])
    assert content.files == {"config.json": "b" * 64, "LICENSE": "c" * 64}
    relay.stop()


def test_an_unsafe_manifest_is_never_published(tmp_path, monkeypatch):
    relay = MockRelay().start()
    nsec, _npub, _pubkey = schema.generate_keypair()
    monkeypatch.setenv("MATELOTAGE_RELAYS", relay.url)
    monkeypatch.setenv("MATELOTAGE_NSEC", nsec)
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps({"magnet": MAGNET, "files": {"../../etc/passwd": "d" * 64}}))
    from matelotage import cli

    with pytest.raises(SystemExit) as caught:
        cli.main(["publish", REPO, "--files", str(manifest), "--license", "mit"])
    assert "unsafe path" in str(caught.value)
    assert relay.published == [], "an unreadable record reached a relay and would replace a good one"
    relay.stop()


def test_pf_only_without_a_torrent_is_refused(tmp_path, monkeypatch):
    relay = MockRelay().start()
    nsec, _npub, _pubkey = schema.generate_keypair()
    monkeypatch.setenv("MATELOTAGE_RELAYS", relay.url)
    monkeypatch.setenv("MATELOTAGE_NSEC", nsec)
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps({"magnet": MAGNET, "files": {"a.txt": "b" * 64}}))
    from matelotage import cli

    with pytest.raises(SystemExit):
        cli.main(["publish", REPO, "--files", str(manifest), "--license", "mit", "--pf-only"])
    assert relay.published == []
    relay.stop()


def test_keyrevoke_accepts_an_npub(monkeypatch):
    relay = MockRelay().start()
    cold, cold_npub, _cold_hex = schema.generate_keypair()
    _target, target_npub, target_hex = schema.generate_keypair()
    monkeypatch.setenv("MATELOTAGE_RELAYS", relay.url)
    monkeypatch.setenv("MATELOTAGE_NPUBS", cold_npub)
    monkeypatch.setenv("MATELOTAGE_TIMEOUT", "0.5")
    index.clear_cache()

    results = publish.keyrevoke(target_npub, "stolen", nsec=cold)
    assert any(status == "ok" for status in results.values())
    relay.events.append(relay.published[-1])
    assert index.revoked_keys() == {target_hex}, "a bech32 key in the record is unreadable"
    relay.stop()
    index.clear_cache()


def test_adopt_excludes_secrets_and_reports_them(tmp_path):
    model = make_model(tmp_path / "leaky")
    (model / ".env").write_text("TOKEN=1")
    (model / "id_rsa").write_text("private")
    (model / ".git").mkdir()
    (model / ".git" / "config").write_text("x")
    (model / "training.pem").write_text("pem")

    content, _blob, skipped = preserve.build_record(REPO, model, license_id="mit")
    assert set(content.files) == {"config.json", "model.safetensors", "LICENSE"}
    assert {".env", "id_rsa", ".git/config", "training.pem"} <= set(skipped)


def test_adopt_refuses_a_link_pointing_outside(tmp_path):
    model = make_model(tmp_path / "linked")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    try:
        (model / "leak.txt").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("this host cannot create symlinks without privileges")
    with pytest.raises(preserve.AdoptError, match="outside the folder"):
        preserve.build_record(REPO, model, license_id="mit")


def test_write_staging_keeps_hostile_repo_ids_inside_the_output_dir(tmp_path):
    content = publish.build_content(
        r"..\evil", magnet=MAGNET, files={"a.txt": "b" * 64}, license_id="mit"
    )
    outcome = {"content": content, "torrent": b"x", "event": {}}
    written = preserve.write_staging(outcome, tmp_path / "out")
    root = (tmp_path / "out").resolve()
    for path in written.values():
        assert path.parent == root


def test_the_budget_is_counted_in_bytes_not_characters(tmp_path):
    model = make_model(tmp_path / "unicode")
    (model / "modèle.json").write_text("{}")
    content, _blob, _skipped = preserve.build_record(REPO, model, license_id="mit")
    event = schema.build_signed_event(schema.generate_keypair()[0], REPO, content)
    chars = len(json.dumps(event, separators=(",", ":"), ensure_ascii=False))
    assert publish.wire_size(event) > chars, "multibyte paths make bytes exceed characters"


def test_adopt_reuses_the_torrent_pirate_face_publishes(tmp_path, monkeypatch):
    """One repo, one swarm: a published repo must be adopted through PF's own torrent."""
    from pirateface.seed import package

    model = make_model(tmp_path / "SmolLM2-135M")
    blob, v1, v2 = package.make_torrent(tmp_path, "SmolLM2-135M", ["udp://t:6969/announce"])
    magnet = package.magnet(v1, v2, "SmolLM2-135M", ["udp://t:6969/announce"])
    monkeypatch.setattr(
        preserve, "_server_entry", lambda repo_id: {"magnet": magnet, "revision": "abc123", "hf": True}
    )
    monkeypatch.setattr(preserve, "_server_torrent", lambda repo_id: blob)

    content, out_blob, skipped = preserve.build_record(REPO, model, license_id="mit")

    assert content.magnet == magnet, "the record must point at the swarm that exists"
    assert schema.magnet_btih(content.magnet) == v1
    assert str(lt.torrent_info(out_blob).info_hashes().v1) == v1
    assert str(lt.torrent_info(content.torrent_bytes).info_hashes().v1) == v1
    assert content.revision == "abc123"
    assert set(content.files) == {"config.json", "model.safetensors", "LICENSE"}
    assert skipped == []


def test_adopt_refuses_when_the_published_torrent_lists_files_we_lack(tmp_path, monkeypatch):
    from pirateface.seed import package

    model = make_model(tmp_path / "m")
    other = tmp_path / "other" / "m"
    make_model(other)
    (other / "extra.bin").write_bytes(b"x" * 100)
    blob, v1, v2 = package.make_torrent(other.parent, "m", ["udp://t:6969/announce"])
    magnet = package.magnet(v1, v2, "m", ["udp://t:6969/announce"])
    monkeypatch.setattr(preserve, "_server_entry", lambda repo_id: {"magnet": magnet, "hf": True})
    monkeypatch.setattr(preserve, "_server_torrent", lambda repo_id: blob)

    with pytest.raises(preserve.AdoptError, match="does not have"):
        preserve.build_record(REPO, model, license_id="mit")


def test_adopt_rejects_a_magnet_that_disagrees_with_the_published_torrent(tmp_path, monkeypatch):
    from pirateface.seed import package

    model = make_model(tmp_path / "m")
    blob, _v1, _v2 = package.make_torrent(tmp_path, "m", ["udp://t:6969/announce"])
    monkeypatch.setattr(
        preserve, "_server_entry", lambda repo_id: {"magnet": "magnet:?xt=urn:btih:" + "9" * 40, "hf": True}
    )
    monkeypatch.setattr(preserve, "_server_torrent", lambda repo_id: blob)

    with pytest.raises(preserve.AdoptError, match="disagree"):
        preserve.build_record(REPO, model, license_id="mit")


def test_coverage_records_files_the_swarm_does_not_carry(tmp_path, monkeypatch):
    """PF's torrents are partial; a record must not imply it keeps what the swarm lacks."""
    from pirateface.seed import package

    listed = tmp_path / "listed" / "m"
    make_model(listed)
    blob, v1, v2 = package.make_torrent(listed.parent, "m", ["udp://t:6969/announce"])
    magnet = package.magnet(v1, v2, "m", ["udp://t:6969/announce"])

    # the local copy is the same bytes (make_model is random, so copy it) plus two extra files
    import shutil

    local = tmp_path / "local" / "m"
    shutil.copytree(listed, local)
    (local / "pytorch_model.bin").write_bytes(b"w" * 1000)
    (local / "flax_model.msgpack").write_bytes(b"f" * 1000)

    monkeypatch.setattr(preserve, "_server_entry", lambda repo_id: {"magnet": magnet, "hf": True})
    monkeypatch.setattr(preserve, "_server_torrent", lambda repo_id: blob)

    content, _blob, _skipped = preserve.build_record(REPO, local, license_id="mit")
    assert content.not_in_swarm == ["flax_model.msgpack", "pytorch_model.bin"]
    assert set(content.files).isdisjoint(content.not_in_swarm)
    parsed = schema.validate_model_content(json.dumps(content.to_dict()), REPO)
    assert parsed.not_in_swarm == content.not_in_swarm


def test_not_in_swarm_cannot_overlap_the_manifest():
    body = {
        "schema": 1, "repo_id": REPO, "magnet": MAGNET, "license": "mit",
        "timestamp": 1, "files": [{"path": "a.txt", "sha256": "b" * 64}],
        "not_in_swarm": ["a.txt"],
    }
    with pytest.raises(schema.SchemaError, match="overlaps"):
        schema.validate_model_content(json.dumps(body), REPO)


def test_the_stored_torrent_drops_web_seeds_but_keeps_the_infohash(tmp_path):
    from pirateface.seed import package

    make_model(tmp_path / "m")
    blob, v1, _v2 = package.make_torrent(tmp_path, "m", ["udp://t:6969/announce"])
    seeded = lt.bencode({**lt.bdecode(blob), b"url-list": [b"https://example.invalid/ws/"]})
    assert b"url-list" in lt.bdecode(seeded)

    stored = schema.storage_blob(seeded)
    assert b"url-list" not in lt.bdecode(stored)
    assert str(lt.torrent_info(stored).info_hashes().v1) == v1, "the swarm identity must not change"


def test_seeders_are_recorded_with_the_claim(tmp_path, monkeypatch):
    from pirateface.seed import package

    model = make_model(tmp_path / "m")
    blob, v1, v2 = package.make_torrent(tmp_path, "m", ["udp://t:6969/announce"])
    magnet = package.magnet(v1, v2, "m", ["udp://t:6969/announce"])
    monkeypatch.setattr(
        preserve, "_server_entry",
        lambda repo_id: {"magnet": magnet, "hf": True, "seeders": 3, "revision": "r1"},
    )
    monkeypatch.setattr(preserve, "_server_torrent", lambda repo_id: blob)

    content, _blob, _skipped = preserve.build_record(REPO, model, license_id="mit")
    assert content.seeders_at_publish == 3
    parsed = schema.validate_model_content(json.dumps(content.to_dict()), REPO)
    assert parsed.seeders_at_publish == 3


def test_seeders_must_be_a_non_negative_int():
    body = {
        "schema": 1, "repo_id": REPO, "magnet": MAGNET, "license": "mit",
        "timestamp": 1, "files": [{"path": "a.txt", "sha256": "b" * 64}],
        "seeders_at_publish": -1,
    }
    with pytest.raises(schema.SchemaError, match="seeders_at_publish"):
        schema.validate_model_content(json.dumps(body), REPO)
