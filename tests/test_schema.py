"""Schema, crypto and torrent invariants. No network, no swarm."""

from __future__ import annotations

import base64
import json
import time

import libtorrent as lt
import pytest
from pirateface.seed import package

from matelotage import schema

TRACKERS = ["udp://tracker.pirateface.co:6969/announce"]
REPO = "BAAI/bge-micro-v2"


@pytest.fixture(scope="module")
def model(tmp_path_factory):
    """A small multi-file model folder plus its hybrid torrent."""
    root = tmp_path_factory.mktemp("hub")
    save = root / "s"
    model_dir = save / "model"
    model_dir.mkdir(parents=True)
    (model_dir / "config.json").write_text('{"hidden_size": 384}\n')
    (model_dir / "tokenizer.json").write_text("t" * 5000)
    (model_dir / "model.safetensors").write_bytes(bytes(range(256)) * 8000)
    blob, v1, v2 = package.make_torrent(save, "model", TRACKERS)
    paths = [p for p, _, _ in __import__("pirateface.client.torrent", fromlist=["x"]).files_in(blob)]
    digests = package.checksums(model_dir, paths)
    return {
        "blob": blob, "v1": v1, "v2": v2, "files": digests,
        "magnet": package.magnet(v1, v2, "model", TRACKERS),
        "name": "model", "dir": model_dir,
    }


def content_for(model, **overrides):
    fields = {
        "repo_id": REPO,
        "magnet": model["magnet"],
        "hf": True,
        "license": "mit",
        "timestamp": int(time.time()),
        "files": model["files"],
        "torrent_bytes": model["blob"],
    }
    fields.update(overrides)
    return schema.NostrModelContent(**fields)


@pytest.fixture
def keys():
    nsec, npub, hex_pub = schema.generate_keypair()
    return {"nsec": nsec, "npub": npub, "hex": hex_pub}


# ---------------------------------------------------------------- bech32


def test_bech32_roundtrip_npub_and_nsec(keys):
    assert schema.bech32_to_hex(keys["npub"], "npub") == keys["hex"]
    assert schema.bech32_to_hex(keys["nsec"], "nsec") == schema.bech32_to_hex(keys["nsec"], "nsec")
    assert schema.hex_to_bech32(keys["hex"], "npub") == keys["npub"]
    assert len(keys["npub"]) == 63


def test_zero_sentinel_is_unconfigured_and_not_a_key():
    assert schema.bech32_to_hex(schema.DEFAULT_TRUSTED_NPUB) == schema.ZERO_PUBKEY_HEX
    assert schema.hex_to_bech32(schema.ZERO_PUBKEY_HEX) == schema.DEFAULT_TRUSTED_NPUB


def test_bech32_rejects_bad_checksum_and_wrong_hrp(keys):
    broken = keys["npub"][:-1] + ("q" if keys["npub"][-1] != "q" else "p")
    with pytest.raises(schema.SchemaError):
        schema.bech32_to_hex(broken)
    with pytest.raises(schema.SchemaError):
        schema.bech32_to_hex(keys["nsec"], "npub")
    with pytest.raises(schema.SchemaError):
        schema.hex_to_bech32("zz" * 32)


# ---------------------------------------------------------------- signing


def test_sign_and_verify_two_repos(keys, model):
    for repo in (REPO, "HuggingFaceTB/SmolLM2-135M"):
        event = schema.build_signed_event(keys["nsec"], repo, content_for(model, repo_id=repo))
        parsed, content, index = schema.verify_and_parse_event(event, repo, [keys["hex"]])
        assert parsed.id == event["id"]
        assert content.repo_id == repo
        assert content.files == model["files"]
        assert content.torrent_bytes is not None
        assert index == 0


def test_rejects_tampered_content(keys, model):
    event = schema.build_signed_event(keys["nsec"], REPO, content_for(model))
    body = json.loads(event["content"])
    body["magnet"] = body["magnet"].replace("btih:", "btih:0" * 1)
    event["content"] = json.dumps(body, separators=(",", ":"))
    with pytest.raises(schema.SchemaError, match="tampered"):
        schema.verify_and_parse_event(event, REPO, [keys["hex"]])


def test_rejects_forged_id(keys, model):
    event = schema.build_signed_event(keys["nsec"], REPO, content_for(model))
    event["id"] = "f" * 64
    with pytest.raises(schema.SchemaError, match="tampered"):
        schema.verify_and_parse_event(event, REPO, [keys["hex"]])


def test_rejects_untrusted_author(keys, model):
    other = schema.generate_keypair()
    event = schema.build_signed_event(keys["nsec"], REPO, content_for(model))
    with pytest.raises(schema.SchemaError, match="not trusted"):
        schema.verify_and_parse_event(event, REPO, [other[2]])


def test_rejects_wrong_kind_and_d_tag(keys, model):
    event = schema.build_signed_event(keys["nsec"], REPO, content_for(model))
    bad_kind = dict(event, kind=1)
    with pytest.raises(schema.SchemaError, match="kind"):
        schema.verify_and_parse_event(bad_kind, REPO, [keys["hex"]])
    with pytest.raises(schema.SchemaError, match="d tag"):
        schema.verify_and_parse_event(event, "other/repo", [keys["hex"]])


def test_rejects_future_created_at(keys, model):
    event = schema.build_signed_event(
        keys["nsec"], REPO, content_for(model), created_at=int(time.time()) + schema.MAX_CLOCK_SKEW + 60
    )
    with pytest.raises(schema.SchemaError, match="window"):
        schema.verify_and_parse_event(event, REPO, [keys["hex"]])


# ---------------------------------------------------------------- content


@pytest.mark.parametrize("bad", ["../evil", "/etc/passwd", "C:/x", "a/../../b", "", "a//b"])
def test_rejects_unsafe_paths(keys, model, bad):
    event = schema.build_signed_event(keys["nsec"], REPO, content_for(model))
    body = json.loads(event["content"])
    body["files"][0]["path"] = bad
    event["content"] = json.dumps(body, separators=(",", ":"))
    with pytest.raises(schema.SchemaError):
        schema.validate_model_content(event["content"], REPO)


def test_rejects_missing_files(keys, model):
    event = schema.build_signed_event(keys["nsec"], REPO, content_for(model))
    body = json.loads(event["content"])
    body["files"] = []
    event["content"] = json.dumps(body, separators=(",", ":"))
    with pytest.raises(schema.SchemaError, match="files"):
        schema.validate_model_content(event["content"], REPO)


def test_hf_false_requires_torrent(keys, model):
    event = schema.build_signed_event(keys["nsec"], REPO, content_for(model, hf=False))
    body = json.loads(event["content"])
    body["torrent_b64"] = None
    event["content"] = json.dumps(body, separators=(",", ":"))
    with pytest.raises(schema.SchemaError, match="torrent_b64 is required"):
        schema.validate_model_content(event["content"], REPO)


def test_rejects_torrent_that_does_not_match_magnet(keys, model):
    wrong_magnet = package.magnet("1" * 40, None, "model", TRACKERS)
    event = schema.build_signed_event(keys["nsec"], REPO, content_for(model, magnet=wrong_magnet))
    with pytest.raises(schema.SchemaError, match="does not match magnet"):
        schema.verify_and_parse_event(event, REPO, [keys["hex"]])


def test_accepts_base32_btih(model):
    hex_hash = model["v1"]
    b32 = base64.b32encode(bytes.fromhex(hex_hash)).decode().lower()
    assert schema.magnet_btih(f"magnet:?xt=urn:btih:{b32}") == hex_hash
    assert schema.magnet_btih(f"magnet:?xt=urn:btih:{hex_hash.upper()}") == hex_hash


def test_timestamp_after_created_at_rejected(model):
    created = int(time.time()) - 60
    record = content_for(model, timestamp=int(time.time()))
    event = schema.build_signed_event(schema.generate_keypair()[0], REPO, record, created_at=created)
    with pytest.raises(schema.SchemaError, match="after the event"):
        schema.validate_model_content(event["content"], REPO, event_created_at=created)


def test_revoked_record_needs_no_payload():
    body = json.dumps({"schema": 1, "repo_id": REPO, "revoked": True, "license": "mit",
                       "timestamp": int(time.time()), "reason": "operator withdrew it"})
    parsed = schema.validate_model_content(body, REPO)
    assert parsed.revoked and parsed.magnet is None


def test_keyrevoke_content(keys):
    event = schema.build_keyrevoke_event(keys["nsec"], "a" * 64, reason="stolen")
    parsed = schema.validate_keyrevoke_content(event["content"])
    assert parsed["action"] == "revoke" and parsed["key"] == "a" * 64
    with pytest.raises(schema.SchemaError):
        schema.validate_keyrevoke_content('{"schema":1,"action":"shrug","key":"' + "a" * 64 + '"}')


# ---------------------------------------------------------------- E1 / E2


def test_e1_stripping_piece_layers_keeps_the_v1_infohash(model):
    stripped = schema.strip_piece_layers(model["blob"])
    assert len(stripped) < len(model["blob"])
    assert str(lt.torrent_info(stripped).info_hashes().v1) == model["v1"]
    assert b"piece layers" not in lt.bdecode(stripped)
    assert b"piece layers" in lt.bdecode(model["blob"])


def test_e2_stripping_v2_keys_changes_the_v1_infohash(model):
    """Documents why we never do the aggressive strip: it breaks the magnet binding."""
    torrent = lt.bdecode(model["blob"])
    torrent.pop(b"piece layers", None)
    torrent[b"info"].pop(b"meta version", None)
    torrent[b"info"].pop(b"file tree", None)
    pure = lt.bencode(torrent)
    assert str(lt.torrent_info(pure).info_hashes().v1) != model["v1"]
