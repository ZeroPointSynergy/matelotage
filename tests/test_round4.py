"""Regressions from adversary round 4 — the repository as a published artefact.

Round 3 hardened the logic of one code path. This round is about what a user, a maintainer or an
attacker hits *after* `pip install`: a junction walked on the scratch path, a mode that ignored the
key the README tells you to publish with, a CLI that stripped web seeds on one path and not the
other, and a staging writer that ate existing files.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from matelotage import cli, index, preserve, publish, schema

REPO = "org/model"
MAGNET = "magnet:?xt=urn:btih:" + "a" * 40


@pytest.fixture(autouse=True)
def keeper_mode(monkeypatch):
    monkeypatch.setenv("MATELOTAGE_MODE", "keeper")
    index.set_publication_check(None)


def make_model(root, seed=b"a"):
    root.mkdir(parents=True, exist_ok=True)
    (root / "config.json").write_text('{"hidden_size": 64}\n')
    (root / "model.bin").write_bytes(seed * 50_000)
    return root


# --- R4-1: the scratch path must not walk through a junction -------------------------------


def test_a_junction_directory_is_not_walked_into(tmp_path):
    """`is_symlink()` is False for a junction, and os.walk descends it: without resolution the
    scratch path would hash files that live outside the folder."""
    root = make_model(tmp_path / "model")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.bin").write_bytes(b"secret")

    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(root / "weights"), str(outside)],
        capture_output=True, text=True, check=False,
    )
    if made.returncode != 0:
        pytest.skip(f"cannot create a junction here: {made.stderr.strip()}")

    included, _skipped, escaping = preserve._collect(root)
    assert "weights/private.bin" not in included, "files outside the folder must never be hashed"
    assert any("weights" in p for p in escaping), escaping


def test_a_junction_makes_build_record_refuse(tmp_path):
    root = make_model(tmp_path / "model")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.bin").write_bytes(b"secret")
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(root / "weights"), str(outside)],
        capture_output=True, text=True, check=False,
    )
    if made.returncode != 0:
        pytest.skip(f"cannot create a junction here: {made.stderr.strip()}")

    from pirateface.client import api

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(preserve, "_server_entry", lambda repo_id: api.NOT_LISTED)
        with pytest.raises(preserve.AdoptError, match="links point outside"):
            preserve.build_record(REPO, root, license_id="mit")


# --- R4-2: mirror serves the operator's own keys, not just index 0 -------------------------


def _record() -> schema.NostrModelContent:
    return schema.NostrModelContent(
        repo_id=REPO, magnet=MAGNET, hf=True, license="mit", timestamp=1,
        files={"model.bin": "b" * 64},
    )


def _resolved(author_index: int) -> index.Resolved:
    return index.Resolved(content=_record(), event=None, author_index=author_index)


def test_mirror_serves_the_publisher_at_index_1(monkeypatch):
    monkeypatch.setenv("MATELOTAGE_MODE", "mirror")
    index.set_publication_check(lambda repo_id: True)
    assert index.admissible(_resolved(0)) is True
    assert index.admissible(_resolved(1)) is True, "the README's publisher key must be served"


def test_mirror_refuses_the_fill_in_tier(monkeypatch):
    monkeypatch.setenv("MATELOTAGE_MODE", "mirror")
    index.set_publication_check(lambda repo_id: True)
    assert index.admissible(_resolved(index.MIRROR_TIERS)) is False
    assert index.admissible(_resolved(7)) is False


def test_mirror_still_refuses_a_repo_the_site_withdrew(monkeypatch):
    monkeypatch.setenv("MATELOTAGE_MODE", "mirror")
    index.set_publication_check(lambda repo_id: False)
    assert index.admissible(_resolved(0)) is False


# --- R4-3: the publish path strips web seeds too ------------------------------------------


def test_publish_strips_the_web_seed_from_the_stored_torrent(tmp_path, monkeypatch):
    import libtorrent as lt
    from pirateface.seed import package

    source = make_model(tmp_path / "m")
    blob, v1, v2 = package.make_torrent(source.parent, source.name, ["udp://t:6969/announce"])
    magnet = package.magnet(v1, v2, source.name, ["udp://t:6969/announce"])
    seeded = lt.bencode({**lt.bdecode(blob), b"url-list": [b"https://example.invalid/ws/"]})
    torrent_path = tmp_path / "s.torrent"
    torrent_path.write_bytes(seeded)

    manifest_path = tmp_path / "m.json"
    manifest_path.write_text(json.dumps({"files": {"model.bin": "b" * 64}}))

    captured: dict = {}

    def fake_publish(event, *a, **k):
        captured["event"] = event
        return {"wss://relay.invalid": "ok"}

    monkeypatch.setattr(publish, "publish", fake_publish)
    nsec, npub, _hex = schema.generate_keypair()
    monkeypatch.setenv("MATELOTAGE_NSEC", nsec)
    monkeypatch.setenv("MATELOTAGE_NPUBS", npub)

    rc = cli.main([
        "publish", REPO, "--files", str(manifest_path), "--torrent", str(torrent_path),
        "--magnet", magnet, "--license", "mit",
    ])
    assert rc == 0
    body = json.loads(captured["event"]["content"])
    assert body["torrent_b64"]
    stored = __import__("base64").b64decode(body["torrent_b64"])
    assert b"url-list" not in lt.bdecode(stored), "a record must not point at the host it outlives"


# --- R4-5 / R4-6: staging never clobbers, and an untrusted key is refused -----------------


def test_staging_refuses_to_overwrite(tmp_path):
    from pirateface.seed import package

    source = make_model(tmp_path / "m")
    blob, v1, v2 = package.make_torrent(source.parent, "m", ["udp://t:6969/announce"])
    magnet = package.magnet(v1, v2, "m", ["udp://t:6969/announce"])
    content = publish.build_content(
        "m", magnet=magnet, files={"model.bin": "b" * 64}, license_id="mit", torrent_bytes=blob,
    )
    nsec, _npub, _hex = schema.generate_keypair()
    outcome = {"content": content, "event": publish.fit_event(nsec, content), "torrent": blob}

    out = tmp_path / "out"
    out.mkdir()
    (out / "m.torrent").write_text("PRECIOUS")

    with pytest.raises(preserve.AdoptError, match="refusing to overwrite"):
        preserve.write_staging(outcome, out)
    assert (out / "m.torrent").read_text() == "PRECIOUS"

    preserve.write_staging(outcome, out, force=True)
    assert (out / "m.torrent").read_bytes() == blob


def test_publishing_with_a_key_nobody_trusts_is_refused(tmp_path, capsys):
    nsec, _npub, _hex = schema.generate_keypair()
    _other_nsec, other_npub, _ = schema.generate_keypair()
    tmp_path.joinpath("m.json").write_text(json.dumps({"files": {"model.bin": "b" * 64}}))

    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("MATELOTAGE_NSEC", nsec)
        mp.setenv("MATELOTAGE_NPUBS", other_npub)  # we are signing with a key the operator never listed
        with pytest.raises(SystemExit) as excinfo:
            cli.main([
                "publish", REPO, "--files", str(tmp_path / "m.json"), "--magnet",
                MAGNET, "--license", "mit",
            ])
    assert "not in MATELOTAGE_NPUBS" in str(excinfo.value)


# --- R4-J: a timeout that disables the fallback must not be accepted ----------------------


@pytest.mark.parametrize("value", ["inf", "-inf", "nan", "abc", "1e12"])
def test_absurd_timeouts_fall_back_to_the_default(monkeypatch, value):
    monkeypatch.setenv("MATELOTAGE_TIMEOUT", value)
    assert 0.2 <= index.get_timeout() <= index.MAX_TIMEOUT
