"""Regressions from adversary round 5 — the last uncovered seam.

Two of these are the difference between "the tests pass" and "the thing works": an install() that
captured its own functions and recursed on first use, and a hardlink that walked an outside file into
a public record. The rest close gaps that would have made a green suite lie.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from conftest import MAGNET_A, MockRelay, record, tombstone

from matelotage import cli, index, preserve, publish, schema

REPO = "org/model"
SRC = Path(__file__).resolve().parents[1] / "src"


@pytest.fixture(autouse=True)
def keeper_mode(monkeypatch):
    monkeypatch.setenv("MATELOTAGE_MODE", "keeper")
    index.set_publication_check(None)


def make_model(root):
    root.mkdir(parents=True, exist_ok=True)
    (root / "config.json").write_text('{"hidden_size": 64}\n')
    (root / "model.bin").write_bytes(b"a" * 40_000)
    return root


# --- R5-1: install() must never capture its own functions ----------------------------------


def test_install_before_any_import_does_not_poison_the_originals():
    """`install()` imports pirateface.client.api, and that import is intercepted by our own meta-path
    finder, which calls install() again. Without a guard the outer call captured the *patched*
    functions as the originals and every later call recursed until the stack died."""
    script = (
        "import matelotage._boot  # installs the finder, as the .pth does\n"
        "from matelotage import patch\n"
        "patch.install()\n"
        "import pirateface.client.api as api\n"
        "assert patch._orig['pf_only'] is not patch.pf_only, 'originals were captured after patching'\n"
        "assert patch._orig['lookup_magnet'] is not patch.lookup_magnet\n"
        "assert api.pf_only is patch.pf_only and api.lookup_magnet is patch.lookup_magnet\n"
        "print('ok', api.pf_only('acme/definitely-not-listed'))\n"
    )
    env = {
        **os.environ,
        "PYTHONPATH": str(SRC),
        "PF_API": "http://127.0.0.1:9",
        "MATELOTAGE_RELAYS": "ws://127.0.0.1:9",
        "MATELOTAGE_NPUBS": "",
        "MATELOTAGE_TIMEOUT": "0.2",
    }
    done = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=False, env=env, timeout=120
    )
    assert done.returncode == 0, done.stderr[-800:]
    assert "RecursionError" not in done.stderr
    assert "ok None" in done.stdout


# --- R5-2: a hardlink is an escape containment cannot see ----------------------------------


def test_a_hardlink_to_an_outside_file_is_refused(tmp_path):
    model = make_model(tmp_path / "model")
    secret = tmp_path / "outside" / "id_rsa"
    secret.parent.mkdir()
    secret.write_text("PRIVATE KEY")

    link = model / "weights.bin"
    try:
        os.link(secret, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create a hardlink here: {exc}")

    included, _skipped, escaping = preserve._collect(model)
    assert "weights.bin" not in included
    assert any("hardlink" in entry for entry in escaping), escaping

    with pytest.raises(preserve.AdoptError, match="hardlink"):
        preserve._screen_paths(model.resolve(), {"weights.bin": 11})


def test_hardlinks_can_be_accepted_explicitly(tmp_path, monkeypatch):
    model = make_model(tmp_path / "model")
    secret = tmp_path / "outside"
    secret.mkdir()
    (secret / "f").write_text("x")
    try:
        os.link(secret / "f", model / "weights.bin")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create a hardlink here: {exc}")

    monkeypatch.setenv("MATELOTAGE_ALLOW_HARDLINKS", "1")
    included, _skipped, _escaping = preserve._collect(model)
    assert "weights.bin" in included


# --- R5-3: no allowlist means no client will serve it --------------------------------------


def test_publishing_with_no_allowlist_at_all_is_refused(tmp_path, monkeypatch):
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps({"files": {"model.bin": "b" * 64}}))
    monkeypatch.setenv("MATELOTAGE_NSEC", schema.generate_keypair()[0])
    monkeypatch.delenv("MATELOTAGE_NPUBS", raising=False)
    monkeypatch.delenv("MATELOTAGE_NPUB", raising=False)

    with pytest.raises(SystemExit, match="no MATELOTAGE_NPUBS configured"):
        cli.main(["publish", REPO, "--files", str(manifest), "--magnet", MAGNET_A, "--license", "mit"])


# --- R5-4: a staging refusal is a message, not a traceback ---------------------------------


def test_staging_refusal_exits_with_an_error_line(tmp_path, monkeypatch, capsys):
    from pirateface.client import api
    model = make_model(tmp_path / "model")
    monkeypatch.setattr(preserve, "_server_entry", lambda repo_id: api.NOT_LISTED)
    nsec, npub, _hex = schema.generate_keypair()
    monkeypatch.setenv("MATELOTAGE_NSEC", nsec)
    monkeypatch.setenv("MATELOTAGE_NPUBS", npub)

    out = tmp_path / "out"
    out.mkdir()
    stem = "org-model"
    (out / f"{stem}.event.json").write_text("PRECIOUS")

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["adopt", REPO, "--from-dir", str(model), "--license", "mit", "--local",
                  "--out", str(out)])
    assert str(excinfo.value).startswith("error:")
    assert (out / f"{stem}.event.json").read_text() == "PRECIOUS"


# --- R5-5: a record may not describe files its own torrent does not carry -----------------


def test_a_manifest_naming_files_outside_the_torrent_is_rejected(tmp_path):
    from pirateface.seed import package

    model = make_model(tmp_path / "model")
    blob, v1, v2 = package.make_torrent(model.parent, "model", ["udp://t:6969/announce"])
    magnet = package.magnet(v1, v2, "model", ["udp://t:6969/announce"])
    content = publish.build_content(
        REPO, magnet=magnet, files={"model.bin": "b" * 64}, license_id="mit",
        torrent_bytes=schema.storage_blob(blob),
    )
    nsec, _npub, _hex = schema.generate_keypair()
    event = publish.fit_event(nsec, content)

    tampered = json.loads(event["content"])
    tampered["files"] = {"model.bin": "b" * 64, "not-in-swarm.bin": "c" * 64}
    with pytest.raises(schema.SchemaError, match="does not contain"):
        schema.validate_model_content(json.dumps(tampered), REPO)


# --- R5-6: a long-running process must eventually see a withdrawal ------------------------


def test_a_withdrawal_is_observed_after_the_cache_ttl_expires(monkeypatch):
    keys = [schema.generate_keypair() for _ in range(2)]
    relay = MockRelay().start()
    try:
        monkeypatch.setenv("MATELOTAGE_RELAYS", relay.url)
        monkeypatch.setenv("MATELOTAGE_NPUBS", ",".join(k[1] for k in keys))
        monkeypatch.setenv("MATELOTAGE_TIMEOUT", "0.6")
        monkeypatch.setenv("MATELOTAGE_CACHE_TTL", "0.05")
        index.clear_cache()

        relay.events.append(record(keys[1][0], REPO, MAGNET_A))
        assert index.resolve_magnet(REPO) == MAGNET_A

        relay.events.append(tombstone(keys[1][0], REPO, created_at=int(time.time()) + 1))
        time.sleep(0.1)
        assert index.resolve_magnet(REPO) is None, "a revival that outlives its withdrawal is a bug"
    finally:
        relay.stop()
        index.clear_cache()
