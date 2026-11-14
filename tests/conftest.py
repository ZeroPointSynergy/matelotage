"""A loopback NIP-01 relay for tests. Real sockets, no network."""

from __future__ import annotations

import contextlib
import json
import socket
import threading
import time

import pytest
from websockets.sync.server import serve

from matelotage import schema

MAGNET_A = "magnet:?xt=urn:btih:" + "a" * 40 + "&dn=model-a"
MAGNET_B = "magnet:?xt=urn:btih:" + "b" * 40 + "&dn=model-b"
FILES = {"config.json": "c" * 64, "model.safetensors": "d" * 64}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def matches(event: dict, flt: dict) -> bool:
    if "kinds" in flt and event.get("kind") not in flt["kinds"]:
        return False
    if "authors" in flt and event.get("pubkey") not in flt["authors"]:
        return False
    wanted = flt.get("#d")
    if wanted:
        d_tag = next((t[1] for t in event.get("tags", []) if t and t[0] == "d"), None)
        if d_tag not in wanted:
            return False
    return True


class MockRelay:
    """Serves stored events over a real WebSocket. `silent=True` accepts and never answers."""

    def __init__(self, events: list[dict] | None = None, silent: bool = False):
        self.events: list[dict] = list(events or [])
        self.silent = silent
        self.connects = 0
        self.published: list[dict] = []
        self._started = threading.Event()
        self.port = free_port()
        self._server = serve(self._handler, "127.0.0.1", self.port)
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        # shutdown() closes the listening socket under the poller, which Windows reports as
        # WinError 10038; it is the documented way to stop, so swallow it.
        self._started.set()
        with contextlib.suppress(Exception):
            self._server.serve_forever()

    @property
    def url(self) -> str:
        return f"ws://127.0.0.1:{self.port}"

    def start(self) -> MockRelay:
        # `serve()` already bound the socket, so the listen backlog accepts connections as soon
        # as the loop runs; no probe connection is needed (and a bare TCP probe never reaches
        # the handler, it just fails the HTTP handshake).
        self._thread.start()
        self._started.wait(timeout=5)
        return self

    def stop(self) -> None:
        self._server.shutdown()

    def _handler(self, ws) -> None:
        self.connects += 1
        try:
            for raw in ws:
                try:
                    msg = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(msg, list) or not msg:
                    continue
                if msg[0] == "REQ":
                    if self.silent:
                        continue
                    sub = msg[1]
                    flt = msg[2] if len(msg) > 2 else {}
                    for event in self.events:
                        if matches(event, flt):
                            ws.send(json.dumps(["EVENT", sub, event]))
                    ws.send(json.dumps(["EOSE", sub]))
                elif msg[0] == "EVENT" and len(msg) > 1:
                    event = msg[1]
                    self.published.append(event)
                    if not self.silent:
                        ws.send(json.dumps(["OK", event.get("id"), True, ""]))
                elif msg[0] == "CLOSE":
                    return
        except Exception:
            return


def record(nsec: str, repo: str, magnet: str = MAGNET_A, *, created_at: int | None = None,
           files: dict | None = None, hf: bool = True, torrent: bytes | None = None) -> dict:
    when = int(time.time()) if created_at is None else created_at
    body = schema.NostrModelContent(
        repo_id=repo, magnet=magnet, hf=hf, license="mit",
        timestamp=when, files=dict(files or FILES), torrent_bytes=torrent,
    )
    return schema.build_signed_event(nsec, repo, body, created_at=when)


@pytest.fixture(scope="session")
def tiny_torrent(tmp_path_factory):
    """A real hybrid torrent over a real folder, with its manifest — for hf:false records."""
    import os

    from pirateface.client.torrent import files_in
    from pirateface.seed import package

    root = tmp_path_factory.mktemp("tiny")
    save = root / "s"
    model = save / "model"
    model.mkdir(parents=True)
    (model / "a.bin").write_bytes(os.urandom(300_000))
    (model / "b.bin").write_bytes(os.urandom(300_000))
    trackers = ["udp://tracker.example:6969/announce"]
    blob, v1, v2 = package.make_torrent(save, "model", trackers)
    paths = [path for path, _, _ in files_in(blob)]
    return {
        "blob": blob,
        "v1": v1,
        "magnet": package.magnet(v1, v2, "model", trackers),
        "files": package.checksums(model, paths),
        "paths": paths,
    }


def tombstone(nsec: str, repo: str, *, created_at: int | None = None) -> dict:
    when = int(time.time()) if created_at is None else created_at
    body = schema.NostrModelContent(
        repo_id=repo, magnet=None, hf=True, license="mit", timestamp=when,
        revoked=True, reason="withdrawn by the operator",
    )
    return schema.build_signed_event(nsec, repo, body, created_at=when)
