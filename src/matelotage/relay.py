"""Relay I/O: one daemon event loop, concurrent fan-out, and silence treated as failure.

Measured 2026-11-14: nos.lol opens a socket and never answers, and damus was returning HTTP 521.
A relay that says nothing is not "maybe" — it is a failed relay, and it must not extend the
timeout budget of the ones that do answer.
"""

from __future__ import annotations

import asyncio
import atexit
import contextlib
import json
import logging
import secrets
import threading
from dataclasses import dataclass
from typing import Any

from . import schema

log = logging.getLogger("matelotage.relay")

_loop: asyncio.AbstractEventLoop | None = None
_thread: threading.Thread | None = None
_lock = threading.Lock()


@dataclass(frozen=True, slots=True)
class QueryResult:
    events: list[dict[str, Any]]
    responded: int  # relays that actually reached EOSE
    attempted: int

    @property
    def total_silence(self) -> bool:
        return self.attempted > 0 and self.responded == 0


def _run(loop: asyncio.AbstractEventLoop) -> None:
    asyncio.set_event_loop(loop)
    loop.run_forever()


def ensure_loop() -> asyncio.AbstractEventLoop:
    """The one background loop. Started lazily so importing matelotage costs nothing.

    Rebuilt if it died: `atexit` stops it, and a stopped loop would otherwise swallow every
    later query for the full timeout and leave an un-awaited coroutine behind.
    """
    global _loop, _thread
    with _lock:
        if _loop is None or _loop.is_closed() or _thread is None or not _thread.is_alive():
            _loop = asyncio.new_event_loop()
            _thread = threading.Thread(target=_run, args=(_loop,), name="matelotage-relay", daemon=True)
            _thread.start()
        return _loop


@atexit.register
def _stop() -> None:
    loop = _loop
    if loop is not None and loop.is_running():
        loop.call_soon_threadsafe(loop.stop)


async def _query_one(
    relay: str, sub_id: str, req_filter: dict[str, Any], timeout: float, max_events: int
) -> tuple[list[dict[str, Any]], bool]:
    from websockets.asyncio.client import connect

    events: list[dict[str, Any]] = []
    responded = False
    dropped = 0
    try:
        async with connect(relay, open_timeout=timeout, close_timeout=1) as ws:
            await ws.send(json.dumps(["REQ", sub_id, req_filter], separators=(",", ":")))
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    frame = await asyncio.wait_for(ws.recv(), remaining)
                except TimeoutError:
                    break
                try:
                    msg = json.loads(frame)
                except ValueError:
                    continue
                if not isinstance(msg, list) or not msg:
                    continue
                if msg[0] == "EOSE":
                    if len(msg) < 2 or msg[1] == sub_id:
                        responded = True
                    break
                if msg[0] == "CLOSED":
                    break
                if msg[0] != "EVENT" or len(msg) < 3 or not isinstance(msg[2], dict):
                    continue
                if len(msg) > 1 and msg[1] != sub_id:
                    continue  # a frame for someone else's subscription is not ours to trust
                event = msg[2]
                # A relay is untrusted: cap what one lookup can make this process hold.
                if len(json.dumps(event, separators=(",", ":"), ensure_ascii=False)) > schema.MAX_EVENT_BYTES:
                    dropped += 1
                    continue
                events.append(event)
                if len(events) >= max_events:
                    responded = True  # we stopped reading on purpose, not because it went quiet
                    break
            with contextlib.suppress(Exception):
                await ws.send(json.dumps(["CLOSE", sub_id]))
    except Exception as exc:  # any transport failure is just "this relay did not answer"
        log.debug("relay %s: %s: %s", relay, type(exc).__name__, exc)
    if dropped:
        log.warning("relay %s: dropped %d oversized event(s) over %d bytes", relay, dropped, schema.MAX_EVENT_BYTES)
    return events, responded


async def query_async(relays: list[str], req_filter: dict[str, Any], timeout: float) -> QueryResult:
    sub_id = "mtl" + secrets.token_hex(4)
    limit = req_filter.get("limit")
    max_events = max(64, 2 * limit + 8) if isinstance(limit, int) else 64
    results = await asyncio.gather(
        *(_query_one(relay, sub_id, req_filter, timeout, max_events) for relay in relays),
        return_exceptions=True,
    )
    events: list[dict[str, Any]] = []
    responded = 0
    for result in results:
        if isinstance(result, BaseException):
            continue
        got, ok = result
        responded += bool(ok)
        events.extend(got)
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for event in events:
        event_id = event.get("id")
        if isinstance(event_id, str) and event_id not in seen:
            seen.add(event_id)
            unique.append(event)
    return QueryResult(unique, responded, len(relays))


def query(relays: list[str], req_filter: dict[str, Any], timeout: float) -> QueryResult:
    """Synchronous fan-out on the shared loop. Never raises; an empty result is a normal answer."""
    if not relays:
        return QueryResult([], 0, 0)
    loop = ensure_loop()
    coro = query_async(relays, req_filter, timeout)
    if not loop.is_running():
        coro.close()  # never leave an un-awaited coroutine behind
        return QueryResult([], 0, len(relays))
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    try:
        return future.result(timeout + 0.5)
    except Exception as exc:
        log.debug("fan-out failed: %s", exc)
        future.cancel()
        return QueryResult([], 0, len(relays))


async def publish_async(event: dict[str, Any], relays: list[str], timeout: float = 5.0) -> dict[str, str]:
    from websockets.asyncio.client import connect

    async def one(relay: str) -> tuple[str, str]:
        try:
            async with connect(relay, open_timeout=timeout, close_timeout=2) as ws:
                await ws.send(json.dumps(["EVENT", event], separators=(",", ":")))
                loop = asyncio.get_running_loop()
                deadline = loop.time() + timeout
                while loop.time() < deadline:
                    try:
                        frame = await asyncio.wait_for(ws.recv(), deadline - loop.time())
                    except TimeoutError:
                        break
                    try:
                        msg = json.loads(frame)
                    except ValueError:
                        continue
                    if msg[0] == "OK" and msg[1] == event.get("id"):
                        return relay, "ok" if msg[2] else f"rejected: {msg[3] if len(msg) > 3 else ''}"[:200]
                    if msg[0] in ("NOTICE", "CLOSED"):
                        return relay, f"{msg[0].lower()}: {str(msg[1])[:180]}"
                return relay, "silent: no OK"
        except Exception as exc:
            return relay, f"unreachable: {type(exc).__name__}"

    if not relays:
        return {}
    pairs = await asyncio.gather(*(one(relay) for relay in relays), return_exceptions=True)
    out: dict[str, str] = {}
    for pair in pairs:
        if isinstance(pair, BaseException):
            continue
        relay, status = pair
        out[relay] = status
    return out


def publish(event: dict[str, Any], relays: list[str], timeout: float = 5.0) -> dict[str, str]:
    loop = ensure_loop()
    coro = publish_async(event, relays, timeout)
    if not loop.is_running():
        coro.close()
        return {relay: "unreachable: no event loop" for relay in relays}
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    try:
        return future.result(timeout + 2.0)
    except Exception as exc:
        log.debug("publish failed: %s", exc)
        future.cancel()
        return {relay: "unreachable: timeout" for relay in relays}
