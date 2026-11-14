"""Relay hardening: untrusted peers must not be able to grow or wedge this process."""

from __future__ import annotations

import time

from conftest import MockRelay

from matelotage import relay, schema


def event(n: int, kind: int = 30078) -> dict:
    return {"id": f"{n:064x}", "pubkey": "0" * 64, "created_at": 0, "kind": kind,
            "tags": [["d", f"x/{n}"]], "content": "y" * 10, "sig": "0" * 128}


def test_oversized_events_are_dropped_before_they_are_retained():
    server = MockRelay()
    server.events = [
        event(1),
        {**event(2), "content": "z" * (schema.MAX_EVENT_BYTES + 1000)},
        event(3),
    ]
    server.start()
    try:
        result = relay.query([server.url], {"kinds": [30078], "limit": 10}, 1.0)
        assert result.responded == 1
        ids = [e["id"] for e in result.events]
        assert ids == [f"{1:064x}", f"{3:064x}"], "the oversized event was retained"
    finally:
        server.stop()


def test_a_flooding_relay_is_capped_by_the_subscription_limit():
    server = MockRelay()
    server.events = [event(n) for n in range(400)]
    server.start()
    try:
        started = time.perf_counter()
        result = relay.query([server.url], {"kinds": [30078], "limit": 10}, 2.0)
        elapsed = time.perf_counter() - started
        assert result.responded == 1
        assert len(result.events) <= 64, f"held {len(result.events)} events for one lookup"
        assert elapsed < 2.0, "the cap should stop reading, not wait out the timeout"
    finally:
        server.stop()


def test_frames_for_another_subscription_are_ignored():
    class CrossTalk(MockRelay):
        def _handler(self, ws):
            self.connects += 1
            for raw in ws:
                import json

                msg = json.loads(raw)
                if msg[0] == "REQ":
                    ws.send(json.dumps(["EVENT", "someone-else", event(9)]))
                    ws.send(json.dumps(["EOSE", msg[1]]))

    server = CrossTalk().start()
    try:
        result = relay.query([server.url], {"kinds": [30078], "limit": 10}, 1.0)
        assert result.responded == 1
        assert result.events == []
    finally:
        server.stop()


def test_query_recovers_after_the_daemon_loop_dies():
    """`atexit` stops the loop; a later query must rebuild it rather than silently time out."""
    server = MockRelay(events=[event(1)]).start()
    try:
        first = relay.query([server.url], {"kinds": [30078], "limit": 10}, 0.5)
        assert first.responded == 1

        relay._loop.call_soon_threadsafe(relay._loop.stop)  # what atexit does
        relay._thread.join(timeout=5)
        assert not relay._loop.is_running()

        second = relay.query([server.url], {"kinds": [30078], "limit": 10}, 0.5)
        assert second.responded == 1, "the loop was not rebuilt"
        assert len(second.events) == 1
    finally:
        server.stop()
