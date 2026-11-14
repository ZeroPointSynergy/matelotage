"""Sign and publish records. No licence policy lives here — only the claim and its signature."""

from __future__ import annotations

import json
import os
import time
from dataclasses import replace
from typing import Any

from . import index, relay, schema


def signing_key(explicit: str | None = None) -> str:
    """The nsec to sign with. Never a CLI flag: shell history is forever."""
    key = explicit or os.environ.get("MATELOTAGE_NSEC")
    if not key:
        raise ValueError(
            "no signing key: set MATELOTAGE_NSEC, or run without --local and let the tool prompt"
        )
    return key


def build_content(
    repo_id: str,
    *,
    magnet: str | None,
    files: dict[str, str] | None,
    license_id: str,
    hf: bool = True,
    torrent_bytes: bytes | None = None,
    revision: str | None = None,
    revoked: bool = False,
    reason: str | None = None,
    license_file: str | None = None,
    not_in_swarm: list[str] | None = None,
    seeders_at_publish: int | None = None,
) -> schema.NostrModelContent:
    if not isinstance(hf, bool):
        raise TypeError(f"hf must be a bool, not {type(hf).__name__}")
    content = schema.NostrModelContent(
        repo_id=repo_id,
        magnet=magnet,
        hf=hf,
        license=license_id,
        timestamp=int(time.time()),
        files=dict(files) if files else None,
        torrent_bytes=torrent_bytes,
        revision=revision,
        revoked=revoked,
        reason=reason,
        license_file=license_file,
        not_in_swarm=not_in_swarm,
        seeders_at_publish=seeders_at_publish,
    )
    return content


def wire_size(event: dict[str, Any]) -> int:
    """Bytes on the wire, not characters: relays count UTF-8 bytes, and unicode paths differ."""
    return len(json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _sign_and_check(nsec: str, content: schema.NostrModelContent) -> dict[str, Any]:
    """Sign, then read it back through the same validator every client uses.

    Without this, a record the package itself would reject can be published — and because
    kind 30078 is replaceable, a bad record *replaces* a good one for that repo.
    """
    event = schema.build_signed_event(nsec, content.repo_id, content)
    schema.verify_and_parse_event(event, content.repo_id, [event["pubkey"]])
    return event


def fit_event_and_content(
    nsec: str, content: schema.NostrModelContent, limit: int = schema.MAX_EVENT_BYTES
) -> tuple[dict[str, Any], schema.NostrModelContent]:
    """Sign and fit the event into a relay frame; returns `(event, content_that_was_signed)`.

    The shed order is stated, not incidental: the informational `not_in_swarm` list goes first, then
    `torrent_b64`, because losing the torrent costs cold-start time while losing the manifest costs
    the attestation. `hf: false` records keep their torrent or fail — without it the download cannot
    start at all.
    """
    event = _sign_and_check(nsec, content)
    if wire_size(event) <= limit:
        return event, content
    if content.not_in_swarm:
        content = replace(content, not_in_swarm=None)
        event = _sign_and_check(nsec, content)
        if wire_size(event) <= limit:
            return event, content
    if content.hf is True and content.torrent_bytes is not None:
        content = replace(content, torrent_bytes=None)
        event = _sign_and_check(nsec, content)
        if wire_size(event) <= limit:
            return event, content
    raise ValueError(
        f"record is {wire_size(event)} bytes, over the {limit}-byte relay budget, and cannot shed "
        "anything else without losing the attestation"
    )


def fit_event(
    nsec: str, content: schema.NostrModelContent, limit: int = schema.MAX_EVENT_BYTES
) -> dict[str, Any]:
    """The signed event alone; see `fit_event_and_content` for what was actually signed."""
    return fit_event_and_content(nsec, content, limit)[0]


def publish(event: dict[str, Any], relays: list[str] | None = None, timeout: float = 5.0) -> dict[str, str]:
    return relay.publish(event, relays if relays is not None else index.get_relays(), timeout)


def publish_record(
    repo_id: str,
    *,
    nsec: str | None = None,
    relays: list[str] | None = None,
    timeout: float = 5.0,
    **content_kwargs: Any,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Sign a record and publish it. Returns (event, per-relay status)."""
    key = signing_key(nsec)
    content = build_content(repo_id, **content_kwargs)
    event = fit_event(key, content)
    results = publish(event, relays, timeout)
    if not any(status == "ok" for status in results.values()):
        raise RuntimeError(f"no relay accepted the record: {results}")
    return event, results


def revoke(
    repo_id: str, reason: str, *, nsec: str | None = None, relays: list[str] | None = None
) -> tuple[dict[str, Any], dict[str, str]]:
    """Withdraw a repo: a tombstone that a lower-precedence key cannot undo."""
    return publish_record(
        repo_id, nsec=nsec, relays=relays, magnet=None, files=None,
        license_id="withdrawn", revoked=True, reason=reason,
    )


def keyrevoke(
    target_pubkey: str, reason: str, *, nsec: str | None = None, relays: list[str] | None = None
) -> dict[str, str]:
    """Cold-root act: revoke a publisher key across every client, without a release."""
    event = schema.build_keyrevoke_event(signing_key(nsec), target_pubkey, "revoke", reason=reason)
    schema.validate_keyrevoke_content(event["content"])
    return publish(event, relays)


def succeed(
    old_pubkey: str, new_pubkey: str, *, nsec: str | None = None, relays: list[str] | None = None
) -> dict[str, str]:
    """Record a key succession. Clients learn the successor from a release, by design."""
    event = schema.build_keyrevoke_event(signing_key(nsec), old_pubkey, "succeed", successor=new_pubkey)
    schema.validate_keyrevoke_content(event["content"])
    return publish(event, relays)
