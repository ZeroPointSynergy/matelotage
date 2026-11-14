"""Resolve `repo_id` to a signed record: ordered allowlist, two levels of revocation, no exceptions.

Precedence is `(author_index, -created_at, event_id)`. Within one key the newest record wins, so a
tombstone from that key sticks. Across keys the earlier index wins unconditionally, so a community
indexer can fill gaps but can never correct or revive what a higher-precedence key has said.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from . import relay, schema

log = logging.getLogger("matelotage.index")

DEFAULT_RELAYS: tuple[str, ...] = (
    "wss://relay.primal.net",
    "wss://relay.snort.social",
    "wss://relay.damus.io",
    "wss://nos.lol",
)
BREAKER_THRESHOLD = 2
BREAKER_SECONDS = 60.0
REVOCATION_LIMIT = 100
DEFAULT_TIMEOUT = 1.5
MODES = ("mirror", "keeper")
DEFAULT_MODE = "mirror"

_DISABLED = ("", "0", "none", "false")

# Injected by patch.install(): Callable[[str], bool | None]. None means "cannot tell", which is the
# correct answer when pirateface is not installed or the site is unreachable.
check_publication = None


def set_publication_check(fn) -> None:
    """Tell the resolver how to ask whether Pirate Face publishes a repo. `None` clears it."""
    global check_publication
    check_publication = fn


@dataclass(frozen=True, slots=True)
class Resolved:
    content: schema.NostrModelContent
    event: schema.NostrEvent
    author_index: int


_hits: dict[str, Resolved] = {}
_served: set[str] = set()  # provenance: only the magnet path marks a repo as served
_revoked: set[str] | None = None
_failures = 0
_open_until = 0.0
_lock = threading.Lock()


# ---------------------------------------------------------------- configuration


def get_relays() -> list[str]:
    raw = os.environ.get("MATELOTAGE_RELAYS")
    if raw is None:
        return list(DEFAULT_RELAYS)
    if raw.strip().lower() in _DISABLED:
        return []
    out: list[str] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        parts = urlsplit(part)
        if parts.scheme not in ("ws", "wss") or not parts.netloc:
            log.warning("ignoring relay %r: needs ws:// or wss://", part)
            continue
        if part not in out:
            out.append(part)
    return out


def get_trusted_pubkeys() -> list[str]:
    """Ordered allowlist of author pubkeys (hex). Index 0 outranks everything after it."""
    raw = (
        os.environ.get("MATELOTAGE_NPUBS")
        or os.environ.get("MATELOTAGE_NPUB")
        or schema.DEFAULT_TRUSTED_NPUB
    )
    out: list[str] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            key = schema.bech32_to_hex(part)
        except schema.SchemaError as exc:
            log.warning("ignoring npub %r: %s", part, exc)
            continue
        if key == schema.ZERO_PUBKEY_HEX:  # the documented unconfigured sentinel
            continue
        if key not in out:
            out.append(key)
    return out


def get_timeout() -> float:
    try:
        return max(0.2, float(os.environ.get("MATELOTAGE_TIMEOUT", DEFAULT_TIMEOUT)))
    except ValueError:
        return DEFAULT_TIMEOUT


def get_mode() -> str:
    """`mirror` (default) serves only what Pirate Face publishes; `keeper` serves any trusted record."""
    raw = (os.environ.get("MATELOTAGE_MODE") or DEFAULT_MODE).strip().lower()
    if raw not in MODES:
        log.warning("unknown MATELOTAGE_MODE %r, using %s", raw, DEFAULT_MODE)
        return DEFAULT_MODE
    return raw


def admissible(resolved: Resolved) -> bool:
    """Whether this record may be served under the current mode. One predicate, one place.

    `mirror` requires both: the record is the operator's own (index 0), **and** Pirate Face has
    not said no. Either alone would be wrong — index 0 alone would keep serving a repo the site
    has since withdrawn, and "the site publishes the repo" alone would let any community key
    redirect a published repo to a magnet the operator never signed.
    """
    if get_mode() == "keeper":
        return True
    if resolved.author_index != 0:
        return False
    published = None
    if check_publication is not None:
        try:
            published = check_publication(resolved.content.repo_id)
        except Exception as exc:  # a broken publication check is "cannot tell", not "yes"
            log.debug("publication check failed: %s", exc)
            published = None
    # Only an explicit yes counts. A checker returning 0 or '' must fail closed, not open.
    return published is None or published is True


def clear_cache() -> None:
    """Reset every per-process cache. Tests and `mlt --refresh` use this."""
    global _revoked, _failures, _open_until
    with _lock:
        _hits.clear()
        _served.clear()
        _revoked = None
        _failures = 0
        _open_until = 0.0


# ---------------------------------------------------------------- key revocation


def revoked_keys() -> set[str]:
    """Pubkeys revoked by the cold root. Empty when unconfigured, unreachable, or genuinely empty."""
    global _revoked
    if _revoked is not None:
        return _revoked
    keys = get_trusted_pubkeys()
    relays = get_relays()
    if not keys or not relays:
        _revoked = set()
        return _revoked

    cold_root = keys[0]
    result = relay.query(
        relays,
        {"kinds": [schema.NOSTR_KIND_MODEL_INDEX], "authors": [cold_root], "limit": REVOCATION_LIMIT},
        get_timeout(),
    )
    found: set[str] = set()
    for raw in result.events:
        try:
            event = schema.verify_event_signature(raw)
        except schema.SchemaError as exc:
            log.debug("revocation event rejected: %s", exc)
            continue
        if event.pubkey != cold_root:
            continue
        d_tag = event.d_tag or ""
        # F3: the cold root also publishes repo tombstones, so filter before parsing.
        if not d_tag.startswith(schema.KEYREVOKE_PREFIX):
            continue
        try:
            data = schema.validate_keyrevoke_content(event.content)
        except schema.SchemaError as exc:
            log.debug("revocation record rejected: %s", exc)
            continue
        if data["action"] == "revoke":
            found.add(data["key"].lower())

    if result.total_silence and not found:
        # A revocation check that cannot run must not break resolution — and must not be cached,
        # so a later call retries once the relays answer.
        log.debug("no relay answered the revocation query; keeping the static allowlist")
        return set()

    _revoked = found
    return _revoked


# ---------------------------------------------------------------- resolution


def _note_silence(result: relay.QueryResult) -> None:
    global _failures, _open_until
    with _lock:
        if result.total_silence:
            _failures += 1
            if _failures >= BREAKER_THRESHOLD:
                _open_until = time.monotonic() + BREAKER_SECONDS
                _failures = 0
                log.warning("all relays silent %d times; pausing nostr for %.0fs", BREAKER_THRESHOLD, BREAKER_SECONDS)
        else:
            _failures = 0


def breaker_open() -> bool:
    return time.monotonic() < _open_until


def _resolve(repo_id: str, keys: list[str], relays: list[str]) -> Resolved | None:
    revoked = revoked_keys()
    effective = [key for key in keys if key not in revoked]
    if not effective:
        log.debug("every trusted key is revoked; %s cannot resolve", repo_id)
        return None

    result = relay.query(
        relays,
        {
            "kinds": [schema.NOSTR_KIND_MODEL_INDEX],
            "authors": effective,
            "#d": [f"{schema.D_TAG_PREFIX}{repo_id}"],
            "limit": 10,
        },
        get_timeout(),
    )
    _note_silence(result)

    candidates: list[Resolved] = []
    for raw in result.events:
        try:
            event, content, _ = schema.verify_and_parse_event(raw, repo_id, effective)
        except schema.SchemaError as exc:
            log.debug("%s: relay event rejected: %s", repo_id, exc)
            continue
        # Rank by the position in the ORIGINAL allowlist, not the revocation-filtered one.
        candidates.append(Resolved(content=content, event=event, author_index=keys.index(event.pubkey)))

    if not candidates:
        return None
    return min(candidates, key=lambda r: (r.author_index, -r.event.created_at, r.event.id))


def get(repo_id: str) -> Resolved | None:
    """The winning record for repo_id, or None. Never raises."""
    try:
        with _lock:
            resolved = _hits.get(repo_id)
        if resolved is None:
            keys, relays = get_trusted_pubkeys(), get_relays()
            if not keys or not relays or breaker_open():
                return None
            resolved = _resolve(repo_id, keys, relays)
            if resolved is not None:
                with _lock:
                    _hits[repo_id] = resolved
        if resolved is None or not admissible(resolved):
            return None
        return resolved
    except Exception as exc:  # resolution must never take a download down with it
        log.warning("%s: resolve failed: %s", repo_id, exc)
        return None


def resolve_magnet(repo_id: str) -> str | None:
    """The magnet for a live record, and the only thing that grants provenance to a repo.

    `served()` is deliberately keyed off this, not off cache presence: `pf_only()` also fills the
    cache, and a repo that merely has a record is not a repo whose magnet the downloader was given.
    """
    resolved = get(repo_id)
    if resolved is None or resolved.content.revoked:
        with _lock:
            _served.discard(repo_id)
        return None
    with _lock:
        _served.add(repo_id)
    return resolved.content.magnet


def torrent_bytes(repo_id: str) -> bytes | None:
    resolved = get(repo_id)
    return resolved.content.torrent_bytes if resolved and not resolved.content.revoked else None


def live(repo_id: str) -> bool:
    """True if a servable record exists for the repo and has not been tombstoned."""
    with _lock:
        resolved = _hits.get(repo_id)
    return bool(resolved is not None and not resolved.content.revoked and admissible(resolved))


def served(repo_id: str) -> bool:
    """True only for a servable, live record whose magnet this process actually returned."""
    with _lock:
        resolved = _hits.get(repo_id)
        granted = repo_id in _served
    return bool(granted and resolved is not None and not resolved.content.revoked and admissible(resolved))
