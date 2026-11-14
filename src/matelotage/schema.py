"""NIP-19 bech32, NIP-01 event IDs, BIP-340 signatures, and the matelotage record schema.

Everything here is validation. A relay's bytes are hostile until the signature verifies, so every
function either returns a fully-checked object or raises ValueError. Nothing here talks to a network.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any

# Kind 30078 is NIP-78 "application-specific data": parameterised replaceable, keyed by (pubkey, kind, d).
MAX_NOT_IN_SWARM: int = 64
NOSTR_KIND_MODEL_INDEX = 30078
SCHEMA_VERSION = 1
D_TAG_PREFIX = "matelotage:v1:model:"
KEYREVOKE_PREFIX = "matelotage:v1:keyrevoke:"

# bech32 of 32 zero bytes. Not a valid x-only key, so it can never match a real author.
DEFAULT_TRUSTED_NPUB = "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzqujme"
ZERO_PUBKEY_HEX = "0" * 64

MAX_CLOCK_SKEW = 900
MAX_EVENT_BYTES = 32_000

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
BTIH_HEX_RE = re.compile(r"^[0-9a-f]{40}$")
BTIH_B32_RE = re.compile(r"^[A-Za-z2-7]{32}$")
MAGNET_PREFIX = "magnet:?"
BTIH_PARAM_RE = re.compile(r"[?&]xt=urn:btih:([^&]+)")
DRIVE_RE = re.compile(r"^[A-Za-z]:")


class SchemaError(ValueError):
    """A relay event or record failed validation."""


# ---------------------------------------------------------------- NIP-19 bech32

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values: list[int]) -> int:
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= _GENERATOR[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _checksum(hrp: str, data: list[int]) -> list[int]:
    payload = _hrp_expand(hrp) + data + [0] * 6
    mod = _polymod(payload) ^ 1
    return [(mod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data: bytes | list[int], frm: int, to: int, pad: bool = True) -> list[int]:
    acc = bits = 0
    out: list[int] = []
    maxv = (1 << to) - 1
    for value in data:
        if value < 0 or value >> frm:
            raise SchemaError("bech32: value out of range")
        acc = (acc << frm) | value
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (to - bits)) & maxv)
    elif bits >= frm or ((acc << (to - bits)) & maxv):
        raise SchemaError("bech32: invalid padding")
    return out


def hex_to_bech32(hex_key: str, hrp: str = "npub") -> str:
    """32-byte hex -> npub1… / nsec1…"""
    if not isinstance(hex_key, str) or len(hex_key) != 64:
        raise SchemaError("bech32: key must be 64 hex characters")
    if not hrp or not hrp.isascii() or not hrp.islower():
        raise SchemaError("bech32: hrp must be non-empty lowercase ascii")
    try:
        raw = bytes.fromhex(hex_key)
    except ValueError as exc:
        raise SchemaError(f"bech32: key is not hex: {exc}") from exc
    data = _convertbits(raw, 8, 5)
    return hrp + "1" + "".join(_CHARSET[d] for d in data + _checksum(hrp, data))


def bech32_to_hex(bech32_or_hex: str, expected_hrp: str = "npub") -> str:
    """npub1… / nsec1… (or plain 64-hex) -> lowercase hex. Raises on bad checksum or wrong hrp."""
    if not isinstance(bech32_or_hex, str) or not bech32_or_hex:
        raise SchemaError("bech32: empty key")
    lowered = bech32_or_hex.lower()
    if SHA256_RE.match(lowered):
        return lowered
    if any(c.isupper() for c in bech32_or_hex) and any(c.islower() for c in bech32_or_hex):
        raise SchemaError("bech32: mixed case")
    pos = lowered.rfind("1")
    if pos < 1 or pos + 7 > len(lowered):
        raise SchemaError("bech32: missing separator or checksum")
    hrp, body = lowered[:pos], lowered[pos + 1 :]
    if hrp != expected_hrp:
        raise SchemaError(f"bech32: expected {expected_hrp}, got {hrp}")
    try:
        data = [_CHARSET.index(c) for c in body]
    except ValueError as exc:
        raise SchemaError("bech32: character outside charset") from exc
    if _polymod(_hrp_expand(hrp) + data) != 1:
        raise SchemaError("bech32: bad checksum")
    raw = bytes(_convertbits(data[:-6], 5, 8, pad=False))
    if len(raw) != 32:
        raise SchemaError(f"bech32: expected 32 bytes, got {len(raw)}")
    return raw.hex()


# ---------------------------------------------------------------- NIP-01 events


def compute_event_id(pubkey_hex: str, created_at: int, kind: int, tags: list[list[str]], content: str) -> str:
    """NIP-01: sha256 of the compact JSON array [0, pubkey, created_at, kind, tags, content]."""
    payload = json.dumps(
        [0, pubkey_hex.lower(), created_at, kind, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class NostrEvent:
    id: str
    pubkey: str
    created_at: int
    kind: int
    tags: list[list[str]]
    content: str
    sig: str

    @property
    def d_tag(self) -> str | None:
        for tag in self.tags:
            if len(tag) >= 2 and tag[0] == "d":
                return tag[1]
        return None


@dataclass(frozen=True, slots=True)
class NostrModelContent:
    repo_id: str
    magnet: str | None
    hf: bool
    license: str
    timestamp: int
    files: dict[str, str] | None = None
    torrent_bytes: bytes | None = None
    revision: str | None = None
    revoked: bool = False
    reason: str | None = None
    schema: int = SCHEMA_VERSION
    license_file: str | None = None
    # Files present in the preserved folder but absent from the swarm this record points at.
    # Recorded so a reader can see exactly what the record does and does not keep.
    not_in_swarm: list[str] | None = None
    # How many seeders the source reported when this was signed. A dated measurement, not a promise.
    seeders_at_publish: int | None = None

    def to_dict(self, include_torrent: bool = True) -> dict[str, Any]:
        out: dict[str, Any] = {
            "schema": self.schema,
            "repo_id": self.repo_id,
            "revision": self.revision,
            "magnet": self.magnet,
            "hf": self.hf,
            "files": [{"path": p, "sha256": h} for p, h in (self.files or {}).items()],
            "license": self.license,
            "license_file": self.license_file,
            "not_in_swarm": self.not_in_swarm,
            "seeders_at_publish": self.seeders_at_publish,
            "revoked": self.revoked,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }
        if include_torrent:
            out["torrent_b64"] = base64.b64encode(self.torrent_bytes).decode("ascii") if self.torrent_bytes else None
        return out


# ---------------------------------------------------------------- torrents


def _bdecode(blob: bytes) -> Any:
    """Bdecode, or raise SchemaError. libtorrent raises RuntimeError on hostile input."""
    import libtorrent as lt

    try:
        return lt.bdecode(blob)
    except Exception as exc:
        raise SchemaError(f"torrent: unparseable: {exc}") from exc


def strip_piece_layers(blob: bytes) -> bytes:
    """Drop BitTorrent v2 `piece layers` to shrink the record.

    Measured 2026-11-14: `piece layers` sits *outside* the info dict, so removing it leaves the v1
    infohash untouched (3.0 KB vs 6.8 KB on a 30 MB fixture). Removing the v2 keys
    (`meta version`, `file tree`) instead *does* change the v1 infohash — never do that.
    """
    import libtorrent as lt

    torrent = _bdecode(blob)
    if not isinstance(torrent, dict):
        raise SchemaError("torrent: not a bencoded dict")
    torrent.pop(b"piece layers", None)
    return lt.bencode(torrent)


def strip_web_seeds(blob: bytes) -> bytes:
    """Drop BEP 19 web seeds (`url-list`, `httpseeds`).

    Both are top-level keys, outside the info dict, so the v1 infohash is untouched and the record
    still joins the same swarm. A preservation record should not depend on the server it exists to
    survive: with a dead `url-list` libtorrent just retries a URL that will never answer.
    """
    import libtorrent as lt

    torrent = _bdecode(blob)
    if not isinstance(torrent, dict):
        raise SchemaError("torrent: not a bencoded dict")
    torrent.pop(b"url-list", None)
    torrent.pop(b"httpseeds", None)
    return lt.bencode(torrent)


def storage_blob(blob: bytes) -> bytes:
    """What actually goes into a record: no piece layers, no web seeds, same infohash.

    The infohash is re-checked rather than assumed: a bencoded torrent with a duplicate top-level
    `info` key decodes to one dict but re-encodes as the other, which would silently move the record
    to a different swarm.
    """
    stored = strip_web_seeds(strip_piece_layers(blob))
    before = _torrent_info(blob).info_hashes().v1
    after = _torrent_info(stored).info_hashes().v1
    if before != after:
        raise SchemaError("torrent: re-encoding changed the infohash; refusing to store it")
    return stored


def _torrent_info(blob: bytes):
    import libtorrent as lt

    try:
        return lt.torrent_info(blob)
    except Exception as exc:
        raise SchemaError(f"torrent: unparseable: {exc}") from exc


def magnet_btih(magnet: str) -> str:
    """The v1 infohash in a magnet URI, lowercased hex (accepts base32 btih)."""
    if not isinstance(magnet, str) or not magnet.startswith(MAGNET_PREFIX):
        raise SchemaError("magnet: must start with 'magnet:?'")
    match = BTIH_PARAM_RE.search(magnet)
    if not match:
        raise SchemaError("magnet: missing xt=urn:btih:")
    value = match.group(1)
    if BTIH_HEX_RE.match(value.lower()):
        return value.lower()
    if BTIH_B32_RE.match(value):
        try:
            return base64.b32decode(value.upper()).hex()
        except binascii.Error as exc:
            raise SchemaError(f"magnet: bad base32 btih: {exc}") from exc
    raise SchemaError("magnet: btih must be 40 hex or 32 base32 characters")


# ---------------------------------------------------------------- content


def _safe_path(path: Any) -> str:
    if not isinstance(path, str) or not path:
        raise SchemaError("files: path must be a non-empty string")
    if path.startswith(("/", "\\", "..")) or DRIVE_RE.match(path):
        raise SchemaError(f"files: unsafe path {path!r}")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
        raise SchemaError(f"files: unsafe path {path!r} (control character)")
    parts = path.replace("\\", "/").split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise SchemaError(f"files: unsafe path {path!r}")
    return path


def safe_relative_path(path: Any) -> str:
    """Public form of the path predicate: a record may only name files inside its own folder."""
    return _safe_path(path)


def normalise_files(raw: Any) -> dict[str, str]:
    """Accept `[{path, sha256}]` or `{path: sha256}` and return a validated mapping."""
    if isinstance(raw, dict):
        items = list(raw.items())
    elif isinstance(raw, list):
        items = []
        for entry in raw:
            if not isinstance(entry, dict) or "path" not in entry or "sha256" not in entry:
                raise SchemaError("files: each entry needs 'path' and 'sha256'")
            items.append((entry["path"], entry["sha256"]))
    else:
        raise SchemaError("files: must be a list of {path, sha256} or a {path: sha256} object")
    out: dict[str, str] = {}
    for path, digest in items:
        path = _safe_path(path)
        if not isinstance(digest, str) or not SHA256_RE.match(digest):
            raise SchemaError(f"files: {path!r} has an invalid sha256")
        out[path] = digest
    if not out:
        raise SchemaError("files: empty manifest")
    return out


def validate_model_content(
    raw_content: str, expected_repo_id: str, event_created_at: int | None = None
) -> NostrModelContent:
    """Parse and fully validate a record's `content`. Raises SchemaError on any defect."""
    if not isinstance(raw_content, str):
        raise SchemaError("content: not a string")
    try:
        data = json.loads(raw_content)
    except json.JSONDecodeError as exc:
        raise SchemaError(f"content: not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SchemaError("content: not a JSON object")

    if data.get("schema") != SCHEMA_VERSION:
        raise SchemaError(f"content: unsupported schema {data.get('schema')!r}")
    repo_id = data.get("repo_id")
    if not isinstance(repo_id, str) or repo_id != expected_repo_id:
        raise SchemaError(f"content: repo_id {repo_id!r} does not match {expected_repo_id!r}")

    timestamp = data.get("timestamp")
    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp <= 0:
        raise SchemaError("content: timestamp must be a positive int")
    if event_created_at is not None and timestamp > event_created_at:
        raise SchemaError("content: timestamp is after the event's created_at")

    license_id = data.get("license")
    if not isinstance(license_id, str) or not license_id.strip():
        raise SchemaError("content: license must be a non-empty string")

    revision = data.get("revision")
    if revision is not None and not isinstance(revision, str):
        raise SchemaError("content: revision must be a string or null")

    revoked = data.get("revoked", False)
    if not isinstance(revoked, bool):
        raise SchemaError("content: revoked must be a bool")
    reason = data.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise SchemaError("content: reason must be a string or null")

    if revoked:
        return NostrModelContent(
            repo_id=repo_id, magnet=None, hf=bool(data.get("hf", True)), license=license_id,
            timestamp=timestamp, revision=revision, revoked=True, reason=reason,
        )

    magnet = data.get("magnet")
    btih = magnet_btih(magnet)
    files = normalise_files(data.get("files"))
    hf = data.get("hf", True)
    if not isinstance(hf, bool):
        raise SchemaError("content: hf must be a bool")

    license_file = data.get("license_file")
    if license_file is not None:
        license_file = _safe_path(license_file)
        if license_file not in files:
            raise SchemaError(f"content: license_file {license_file!r} is not in the manifest")

    not_in_swarm = data.get("not_in_swarm")
    if not_in_swarm is not None:
        if not isinstance(not_in_swarm, list) or not all(isinstance(p, str) for p in not_in_swarm):
            raise SchemaError("content: not_in_swarm must be a list of paths")
        not_in_swarm = [_safe_path(p) for p in not_in_swarm]
        overlap = set(not_in_swarm) & set(files)
        if overlap:
            raise SchemaError(f"content: not_in_swarm overlaps the manifest: {sorted(overlap)[:3]}")
        # Normalise, so two records describing the same coverage have the same id.
        not_in_swarm = sorted(set(not_in_swarm))[:MAX_NOT_IN_SWARM] or None

    seeders = data.get("seeders_at_publish")
    if seeders is not None and (not isinstance(seeders, int) or isinstance(seeders, bool) or seeders < 0):
        raise SchemaError("content: seeders_at_publish must be a non-negative int or null")

    torrent_bytes = None
    encoded = data.get("torrent_b64")
    if encoded is not None:
        if not isinstance(encoded, str):
            raise SchemaError("content: torrent_b64 must be a string or null")
        try:
            torrent_bytes = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SchemaError(f"content: torrent_b64 is not base64: {exc}") from exc
        info = _torrent_info(torrent_bytes)
        got = str(info.info_hashes().v1)
        if got != btih:
            raise SchemaError(f"content: torrent infohash {got} does not match magnet {btih}")
    elif not hf:
        raise SchemaError("content: hf is false, so torrent_b64 is required (pf_only needs file sizes)")

    return NostrModelContent(
        repo_id=repo_id, magnet=magnet, hf=hf, license=license_id, timestamp=timestamp,
        files=files, torrent_bytes=torrent_bytes, revision=revision, revoked=False, reason=reason,
        license_file=license_file, not_in_swarm=not_in_swarm, seeders_at_publish=seeders,
    )


def validate_keyrevoke_content(raw_content: str) -> dict[str, Any]:
    """Key-revocation records share the kind but not the model shape."""
    try:
        data = json.loads(raw_content)
    except json.JSONDecodeError as exc:
        raise SchemaError(f"content: not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SchemaError("content: not a JSON object")
    if data.get("schema") != SCHEMA_VERSION:
        raise SchemaError("content: unsupported schema")
    action = data.get("action")
    if action not in ("revoke", "succeed"):
        raise SchemaError(f"content: action must be revoke or succeed, got {action!r}")
    key = data.get("key")
    if not isinstance(key, str) or not SHA256_RE.match(key.lower()):
        raise SchemaError("content: key must be a 64-hex pubkey")
    if action == "succeed":
        successor = data.get("successor")
        if not isinstance(successor, str) or not SHA256_RE.match(successor.lower()):
            raise SchemaError("content: successor must be a 64-hex pubkey")
    return data


# ---------------------------------------------------------------- verification


def _schnorr_ok(pubkey_hex: str, sig_hex: str, event_id_hex: str) -> bool:
    from coincurve import PublicKeyXOnly

    try:
        return PublicKeyXOnly(bytes.fromhex(pubkey_hex)).verify(
            bytes.fromhex(sig_hex), bytes.fromhex(event_id_hex)
        )
    except Exception:
        return False


def verify_event_signature(raw_event: Any) -> NostrEvent:
    """Structure, NIP-01 id and BIP-340 signature for any kind-30078 event.

    No author-trust and no `d`-tag binding — those are the caller's job, because key-revocation
    records use a different tag namespace than model records.
    """
    if not isinstance(raw_event, dict):
        raise SchemaError("event: not an object")
    for key, kind in (("id", str), ("pubkey", str), ("created_at", int), ("kind", int),
                      ("tags", list), ("content", str), ("sig", str)):
        if not isinstance(raw_event.get(key), kind) or isinstance(raw_event.get(key), bool):
            raise SchemaError(f"event: {key} missing or not a {kind.__name__}")

    if raw_event["kind"] != NOSTR_KIND_MODEL_INDEX:
        raise SchemaError(f"event: kind {raw_event['kind']} is not {NOSTR_KIND_MODEL_INDEX}")

    pubkey = raw_event["pubkey"].lower()
    if not SHA256_RE.match(pubkey):
        raise SchemaError("event: pubkey is not 64 hex")

    created_at = raw_event["created_at"]
    if created_at < 0 or created_at > int(time.time()) + MAX_CLOCK_SKEW:
        raise SchemaError(f"event: created_at {created_at} is outside the allowed window")

    tags = raw_event["tags"]
    for tag in tags:
        if not isinstance(tag, list) or not all(isinstance(t, str) for t in tag):
            raise SchemaError("event: tags must be arrays of strings")

    event = NostrEvent(
        id=raw_event["id"].lower(), pubkey=pubkey, created_at=created_at, kind=raw_event["kind"],
        tags=tags, content=raw_event["content"], sig=raw_event["sig"].lower(),
    )
    if compute_event_id(pubkey, created_at, event.kind, tags, event.content) != event.id:
        raise SchemaError("event: id does not match its content (tampered)")
    if not _schnorr_ok(pubkey, event.sig, event.id):
        raise SchemaError("event: invalid BIP-340 Schnorr signature")
    return event


def verify_and_parse_event(
    raw_event: Any, expected_repo_id: str, trusted_pubkeys: list[str]
) -> tuple[NostrEvent, NostrModelContent, int]:
    """Validate a relay's EVENT frame. Returns (event, content, author_index) or raises SchemaError."""
    event = verify_event_signature(raw_event)
    pubkey = event.pubkey
    try:
        author_index = [p.lower() for p in trusted_pubkeys].index(pubkey)
    except ValueError:
        raise SchemaError("event: author is not trusted") from None

    expected_d = f"{D_TAG_PREFIX}{expected_repo_id}"
    if event.d_tag != expected_d:
        raise SchemaError(f"event: d tag {event.d_tag!r} is not {expected_d!r}")

    content = validate_model_content(event.content, expected_repo_id, event_created_at=event.created_at)
    return event, content, author_index


# ---------------------------------------------------------------- signing


def generate_keypair() -> tuple[str, str, str]:
    """(nsec, npub, pubkey hex) from a fresh 32-byte secp256k1 secret."""
    from coincurve import PublicKey

    secret = secrets.token_bytes(32)
    pubkey_hex = PublicKey.from_valid_secret(secret).format(compressed=True)[1:].hex()
    return hex_to_bech32(secret.hex(), "nsec"), hex_to_bech32(pubkey_hex, "npub"), pubkey_hex


def build_signed_event(
    nsec_or_hex_sk: str, repo_id: str, content_obj: NostrModelContent, created_at: int | None = None
) -> dict[str, Any]:
    """Build and BIP-340-sign a kind-30078 record for repo_id."""
    from coincurve import PrivateKey

    secret = bytes.fromhex(bech32_to_hex(nsec_or_hex_sk, expected_hrp="nsec"))
    sk = PrivateKey(secret)
    pubkey = sk.public_key.format(compressed=True)[1:].hex()
    tags = [
        ["d", f"{D_TAG_PREFIX}{repo_id}"],
        ["t", "matelotage"],
        ["l", content_obj.license],
        ["alt", f"Matelotage index: {repo_id}"],
    ]
    content = content_obj.to_dict()
    body = json.dumps(content, separators=(",", ":"), ensure_ascii=False)
    created = int(time.time()) if created_at is None else created_at
    event_id = compute_event_id(pubkey, created, NOSTR_KIND_MODEL_INDEX, tags, body)
    return {
        "id": event_id,
        "pubkey": pubkey,
        "created_at": created,
        "kind": NOSTR_KIND_MODEL_INDEX,
        "tags": tags,
        "content": body,
        "sig": sk.sign_schnorr(bytes.fromhex(event_id)).hex(),
    }


def build_keyrevoke_event(
    nsec_or_hex_sk: str, key_hex: str, action: str = "revoke", reason: str | None = None,
    successor: str | None = None, created_at: int | None = None,
) -> dict[str, Any]:
    """A cold-root record revoking (or succeeding) a publisher key.

    `key_hex` accepts an npub as well as 64-hex — the CLI advertises both, and a bech32 string
    signed verbatim would produce a revocation every reader rejects.
    """
    from coincurve import PrivateKey

    key_hex = bech32_to_hex(key_hex, expected_hrp="npub")
    if successor:
        successor = bech32_to_hex(successor, expected_hrp="npub")
    sk = PrivateKey(bytes.fromhex(bech32_to_hex(nsec_or_hex_sk, expected_hrp="nsec")))
    pubkey = sk.public_key.format(compressed=True)[1:].hex()
    content: dict[str, Any] = {"schema": SCHEMA_VERSION, "action": action, "key": key_hex.lower()}
    if successor:
        content["successor"] = successor.lower()
    if reason:
        content["reason"] = reason
    content["timestamp"] = int(time.time()) if created_at is None else created_at
    tags = [["d", f"{KEYREVOKE_PREFIX}{key_hex.lower()}"], ["t", "matelotage"]]
    body = json.dumps(content, separators=(",", ":"), ensure_ascii=False)
    created = int(time.time()) if created_at is None else created_at
    event_id = compute_event_id(pubkey, created, NOSTR_KIND_MODEL_INDEX, tags, body)
    return {
        "id": event_id, "pubkey": pubkey, "created_at": created, "kind": NOSTR_KIND_MODEL_INDEX,
        "tags": tags, "content": body, "sig": sk.sign_schnorr(bytes.fromhex(event_id)).hex(),
    }
