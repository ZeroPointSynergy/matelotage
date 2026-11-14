"""`adopt` builds the record; `verify` re-checks it later. Both reuse pirateface's own machinery.

Trackers default to public ones on purpose: a matelotage record must never announce through
`tracker.pirateface.co` for a repo the operator never signed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from . import index, publish, schema

PUBLIC_TRACKERS: tuple[str, ...] = (
    "udp://tracker.opentrackr.org:1337/announce",
    "udp://open.demonii.com:1337/announce",
    "udp://tracker.torrent.eu.org:451/announce",
)
LICENSE_NAMES = ("LICENSE", "LICENSE.MD", "LICENSE.TXT", "COPYING", "NOTICE")


class AdoptError(RuntimeError):
    pass


def trackers() -> list[str]:
    raw = os.environ.get("MATELOTAGE_TRACKERS")
    if raw:
        return [part.strip() for part in raw.split(",") if part.strip()]
    return list(PUBLIC_TRACKERS)


def _materialise(repo_id: str, revision: str | None, source: str | None) -> tuple[Path, Path, Path | None]:
    """Return (torrent_root, model_dir, cleanup_dir)."""
    if source:
        model_dir = Path(source).expanduser().resolve()
        if not model_dir.is_dir():
            raise AdoptError(f"{source} is not a directory")
        return model_dir.parent, model_dir, None

    name = repo_id.split("/")[-1]
    tmp = Path(tempfile.mkdtemp(prefix="matelotage-"))
    model_dir = tmp / name
    try:
        from huggingface_hub import snapshot_download

        snapshot_download(repo_id=repo_id, revision=revision or "main", local_dir=str(model_dir))
    except Exception as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        raise AdoptError(f"could not fetch {repo_id}: {exc}") from exc
    return tmp, model_dir, tmp


def _hardlinked(path: Path) -> bool:
    """A hardlink resolves to itself, so containment cannot see where it came from.

    It is also the only link a plain Windows user can create without admin rights or Developer Mode,
    which makes it the likeliest way an outside file ends up inside a folder someone adopts.
    """
    if (os.environ.get("MATELOTAGE_ALLOW_HARDLINKS") or "").strip() in ("1", "true", "yes"):
        return False
    try:
        return path.is_file() and path.stat().st_nlink > 1
    except OSError:
        return False


def _escapes(path: Path, root: Path) -> bool:
    """True when `path` resolves outside `root`.

    `is_symlink()` is not sufficient on Windows: a directory junction reports **False** and
    `os.walk` descends into it, so a folder containing one would hash files from somewhere else
    entirely into a public record. Resolution catches links, junctions and reparse points alike.
    """
    try:
        path.resolve().relative_to(root)
    except (OSError, ValueError):
        return True
    return False


def _collect(model_dir: Path) -> tuple[list[str], list[str], list[str]]:
    """(included, skipped by pirateface's own rules, links pointing outside the folder).

    `package.make_torrent` builds straight from a directory and follows links, so adopting a
    working folder would hash `.env`, `id_rsa`, `.git/config` and anything a junction points at
    into a record that goes to public relays forever. We screen first, using pirateface's own
    `SKIP` regex, so a matelotage torrent contains exactly what `pf seed` would.
    """
    from pirateface.seed import package

    root = Path(model_dir).resolve()
    included: list[str] = []
    skipped: list[str] = []
    outside: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        keep: list[str] = []
        for name in sorted(dirnames):
            child = here / name
            if _escapes(child, root):
                outside.append(child.relative_to(root).as_posix() + "/")
                continue
            keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            path = here / name
            relative = path.relative_to(root).as_posix()
            if package.SKIP.search(relative):
                skipped.append(relative)
                continue
            if _escapes(path, root):
                outside.append(relative)
                continue
            if _hardlinked(path):
                outside.append(
                    f"{relative} (hardlink: set MATELOTAGE_ALLOW_HARDLINKS=1 to accept it)"
                )
                continue
            included.append(relative)
    return included, skipped, outside


def _server_entry(repo_id: str) -> Any:
    """Pirate Face's listing: a dict, `api.NOT_LISTED` (a real answer), or None (no answer).

    The three cases must stay distinct. "Nobody has published this repo" is permission to found a
    swarm; "I could not reach the site" is not. Collapsing them lets a transient outage overwrite a
    good record with one that points at a swarm nobody is in.
    """
    from pirateface.client import api

    try:
        return api.lookup(repo_id)
    except Exception:
        return None


def _server_torrent(repo_id: str) -> bytes | None:
    try:
        from pirateface.client import api

        return api.torrent_file(repo_id)
    except Exception:
        return None


def build_record(
    repo_id: str,
    model_dir: Path,
    *,
    license_id: str,
    hf: bool = True,
    revision: str | None = None,
) -> tuple[schema.NostrModelContent, bytes, list[str]]:
    """Hash the folder and produce a signed record.

    When Pirate Face already publishes the repo we adopt **its** torrent, infohash and magnet, so
    the record joins the swarm that exists instead of founding a parallel one with no peers. That
    is also the project's stated rule: one repo, one swarm. Building a fresh torrent is only right
    for repos nobody has published yet.
    """
    from pirateface.client import api

    model_dir = Path(model_dir)
    entry = _server_entry(repo_id)

    if isinstance(entry, dict) and entry.get("magnet"):
        blob = _server_torrent(repo_id)
        if not blob:
            raise AdoptError(
                f"{repo_id} is listed by Pirate Face but its .torrent could not be downloaded; "
                "refusing to publish a record that would point at a different swarm"
            )
        content, skipped = _record_from_published(repo_id, model_dir, entry, blob, license_id, hf, revision)
        return content, blob, skipped

    if isinstance(entry, dict):
        raise AdoptError(
            f"{repo_id} is listed by Pirate Face but the magnet is withheld (terms not accepted "
            "on the site?); there is nothing to adopt"
        )

    if entry is api.NOT_LISTED:
        return _record_from_scratch(repo_id, model_dir, license_id=license_id, hf=hf, revision=revision)

    if index.get_mode() != "keeper":
        raise AdoptError(
            f"cannot reach Pirate Face to check how {repo_id} is published; retry, or set "
            "MATELOTAGE_MODE=keeper to found a new swarm deliberately"
        )
    return _record_from_scratch(repo_id, model_dir, license_id=license_id, hf=hf, revision=revision)


MAX_NOT_IN_SWARM = 64
_PAD_RE = re.compile(r"^\.pad(/|$)")


def _screen_paths(root: Path, wanted: dict[str, int]) -> None:
    """Refuse the whole torrent if any name escapes the folder, before anything is read."""
    for relative in wanted:
        try:
            schema.safe_relative_path(relative)
        except schema.SchemaError as exc:
            raise AdoptError(f"refusing to adopt: hostile path in the published torrent: {exc}") from None
        candidate = root / relative
        try:
            resolved = candidate.resolve()
        except OSError:
            raise AdoptError(f"refusing to adopt: {relative} cannot be resolved") from None
        try:
            resolved.relative_to(root)
        except ValueError:
            raise AdoptError(
                f"refusing to adopt: {relative} resolves outside the folder ({resolved}); "
                "a junction or link is pointing at files this record must not publish"
            ) from None
        if _hardlinked(resolved):
            raise AdoptError(
                f"refusing to adopt: {relative} is a hardlink, so it may be the same bytes as a file "
                "outside this folder; set MATELOTAGE_ALLOW_HARDLINKS=1 if that is intended"
            )


def _piece_hex(value: Any) -> str:
    return value.hex() if isinstance(value, (bytes, bytearray)) else str(value)


def _verify_pieces(blob: bytes, root: Path, repo_id: str) -> None:
    """Check local bytes against the torrent's piece hashes, pad files included as zeroes.

    This is the only check that makes the manifest an attestation about *content* rather than size.
    The hashes are read from the bencoded `info` dict rather than libtorrent's `files()`/`file_at()`,
    which are deprecated in 2.1 and return platform separators.
    """
    import hashlib

    raw = schema._bdecode(blob)
    info = raw.get(b"info") if isinstance(raw, dict) else None
    if not isinstance(info, dict):
        raise AdoptError(f"refusing to adopt: {repo_id}: torrent has no info dict")
    piece_len = info.get(b"piece length")
    pieces = info.get(b"pieces")
    if not isinstance(piece_len, int) or not isinstance(pieces, (bytes, bytearray)) or not pieces:
        raise AdoptError(f"refusing to adopt: {repo_id}: torrent has no v1 piece hashes")
    if len(pieces) % 20:
        raise AdoptError(f"refusing to adopt: {repo_id}: malformed piece hash block")
    expected = [bytes(pieces[i : i + 20]) for i in range(0, len(pieces), 20)]

    entries: list[tuple[str, int]] = []
    if isinstance(info.get(b"files"), list):
        for entry in info[b"files"]:
            path = "/".join(part.decode("utf-8", "surrogateescape") for part in entry.get(b"path", []))
            entries.append((path, entry.get(b"length", 0)))
    elif isinstance(info.get(b"length"), int):
        entries.append((info[b"name"].decode("utf-8", "surrogateescape"), info[b"length"]))
    else:
        raise AdoptError(f"refusing to adopt: {repo_id}: torrent lists no files")

    buf = bytearray()
    seen = 0

    def digest() -> None:
        nonlocal seen
        if hashlib.sha1(buf).hexdigest() != expected[seen].hex():
            raise AdoptError(
                f"refusing to adopt: local bytes do not match the published torrent for {repo_id} "
                f"(piece {seen} of {len(expected)})"
            )
        seen += 1
        buf.clear()

    for path, size in entries:
        if _PAD_RE.match(path):
            remaining = size
            while remaining:
                take = min(remaining, piece_len - len(buf))
                buf.extend(b"\0" * take)
                remaining -= take
                if len(buf) == piece_len:
                    digest()
            continue
        with (root / path).open("rb") as handle:
            while True:
                chunk = handle.read(1 << 20)
                if not chunk:
                    break
                while chunk:
                    take = min(len(chunk), piece_len - len(buf))
                    buf.extend(chunk[:take])
                    chunk = chunk[take:]
                    if len(buf) == piece_len:
                        digest()
    if buf:
        digest()
    if seen != len(expected):
        raise AdoptError(
            f"refusing to adopt: torrent has {len(expected)} pieces but {seen} were read for {repo_id}"
        )


def _record_from_published(
    repo_id: str,
    model_dir: Path,
    entry: dict[str, Any],
    blob: bytes,
    license_id: str,
    hf: bool,
    revision: str | None,
) -> tuple[schema.NostrModelContent, list[str]]:
    """Attest a local copy against the torrent Pirate Face already lists."""
    from pirateface.client.torrent import files_in
    from pirateface.seed import package

    root = Path(model_dir).resolve()
    stored = schema.storage_blob(blob)  # re-checks the infohash survives re-encoding
    infohash = str(schema._torrent_info(stored).info_hashes().v1)
    if schema.magnet_btih(entry["magnet"]) != infohash:
        raise AdoptError(f"Pirate Face's magnet and torrent disagree for {repo_id}")

    wanted = {path: size for path, size, _url in files_in(stored)}

    # Screen every path BEFORE reading a byte: a torrent that names `../../id_rsa`, or a folder that
    # is really a junction to somewhere else, must fail before its contents are hashed into a record
    # that goes to public relays forever.
    _screen_paths(root, wanted)

    problems = package.unportable(sorted(wanted))
    if problems:
        raise AdoptError("refusing to adopt: " + "; ".join(problems[:4]))

    missing = [p for p, size in wanted.items() if not (root / p).is_file() or (root / p).stat().st_size != size]
    if missing:
        raise AdoptError(
            "refusing to adopt: the published torrent lists files this folder does not have — "
            + ", ".join(missing[:8])
        )

    # Size is not an attestation. A same-size corrupt copy would be signed into a record the swarm
    # can never reproduce, so the bytes are checked against the torrent's own piece hashes.
    _verify_pieces(stored, root, repo_id)

    files = package.checksums(root, sorted(wanted))
    wanted_names = {name.upper() for name in LICENSE_NAMES}
    license_file = next((p for p in files if Path(p).name.upper() in wanted_names), None)
    # Be explicit about what the swarm does not carry: PF's torrents are often partial. Capped,
    # because this list is informational and must never crowd the torrent out of the relay frame.
    local, _skipped, _outside = _collect(root)
    not_in_swarm = sorted(set(local) - set(wanted))[:MAX_NOT_IN_SWARM] or None
    content = publish.build_content(
        repo_id,
        magnet=entry["magnet"],
        files=files,
        license_id=license_id,
        hf=hf,
        torrent_bytes=stored,
        revision=entry.get("revision") or revision,
        license_file=license_file,
        not_in_swarm=not_in_swarm,
        seeders_at_publish=entry.get("seeders"),
    )
    return content, []


def _record_from_scratch(
    repo_id: str, model_dir: Path, *, license_id: str, hf: bool, revision: str | None
) -> tuple[schema.NostrModelContent, bytes, list[str]]:
    """Build a brand-new torrent. This founds a swarm, so it is only for repos nobody published."""
    from pirateface.client.torrent import files_in
    from pirateface.seed import package

    model_dir = Path(model_dir)
    included, skipped, outside = _collect(model_dir)
    if outside:
        raise AdoptError(
            "refusing to adopt: these links point outside the folder — " + ", ".join(outside[:8])
        )
    if not included:
        raise AdoptError(f"{model_dir} has no files to adopt")

    problems = package.unportable(sorted(included))
    if problems:
        raise AdoptError("rename or remove these files first: " + "; ".join(problems[:8]))

    scratch = Path(tempfile.mkdtemp(prefix="matelotage-stage-"))
    try:
        staged = scratch / model_dir.name
        for relative in included:
            package.link(Path(model_dir, relative).absolute(), staged / relative)
        track = trackers()
        blob, v1, v2 = package.make_torrent(scratch, staged.name, track)
        paths = [path for path, _, _ in files_in(blob)]
        files = package.checksums(staged, paths)
        magnet = package.magnet(v1, v2, staged.name, track)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    if not paths:
        raise AdoptError(f"{model_dir} produced no files in the torrent")
    wanted = {name.upper() for name in LICENSE_NAMES}
    license_file = next((path for path in files if Path(path).name.upper() in wanted), None)
    content = publish.build_content(
        repo_id,
        magnet=magnet,
        files=files,
        license_id=license_id,
        hf=hf,
        torrent_bytes=schema.storage_blob(blob),
        revision=revision,
        license_file=license_file,
    )
    return content, blob, skipped


def require_publishable(repo_id: str) -> None:
    """In `mirror`, refuse to build a record that could never serve."""
    if index.get_mode() != "mirror":
        return
    published = None
    if index.check_publication is not None:
        try:
            published = index.check_publication(repo_id)
        except Exception:
            published = None
    # Only an explicit yes is safe here; 0 or '' from an injected checker must fail closed.
    if published is not None and published is not True:
        raise AdoptError(
            f"Pirate Face does not publish {repo_id}, so mirror mode would never serve this record.\n"
            f"Preserve it anyway with: MATELOTAGE_MODE=keeper mlt adopt {repo_id}"
        )


def adopt(
    repo_id: str,
    *,
    source: str | None = None,
    revision: str | None = None,
    license_id: str | None = None,
    nsec: str | None = None,
    relays: list[str] | None = None,
    local: bool = False,
    hf: bool = True,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Snapshot -> hashes -> hybrid torrent -> signed record -> publish (unless `local`)."""
    if not license_id:
        raise AdoptError("--license is required: state the licence you are asserting")
    require_publishable(repo_id)

    _root, model_dir, cleanup = _materialise(repo_id, revision, source)
    try:
        content, blob, skipped = build_record(
            repo_id, model_dir, license_id=license_id, hf=hf, revision=revision
        )
        event, signed = publish.fit_event_and_content(publish.signing_key(nsec), content)
        results: dict[str, str] = {}
        if not local:
            results = publish.publish(event, relays, timeout)
            if not any(status == "ok" for status in results.values()):
                raise AdoptError(f"no relay accepted the record: {results}")
        return {
            "event": event,
            "content": signed,
            "torrent": blob,
            # True when the record could not carry its .torrent and was published without one.
            "torrent_dropped": signed.torrent_bytes is None and content.torrent_bytes is not None,
            "relay_results": results,
            "skipped": skipped,
        }
    finally:
        if cleanup is not None:
            shutil.rmtree(cleanup, ignore_errors=True)


_UNSAFE_STEM = re.compile(r"[^A-Za-z0-9._-]+")


def _stem(repo_id: str) -> str:
    """A file-name-safe stem. Anything outside the whitelist is replaced, never trusted."""
    stem = _UNSAFE_STEM.sub("-", repo_id).strip("-.")
    if not stem or ".." in stem:
        raise AdoptError(f"cannot use {repo_id!r} as a file name")
    return stem


def write_staging(outcome: dict[str, Any], out_dir: str | Path, force: bool = False) -> dict[str, Path]:
    """`--local`: write the torrent, the manifest and the signed event for inspection.

    Refuses to clobber an existing file unless `force`. That `.torrent` may be someone's only copy of
    the swarm it describes, and losing it to a typo is not a recoverable mistake.
    """
    out = Path(out_dir).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    content = outcome["content"]
    name = _stem(content.repo_id)
    written = {
        "torrent": out / f"{name}.torrent",
        "manifest": out / f"{name}.manifest.json",
        "event": out / f"{name}.event.json",
    }
    for path in written.values():
        if path.parent != out:  # belt and braces: _stem should already make this impossible
            raise AdoptError(f"refusing to write outside {out}: {path}")
    if not force:
        existing = [path.name for path in written.values() if path.exists()]
        if existing:
            raise AdoptError(
                f"refusing to overwrite {', '.join(existing)} in {out}: pass --force if that is "
                "what you mean"
            )
    written["torrent"].write_bytes(outcome["torrent"])
    written["manifest"].write_text(
        json.dumps({"repo_id": content.repo_id, "magnet": content.magnet,
                    "files": content.files, "license": content.license,
                    "license_file": content.license_file}, indent=2)
    )
    written["event"].write_text(json.dumps(outcome["event"], indent=2))
    return written


def verify(repo_id: str, directory: str | Path) -> dict[str, Any]:
    """Re-check a local copy against the signed manifest."""
    resolved = index.get(repo_id)
    if resolved is None:
        raise AdoptError(f"no servable record for {repo_id}")
    if resolved.content.revoked:
        raise AdoptError(f"{repo_id} is revoked: {resolved.content.reason or 'withdrawn'}")
    files = resolved.content.files or {}
    if not files:
        raise AdoptError(f"the record for {repo_id} carries no manifest")

    root = Path(directory).expanduser().resolve()
    ok, mismatched, missing = 0, [], []
    for path, want in files.items():
        local = root / path
        if not local.is_file():
            missing.append(path)
            continue
        with local.open("rb") as handle:
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
        if digest == want:
            ok += 1
        else:
            mismatched.append(path)
    return {
        "repo_id": repo_id,
        "ok": ok,
        "total": len(files),
        "mismatched": mismatched,
        "missing": missing,
        "not_in_swarm": resolved.content.not_in_swarm or [],
        "license_file": resolved.content.license_file,
        "license_file_present": (
            None if resolved.content.license_file is None
            else (root / resolved.content.license_file).is_file()
        ),
    }
