"""`mlt` — the command line."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from . import __version__, index, pact, patch, preserve, publish, schema


def _signing_key() -> str:
    """Never a command-line flag: shell history is forever."""
    key = os.environ.get("MATELOTAGE_NSEC")
    if key:
        return key.strip()
    typed = getpass.getpass("nsec (input hidden): ").strip()
    if not typed:
        raise SystemExit("error: no signing key")
    return typed


def _pubkey_of(nsec: str) -> str:
    from coincurve import PrivateKey

    secret = bytes.fromhex(schema.bech32_to_hex(nsec, "nsec"))
    return PrivateKey(secret).public_key.format(compressed=True)[1:].hex()


def _doctor(args) -> int:
    state = patch.status()
    keys = index.get_trusted_pubkeys()
    relays = index.get_relays()
    print(f"matelotage {__version__}")
    print(f"  mode            : {index.get_mode()}")
    print(f"  patch installed : {state.get('installed')}")
    print(f"  patch live      : {state.get('live')}  ({state.get('module', state.get('error', '?'))})")
    print(f"  lookup untouched: {state.get('lookup_untouched')}")
    print(f"  trusted keys    : {len(keys)}" + ("  [index 0 = cold root]" if keys else "  [fallback disabled]"))
    print(f"  relays          : {len(relays)}")
    print(f"  timeout         : {index.get_timeout()}s")
    print(f"  breaker         : {'open' if index.breaker_open() else 'closed'}")
    if args.offline or not keys or not relays:
        return 0 if keys and relays else 1
    from . import relay

    result = relay.query(
        relays,
        {"kinds": [schema.NOSTR_KIND_MODEL_INDEX], "authors": [keys[0]], "limit": 1},
        index.get_timeout(),
    )
    print(f"  relays answered : {result.responded}/{result.attempted}")
    return 0 if result.responded else 1


def _keygen(args) -> int:
    nsec, npub, _ = schema.generate_keypair()
    print(f"NSEC={nsec}")
    print(f"NPUB={npub}")
    print()
    print("Keep the nsec offline. Put the npub in MATELOTAGE_NPUBS, cold root first.")
    return 0


def _pact(args) -> int:
    info = pact.describe(with_network=not args.offline)
    info["mode"] = index.get_mode()
    print(json.dumps(info, indent=2) if args.json else pact.format_text(info))
    return 0


def _fetch(args) -> int:
    resolved = index.get(args.repo)
    if resolved is None:
        print(f"{args.repo}: nothing servable in {index.get_mode()} mode")
        return 1
    content = resolved.content
    licence = content.license + (f" ({content.license_file})" if content.license_file else "")
    print(f"repo    : {content.repo_id}")
    print(f"mode    : {index.get_mode()}")
    print(f"signer  : index {resolved.author_index} of your allowlist")
    print(f"magnet  : {content.magnet}")
    print(f"license : {licence}")
    if content.seeders_at_publish is not None:
        print(f"seeders : {content.seeders_at_publish} when this record was signed")
    return 0


def _require_trusted(nsec: str, force: bool) -> None:
    """A signature nobody is allowed to accept is a wasted replaceable slot, not a publication."""
    try:
        keys = index.get_trusted_pubkeys()
    except Exception:  # configuration problems are reported by `mlt doctor`
        return
    if not keys:
        if force:
            print("warning: no MATELOTAGE_NPUBS configured; publishing a record no client will serve")
            return
        raise SystemExit(
            "error: no MATELOTAGE_NPUBS configured; no client would serve this record "
            "(pass --force to publish anyway)"
        )
    signer = schema.pubkey_from_nsec(nsec)
    if signer in keys:
        rank = keys.index(signer)
        print(f"signing key  index {rank} of {len(keys) - 1}" + ("" if rank < index.MIRROR_TIERS else " (fill-in tier: mirror mode will not serve it)"))
        return
    message = f"the signing key {signer[:16]}… is not in MATELOTAGE_NPUBS; no client will serve this record"
    if not force:
        raise SystemExit(f"error: {message} (pass --force to publish anyway)")
    print(f"warning: {message}")


def _adopt(args) -> int:
    if not args.local:
        _require_trusted(_signing_key(), getattr(args, "force", False))
    try:
        out = preserve.adopt(
            args.repo, source=args.from_dir, revision=args.revision, license_id=args.license,
            nsec=_signing_key(), local=args.local, hf=not args.pf_only,
        )
    except (preserve.AdoptError, ValueError, TypeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
    for path in out.get("skipped") or []:
        print(f"excluded  {path}")
    if args.local:
        try:
            written = preserve.write_staging(out, args.out or ".", force=args.overwrite)
        except preserve.AdoptError as exc:
            raise SystemExit(f"error: {exc}") from exc
        for kind, path in written.items():
            print(f"{kind:9} {path}")
        print("not published (--local)")
        return 0
    for relay, status in out["relay_results"].items():
        print(f"{relay}  {status}")
    print(f"published {args.repo}")
    return 0


def _publish(args) -> int:
    if not args.files:
        raise SystemExit(
            "error: --files is required: piece hashes are not file SHA-256s, so a .torrent alone "
            "cannot produce the signed manifest"
        )
    path = Path(args.files)
    try:
        manifest = json.loads(path.read_text())
    except OSError as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: {path} is not JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise SystemExit(f"error: {path} must be a JSON object, not {type(manifest).__name__}")
    if "files" not in manifest and any(k in manifest for k in ("magnet", "repo_id", "license")):
        raise SystemExit(f"error: {path} looks like a record; put the hashes under a 'files' key")
    try:
        files = schema.normalise_files(manifest.get("files", manifest))
    except schema.SchemaError as exc:
        raise SystemExit(f"error: {exc}") from exc
    torrent = schema.storage_blob(Path(args.torrent).read_bytes()) if args.torrent else None
    magnet = args.magnet or manifest.get("magnet")
    if not magnet:
        raise SystemExit("error: --magnet is required (or a manifest that carries one)")
    _require_trusted(_signing_key(), getattr(args, "force", False))
    content = publish.build_content(
        args.repo, magnet=magnet, files=files, license_id=args.license, hf=not args.pf_only,
        torrent_bytes=torrent, revision=args.revision,
    )
    try:
        event = publish.fit_event(_signing_key(), content)
    except (ValueError, TypeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
    results = publish.publish(event)
    for relay, status in results.items():
        print(f"{relay}  {status}")
    return 0 if any(status == "ok" for status in results.values()) else 1


def _verify(args) -> int:
    try:
        result = preserve.verify(args.repo, args.dir)
    except preserve.AdoptError as exc:
        raise SystemExit(f"error: {exc}") from exc
    print(json.dumps(result, indent=2))
    return 0 if not result["mismatched"] and not result["missing"] else 1


def _revoke(args) -> int:
    if args.key:
        keys = index.get_trusted_pubkeys()
        mine = _pubkey_of(_signing_key())
        if not keys or mine != keys[0]:
            position = keys.index(mine) if mine in keys else "not in MATELOTAGE_NPUBS"
            raise SystemExit(
                f"error: only index 0 may revoke a publisher key; yours is {position}"
            )
        results = publish.keyrevoke(args.key, args.reason, nsec=_signing_key())
        for relay, status in results.items():
            print(f"{relay}  {status}")
        return 0 if any(status == "ok" for status in results.values()) else 1
    if not args.repo:
        raise SystemExit("error: give a repo, or --key <npub> to revoke a publisher key")
    try:
        _event, results = publish.revoke(args.repo, args.reason, nsec=_signing_key())
    except RuntimeError as exc:
        raise SystemExit(f"error: {exc}") from exc
    for relay, status in results.items():
        print(f"{relay}  {status}")
    return 0


def _restate(args) -> int:
    """Undo an erroneous self-takedown. Only a key of equal-or-higher precedence may."""
    mine = _pubkey_of(_signing_key())
    keys = index.get_trusted_pubkeys()
    if mine not in keys:
        raise SystemExit("error: the signing key is not in MATELOTAGE_NPUBS")
    resolved = index.get(args.repo)
    if resolved is not None and resolved.author_index < keys.index(mine):
        raise SystemExit(
            f"error: {args.repo} is held at precedence {resolved.author_index}; "
            f"yours is {keys.index(mine)} and cannot restate it"
        )
    raise SystemExit(
        "error: restate needs the original manifest — publish again with "
        f"`mlt publish {args.repo} --files ... --license ...`"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mlt", description="Matelotage — what one keeps, the other keeps."
    )
    parser.add_argument("--version", action="version", version=f"matelotage {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="check the patch, the relays and the pact")
    doctor.add_argument("--offline", action="store_true", help="skip the relay probe")
    doctor.set_defaults(run=_doctor)

    keygen = sub.add_parser("keygen", help="generate a keypair")
    keygen.set_defaults(run=_keygen)

    show = sub.add_parser("pact", help="show keys, order and revocations")
    show.add_argument("--json", action="store_true")
    show.add_argument("--offline", action="store_true")
    show.set_defaults(run=_pact)

    fetch = sub.add_parser("fetch", help="show what the fallback would serve for a repo")
    fetch.add_argument("repo")
    fetch.set_defaults(run=_fetch)

    adopt = sub.add_parser("adopt", help="preserve a model: snapshot, hash, torrent, sign, publish")
    adopt.add_argument("repo")
    adopt.add_argument("--from-dir", help="adopt an existing folder instead of downloading")
    adopt.add_argument("--revision")
    adopt.add_argument("--license", required=True, help="the licence you are asserting")
    adopt.add_argument("--local", action="store_true", help="write the files, do not publish")
    adopt.add_argument("--out", help="where --local writes (default: .)")
    adopt.add_argument("--overwrite", action="store_true", help="overwrite files already in --out")
    adopt.add_argument(
        "--force", action="store_true",
        help="publish even if the signing key is not in MATELOTAGE_NPUBS",
    )
    adopt.add_argument("--pf-only", action="store_true", help="the repo exists only on Pirate Face")
    adopt.set_defaults(run=_adopt)

    pub = sub.add_parser("publish", help="sign and publish a record from a manifest")
    pub.add_argument("repo")
    pub.add_argument("--files", help="manifest JSON ({path: sha256} or {files: [...]})")
    pub.add_argument("--torrent")
    pub.add_argument("--magnet")
    pub.add_argument("--revision")
    pub.add_argument("--license", required=True)
    pub.add_argument("--pf-only", action="store_true")
    pub.add_argument("--force", action="store_true", help="publish even if the key is not trusted")
    pub.set_defaults(run=_publish)

    ver = sub.add_parser("verify", help="re-check a local copy against the signed manifest")
    ver.add_argument("repo")
    ver.add_argument("--dir", required=True)
    ver.set_defaults(run=_verify)

    rev = sub.add_parser("revoke", help="withdraw a repo, or revoke a publisher key")
    rev.add_argument("repo", nargs="?")
    rev.add_argument("--key", help="64-hex or npub of the publisher key to revoke")
    rev.add_argument("--reason", default="withdrawn")
    rev.set_defaults(run=_revoke)

    res = sub.add_parser("restate", help="undo an erroneous self-takedown")
    res.add_argument("repo")
    res.add_argument("--reason", required=True)
    res.set_defaults(run=_restate)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.run(args))


if __name__ == "__main__":
    sys.exit(main())
