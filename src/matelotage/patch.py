"""The three swaps. `pirateface_hub` is never modified — only three module attributes move.

Order matters twice over:

* `__wrapped__` — `torrent_file` and `pf_only` are `@functools.cache`d, so calling the decorated
  original memoises its `None` for the life of the process and silently disables the fallback.
* hit-only caching — caching our own `None` would re-create the same bug, so only non-`None`
  results are stored.
"""

from __future__ import annotations

import contextlib
import logging
import threading
from typing import Any

from . import index

log = logging.getLogger("matelotage.patch")

_orig: dict[str, Any] = {}
_installed = False
_installing = False
_install_lock = threading.RLock()
_torrent_hits: dict[tuple[str, str | None], tuple[bytes, bool]] = {}
_pf_hits: dict[str, tuple[dict[str, Any], bool]] = {}


def _unwrap(function):
    """The undecorated body of an `lru_cache`-wrapped function, so its cache is not polluted."""
    return getattr(function, "__wrapped__", function)


def _originals(module) -> dict[str, Any]:
    return {
        "module": module,
        "lookup_magnet": module.lookup_magnet,
        "torrent_file": module.torrent_file,
        "pf_only": module.pf_only,
        "not_listed": module.NOT_LISTED,
    }


# ---------------------------------------------------------------- the swaps


def lookup_magnet(repo_id: str):
    magnet = _orig["lookup_magnet"](repo_id)
    if magnet is not None and magnet is not _orig["not_listed"]:
        return magnet

    # A dict means the site answered, and the site decides. An entry without a magnet is the
    # documented "accept the licence terms first" answer — not an outage. Falling back here would
    # hand the downloader a third-party magnet and walk around the operator's licence gate.
    if isinstance(_orig["module"].lookup(repo_id), dict):
        return magnet

    # `None or NOT_LISTED` keeps identity semantics, so request_rescue() still fires.
    return index.resolve_magnet(repo_id) or magnet


def torrent_file(repo_id: str, quant: str | None = None):
    """Mirror pirateface's own signature: `seed/command.py` calls this with a quant.

    A matelotage record describes the whole repo, never one quant, so relay bytes are only
    substituted when no quant was asked for. Cache entries record their provenance, so a
    tombstoned or refreshed record cannot keep serving bytes from the cache.
    """
    key = (repo_id, quant)
    if (cached := _torrent_hits.get(key)) is not None:
        data, from_nostr = cached
        if not from_nostr or index.served(repo_id):
            return data
        _torrent_hits.pop(key, None)

    data = _unwrap(_orig["torrent_file"])(repo_id, quant)
    from_nostr = False
    if not data and quant is None and index.served(repo_id):
        data = index.torrent_bytes(repo_id)
        from_nostr = data is not None
    if data:
        _torrent_hits[key] = (data, from_nostr)
    return data


def pf_only(repo_id: str):
    if (cached := _pf_hits.get(repo_id)) is not None:
        value, from_nostr = cached
        if not from_nostr or index.live(repo_id):
            return value
        _pf_hits.pop(repo_id, None)

    found = _unwrap(_orig["pf_only"])(repo_id)
    if found:
        _pf_hits[repo_id] = (found, False)
        return found

    # Never consult the relays while the site is answering. `pf_only` returns None for every
    # ordinary HF repo, so this check is what keeps a healthy site free of Nostr traffic.
    entry = _orig["module"].lookup(repo_id)
    if isinstance(entry, dict) and entry.get("hf") is not False:
        return None

    resolved = index.get(repo_id)
    if resolved is None or resolved.content.revoked:
        return None
    content = resolved.content
    if content.hf is not False or not content.files or not content.torrent_bytes:
        return None
    built = build_pf_only(content)
    if built:
        _pf_hits[repo_id] = (built, True)
    return built


def build_pf_only(content) -> dict[str, Any] | None:
    """The `{path: (size, sha256, url)}` map `responses.py` consumes, built from signed data."""
    from pirateface.client.torrent import files_in

    sizes = {path: (size, url) for path, size, url in files_in(content.torrent_bytes)}
    files = {
        path: (sizes[path][0], digest, sizes[path][1])
        for path, digest in content.files.items()
        if path in sizes
    }
    if not files:
        return None
    return {"repo_id": content.repo_id, "commit": content.revision or "main", "files": files}


# ---------------------------------------------------------------- lifecycle


def _publication_check(repo_id: str):
    """True/False when the site answers, None when it cannot be asked."""
    entry = _orig["module"].lookup(repo_id)
    if isinstance(entry, dict):
        return bool(entry.get("magnet"))
    if entry is _orig["not_listed"]:
        return False
    return None


def install(module=None) -> bool:
    """Swap the three attributes. Idempotent; never raises (the boot hook depends on that).

    Re-entrancy is the trap here: `module=None` imports pirateface.client.api, and that import is
    itself intercepted by the boot finder, which calls install(module) from inside this call. Without
    a guard the outer call resumes after the inner one has already patched the module, captures the
    *patched* functions as the "originals", and every later call recurses until the stack dies.

    So: a guard flag while importing, and a hard refusal to ever record our own functions.
    """
    global _installed, _installing
    if _installed:
        return True
    with _install_lock:
        if _installed:
            return True
        if _installing:
            return False  # the import hook is mid-flight and will finish the install itself
        if module is None:
            _installing = True
            try:
                import pirateface.client.api as module
            finally:
                _installing = False
            if _installed:
                return True
            if module.lookup_magnet is lookup_magnet:
                _installed = True
                return True
        _orig.update(_originals(module))
        module.lookup_magnet = lookup_magnet
        module.torrent_file = torrent_file
        module.pf_only = pf_only
        index.set_publication_check(_publication_check)
        _installed = True
        # A fourth, narrower surface: answer when Hugging Face itself is unreachable. See offline.py
        # for why this cannot be done from inside pf_only().
        with contextlib.suppress(Exception):
            from matelotage import offline

            offline.install()
        log.debug("patched pirateface.client.api: lookup_magnet, torrent_file, pf_only")
        return True


def uninstall() -> bool:
    """Put the originals back. Used by the tests and by `mlt uninstall`."""
    global _installed
    if not _installed:
        return False
    module = _orig["module"]
    module.lookup_magnet = _orig["lookup_magnet"]
    module.torrent_file = _orig["torrent_file"]
    module.pf_only = _orig["pf_only"]
    _installed = False
    index.set_publication_check(None)
    reset_caches()
    with contextlib.suppress(Exception):
        from matelotage import offline

        offline.disable()
    return True


def reset_caches() -> None:
    _torrent_hits.clear()
    _pf_hits.clear()


def is_installed() -> bool:
    return _installed


def status() -> dict[str, Any]:
    """What `mlt doctor` prints: is the swap live, and on which module."""
    try:
        from pirateface.client import api
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "installed": _installed, "live": False}
    return {
        "installed": _installed,
        "live": api.lookup_magnet is lookup_magnet and api.pf_only is pf_only,
        "lookup_untouched": api.lookup.__module__ == "pirateface.client.api",
        "module": api.__name__,
    }
