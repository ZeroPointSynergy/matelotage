"""Answer huggingface_hub's questions when Hugging Face itself is unreachable.

Upstream's transport decides whether to answer from the index in two places: proactively for the
`pirateface/*` namespace, and reactively *after* asking Hugging Face and seeing a 401/404. So when
Hugging Face cannot be reached at all, the request raises and the signed record is never read — even
though it carries everything needed.

Scope: the synchronous client (`_GLOBAL_CLIENT_FACTORY`). huggingface_hub's async factory is left
alone, so `AsyncInferenceClient`-style paths still fail against an unreachable hub.

This wrapper sits outside upstream's transport and only acts on failure: if the inner call raises, it
tries the index before letting the error through. Two independent guards keep it honest:

* it never runs while Hugging Face is answering, because the inner call has to fail first;
* `api.pf_only()` only ever returns data for an `hf: false` record — a model Hugging Face does not
  have — so an ordinary model can never be answered from a record by mistake.
"""

from __future__ import annotations

import contextlib
import logging
import os
import urllib.parse
from typing import Any

log = logging.getLogger(__name__)

_installed = False
_disabled = False

try:  # httpx2 ships with huggingface_hub; the tuple is built once, not per request
    import httpx2

    NETWORK_ERRORS: tuple[type[BaseException], ...] = (
        httpx2.TransportError,
        httpx2.TimeoutException,
        OSError,
    )
except Exception:  # pragma: no cover - huggingface_hub without httpx2 is not a case we support
    NETWORK_ERRORS = (OSError,)


def enabled() -> bool:
    raw = (os.environ.get("MATELOTAGE_OFFLINE_FIRST") or "").strip().lower()
    return raw not in ("0", "false", "no", "off")


def _answer_from_index(request: Any) -> Any:
    """A response built from a signed record, or None when no record covers this path."""
    import httpx2
    from huggingface_hub import constants
    from pirateface.client import api
    from pirateface.huggingface import responses, transport

    host = urllib.parse.urlsplit(constants.ENDPOINT).hostname
    if request.url.host != host:
        return None
    path = urllib.parse.unquote(request.url.path)
    for pattern, answer in (
        (transport.TREE, responses.tree),
        (transport.INFO, responses.info),
        (transport.RESOLVE, responses.resolve),
    ):
        match = pattern.fullmatch(path)
        if not match:
            continue
        found = api.pf_only(match[1])  # patched: None unless an hf:false record exists
        if not found:
            continue
        status, headers, body = answer(found, request.method, *match.groups()[1:])
        if body is not None and pattern is transport.TREE:
            body = _direct_children_only(body, request)
        if body is None:
            return httpx2.Response(status, headers=headers, request=request)
        return httpx2.Response(status, headers=headers, json=body, request=request)
    return None


def _direct_children_only(body: Any, request: Any) -> Any:
    """Honour `recursive=false`: upstream's `tree()` filters by prefix, so it also returns nested
    files that a non-recursive listing must not contain."""
    try:
        if (request.url.params.get("recursive") or "").lower() != "false":
            return body
    except Exception:
        return body
    if not isinstance(body, list):
        return body
    prefix = ""
    try:
        folder = request.url.params.get("path") or ""
        prefix = folder.strip("/") + "/" if folder else ""
    except Exception:
        return body
    out = []
    for entry in body:
        path = str(entry.get("path", "")) if isinstance(entry, dict) else ""
        rest = path.removeprefix(prefix)
        if rest and "/" not in rest:
            out.append(entry)
    return out


class OfflineFirst:
    """Duck-typed httpx2 transport: try the network, fall back to the record, then re-raise."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner

    def handle_request(self, request: Any) -> Any:
        try:
            return self.inner.handle_request(request)
        except NETWORK_ERRORS as original:
            if _disabled:
                raise
            try:
                answered = _answer_from_index(request)
            except Exception as exc:
                # Surfacing *our* exception here would mask the network failure the caller is set up
                # to handle, so log it and re-raise the original explicitly. (A bare `raise` here
                # would re-raise the inner exception: it is the one currently being handled.)
                log.debug("offline fallback failed: %s", exc)
                raise original from exc
            if answered is None:
                raise
            log.debug(
                "answered %s from a signed record: Hugging Face was unreachable", request.url.path
            )
            return answered

    def close(self) -> None:
        return self.inner.close()


def already_wrapped(transport: Any) -> bool:
    """True when an OfflineFirst already sits anywhere in this transport chain.

    A marker attribute on the current factory is not enough: pirateface installs a brand-new,
    unmarked factory every time its hook runs, so a marker is discarded exactly when we need it and
    each reinstall used to stack another pair of wrappers. The chain is the truth.
    """
    seen: set[int] = set()
    while transport is not None and id(transport) not in seen:
        if isinstance(transport, OfflineFirst):
            return True
        seen.add(id(transport))
        transport = getattr(transport, "inner", None)
    return False


def _wrap_factory(http_module: Any) -> bool:
    current = http_module._GLOBAL_CLIENT_FACTORY

    def factory():
        client = current()
        if already_wrapped(getattr(client, "_transport", None)):
            return client
        client._transport = OfflineFirst(client._transport)
        return client

    factory._matelotage_offline_first = True
    http_module.set_client_factory(factory)
    return True


def install() -> bool:
    """Wrap the client factory, and keep wrapping after pirateface reinstalls its own transport."""
    global _installed, _disabled
    if not enabled():
        return False
    # A reinstall has to undo an earlier disable(), or `patch.uninstall()` followed by `install()`
    # leaves the wrapper in place but permanently inert.
    _disabled = False
    try:
        from huggingface_hub.utils import _http
        from pirateface.huggingface import hook as pf_hook
    except Exception as exc:  # never take a startup down over this
        log.debug("offline-first not installed: %s", exc)
        return False

    wrapped = False
    with contextlib.suppress(Exception):
        wrapped = _wrap_factory(_http)

    original = pf_hook.install
    if not getattr(original, "_matelotage_offline_first", False):

        def install_hook(*args: Any, **kwargs: Any):
            result = original(*args, **kwargs)
            with contextlib.suppress(Exception):
                _wrap_factory(_http)
            return result

        install_hook._matelotage_offline_first = True
        pf_hook.install = install_hook

    _installed = bool(wrapped)
    return _installed


def is_installed() -> bool:
    return _installed


def disable() -> None:
    """Stop answering from records. The wrapper stays in place and passes everything through."""
    global _disabled
    _disabled = True
