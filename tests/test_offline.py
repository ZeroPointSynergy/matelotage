"""The offline-first wrapper: answer only when the network is gone, and only for hf:false records."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from matelotage import offline

FOUND = {
    "repo_id": "acme/offline-model",
    "commit": "main",
    "files": {"config.json": (21, "c" * 64, None)},
}


@pytest.fixture
def hf_host():
    from huggingface_hub import constants

    def request(path, method="GET"):
        url = SimpleNamespace(host=__import__("urllib.parse", fromlist=["x"]).urlsplit(constants.ENDPOINT).hostname,
                              path=path)
        return SimpleNamespace(url=url, method=method)

    return request


class Boom:
    """A transport that behaves like an unreachable host."""

    def __init__(self):
        self.calls = 0

    def handle_request(self, request):
        self.calls += 1
        raise ConnectionError("simulated: Hugging Face is unreachable")

    def close(self):
        pass


class Healthy:
    def __init__(self):
        self.calls = 0

    def handle_request(self, request):
        self.calls += 1
        return "answered-by-hf"

    def close(self):
        pass


def test_answers_from_a_record_when_the_network_is_gone(monkeypatch, hf_host):
    monkeypatch.setattr("pirateface.client.api.pf_only", lambda repo_id: FOUND)
    transport = offline.OfflineFirst(Boom())
    response = transport.handle_request(hf_host("/api/models/acme/offline-model"))
    assert response is not None and response.status_code == 200


def test_never_runs_while_hugging_face_is_answering(monkeypatch, hf_host):
    called = []
    monkeypatch.setattr("pirateface.client.api.pf_only", lambda repo_id: called.append(repo_id) or FOUND)
    inner = Healthy()
    assert offline.OfflineFirst(inner).handle_request(hf_host("/api/models/acme/x")) == "answered-by-hf"
    assert called == [], "the record must not be consulted when the network answered"


def test_re_raises_when_no_record_covers_the_request(monkeypatch, hf_host):
    monkeypatch.setattr("pirateface.client.api.pf_only", lambda repo_id: None)
    with pytest.raises(ConnectionError):
        offline.OfflineFirst(Boom()).handle_request(hf_host("/api/models/acme/unknown"))


def test_ignores_requests_for_other_hosts(monkeypatch, hf_host):
    monkeypatch.setattr("pirateface.client.api.pf_only", lambda repo_id: FOUND)
    request = hf_host("/api/models/acme/offline-model")
    request.url.host = "example.invalid"
    with pytest.raises(ConnectionError):
        offline.OfflineFirst(Boom()).handle_request(request)


def test_disable_stops_answering(monkeypatch, hf_host):
    monkeypatch.setattr("pirateface.client.api.pf_only", lambda repo_id: FOUND)
    transport = offline.OfflineFirst(Boom())
    offline.disable()
    try:
        with pytest.raises(ConnectionError):
            transport.handle_request(hf_host("/api/models/acme/offline-model"))
    finally:
        offline._disabled = False


def test_switched_off_by_environment(monkeypatch):
    monkeypatch.setenv("MATELOTAGE_OFFLINE_FIRST", "0")
    assert offline.enabled() is False
    monkeypatch.delenv("MATELOTAGE_OFFLINE_FIRST")
    assert offline.enabled() is True


def test_a_failing_fallback_surfaces_the_network_error(monkeypatch, hf_host):
    """If our own lookup blows up, the caller must still see the connection error it handles."""
    def explode(repo_id):
        raise RuntimeError("record is corrupt")

    monkeypatch.setattr("pirateface.client.api.pf_only", explode)
    with pytest.raises(ConnectionError):
        offline.OfflineFirst(Boom()).handle_request(hf_host("/api/models/acme/offline-model"))


def test_reports_whether_it_is_installed():
    assert isinstance(offline.is_installed(), bool)
