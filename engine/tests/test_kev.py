import json
import os
import stat
import urllib.error
from pathlib import Path

import pytest

from watchtower_engine.feeds import kev
from watchtower_engine.feeds.homebrew import Response

FIX = Path(__file__).parent / "fixtures" / "kev" / "known_exploited_vulnerabilities.json"
BODY = FIX.read_bytes()
T1, T2 = "2026-10-29T08:00:00Z", "2026-10-30T08:00:00Z"


class FakeFetch:
    """Answers by URL with a Response, or raises. Never uses the network."""

    def __init__(self, primary=None, mirror=None):
        self.answers = {kev.PRIMARY_URL: primary, kev.MIRROR_URL: mirror}
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        answer = self.answers[url]
        if answer is None:
            raise OSError("network is disabled in tests")
        if isinstance(answer, BaseException):
            raise answer
        return answer


def ok(body=BODY):
    return Response(200, {}, body)


def http_error(code):
    return urllib.error.HTTPError("u", code, "x", {}, None)


def test_primary_source_is_used_first_and_sends_nothing_about_this_mac(tmp_path):
    fetch = FakeFetch(primary=ok(), mirror=ok())
    data = kev.load(tmp_path, fetch, lambda: T1)
    assert [u for u, _ in fetch.calls] == [kev.PRIMARY_URL]
    assert set(fetch.calls[0][1]) == {"User-Agent", "Accept"}
    assert (data.fresh, data.via_mirror, data.fetched_at, data.error) == (True, False, T1, None)
    assert data.entries["CVE-2021-23337"] == {
        "cve": "CVE-2021-23337", "date_added": "2026-10-22", "due_date": "2026-11-12", "ransomware": False}
    assert data.entries["CVE-2024-22195"]["ransomware"] is True  # The id is upper-cased.
    assert len(data.entries) == 2  # Rows without a CVE id are skipped.
    cov = data.coverage()
    assert (cov.source, cov.label, cov.state, cov.source_at, cov.note) == ("kev", "CISA KEV", "complete", T1, None)


@pytest.mark.parametrize("failure", [
    OSError("down"), http_error(403), http_error(503), Response(403, {}, b"denied"), Response(200, {}, b"not json"),
    Response(200, {}, b'{"vulnerabilities": []}'), Response(200, {}, b'{"vulnerabilities": "x"}'),
])
def test_official_mirror_is_used_when_the_cisa_source_fails(tmp_path, failure):
    fetch = FakeFetch(primary=failure, mirror=ok())
    data = kev.load(tmp_path, fetch, lambda: T1)
    assert [u for u, _ in fetch.calls] == [kev.PRIMARY_URL, kev.MIRROR_URL]
    assert (data.fresh, data.via_mirror, data.fetched_at) == (True, True, T1)
    assert "CVE-2021-23337" in data.entries
    cov = data.coverage()
    assert (cov.state, cov.note, cov.error) == ("complete", "official mirror", None)
    assert cov.detail and cov.detail.startswith(f"GET {kev.PRIMARY_URL}")  # Why the primary failed.


def test_both_sources_failing_use_the_cache_and_keep_its_age(tmp_path):
    kev.load(tmp_path, FakeFetch(primary=ok()), lambda: T1)
    data = kev.load(tmp_path, FakeFetch(primary=http_error(403), mirror=OSError("down")), lambda: T2)
    assert (data.fresh, data.fetched_at, data.reason) == (False, T1, "HTTP 403")
    assert "CVE-2021-23337" in data.entries
    cov = data.coverage()
    assert (cov.state, cov.source_at, cov.note, cov.error) == ("failed", T1, "HTTP 403", "CISA KEV did not load.")
    assert "403" in cov.detail and "down" in cov.detail


def test_both_failing_with_no_cache_has_no_data(tmp_path):
    data = kev.load(tmp_path, FakeFetch(primary=OSError("x"), mirror=Response(200, {}, b"[]")), lambda: T1)
    assert not data.loaded and data.entries == {}
    cov = data.coverage()
    assert (cov.state, cov.source_at, cov.note) == ("failed", None, "network error")


def test_reasons_for_the_source_row(tmp_path):
    for first, reason in [(OSError("x"), "network error"), (http_error(429), "HTTP 429"),
                          (Response(500, {}, b""), "HTTP 500"), (Response(200, {}, b"junk"), "bad data")]:
        data = kev.load(tmp_path / reason.replace(" ", "-"), FakeFetch(primary=first, mirror=OSError("x")), lambda: T1)
        assert data.reason == reason


def test_cache_keeps_where_the_copy_came_from(tmp_path):
    kev.load(tmp_path, FakeFetch(primary=OSError("x"), mirror=ok()), lambda: T1)
    data = kev.load(tmp_path, FakeFetch(primary=OSError("x"), mirror=OSError("x")), lambda: T2)
    assert data.via_mirror and data.fetched_at == T1 and not data.fresh


def test_a_corrupt_or_old_format_cache_is_ignored(tmp_path):
    cache = tmp_path / "cache" / "kev"
    cache.mkdir(parents=True)
    for text in ("{broken", json.dumps({"format": 99, "fetched_at": T1, "entries": {}}), "[]"):
        (cache / "kev.json").write_text(text)
        assert not kev.load(tmp_path, FakeFetch(primary=OSError("x"), mirror=OSError("x")), lambda: T2).loaded


def test_cache_is_private(tmp_path):
    old = os.umask(0o022)
    try:
        kev.load(tmp_path, FakeFetch(primary=ok()), lambda: T1)
    finally:
        os.umask(old)
    folder = tmp_path / "cache" / "kev"
    assert stat.S_IMODE(os.stat(folder).st_mode) == 0o700
    assert [stat.S_IMODE(os.stat(f).st_mode) for f in folder.iterdir()] == [0o600]


def test_oversize_body_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(kev, "MAX_BYTES", 10)
    data = kev.load(tmp_path, FakeFetch(primary=ok(), mirror=ok()), lambda: T1)
    assert not data.loaded and data.reason == "bad data"
