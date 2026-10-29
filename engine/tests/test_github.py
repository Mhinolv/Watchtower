import json
import urllib.parse
from pathlib import Path

import pytest

from watchtower_engine.feeds import github
from watchtower_engine.feeds.github import GithubData, load, lookup_targets, next_link
from watchtower_engine.feeds.homebrew import Response

FIX = Path(__file__).parent / "fixtures" / "github"
MALWARE = json.loads((FIX / "malware.json").read_text())
REVIEWED = json.loads((FIX / "reviewed.json").read_text())
T1, T2, T3 = "2026-10-29T08:00:00Z", "2026-10-29T10:00:00Z", "2026-10-30T08:00:00Z"
LODASH = ["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"]
MAL = ["GHSA-mal1-ware-0001"]


def reply(data, status=200, **headers):
    return Response(status, {k.replace("_", "-"): v for k, v in headers.items()}, json.dumps(data).encode())


def query(url):
    return {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(url).query).items()}


class FakeFetch:
    """Answers by (type, id). A value is a Response, a list of Responses (pages) or an exception."""

    def __init__(self, answers=None, default=None):
        self.answers = answers or {}
        self.default = default if default is not None else reply([])
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        q = query(url)
        ident = q.get("ghsa_id") or q.get("cve_id")
        answer = self.answers.get((q["type"], ident), self.default)
        if isinstance(answer, list):
            answer = answer.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def asked(self):
        return [(query(u)["type"], query(u).get("ghsa_id") or query(u).get("cve_id")) for u, _ in self.calls]


def standard():
    return FakeFetch({("reviewed", "GHSA-35jh-r3h4-6jhm"): reply(REVIEWED),
                      ("malware", "GHSA-mal1-ware-0001"): reply(MALWARE)})


# Requests


def test_reviewed_and_malware_are_separate_requests_with_only_an_advisory_id(tmp_path):
    fetch = standard()
    load(tmp_path, [LODASH], fetch, lambda: T1)
    assert fetch.asked() == [("reviewed", "GHSA-35jh-r3h4-6jhm"), ("malware", "GHSA-35jh-r3h4-6jhm")]
    for url, headers in fetch.calls:
        assert url.startswith("https://api.github.com/advisories?")
        assert set(query(url)) == {"ghsa_id", "type", "per_page"}
        assert query(url)["per_page"] == "100"
        assert set(headers) == {"User-Agent", "Accept", "X-GitHub-Api-Version"}
        assert headers["Accept"] == "application/vnd.github+json"
        assert headers["X-GitHub-Api-Version"] == "2026-03-10"


def test_a_finding_without_a_ghsa_id_is_asked_by_its_cve_id_and_other_ids_are_not_sent(tmp_path):
    fetch = FakeFetch()
    load(tmp_path, [["CVE-2020-1111", "PYSEC-2020-1", "OSV-2020-1"], ["PYSEC-2021-9"]], fetch, lambda: T1)
    assert fetch.asked() == [("reviewed", "CVE-2020-1111"), ("malware", "CVE-2020-1111")]
    assert lookup_targets(["ghsa-35JH-R3H4-6JHM", "CVE-1-1"]) == [("ghsa_id", "GHSA-35jh-r3h4-6jhm")]
    assert lookup_targets(["cve-2020-1111", "OSV-1"]) == [("cve_id", "CVE-2020-1111")]
    assert lookup_targets(["GHSA-nope", "x"]) == []


def test_duplicate_ids_across_findings_are_asked_once(tmp_path):
    fetch = FakeFetch()
    load(tmp_path, [LODASH, ["GHSA-35jh-r3h4-6jhm"], ["ghsa-35jh-r3h4-6jhm"]], fetch, lambda: T1)
    assert len(fetch.calls) == 2


def test_no_ids_means_no_requests_and_a_complete_feed(tmp_path):
    fetch = FakeFetch()
    data = load(tmp_path, [], fetch, lambda: T1)
    assert fetch.calls == [] and data.state == "complete" and data.fetched_at == T1


# Assessment


def test_malware_withdrawn_and_complete_answers(tmp_path):
    data = load(tmp_path, [LODASH, MAL], standard(), lambda: T1)
    assert data.state == "complete" and data.fetched_at == T1
    lodash = data.assess(LODASH)
    assert (lodash.withdrawn_at, lodash.withdrawn_known, lodash.malware_id, lodash.malware_known) == (
        "2026-10-28T08:00:00Z", True, None, True)
    mal = data.assess(MAL)
    assert (mal.malware_id, mal.malware_known, mal.withdrawn_at) == ("GHSA-mal1-ware-0001", True, None)
    unknown = data.assess(["GHSA-zzzz-zzzz-zzzz"])
    assert (unknown.malware_known, unknown.withdrawn_known) == (False, False)
    assert not data.assess(["OSV-1"]).malware_known  # Nothing was asked for this id.


def test_a_withdrawn_malware_advisory_is_not_malware(tmp_path):
    withdrawn = [{**MALWARE[0], "withdrawn_at": "2026-10-28T00:00:00Z"}]
    data = load(tmp_path, [MAL], FakeFetch({("malware", "GHSA-mal1-ware-0001"): reply(withdrawn)}), lambda: T1)
    assert data.assess(MAL).malware_id is None and data.assess(MAL).malware_known


def test_only_known_fields_are_kept(tmp_path):
    data = load(tmp_path, [MAL], standard(), lambda: T1)
    [lookup] = [l for l in data.lookups.values() if l.kind == "malware"]
    assert lookup.advisories == [{"ghsa_id": "GHSA-mal1-ware-0001", "cve_id": None, "type": "malware",
                                  "severity": "critical", "withdrawn_at": None,
                                  "published_at": "2026-10-27T10:00:00Z"}]


def test_non_advisory_rows_are_skipped(tmp_path):
    data = load(tmp_path, [MAL], FakeFetch({("malware", "GHSA-mal1-ware-0001"): reply([{"x": 1}, 5, MALWARE[0]])}),
                lambda: T1)
    assert data.state == "complete"
    assert [a["ghsa_id"] for l in data.lookups.values() for a in l.advisories] == ["GHSA-mal1-ware-0001"]


# Pagination


def page(rows, nxt=None):
    headers = {"link": f'<{nxt}>; rel="next", <https://api.github.com/advisories?page=9>; rel="last"'} if nxt else {}
    return Response(200, headers, json.dumps(rows).encode())


def many(n):
    return [{**MALWARE[0], "ghsa_id": f"GHSA-aaaa-bbbb-{i:04d}"} for i in range(n)]


def test_pagination_is_followed_through_the_link_header(tmp_path):
    nxt = "https://api.github.com/advisories?ghsa_id=GHSA-mal1-ware-0001&type=malware&per_page=100&page=2"
    fetch = FakeFetch({("malware", "GHSA-mal1-ware-0001"): [page(many(2), nxt), page(many(1))]})
    data = load(tmp_path, [MAL], fetch, lambda: T1)
    assert len(fetch.calls) == 3  # Two pages for malware, one for reviewed.
    [lookup] = [l for l in data.lookups.values() if l.kind == "malware"]
    assert len(lookup.advisories) == 3 and not lookup.incomplete
    assert data.state == "complete"


def test_pagination_that_stops_early_is_incomplete(tmp_path):
    nxt = "https://api.github.com/advisories?ghsa_id=GHSA-mal1-ware-0001&type=malware&page=2"
    pages = [page(many(1), nxt)] * 10
    fetch = FakeFetch({("malware", "GHSA-mal1-ware-0001"): pages})
    data = load(tmp_path, [MAL], fetch, lambda: T1)
    assert len(fetch.calls) == github.MAX_PAGES + 1
    assert data.state == "partial" and data.reason == "pagination stopped"
    cov = data.coverage()
    assert (cov.state, cov.note, cov.error) == ("partial", "pagination stopped", "GitHub Advisories are incomplete.")
    # An incomplete answer is asked for again at the next refresh.
    again = FakeFetch({("malware", "GHSA-mal1-ware-0001"): [page([])]})
    load(tmp_path, [MAL], again, lambda: T2)
    assert again.asked() == [("malware", "GHSA-mal1-ware-0001")]


def test_next_link_follows_only_api_github_com():
    ok = '<https://api.github.com/advisories?page=2>; rel="next"'
    assert next_link(ok) == "https://api.github.com/advisories?page=2"
    assert next_link('<https://evil.example/advisories?page=2>; rel="next"') is None
    assert next_link('<http://api.github.com/advisories>; rel="next"') is None
    assert next_link('<https://api.github.com/advisories?page=1>; rel="prev"') is None
    assert next_link(None) is None


def test_a_next_link_to_another_host_is_never_requested(tmp_path):
    fetch = FakeFetch({("malware", "GHSA-mal1-ware-0001"): page(many(1), "https://evil.example/x")})
    data = load(tmp_path, [MAL], fetch, lambda: T1)
    assert all(u.startswith("https://api.github.com/") for u, _ in fetch.calls)
    assert data.state == "complete"


# Failures


def rate_limited(**extra):
    return Response(403, {"x-ratelimit-remaining": "0", **extra}, b'{"message": "API rate limit exceeded"}')


def test_a_rate_limit_stops_later_requests_and_keeps_cached_answers(tmp_path):
    load(tmp_path, [LODASH], standard(), lambda: T1)
    fetch = FakeFetch({("reviewed", "GHSA-35jh-r3h4-6jhm"): rate_limited()})
    data = load(tmp_path, [LODASH, MAL], fetch, lambda: T3)
    assert fetch.asked() == [("reviewed", "GHSA-35jh-r3h4-6jhm")]  # The first request stopped the refresh.
    assert data.state == "failed" and data.reason == "rate limit"
    assert data.fetched_at == T1  # The cached answers keep their original age.
    assert data.assess(LODASH).withdrawn_at == "2026-10-28T08:00:00Z"
    cov = data.coverage()
    assert (cov.state, cov.note, cov.source_at, cov.error) == ("failed", "rate limit", T1,
                                                               "GitHub Advisories did not load.")
    assert "rate limit" in cov.detail


@pytest.mark.parametrize("response", [
    Response(429, {"retry-after": "60"}, b""),
    Response(403, {}, b'{"message": "You have exceeded a secondary rate limit"}'),
    rate_limited(),
])
def test_every_rate_limit_shape_is_detected(tmp_path, response):
    data = load(tmp_path, [LODASH], FakeFetch(default=response), lambda: T1)
    assert (data.state, data.reason) == ("failed", "rate limit")


def test_the_last_allowed_request_that_empties_the_limit_stops_the_rest(tmp_path):
    fetch = FakeFetch(default=reply([], x_ratelimit_remaining="0"))
    data = load(tmp_path, [LODASH], fetch, lambda: T1)
    assert len(fetch.calls) == 1 and data.state == "failed" and data.reason == "rate limit"


def test_a_network_failure_stops_the_refresh(tmp_path):
    fetch = FakeFetch(default=OSError("down"))
    data = load(tmp_path, [LODASH, MAL], fetch, lambda: T1)
    assert len(fetch.calls) == 1
    assert (data.state, data.reason, data.fetched_at) == ("failed", "network error", None)
    assert not data.assess(LODASH).malware_known  # No answer: nothing is cleared.


@pytest.mark.parametrize("response,reason", [
    (Response(500, {}, b""), "HTTP 500"), (Response(404, {}, b""), "HTTP 404"),
    (Response(200, {}, b"not json"), "bad data"), (Response(200, {}, b'{"a": 1}'), "bad data"),
])
def test_a_bad_answer_marks_the_feed_failed_but_the_other_ids_still_run(tmp_path, response, reason):
    fetch = FakeFetch({("reviewed", "GHSA-35jh-r3h4-6jhm"): response, ("malware", "GHSA-mal1-ware-0001"): reply(MALWARE)})
    data = load(tmp_path, [LODASH, MAL], fetch, lambda: T1)
    assert (data.state, data.reason) == ("failed", reason)
    assert len(fetch.calls) == 4
    assert data.assess(MAL).malware_id == "GHSA-mal1-ware-0001"


def test_request_cap_makes_the_feed_incomplete(tmp_path):
    ids = [[f"GHSA-aaaa-bbbb-{i:04d}"] for i in range(5)]
    fetch = FakeFetch()
    data = load(tmp_path, ids, fetch, lambda: T1, max_requests=4)
    assert len(fetch.calls) == 4
    assert (data.state, data.reason) == ("partial", "request limit")
    assert data.coverage().note == "request limit"


# Cache


def test_answers_younger_than_the_ttl_are_reused(tmp_path):
    load(tmp_path, [LODASH], standard(), lambda: T1)
    fetch = FakeFetch()
    data = load(tmp_path, [LODASH], fetch, lambda: T2)  # Two hours later.
    assert fetch.calls == [] and data.state == "complete" and data.fetched_at == T1
    assert data.assess(LODASH).withdrawn_at
    old = FakeFetch()
    load(tmp_path, [LODASH], old, lambda: T3)  # A day later.
    assert len(old.calls) == 2


def test_a_refreshed_answer_replaces_the_cached_one(tmp_path):
    load(tmp_path, [LODASH], standard(), lambda: T1)
    data = load(tmp_path, [LODASH], FakeFetch({("reviewed", "GHSA-35jh-r3h4-6jhm"): reply([])}), lambda: T3)
    assert data.assess(LODASH).withdrawn_at is None and data.assess(LODASH).withdrawn_known
    assert data.fetched_at == T3


def test_cache_only_keeps_the_ids_of_this_refresh_and_is_private(tmp_path):
    import os
    import stat
    load(tmp_path, [LODASH], standard(), lambda: T1)
    load(tmp_path, [MAL], standard(), lambda: T1)
    path = tmp_path / "cache" / "github" / "advisories.json"
    keys = set(json.loads(path.read_text())["lookups"])
    assert keys == {"reviewed|ghsa_id=GHSA-mal1-ware-0001", "malware|ghsa_id=GHSA-mal1-ware-0001"}
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700


def test_a_corrupt_cache_is_ignored(tmp_path):
    folder = tmp_path / "cache" / "github"
    folder.mkdir(parents=True)
    for text in ("{broken", "[]", json.dumps({"format": 7, "lookups": {}}), json.dumps({"format": 1, "lookups": 3})):
        (folder / "advisories.json").write_text(text)
        fetch = FakeFetch()
        assert load(tmp_path, [LODASH], fetch, lambda: T1).state == "complete"
        assert len(fetch.calls) == 2
