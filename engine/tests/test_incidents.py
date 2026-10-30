import json
import signal
import urllib.error
from pathlib import Path

import pytest

from watchtower_engine import cli, refresh
from watchtower_engine.feeds.homebrew import Response
from watchtower_engine.research import records, sources
from watchtower_engine.research.records import Cancelled, classify, next_window
from watchtower_engine.research.sources import (
    SOURCES, Item, Source, SourceError, clean_text, clean_url, fetch_items, parse_date, parse_rss,
)
from watchtower_engine.store import Store

FIX = Path(__file__).parent / "fixtures" / "incidents"
GITHUB, GOOGLE, APPLE = (s for s in SOURCES)
BODY = {"github": (FIX / "github.rss").read_bytes(), "google": (FIX / "google.json").read_bytes(),
        "apple": (FIX / "apple.rss").read_bytes()}
NOW = "2026-10-29T08:00:00Z"


class FakeFetch:
    """Answers by URL with a Response or an exception. Never uses the network."""

    def __init__(self, **overrides):
        self.answers = {s.url: Response(200, {}, BODY[s.key]) for s in SOURCES}
        for key, value in overrides.items():
            self.answers[next(s.url for s in SOURCES if s.key == key)] = value
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        answer = self.answers[url]
        if isinstance(answer, BaseException):
            raise answer
        return answer


def clock(*times):
    items = list(times)
    return lambda: items.pop(0) if len(items) > 1 else items[0]


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "data") as s:
        yield s


def check(store, fetch=None, now=NOW, **kw):
    return records.run_check(store.db, now=lambda: now, fetch=fetch or FakeFetch(), **kw)


def by_title(state):
    return {i["title"]: i for i in state["incidents"]}


# Requests


def test_each_source_is_one_plain_get_with_no_query_and_nothing_about_this_mac(store):
    fetch = FakeFetch()
    check(store, fetch)
    assert [u for u, _ in fetch.calls] == [s.url for s in SOURCES]
    for url, headers in fetch.calls:
        assert url.startswith("https://") and "?" not in url and "#" not in url
        assert set(headers) == {"User-Agent", "Accept"}
        assert "@" not in url
    assert [s.label for s in SOURCES] == ["GitHub", "Google / Gmail", "Apple security"]


def test_the_check_is_not_part_of_a_refresh(tmp_path):
    assert "incidents" not in [s.source for s in refresh.default_sources(tmp_path)]


# Parsing and untrusted text


def test_rss_items_are_cleaned_and_untrusted_links_are_dropped():
    items = {i.guid: i for i in parse_rss(GITHUB, BODY["github"])}
    tokens = items["gh-2026-1027-tokens"]
    assert tokens.title == "Third-party app tokens reset after a security event"
    assert tokens.published == "2026-10-27"
    assert tokens.url == "https://github.blog/security/third-party-tokens-reset/"
    assert tokens.cves == ["CVE-2026-1111"]
    assert tokens.summary.startswith("We have confirmed unauthorized access")
    phish = items["gh-2026-1025-phish"]
    assert phish.title == "Phishing campaign alert(1) targets maintainers"  # Markup removed, text kept.
    assert phish.url is None  # evil.example is not a host of the source.
    assert len(items) == 5


def test_atom_feeds_parse_too():
    atom = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><entry><id>a1</id>
      <title>Token breach</title><link rel="alternate" href="https://github.blog/security/a1"/>
      <updated>2026-10-27T10:00:00Z</updated><summary>We confirmed it.</summary></entry></feed>"""
    [item] = parse_rss(GITHUB, atom)
    assert (item.guid, item.title, item.published, item.url) == ("a1", "Token breach", "2026-10-27",
                                                                "https://github.blog/security/a1")


@pytest.mark.parametrize("body", [
    b"<!DOCTYPE lolz [<!ENTITY a 'aaaa'>]><rss><channel><item><title>&a;</title></item></channel></rss>",
    b'<?xml version="1.0"?><!ENTITY x "y"><rss/>', b"not xml", b"<html><body>nope</body></html>", b"",
])
def test_unsafe_or_wrong_documents_are_refused(body):
    with pytest.raises(SourceError, match="bad data"):
        parse_rss(GITHUB, body)


def test_google_status_rows_and_bad_rows():
    items = {i.guid: i for i in sources.parse_google_status(GOOGLE, BODY["google"])}
    assert set(items) == {"gw-0001", "gw-0002", "gw-0004"}  # A row without a title is dropped.
    assert items["gw-0001"].published == "2026-10-26"
    assert items["gw-0001"].url == "https://www.google.com/appsstatus/dashboard/incidents/gw-0001"
    assert items["gw-0004"].published is None
    for bad in (b"{}", b"nope", b'"x"'):
        with pytest.raises(SourceError):
            sources.parse_google_status(GOOGLE, bad)


def test_text_and_url_cleaning():
    assert clean_text("  <b>Hi</b>\u0000 there\n\tfriend&amp;co‮ ", 50) == "Hi there friend&co"
    assert clean_text("x" * 300, 20) == "x" * 19 + "…"
    assert clean_text(None, 10) == "" and clean_text(5, 10) == ""
    hosts = ("github.blog",)
    assert clean_url("https://github.blog/a", hosts) == "https://github.blog/a"
    assert clean_url("https://news.github.blog/a", hosts)
    for bad in ("http://github.blog/a", "javascript:alert(1)", "https://github.blog.evil.example/a",
                "https://evil.example/github.blog", "https://user:pw@github.blog/a", "file:///etc/passwd", "",
                None, "https://github.blog/" + "a" * 600):
        assert clean_url(bad, hosts) is None


def test_dates_of_every_feed_style():
    assert parse_date("Tue, 27 Oct 2026 23:30:00 -0500") == "2026-10-28"
    assert parse_date("2026-10-27T10:00:00Z") == "2026-10-27"
    assert parse_date("2026-10-27") == "2026-10-27"
    assert parse_date("yesterday") is None and parse_date(None) is None and parse_date("") is None


def test_fetch_failures_give_short_reasons():
    def error(code):
        return urllib.error.HTTPError("u", code, "x", {}, None)

    cases = [(error(403), "HTTP 403"), (error(429), "rate limit"), (OSError("down"), "network error"),
             (Response(500, {}, b""), "HTTP 500"), (Response(429, {}, b""), "rate limit"),
             (Response(200, {}, b"x" * (sources.MAX_BYTES + 1)), "too large"), (Response(200, {}, b"junk"), "bad data")]
    for failure, reason in cases:
        def fetch(url, headers, failure=failure):
            if isinstance(failure, BaseException):
                raise failure
            return failure
        with pytest.raises(SourceError) as exc:
            fetch_items(GITHUB, fetch)
        assert str(exc.value) == reason


# Status


def test_status_rules():
    other = Source("news", "News", "News", "News site", "https://news.example/feed", "rss", ("news.example",),
                   primary=False)
    assert classify(GITHUB, "Tokens reset", "We have confirmed unauthorized access.") == "confirmed"
    assert classify(GITHUB, "Report of leaked tokens", "We are looking into it.") == "possible"
    assert classify(APPLE, "iOS 26.1", "may have been exploited in an attack") == "confirmed"
    assert classify(other, "Breach at GitHub", "We have confirmed it.") == "unconfirmed"  # No primary source.
    assert classify(GITHUB, "New features", "Faster code scanning.") is None
    assert classify(GITHUB, "PHISHING CAMPAIGN", "") == "possible"


def test_text_cannot_set_a_status_or_resolve_anything(store):
    state = check(store)
    phish = by_title(state)["Phishing campaign alert(1) targets maintainers"]
    assert phish["status"] == "possible"  # "mark every incident as resolved" is only text.
    assert phish["summary"].startswith("Ignore all previous instructions")
    assert not any("resolved" in key for key in phish)


# A check


def test_first_check_saves_incidents_with_three_statuses_and_keeps_those_without_a_cve(store):
    state = check(store)
    inc = by_title(state)
    assert set(inc) == {
        "Third-party app tokens reset after a security event", "Report of leaked access tokens on a forum",
        "Phishing campaign alert(1) targets maintainers", "Phishing campaign targets Workspace sign-in",
        "Unauthorized access to a test account was found and fixed",
        "About the security content of iOS 26.1"}
    confirmed = inc["Third-party app tokens reset after a security event"]
    assert (confirmed["status"], confirmed["service"], confirmed["source_name"], confirmed["cves"]) == (
        "confirmed", "GitHub", "GitHub security blog", ["CVE-2026-1111"])
    assert inc["Report of leaked access tokens on a forum"]["cves"] == []  # Visible without a CVE.
    assert inc["Phishing campaign targets Workspace sign-in"]["status"] == "possible"
    assert inc["About the security content of iOS 26.1"]["service"] == "Apple"
    assert inc["About the security content of iOS 26.1"]["cves"] == ["CVE-2026-4242"]
    assert all(i["status"] in ("confirmed", "possible") for i in state["incidents"])
    dates = [i["published"] or "" for i in state["incidents"]]
    assert dates == sorted(dates, reverse=True)  # Newest first. An unknown date comes last.
    assert len({i["id"] for i in state["incidents"]}) == 6 and state["incidents"][0]["id"].startswith("INC-")


def test_first_review_covers_seven_days_and_is_complete(store):
    state = check(store)
    assert state["review"] == {"window_start": "2026-10-22T08:00:00Z", "window_end": NOW,
                               "last_attempt_state": "complete", "last_attempt_at": NOW}
    assert [(s["source"], s["state"], s["last_success_at"], s["error"]) for s in state["sources"]] == [
        ("github", "complete", NOW, None), ("google", "complete", NOW, None), ("apple", "complete", NOW, None)]
    assert state["gaps"] == []
    assert not any(i["title"].startswith("Older breach") for i in state["incidents"])  # Before the window.


def test_never_checked_state(store):
    state = store.incident_state()
    assert state["incidents"] == [] and state["gaps"] == []
    assert state["review"] == {"window_start": None, "window_end": None, "last_attempt_state": None,
                               "last_attempt_at": None}
    assert [(s["label"], s["state"]) for s in state["sources"]] == [
        ("GitHub", "not_run"), ("Google / Gmail", "not_run"), ("Apple security", "not_run")]


def test_progress_reports_each_source_then_the_end(store):
    seen = []
    check(store, progress=lambda d, t, l: seen.append((d, t, l)))
    assert seen == [(0, 3, "GitHub"), (1, 3, "Google / Gmail"), (2, 3, "Apple security"), (3, 3, "")]


def test_a_later_review_overlaps_the_last_one_by_48_hours_and_does_not_duplicate(store):
    first = check(store)
    later = "2026-10-30T08:00:00Z"
    second = check(store, now=later)
    assert second["review"]["window_start"] == "2026-10-27T08:00:00Z"  # Oct 29 08:00 minus 48 hours.
    assert second["review"]["window_end"] == later
    assert len(second["incidents"]) == 6  # The same records, not new ones.
    assert {i["id"] for i in second["incidents"]} == {i["id"] for i in first["incidents"]}
    # The overlap leaves out items older than its start: the Oct 23 forum item is not new, and stays.
    assert any(i["title"].startswith("Report of leaked") for i in second["incidents"])


def test_an_item_older_than_the_window_is_not_saved_by_a_later_check(store):
    check(store)
    second = check(store, now="2026-10-30T08:00:00Z", fetch=FakeFetch(github=Response(200, {}, b"""<rss><channel>
      <item><title>Old leak report</title><guid>old</guid><pubDate>Wed, 21 Oct 2026 09:00:00 GMT</pubDate>
      <description>leak</description></item></channel></rss>""")))
    assert not any(i["title"] == "Old leak report" for i in second["incidents"])


def test_a_record_that_leaves_the_feed_is_never_removed_or_resolved(store):
    check(store)
    empty_feeds = FakeFetch(github=Response(200, {}, b"<rss><channel></channel></rss>"),
                            google=Response(200, {}, b"[]"), apple=Response(200, {}, b"<rss><channel/></rss>"))
    after = check(store, empty_feeds, now="2026-10-30T08:00:00Z")
    assert len(after["incidents"]) == 6
    assert all(i["status"] in ("confirmed", "possible") for i in after["incidents"])
    assert after["review"]["last_attempt_state"] == "complete"


def test_a_status_is_raised_but_never_lowered(store):
    check(store)
    quiet = b"""<rss><channel><item><title>Third-party app tokens reset after a security event</title>
        <guid>gh-2026-1027-tokens</guid><pubDate>Tue, 27 Oct 2026 10:00:00 GMT</pubDate>
        <description>An update about a leak.</description></item>
        <item><title>Report of leaked access tokens on a forum</title><guid>gh-2026-1023-forum</guid>
        <pubDate>Fri, 23 Oct 2026 09:00:00 GMT</pubDate>
        <description>We have confirmed unauthorized access. CVE-2026-9999</description></item>
        </channel></rss>"""
    after = check(store, FakeFetch(github=Response(200, {}, quiet)), now="2026-10-30T08:00:00Z")
    inc = by_title(after)
    assert inc["Third-party app tokens reset after a security event"]["status"] == "confirmed"  # Not lowered.
    leaked = inc["Report of leaked access tokens on a forum"]
    assert leaked["status"] == "confirmed" and leaked["cves"] == ["CVE-2026-9999"]  # Raised. CVE added.
    assert leaked["summary"].startswith("We are looking into")  # The first text stays.
    assert leaked["first_seen"] == NOW and leaked["last_seen"] == "2026-10-30T08:00:00Z"


def test_a_source_without_a_primary_feed_gives_unconfirmed(store):
    news = Source("news", "News", "GitHub", "News report only", "https://news.example/feed", "rss",
                  ("news.example",), primary=False)
    feed = b"<rss><channel><item><title>Report of leaked access tokens</title><guid>n1</guid>" \
           b"<pubDate>Fri, 27 Oct 2026 09:00:00 GMT</pubDate><description>We confirmed it.</description></item></channel></rss>"
    fetch = FakeFetch()
    fetch.answers[news.url] = Response(200, {}, feed)
    state = check(store, fetch, sources=[*SOURCES, news])
    [row] = [i for i in state["incidents"] if i["source"] == "news"]
    assert (row["status"], row["source_name"]) == ("unconfirmed", "News report only")


# Completion, failures and gaps


def test_one_failed_source_makes_a_partial_review_and_the_label_keeps_the_old_end_date(store):
    check(store)
    later = "2026-10-30T08:00:00Z"
    state = check(store, FakeFetch(google=OSError("down"), apple=Response(200, {}, b"<rss><channel/></rss>")), now=later)
    assert state["review"]["window_end"] == NOW  # The last complete review.
    assert state["review"]["last_attempt_state"] == "partial" and state["review"]["last_attempt_at"] == later
    google = next(s for s in state["sources"] if s["source"] == "google")
    assert (google["state"], google["error"], google["note"], google["last_success_at"]) == (
        "failed", "Google / Gmail: check failed. The review is not complete.", "network error", NOW)
    assert "down" in google["detail"] and sources.SOURCES[1].url in google["detail"]
    assert next(s for s in state["sources"] if s["source"] == "github")["last_success_at"] == later
    assert len(state["incidents"]) == 6  # Nothing was lost.


def test_a_partial_review_saves_the_incidents_of_the_sources_that_worked(store):
    state = check(store, FakeFetch(google=Response(500, {}, b"")))
    assert state["review"]["window_end"] is None  # No complete review yet: no review label.
    assert state["review"]["last_attempt_state"] == "partial"
    assert {i["source"] for i in state["incidents"]} == {"github", "apple"}


def test_the_next_window_covers_the_days_of_a_partial_review_again(store):
    check(store)
    check(store, FakeFetch(google=OSError("down")), now="2026-10-30T08:00:00Z")
    third = check(store, now="2026-10-31T08:00:00Z")
    assert third["review"]["window_start"] == "2026-10-27T08:00:00Z"  # 48 hours before the last COMPLETE end.
    assert third["review"]["last_attempt_state"] == "complete"


def test_all_sources_failing_changes_nothing_but_the_rows(store):
    check(store)
    dead = FakeFetch(github=OSError("a"), google=OSError("b"), apple=OSError("c"))
    state = check(store, dead, now="2026-10-30T08:00:00Z")
    assert state["review"]["last_attempt_state"] == "failed" and state["review"]["window_end"] == NOW
    assert {s["state"] for s in state["sources"]} == {"failed"} and len(state["incidents"]) == 6


def test_a_check_of_some_sources_cannot_complete_the_review(store):
    state = check(store, selected=["github"])
    assert state["review"]["last_attempt_state"] == "partial" and state["review"]["window_end"] is None
    assert [(s["source"], s["state"]) for s in state["sources"]] == [
        ("github", "complete"), ("google", "not_run"), ("apple", "not_run")]


def test_stopping_the_check_saves_nothing(store):
    def stop(done, total, label):
        if done == 1:
            raise Cancelled()

    with pytest.raises(Cancelled):
        check(store, progress=stop)
    state = store.incident_state()
    assert state["incidents"] == [] and state["review"]["last_attempt_state"] is None
    assert {s["state"] for s in state["sources"]} == {"not_run"}


def test_a_failed_save_keeps_the_old_data(store, monkeypatch):
    check(store)

    def boom(*a):
        raise RuntimeError("disk")

    monkeypatch.setattr(records, "_save_items", boom)
    with pytest.raises(RuntimeError):
        check(store, now="2026-10-30T08:00:00Z")
    monkeypatch.undo()
    state = store.incident_state()
    assert state["review"]["last_attempt_at"] == NOW and len(state["incidents"]) == 6


def test_missed_days_are_shown_when_the_last_review_is_too_old(store):
    check(store, now="2026-10-20T08:00:00Z")
    state = check(store, now=NOW)
    assert state["review"]["window_start"] == "2026-10-22T08:00:00Z"  # Capped at 7 days.
    assert state["gaps"] == [{"start": "2026-10-20", "end": "2026-10-21"}]
    again = check(store, now="2026-10-30T08:00:00Z")
    assert again["gaps"] == [{"start": "2026-10-20", "end": "2026-10-21"}]  # The gap stays until it is old.
    assert records.incident_state(store.db, now="2026-12-30T08:00:00Z")["gaps"] == []


def test_a_gap_is_recorded_only_by_a_complete_review(store):
    check(store, now="2026-10-20T08:00:00Z")
    partial = check(store, FakeFetch(apple=OSError("x")), now=NOW)
    assert partial["gaps"] == []
    complete = check(store, now="2026-10-29T09:00:00Z")
    assert complete["gaps"] == [{"start": "2026-10-20", "end": "2026-10-21"}]


def test_window_rules():
    assert next_window(None, NOW).start == "2026-10-22T08:00:00Z"
    w = next_window("2026-10-28T08:00:00Z", NOW)
    assert (w.start, w.gap_start) == ("2026-10-26T08:00:00Z", None)
    w = next_window("2026-10-22T08:00:00Z", NOW)  # 48 hours before it is Oct 20: older than the cap.
    assert (w.start, w.gap_start, w.gap_end) == ("2026-10-22T08:00:00Z", None, None)
    w = next_window("2026-10-10T08:00:00Z", NOW)
    assert (w.start, w.gap_start, w.gap_end) == ("2026-10-22T08:00:00Z", "2026-10-10", "2026-10-21")


# CLI


def test_cli_incidents_and_check(tmp_path, monkeypatch, capsys):
    data = str(tmp_path / "data")
    assert cli.main(["--data-dir", data, "incidents"]) == 0
    assert json.loads(capsys.readouterr().out)["incidents"] == []
    monkeypatch.setattr("watchtower_engine.feeds.homebrew.http_fetch", FakeFetch())
    assert cli.main(["--data-dir", data, "incidents-check"]) == 0
    captured = capsys.readouterr()
    state = json.loads(captured.out)
    assert state["schema_version"] == 1 and len(state["incidents"]) >= 5
    assert [json.loads(l)["progress"]["done"] for l in captured.err.splitlines()] == [0, 1, 2, 3]
    assert cli.main(["--data-dir", data, "incidents"]) == 0
    assert len(json.loads(capsys.readouterr().out)["incidents"]) == len(state["incidents"])


def test_cli_stop_exits_130_with_empty_stdout(tmp_path, monkeypatch, capsys):
    def fetch(url, headers):
        raise Cancelled()

    monkeypatch.setattr("watchtower_engine.feeds.homebrew.http_fetch", fetch)
    assert cli.main(["--data-dir", str(tmp_path), "incidents-check"]) == 130
    captured = capsys.readouterr()
    assert captured.out == "" and json.loads(captured.err.splitlines()[-1])["error"] == "The check was stopped."


def test_cli_restores_the_sigterm_handler(tmp_path, monkeypatch):
    monkeypatch.setattr("watchtower_engine.feeds.homebrew.http_fetch", FakeFetch())
    before = signal.getsignal(signal.SIGTERM)
    cli.main(["--data-dir", str(tmp_path), "incidents-check"])
    assert signal.getsignal(signal.SIGTERM) == before
