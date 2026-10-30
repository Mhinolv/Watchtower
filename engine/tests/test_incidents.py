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
GITHUB, GOOGLE, APPLE, HIBP = (s for s in SOURCES)
BODY = {"github": (FIX / "github.rss").read_bytes(), "google": (FIX / "google.json").read_bytes(),
        "apple": (FIX / "apple_security_releases.html").read_bytes(),
        "hibp": (FIX / "hibp-breaches-excerpt.json").read_bytes()}  # Real list excerpt: no watched service in it.
NOW = "2026-10-29T08:00:00Z"
OTHERS = 5  # Records from the GitHub and Google fixtures.
APPLE_RELEASES = 13  # Rows of the Apple fixture that are in the first window (22 Oct 2026 and later).
TOTAL = OTHERS + APPLE_RELEASES
EMPTY_APPLE = Response(200, {}, b"""<html><body><table><tbody>
  <tr><th>Name and information link</th><th>Available for</th><th>Release date</th></tr>
  <tr><td><p><a href="https://support.apple.com/en-us/120303">Old release</a></p></td><td><p>Mac</p></td>
  <td><p>09 Jan 2024</p></td></tr></tbody></table></body></html>""")


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
    assert [s.label for s in SOURCES] == ["GitHub", "Google / Gmail", "Apple security", "Have I Been Pwned"]


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


# #93: the real GitHub feed has `<!DOCTYPE html` text in post bodies (CDATA), first at byte 2366.
DOCTYPE_TEXT_FEED = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel><title>Security</title>
<item><title>Token breach</title><link>https://github.blog/security/t1/</link><guid>t1</guid>
<pubDate>Tue, 27 Oct 2026 10:00:00 +0000</pubDate><description><![CDATA[<p>We confirmed it.</p>]]></description>
<content:encoded><![CDATA[<pre><code><!DOCTYPE html>
<!ENTITY x "y"><html></html></code></pre>]]></content:encoded></item>
<item><title>Escaped markup</title><guid>t2</guid><description>&lt;!DOCTYPE html&gt; in text</description></item>
</channel></rss>"""


def test_doctype_text_inside_a_post_body_is_not_a_declaration():
    items = parse_rss(GITHUB, DOCTYPE_TEXT_FEED)
    assert [(i.guid, i.title) for i in items] == [("t1", "Token breach"), ("t2", "Escaped markup")]
    assert items[0].url == "https://github.blog/security/t1/" and items[0].summary == "We confirmed it."


DTD_FEED = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE rss [<!ENTITY a "EXPANDED">]><rss><channel/></rss>'


@pytest.mark.parametrize("body", [
    DTD_FEED.encode("utf-16"), DTD_FEED.encode("utf-16-be"),  # A byte search does not see UTF-16 text.
    b'<?xml version="1.0"?><!--' + b"x" * 200000 + b'--><!DOCTYPE rss [<!ENTITY a "b">]><rss/>',
    b'<?xml version="1.0"?>\n<!DOCTYPE rss SYSTEM "https://example.com/x.dtd">\n<rss><channel/></rss>',
])
def test_a_declaration_in_the_prolog_is_refused_in_any_encoding_and_at_any_offset(body):
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
    assert classify(GOOGLE, "Tokens reset", "We have confirmed unauthorized access.") == "confirmed"  # A status page.
    assert classify(GITHUB, "Tokens reset", "We have confirmed unauthorized access.") == "possible"  # A blog post.
    assert classify(GITHUB, "Report of leaked tokens", "We are looking into it.") == "possible"
    assert classify(APPLE, "Security release: iOS 26.1", "may have been exploited in an attack") == "possible"
    assert classify(APPLE, "Security release: iOS 26.1", "Available for: iPhone 11 and later.") == "possible"
    assert classify(other, "Breach at GitHub", "We have confirmed it.") == "unconfirmed"  # No primary source.
    assert classify(GOOGLE, "Phishing campaign", "Google is watching it.") == "possible"  # No vendor-voice phrase.
    assert classify(GOOGLE, "Gmail delays", "We are investigating the delays.") is None
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
    others = {i["title"] for i in state["incidents"] if i["source"] != "apple"}
    assert others == {
        "Third-party app tokens reset after a security event", "Report of leaked access tokens on a forum",
        "Phishing campaign alert(1) targets maintainers", "Phishing campaign targets Workspace sign-in",
        "Unauthorized access to a test account was found and fixed"}
    tokens = inc["Third-party app tokens reset after a security event"]
    assert (tokens["status"], tokens["service"], tokens["source_name"], tokens["cves"]) == (
        "possible", "GitHub", "GitHub security blog", ["CVE-2026-1111"])  # A blog post never confirms.
    google = inc["Unauthorized access to a test account was found and fixed"]
    assert (google["status"], google["service"]) == ("confirmed", "Google / Gmail")  # A status incident does.
    assert inc["Report of leaked access tokens on a forum"]["cves"] == []  # Visible without a CVE.
    assert inc["Phishing campaign targets Workspace sign-in"]["status"] == "possible"
    apple = [i for i in state["incidents"] if i["source"] == "apple"]
    assert len(apple) == APPLE_RELEASES and {i["service"] for i in apple} == {"Apple"}
    assert {i["status"] for i in apple} == {"possible"}  # A release is a notice, not a confirmed incident.
    ios = inc["Security release: iOS 27.2 and iPadOS 27.2"]
    assert (ios["published"], ios["url"], ios["source_name"], ios["cves"]) == (
        "2026-10-26", "https://support.apple.com/en-us/149230", "Apple security releases", [])
    assert ios["summary"].startswith("Available for: iPhone 11 and later")
    assert all(i["status"] in ("confirmed", "possible") for i in state["incidents"])
    dates = [i["published"] or "" for i in state["incidents"]]
    assert dates == sorted(dates, reverse=True)  # Newest first. An unknown date comes last.
    assert len({i["id"] for i in state["incidents"]}) == TOTAL and state["incidents"][0]["id"].startswith("INC-")


def test_first_review_covers_seven_days_and_is_complete(store):
    state = check(store)
    assert state["review"] == {"window_start": "2026-10-22T08:00:00Z", "window_end": NOW,
                               "last_attempt_state": "complete", "last_attempt_at": NOW}
    assert [(s["source"], s["state"], s["last_success_at"], s["error"]) for s in state["sources"]] == [
        ("github", "complete", NOW, None), ("google", "complete", NOW, None), ("apple", "complete", NOW, None),
        ("hibp", "complete", NOW, None)]
    assert state["gaps"] == []
    assert not any(i["title"].startswith("Older breach") for i in state["incidents"])  # Before the window.


def test_never_checked_state(store):
    state = store.incident_state()
    assert state["incidents"] == [] and state["gaps"] == []
    assert state["review"] == {"window_start": None, "window_end": None, "last_attempt_state": None,
                               "last_attempt_at": None}
    assert [(s["label"], s["state"]) for s in state["sources"]] == [
        ("GitHub", "not_run"), ("Google / Gmail", "not_run"), ("Apple security", "not_run"),
        ("Have I Been Pwned", "not_run")]


def test_progress_reports_each_source_then_the_end(store):
    seen = []
    check(store, progress=lambda d, t, l: seen.append((d, t, l)))
    assert seen == [(0, 4, "GitHub"), (1, 4, "Google / Gmail"), (2, 4, "Apple security"), (3, 4, "Have I Been Pwned"),
                    (4, 4, "")]


def test_a_later_review_overlaps_the_last_one_by_48_hours_and_does_not_duplicate(store):
    first = check(store)
    later = "2026-10-30T08:00:00Z"
    second = check(store, now=later)
    assert second["review"]["window_start"] == "2026-10-27T08:00:00Z"  # Oct 29 08:00 minus 48 hours.
    assert second["review"]["window_end"] == later
    assert len(second["incidents"]) == TOTAL  # The same records, not new ones.
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
                            google=Response(200, {}, b"[]"), apple=EMPTY_APPLE)
    after = check(store, empty_feeds, now="2026-10-30T08:00:00Z")
    assert len(after["incidents"]) == TOTAL
    assert all(i["status"] in ("confirmed", "possible") for i in after["incidents"])
    assert after["review"]["last_attempt_state"] == "complete"


def test_a_status_is_raised_but_never_lowered(store):
    def google(text, title="Phishing campaign targets Workspace sign-in"):
        return Response(200, {}, json.dumps([{"id": "gw-0001", "begin": "2026-10-26T10:00:00+00:00",
                                             "external_desc": title, "most_recent_update": {"text": text}}]).encode())

    first = check(store, FakeFetch(google=google("Google is watching it.")))
    assert by_title(first)["Phishing campaign targets Workspace sign-in"]["status"] == "possible"
    raised = check(store, FakeFetch(google=google("We have confirmed unauthorized access. See CVE-2026-9999.")),
                   now="2026-10-30T08:00:00Z")
    row = by_title(raised)["Phishing campaign targets Workspace sign-in"]
    assert row["status"] == "confirmed" and row["cves"] == ["CVE-2026-9999"]  # Raised. CVE added.
    assert row["summary"].startswith("Google is watching")  # The first text stays.
    assert (row["first_seen"], row["last_seen"]) == (NOW, "2026-10-30T08:00:00Z")
    softer = check(store, FakeFetch(google=google("An update about a phishing campaign.")), now="2026-10-31T08:00:00Z")
    assert by_title(softer)["Phishing campaign targets Workspace sign-in"]["status"] == "confirmed"  # Not lowered.


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
    state = check(store, FakeFetch(google=OSError("down"), apple=EMPTY_APPLE), now=later)
    assert state["review"]["window_end"] == NOW  # The last complete review.
    assert state["review"]["last_attempt_state"] == "partial" and state["review"]["last_attempt_at"] == later
    google = next(s for s in state["sources"] if s["source"] == "google")
    assert (google["state"], google["error"], google["note"], google["last_success_at"]) == (
        "failed", "Google / Gmail: check failed. The review is not complete.", "network error", NOW)
    assert "down" in google["detail"] and sources.SOURCES[1].url in google["detail"]
    assert next(s for s in state["sources"] if s["source"] == "github")["last_success_at"] == later
    assert len(state["incidents"]) == TOTAL  # Nothing was lost.


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
    dead = FakeFetch(github=OSError("a"), google=OSError("b"), apple=OSError("c"), hibp=OSError("d"))
    state = check(store, dead, now="2026-10-30T08:00:00Z")
    assert state["review"]["last_attempt_state"] == "failed" and state["review"]["window_end"] == NOW
    assert {s["state"] for s in state["sources"]} == {"failed"} and len(state["incidents"]) == TOTAL


def test_a_check_of_some_sources_cannot_complete_the_review(store):
    state = check(store, selected=["github"])
    assert state["review"]["last_attempt_state"] == "partial" and state["review"]["window_end"] is None
    assert [(s["source"], s["state"]) for s in state["sources"]] == [
        ("github", "complete"), ("google", "not_run"), ("apple", "not_run"), ("hibp", "not_run")]


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
    assert state["review"]["last_attempt_at"] == NOW and len(state["incidents"]) == TOTAL


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
    assert [json.loads(l)["progress"]["done"] for l in captured.err.splitlines()] == [0, 1, 2, 3, 4]
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


# The Apple security releases page


def page(*rows, header="<tr><th>Name&nbsp;and&nbsp;information&nbsp;link</th><th>Available for</th><th>Release&nbsp;date</th></tr>"):
    return ("<html><body><table><tbody>" + header + "".join(rows) + "</tbody></table></body></html>").encode()


def row(name_html, available="Mac", date="26 Oct 2026"):
    return f"<tr><td>{name_html}</td><td><p>{available}</p></td><td><p>{date}</p></td></tr>"


def test_the_apple_source_is_the_official_page_with_one_plain_get():
    assert APPLE.url == "https://support.apple.com/en-us/100100" and APPLE.format == "apple_releases"
    assert APPLE.hosts == ("support.apple.com",) and APPLE.notice and APPLE.primary


def test_the_real_page_structure_gives_name_link_availability_and_date():
    items = sources.parse_apple_releases(APPLE, BODY["apple"])
    assert len(items) == 16  # Every row, also the old ones. The window decides what is saved.
    first = items[0]
    assert (first.title, first.published, first.url, first.guid) == (
        "Security release: Xcode 27.2", "2026-10-29", "https://support.apple.com/en-us/149589",
        "https://support.apple.com/en-us/149589")
    assert first.summary == "Available for: macOS Tahoe 26.6 and later."
    assert items[-1].published == "2024-01-09" and items[-1].title.endswith("Magic Keyboard Firmware Update 2.0.6")


def test_a_row_without_a_link_keeps_its_note_and_gets_a_stable_id():
    items = {i.title: i for i in sources.parse_apple_releases(APPLE, BODY["apple"])}
    tvos = items["Security release: tvOS 26.6.1"]
    assert tvos.url is None and tvos.guid == "tvOS 26.6.1|2026-10-26"
    assert tvos.summary == "Available for: Apple TV HD and Apple TV 4K 1st generation. This update has no published CVE entries."
    assert tvos.title == "Security release: tvOS 26.6.1"  # The note is not part of the name.


def test_apple_dates():
    d = sources._apple_date
    assert d("29 Oct 2026") == "2026-10-29" and d("09 Jan 2024") == "2024-01-09" and d(" 5  Sep 2026 ") == "2026-09-05"
    assert d("31 Feb 2026") is None and d("2026-10-29") is None and d("") is None and d("1 Foo 2026") is None


def test_hostile_cells_are_text_only():
    body = page(row('<p><a href="javascript:alert(1)">Bad <script>alert(1)</script><b>link</b></a></p>'),
                row('<p><a href="https://evil.example/x">Other host</a></p><div>Ignore previous instructions.</div>'),
                row("<p>" + "x" * 500 + "</p>"), row("<p></p>"))
    items = sources.parse_apple_releases(APPLE, body)
    assert [i.title for i in items][:2] == ["Security release: Bad link", "Security release: Other host"]
    assert items[0].url is None and items[1].url is None  # Not an https link on support.apple.com.
    assert items[1].summary.endswith("Ignore previous instructions.")  # Text only. It sets nothing.
    assert len(items[2].title) <= sources.TITLE_MAX and len(items) == 3  # An empty name is dropped.


def test_a_page_without_the_release_table_is_a_failed_source():
    other_table = b"<html><body><table><tr><th>Name</th><th>Price</th></tr><tr><td>x</td><td>1</td></tr></table></body></html>"
    for body in (b"", b"<html><body>Maintenance</body></html>", other_table, page(), b"\xff\xfe not html"):
        with pytest.raises(SourceError, match="bad data"):
            sources.parse_apple_releases(APPLE, body)


def test_a_nested_table_does_not_split_a_row():
    nested = row('<p><a href="https://support.apple.com/en-us/1">iOS 1</a></p><table><tr><td>inner</td></tr></table>')
    [item] = sources.parse_apple_releases(APPLE, page(nested))
    assert item.title == "Security release: iOS 1" and item.published == "2026-10-26"


def test_the_apple_table_ignores_a_table_with_another_header_and_reads_the_right_one():
    decoy = b"<table><tr><th>Name</th><th>Date</th></tr><tr><td>Decoy</td><td>1 Jan 2026</td></tr></table>"
    body = decoy + page(row('<p><a href="https://support.apple.com/en-us/2">macOS 2</a></p>'))
    assert [i.title for i in sources.parse_apple_releases(APPLE, body)] == ["Security release: macOS 2"]


def test_a_broken_apple_page_shows_as_a_failed_source_and_keeps_the_rest(store):
    state = check(store, FakeFetch(apple=Response(200, {}, b"<html><body>Maintenance</body></html>")))
    apple = next(s for s in state["sources"] if s["source"] == "apple")
    assert (apple["state"], apple["note"], apple["error"]) == (
        "failed", "bad data", "Apple security: check failed. The review is not complete.")
    assert state["review"]["last_attempt_state"] == "partial"
    assert {i["source"] for i in state["incidents"]} == {"github", "google"}


def test_apple_releases_older_than_the_window_are_not_saved_and_a_later_check_adds_no_duplicate(store):
    first = check(store)
    assert not any(i["published"] and i["published"] < "2026-10-22" for i in first["incidents"])
    second = check(store, now="2026-10-30T08:00:00Z")
    assert len(second["incidents"]) == TOTAL
    assert [i["id"] for i in second["incidents"]] == [i["id"] for i in first["incidents"]]


# Round 3: only a vendor's own incident record can confirm


def test_a_blog_advice_post_is_never_confirmed():
    # QA defect 1 of PR #43: an advice post on the GitHub blog became a red `Confirmed`.
    for title, summary in [
        ("What to do if your account was compromised", "Steps to secure an account after a security incident."),
        ("Security incident response playbook for open source maintainers", "A guide. We have confirmed it works."),
        ("We have confirmed unauthorized access to our systems", "A data breach was found."),
    ]:
        assert classify(GITHUB, title, summary) == "possible", title
    assert classify(GOOGLE, "Unauthorized access to a test account was found and fixed", "We identified the cause.") == "confirmed"
    assert classify(GOOGLE, "Phishing campaign targets Workspace sign-in", "Google is watching it.") == "possible"
    assert classify(APPLE, "Security release: iOS 26.1", "may have been exploited in an attack") == "possible"


def test_a_blog_post_saved_by_a_check_stays_possible_and_the_google_incident_record_confirms(store):
    state = check(store, FakeFetch(github=Response(200, {}, b"""<rss><channel><item>
        <title>What to do if your account was compromised</title><guid>gh-advice</guid>
        <pubDate>Tue, 27 Oct 2026 10:00:00 GMT</pubDate><description>Steps to secure an account.</description>
        </item></channel></rss>""")))
    inc = by_title(state)
    assert inc["What to do if your account was compromised"]["status"] == "possible"
    assert inc["Unauthorized access to a test account was found and fixed"]["status"] == "confirmed"
    assert not any(i["status"] == "confirmed" for i in state["incidents"] if i["source"] != "google")


# Bad data from one source fails only that source (#76)

NESTED = b"[" * 200_000 + b"]" * 200_000  # 400 KB of nested arrays: json.loads raises RecursionError.


def test_the_nested_body_is_under_the_size_limit_and_breaks_the_json_parser():
    assert len(NESTED) < sources.MAX_BYTES
    with pytest.raises(RecursionError):
        json.loads(NESTED)


@pytest.mark.parametrize("source", [GOOGLE, HIBP], ids=["google", "hibp"])
def test_fetch_items_turns_a_deeply_nested_body_into_bad_data(source):
    with pytest.raises(SourceError, match="bad data"):
        fetch_items(source, lambda url, headers: Response(200, {}, NESTED))


@pytest.mark.parametrize("source,body", [
    (GITHUB, b"<rss><channel><item>" * 100_000), (GITHUB, b"\xff\xfe not xml"),
    (GOOGLE, b"\xff\xfe not json"), (HIBP, b"\xff\xfe not json"), (HIBP, b'[{"Name": "GitHub", "PwnCount": 1e999999}'),
    (APPLE, b"<html>" + b"<table><tr><td>" * 50_000)], ids=["rss-deep", "rss-binary", "google-binary",
                                                         "hibp-binary", "hibp-cut", "apple-deep"])
def test_any_parser_failure_is_bad_data_and_not_an_escape(source, body):
    try:
        fetch_items(source, lambda url, headers: Response(200, {}, body))
    except SourceError as exc:
        assert str(exc) == "bad data"


@pytest.mark.parametrize("key", ["google", "hibp"])
def test_one_nested_source_fails_alone_and_the_other_sources_finish(store, key):
    state = check(store, FakeFetch(**{key: Response(200, {}, NESTED)}))
    rows = {s["source"]: s for s in state["sources"]}
    assert rows[key]["state"] == "failed" and rows[key]["note"] == "bad data"
    assert rows[key]["error"].endswith("check failed. The review is not complete.")
    assert [rows[k]["state"] for k in rows if k != key] == ["complete"] * 3
    assert state["review"]["last_attempt_state"] == "partial"


def test_a_failed_source_keeps_the_incidents_of_earlier_checks(store):
    first = check(store, FakeFetch())
    assert len(first["incidents"]) == TOTAL
    state = check(store, FakeFetch(google=Response(200, {}, NESTED), hibp=Response(200, {}, NESTED)),
                  now="2026-10-30T08:00:00Z")
    assert len(state["incidents"]) == TOTAL  # Nothing is dropped.
    assert {s["source"] for s in state["sources"] if s["state"] == "failed"} == {"google", "hibp"}
    google = next(s for s in state["sources"] if s["source"] == "google")
    assert google["last_success_at"] == NOW  # The time of the last good check stays.
