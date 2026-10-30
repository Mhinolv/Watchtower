"""Have I Been Pwned breach list in Incidents (#60). Fixtures only: no network, no account data."""
import json
import re
from pathlib import Path

import pytest

from watchtower_engine.feeds.homebrew import Response
from watchtower_engine.research import records
from watchtower_engine.research.sources import HIBP_URL, SOURCES, SourceError, fetch_items, parse_hibp, watched_service
from watchtower_engine.store import Store

FIX = Path(__file__).parent / "fixtures" / "incidents"
REAL = (FIX / "hibp-breaches-excerpt.json").read_bytes()
SYNTHETIC = (FIX / "hibp-breaches-watched-synthetic.json").read_bytes()
HIBP = next(s for s in SOURCES if s.key == "hibp")
NOW, LATER = "2026-10-29T08:00:00Z", "2026-10-30T08:00:00Z"


class FakeFetch:
    """Answers every source. The HIBP answer is set by the test. Never uses the network."""

    def __init__(self, hibp=SYNTHETIC):
        self.hibp, self.calls = hibp, []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        if url != HIBP_URL:
            return Response(200, {}, b"[]")  # The other sources have no records here.
        if isinstance(self.hibp, BaseException):
            raise self.hibp
        return self.hibp if isinstance(self.hibp, Response) else Response(200, {}, self.hibp)


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "data") as s:
        yield s


def check(store, fetch, now=NOW):
    return records.run_check(store.db, now=lambda: now, fetch=fetch, selected=["hibp"])


def breaches(state):
    return {i["title"]: i for i in state["incidents"] if i["source"] == "hibp"}


# The request


def test_the_request_is_one_get_of_the_public_list_with_nothing_else(store):
    fetch = FakeFetch()
    check(store, fetch)
    assert fetch.calls == [(HIBP_URL, {"User-Agent": fetch.calls[0][1]["User-Agent"],
                                       "Accept": "application/rss+xml, application/json, */*"})]
    assert HIBP_URL == "https://haveibeenpwned.com/api/v3/breaches"
    assert "?" not in HIBP_URL and "@" not in HIBP_URL and fetch.calls[0][1]["User-Agent"].startswith("Watchtower/")


def test_no_fixture_holds_an_email_address_or_an_account_name():
    for name in ("hibp-breaches-excerpt.json", "hibp-breaches-watched-synthetic.json"):
        assert "@" not in (FIX / name).read_text()


# Which breaches count


def test_the_real_list_has_no_breach_for_a_watched_service_and_the_gmail_dump_of_a_forum_is_not_gmail():
    names = [b["Name"] for b in json.loads(REAL)]
    assert "BTSec" in names  # Title: `Bitcoin Security Forum Gmail Dump`.
    assert parse_hibp(HIBP, REAL) == []


@pytest.mark.parametrize("domain,name,title,service", [
    ("github.com", "x", "x", "GitHub"), ("gist.github.com", "x", "x", "GitHub"), ("GitHub.com.", "x", "x", "GitHub"),
    ("", "GitHub", "x", "GitHub"), ("", "x", " github ", "GitHub"),
    ("google.com", "x", "x", "Google / Gmail"), ("accounts.google.com", "x", "x", "Google / Gmail"),
    ("gmail.com", "x", "x", "Google / Gmail"), ("googlemail.com", "x", "x", "Google / Gmail"),
    ("", "Gmail", "x", "Google / Gmail"), ("", "x", "Google", "Google / Gmail"),
    ("notgithub.com", "x", "x", None), ("github.com.evil.example", "x", "x", None), ("forum.btcsec.com", "BTSec",
     "Bitcoin Security Forum Gmail Dump", None), ("", "GitHub Pages Clone", "x", None), (None, None, None, None),
    (5, 5, 5, None)])
def test_the_rules_match_a_domain_or_an_exact_name(domain, name, title, service):
    assert watched_service(domain, name, title) == service


def test_only_the_watched_breaches_are_kept_with_their_details():
    items = {i.guid: i for i in parse_hibp(HIBP, SYNTHETIC)}
    assert sorted(items) == ["GitHub", "GmailSample", "GoogleSample", "OldAdded"]
    gh = items["GitHub"]
    assert (gh.service, gh.title, gh.published, gh.window_date, gh.status) == (
        "GitHub", "GitHub data breach", "2026-10-20", "2026-10-27", "possible")
    assert gh.breach == {"breach_date": "2026-10-20", "added_date": "2026-10-27",
                         "data_classes": ["Email addresses", "Passwords"], "pwn_count": 1200000,
                         "domain": "github.com", "verified": True}
    assert gh.url == "https://haveibeenpwned.com/PwnedWebsites#GitHub"


def test_a_breach_that_is_not_verified_or_is_fabricated_is_unconfirmed_and_none_is_confirmed():
    items = {i.guid: i for i in parse_hibp(HIBP, SYNTHETIC)}
    assert items["GoogleSample"].status == "unconfirmed" and items["GoogleSample"].service == "Google / Gmail"
    assert items["GmailSample"].status == "unconfirmed"  # Fabricated.
    assert all(i.status != "confirmed" for i in items.values())


def test_the_list_is_untrusted_text_only():
    rows = json.loads(SYNTHETIC)
    rows[0]["Description"] = "<script>alert(1)</script><b>Bold</b> \x00 text " + "x" * 2000
    rows[0]["PwnCount"] = True
    rows[0]["DataClasses"] = ["Email addresses", 5, "<i>Names</i>", ""]
    rows[0]["Domain"] = "github.com"
    rows[0]["Name"] = "Git/Hub #1"
    rows[0]["BreachDate"], rows[0]["AddedDate"] = "not a date", None
    rows.insert(0, "a string")
    [gh] = [i for i in parse_hibp(HIBP, json.dumps(rows).encode()) if i.service == "GitHub" and i.guid != "OldAdded"][:1]
    assert "<" not in gh.summary and "\x00" not in gh.summary and len(gh.summary) <= 600
    assert gh.breach["pwn_count"] is None and gh.breach["data_classes"] == ["Email addresses", "Names"]
    assert (gh.published, gh.window_date) == (None, None)
    assert gh.url == "https://haveibeenpwned.com/PwnedWebsites#Git%2FHub%20%231"


@pytest.mark.parametrize("body", [b"not json", b'{"a": 1}', b'"x"'])
def test_a_body_that_is_not_a_list_is_refused(body):
    with pytest.raises(SourceError, match="bad data"):
        parse_hibp(HIBP, body)


def test_a_too_large_body_is_refused():
    with pytest.raises(SourceError, match="too large"):
        fetch_items(HIBP, lambda url, headers: Response(200, {}, b" " * (5 * 1024 * 1024 + 1)))


# The Incidents table


def test_breach_rows_join_the_table_sorted_by_the_day_hibp_added_them(store):
    state = check(store, FakeFetch())
    rows = breaches(state)
    assert sorted(rows) == ["GitHub data breach", "Gmail data breach", "Google account sample data breach"]
    assert [i["service"] for i in state["incidents"]] == ["GitHub", "Google / Gmail", "Google / Gmail"]
    assert [i["breach"]["added_date"] for i in state["incidents"]] == ["2026-10-27", "2026-10-27", "2026-10-25"]
    assert [i["status"] for i in state["incidents"]] == ["possible", "unconfirmed", "unconfirmed"]
    assert {i["source_name"] for i in state["incidents"]} == {"Have I Been Pwned"}


def test_a_breach_added_before_the_review_window_is_not_listed(store):
    assert "GitHub old data breach" not in breaches(check(store, FakeFetch()))


def test_the_hibp_source_row_has_its_state_and_retrieval_time(store):
    state = check(store, FakeFetch())
    row = next(s for s in state["sources"] if s["source"] == "hibp")
    assert (row["label"], row["state"], row["last_success_at"], row["error"]) == (
        "Have I Been Pwned", "complete", NOW, None)


def test_a_row_is_new_only_in_the_check_that_saved_it(store):
    first = check(store, FakeFetch(), NOW)
    assert not any(i["is_new"] for i in first["incidents"])  # The first check makes every row new: no label.
    more = json.loads(SYNTHETIC) + [dict(json.loads(SYNTHETIC)[0], Name="GitHub2", Title="GitHub second",
                                         AddedDate="2026-10-30T01:00:00Z")]
    second = check(store, FakeFetch(json.dumps(more).encode()), LATER)
    new = {i["title"]: i["is_new"] for i in second["incidents"]}
    assert new["GitHub second data breach"] is True and new["GitHub data breach"] is False
    third = check(store, FakeFetch(json.dumps(more).encode()), "2026-10-31T08:00:00Z")
    assert not any(i["is_new"] for i in third["incidents"])


def test_a_failed_fetch_keeps_the_earlier_rows_and_shows_the_failure(store):
    check(store, FakeFetch(), NOW)
    state = check(store, FakeFetch(OSError("down")), LATER)
    assert len(breaches(state)) == 3
    row = next(s for s in state["sources"] if s["source"] == "hibp")
    assert (row["state"], row["last_success_at"], row["note"]) == ("failed", NOW, "network error")
    assert row["error"] == "Have I Been Pwned: check failed. The review is not complete."
    assert state["review"]["last_attempt_state"] == "failed"  # No source finished in this check.


def test_an_error_status_is_a_failure_with_a_short_reason(store):
    state = check(store, FakeFetch(Response(503, {}, b"")))
    row = next(s for s in state["sources"] if s["source"] == "hibp")
    assert (row["state"], row["note"]) == ("failed", "HTTP 503")
    assert breaches(state) == {}


def test_a_list_with_no_watched_breach_gives_a_complete_check_and_no_rows(store):
    state = check(store, FakeFetch(REAL))
    row = next(s for s in state["sources"] if s["source"] == "hibp")
    assert row["state"] == "complete" and breaches(state) == {}


def test_an_old_store_gets_the_breach_column(tmp_path):
    import sqlite3
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript("CREATE TABLE incidents (seq INTEGER PRIMARY KEY, source TEXT, guid TEXT, service TEXT, title TEXT, "
                     "summary TEXT, published TEXT, status TEXT, source_name TEXT, url TEXT, cves TEXT, first_seen TEXT, "
                     "last_seen TEXT);")
    records.migrate(db)
    assert "breach" in {r["name"] for r in db.execute("PRAGMA table_info(incidents)")}
