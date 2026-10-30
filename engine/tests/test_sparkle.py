import json
import os
import stat
from pathlib import Path

import pytest

from watchtower_engine.inventory import apps, sparkle
from watchtower_engine.inventory.sparkle import (
    NOTE_CREDENTIALS, NOTE_LOCAL, NOTE_NOT_HTTPS, NOTE_UPDATE, Target, check, parse_appcast, url_problem,
)
from watchtower_engine.models import CoverageRecord as C
from watchtower_engine.models import ItemRecord as I
from watchtower_engine.refresh import Source, run_refresh
from watchtower_engine.store import Store

from contract import Clock
from test_apps import make_app

FIX = Path(__file__).parent / "fixtures" / "sparkle"
FEED = "https://example.com/appcast.xml"
T1, T2 = "2026-10-28T09:12:00Z", "2026-10-29T09:12:00Z"


def appcast(name):
    return (FIX / name).read_bytes()


class FakeFetch:
    """Answers by URL with bytes or raises. Never uses the network."""

    def __init__(self, answers=None):
        self.answers, self.calls = answers or {}, []

    def __call__(self, url):
        self.calls.append(url)
        answer = self.answers.get(url, OSError("network is disabled in tests"))
        if isinstance(answer, BaseException):
            raise answer
        return answer


def app_item(installed="3.3.0", name="Quillnote"):
    return I(f"com.example.{name.lower()}", "apps", name, "manual", kind="app", installed_version=installed,
             origin="Manual", note="Update this app from its vendor.", attributes={"path": f"/Applications/{name}.app"})


def run(targets, data, fetch, now=T2, os_version="15.1"):
    return check(targets, data, fetch=fetch, now=lambda: now, os_version=os_version)


# URL rules


@pytest.mark.parametrize("url,problem", [
    ("https://example.com/appcast.xml", None),
    ("https://example.com/appcast.xml?channel=beta", None),
    ("http://example.com/appcast.xml", NOTE_NOT_HTTPS),
    ("ftp://example.com/appcast.xml", NOTE_NOT_HTTPS),
    ("appcast.xml", NOTE_NOT_HTTPS),
    ("https://user:secret@example.com/appcast.xml", NOTE_CREDENTIALS),
    ("https://token@example.com/appcast.xml", NOTE_CREDENTIALS),
    ("https://example.com/appcast.xml?token=abc", NOTE_CREDENTIALS),
    ("https://example.com/appcast.xml?api_key=abc&x=1", NOTE_CREDENTIALS),
    ("https://localhost/appcast.xml", NOTE_LOCAL),
    ("https://127.0.0.1/appcast.xml", NOTE_LOCAL),
    ("https://10.0.0.5/appcast.xml", NOTE_LOCAL),
    ("https://192.168.1.2:8443/appcast.xml", NOTE_LOCAL),
    ("https://[::1]/appcast.xml", NOTE_LOCAL),
    ("https://169.254.169.254/latest", NOTE_LOCAL),
    ("https://nas.local/appcast.xml", NOTE_LOCAL),
])
def test_url_rules(url, problem):
    assert url_problem(url) == problem


def test_credentials_are_never_shown():
    assert sparkle.shown_url("https://user:secret@example.com/a.xml") is None
    assert sparkle.shown_url("https://example.com/a.xml?token=x") is None
    assert sparkle.shown_url(FEED) == FEED


def test_redirect_to_an_unsafe_address_is_refused():
    handler = sparkle._SafeRedirects()
    with pytest.raises(Exception):
        handler.redirect_request(None, None, 302, "Found", {}, "http://example.com/appcast.xml")
    with pytest.raises(Exception):
        handler.redirect_request(None, None, 302, "Found", {}, "https://127.0.0.1/appcast.xml")


# Parse (untrusted XML)


def test_parse_reads_version_build_minimum_os_and_channel():
    releases = parse_appcast(appcast("stable.xml"))
    assert [(r.version, r.build, r.minimum_os, r.channel) for r in releases] == [
        ("3.4.1", "341", "14.0", None),
        ("3.3.0", "330", None, None),  # from the enclosure attributes
    ]  # the Windows release is left out
    beta = parse_appcast(appcast("beta.xml"))
    assert [(r.version, r.channel) for r in beta] == [("3.4.1", None), ("3.5b1", "beta")]


@pytest.mark.parametrize("data", [
    b"<rss><channel><item><title>no version</title></item></channel></rss>",
    b"not xml at all",
    b"<rss><channel>",
])
def test_parse_refuses_documents_without_a_release(data):
    with pytest.raises(ValueError):
        parse_appcast(data)


def test_parse_refuses_dtd_and_entities():
    with pytest.raises(ValueError, match="DTD or entities"):
        parse_appcast(appcast("entities.xml"))


# Compare


def test_newer_stable_is_update_available(tmp_path):
    item = app_item("3.3.0")
    result = run([Target(item, FEED, "330")], tmp_path, FakeFetch({FEED: appcast("stable.xml")}))
    assert (item.state, item.latest_version, item.origin) == ("update_available", "3.4.1", "Sparkle feed")
    assert item.note == NOTE_UPDATE == "Use the app's Check for Updates command to install it."
    assert item.attributes["sparkleFeed"] == FEED
    assert item.attributes["sparkleLatest"] == "3.4.1 (341)"
    assert item.attributes["sparkleChannel"] == "Stable"
    assert item.attributes["sparkleMinimumOs"] == "14.0"
    assert item.attributes["sparkleChecked"] == T2
    assert result.coverage == C("sparkle", "Sparkle feeds", "complete", note="1 of 1 read")


def test_same_build_is_up_to_date(tmp_path):
    item = app_item("3.4.1")
    run([Target(item, FEED, "341")], tmp_path, FakeFetch({FEED: appcast("stable.xml")}))
    assert (item.state, item.latest_version, item.note) == ("up_to_date", "3.4.1", None)


def test_only_a_newer_beta_stays_up_to_date_with_a_note(tmp_path):
    item = app_item("3.4.1")
    run([Target(item, FEED, "341")], tmp_path, FakeFetch({FEED: appcast("beta.xml")}))
    assert (item.state, item.latest_version) == ("up_to_date", "3.4.1")
    assert item.note == "A beta (3.5b1) is available."


def test_newer_version_for_a_newer_macos_is_a_manual_update(tmp_path):
    item = app_item("3.3.0")
    run([Target(item, FEED, "330")], tmp_path, FakeFetch({FEED: appcast("newer-os.xml")}), os_version="15.1")
    assert item.state == "manual"
    assert item.note == "3.4.1 needs macOS 15.2. This Mac has 15.1."
    item2 = app_item("3.3.0")
    run([Target(item2, FEED, "330")], tmp_path, FakeFetch({FEED: appcast("newer-os.xml")}), os_version="15.2")
    assert item2.state == "update_available"


@pytest.mark.parametrize("url,note", [
    ("http://example.com/appcast.xml", "Watchtower reads HTTPS feeds only."),
    ("https://user:pw@example.com/appcast.xml", "The feed address has credentials. Watchtower did not read it."),
    ("https://127.0.0.1/appcast.xml", NOTE_LOCAL),
])
def test_rejected_feed_is_unknown_and_never_fetched(tmp_path, url, note):
    item = app_item()
    fetch = FakeFetch()
    result = run([Target(item, url, "330")], tmp_path, fetch)
    assert (item.state, item.note) == ("unknown", note)
    assert fetch.calls == []
    if note == NOTE_CREDENTIALS:
        assert "sparkleFeed" not in item.attributes
    assert result.coverage.note == "0 of 1 read"


def test_failed_check_keeps_the_previous_evidence(tmp_path):
    first = app_item("3.3.0")
    run([Target(first, FEED, "330")], tmp_path, FakeFetch({FEED: appcast("stable.xml")}), now=T1)
    again = app_item("3.3.0")
    result = run([Target(again, FEED, "330")], tmp_path, FakeFetch(), now=T2)  # the feed fails
    assert (again.state, again.latest_version) == ("update_available", "3.4.1")  # earlier badge and version
    assert again.error == "Feed check failed."
    assert again.attributes["sparkleChecked"] == T1  # data from the earlier check
    assert result.coverage.state == "failed" and result.coverage.note == "0 of 1 read"
    assert "network is disabled" in result.coverage.detail


def test_failed_check_with_no_earlier_data_keeps_the_manual_route(tmp_path):
    item = app_item("3.3.0")
    run([Target(item, FEED, "330")], tmp_path, FakeFetch())
    assert (item.state, item.origin, item.latest_version) == ("manual", "Manual", None)
    assert item.error == "Feed check failed."


def test_bad_appcast_is_a_failed_check(tmp_path):
    item = app_item("3.3.0")
    run([Target(item, FEED, "330")], tmp_path, FakeFetch({FEED: appcast("entities.xml")}))
    assert item.error == "Feed check failed." and "DTD" in item.detail


def test_coverage_counts_feeds_read(tmp_path):
    other = "https://example.org/feed.xml"
    targets = [Target(app_item(name="A"), FEED, "330"), Target(app_item(name="B"), other, "330"),
               Target(app_item(name="C"), "http://example.net/x.xml", "330")]
    result = run(targets, tmp_path, FakeFetch({FEED: appcast("stable.xml")}))
    assert (result.coverage.state, result.coverage.note) == ("partial", "1 of 3 read")
    assert result.coverage.error == "Some Sparkle feeds did not load."
    assert run([], tmp_path, FakeFetch()).coverage.state == "not_run"


def test_cache_file_is_private(tmp_path):
    run([Target(app_item(), FEED, "330")], tmp_path, FakeFetch({FEED: appcast("stable.xml")}))
    path = tmp_path / "cache" / "sparkle.json"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert json.loads(path.read_text())["com.example.quillnote"]["build"] == "341"


# The app inventory


def test_app_inventory_checks_feeds_of_manual_apps_only(tmp_path):
    root = tmp_path / "Applications"
    make_app(root, "Quillnote.app", "com.example.quillnote", version="3.3.0", build="330",
             extra={"SUFeedURL": FEED})
    make_app(root, "Plain.app", "com.example.plain", version="1.0", build="100")
    fetch = FakeFetch({FEED: appcast("stable.xml")})
    result = apps.collect((str(root),), sparkle_check=lambda t: check(t, tmp_path / "data", fetch=fetch,
                                                                       now=lambda: T2, os_version="15.1"))
    items = {i.name: i for i in result.items}
    assert (items["Quillnote"].state, items["Quillnote"].latest_version) == ("update_available", "3.4.1")
    assert (items["Plain"].state, items["Plain"].origin) == ("manual", "Manual")  # v1 manual route
    assert fetch.calls == [FEED]
    assert [c.source for c in result.extra_coverage] == ["sparkle"]


def test_without_a_check_the_inventory_is_unchanged(tmp_path):
    root = tmp_path / "Applications"
    make_app(root, "Quillnote.app", "com.example.quillnote", version="3.3.0", build="330",
             extra={"SUFeedURL": FEED})
    result = apps.collect((str(root),))
    assert result.items[0].state == "manual" and not hasattr(result, "extra_coverage")


def test_cask_linked_app_with_a_version_is_not_checked(tmp_path):
    root = tmp_path / "Applications"
    make_app(root, "Fluff.app", "com.example.fluff", version="1.2", build="100", extra={"SUFeedURL": FEED})
    cask = {"token": "fluff", "installed": "1.2", "artifacts": [{"app": ["Fluff.app"]}]}
    cask_item = I("cask:fluff", "homebrew", "fluff", "update_available", kind="cask", installed_version="1.2",
                  latest_version="1.3")
    fetch = FakeFetch({FEED: appcast("stable.xml")})
    result = apps.collect((str(root),), [cask], [cask_item],
                          sparkle_check=lambda t: check(t, tmp_path / "data", fetch=fetch))
    assert result.items[0].latest_version == "1.3" and fetch.calls == []


def test_refresh_saves_the_sparkle_coverage(tmp_path):
    from watchtower_engine.inventory.homebrew import SourceResult

    def apps_source():
        r = SourceResult(C("apps", "Applications", "complete"), [app_item()])
        r.extra_coverage = [C("sparkle", "Sparkle feeds", "complete", note="1 of 1 read")]
        return r

    with Store(tmp_path, clock=Clock(*[f"2026-10-29T10:{m:02d}:00Z" for m in range(10)])) as s:
        state = run_refresh(s, [Source("apps", "Applications", apps_source)])
    cov = {c["source"]: c for c in state["coverage"]}
    assert cov["sparkle"]["note"] == "1 of 1 read" and cov["sparkle"]["state"] == "complete"
