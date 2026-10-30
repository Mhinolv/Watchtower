"""#58: SOFA feeds for macOS and Safari. Real excerpts of the v2 feeds, a fake fetch, no network."""
import json
import os
import stat
from pathlib import Path

import pytest

from watchtower_engine import refresh
from watchtower_engine.feeds import sofa
from watchtower_engine.feeds.homebrew import Response
from watchtower_engine.feeds.sofa import (ERROR_FAILED, MACOS_URL, NOTE_NOT_IN_FEED, SAFARI_URL, check, compare,
                                          parse)
from watchtower_engine.inventory import apps, macos
from watchtower_engine.inventory.homebrew import SourceResult
from watchtower_engine.models import CoverageRecord, ItemRecord
from watchtower_engine.refresh import run_refresh
from watchtower_engine.store import Store

FIX = Path(__file__).parent / "fixtures" / "sofa"
MACOS = (FIX / "macos_data_feed.json").read_bytes()
SAFARI = (FIX / "safari_data_feed.json").read_bytes()
T1, T2 = "2026-10-29T08:00:00Z", "2026-10-30T08:00:00Z"


class FakeFetch:
    def __init__(self, answers=None):
        self.answers = answers if answers is not None else {MACOS_URL: Response(200, {}, MACOS),
                                                            SAFARI_URL: Response(200, {}, SAFARI)}
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        answer = self.answers.get(url, OSError("offline"))
        if isinstance(answer, BaseException):
            raise answer
        return answer


def mac(version="15.7.9", build="24G830"):
    return ItemRecord("macos", "macos", "macOS", "manual", kind="os", installed_version=version,
                      note="Update macOS in System Settings.", attributes={"build": build} if build else {})


def safari(version="26.6.1"):
    return ItemRecord("com.apple.Safari", "apps", "Safari", "manual", kind="app", installed_version=version,
                      attributes={"bundleId": "com.apple.Safari", "path": "/Applications/Safari.app"})


def run(items, data_dir, fetch=None, now=T1):
    return check(items, data_dir, fetch=fetch or FakeFetch(), now=lambda: now)


# Parse


def test_parse_reads_the_real_macos_feed_structure():
    tracks = parse(MACOS, "OSVersions")
    assert sorted(tracks) == [15, 26]
    sequoia = tracks[15]
    assert (sequoia.latest.version, sequoia.latest.builds, sequoia.latest.released) == ("15.8.2", ["24H232"],
                                                                                         "2026-10-26")
    fixed = {r.version: r for r in sequoia.releases}
    assert fixed["15.8.1"].exploited == ["CVE-2026-86950"]
    assert fixed["15.8"].builds == ["24H23"]
    assert fixed["15.7.7"].builds == []  # The feed has an empty build for this release.


def test_parse_reads_the_real_safari_feed_structure():
    tracks = parse(SAFARI, "AppVersions")
    assert sorted(tracks) == [26, 27]
    assert tracks[27].latest.exploited == ["CVE-2026-112626"]
    assert tracks[26].latest.version == "26.6.1"


@pytest.mark.parametrize("body", [b"[]", b"{}", b'{"OSVersions": 3}', b'{"OSVersions": [{"Latest": {}}]}',
                                  b"not json"])
def test_parse_refuses_a_body_that_is_not_a_sofa_feed(body):
    with pytest.raises(ValueError):
        parse(body, "OSVersions")


def test_parse_refuses_a_large_body(monkeypatch):
    monkeypatch.setattr(sofa, "MAX_BYTES", 100)
    with pytest.raises(ValueError, match="larger"):
        parse(MACOS, "OSVersions")


def test_parse_keeps_only_well_formed_values():
    feed = {"OSVersions": [{"Latest": {"ProductVersion": "15.2", "Build": "24C101", "ReleaseDate": "2026-01-01T00:00:00Z"},
                            "SecurityReleases": [
                                {"ProductVersion": "15.2", "Build": "24C101",
                                 "CVEs": {"CVE-2026-0001": {}, "<script>": {}, "CVE-2026-0002": {"ActivelyExploited": True}},
                                 "ActivelyExploitedCVEs": ["CVE-2026-0003", 7, "not a cve"]},
                                {"ProductVersion": "15.1; rm -rf /", "Build": "x"},
                                {"ProductVersion": "15.1", "Build": "bad build!", "AllBuilds": ["24B91", {}]},
                                "not a row"]}]}
    track = parse(json.dumps(feed).encode(), "OSVersions")[15]
    assert [r.version for r in track.releases] == ["15.2", "15.1"]
    assert track.releases[0].cves == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
    assert track.releases[0].exploited == ["CVE-2026-0002", "CVE-2026-0003"]
    assert track.releases[1].builds == ["24B91"]


# Compare (on this Mac)


def test_compare_lists_the_newer_releases_and_their_cves():
    verdict = compare(parse(MACOS, "OSVersions")[15], "15.7.9", "24G830")
    assert verdict.known
    assert [r.version for r in verdict.newer] == ["15.8.2", "15.8.1", "15.8"]
    assert verdict.exploited == ["CVE-2026-86950"]
    assert "CVE-2026-86950" in verdict.fixed and "CVE-2026-65400" not in verdict.fixed


def test_compare_treats_15_0_and_15_as_the_same_version():
    track = parse(json.dumps({"OSVersions": [{"Latest": {"ProductVersion": "15.0"},
                                              "SecurityReleases": [{"ProductVersion": "15.0"}]}]}).encode(),
                  "OSVersions")[15]
    assert compare(track, "15").known and compare(track, "15").newer == []


def test_a_build_that_is_not_in_the_feed_is_unknown():
    track = parse(MACOS, "OSVersions")[15]
    assert not compare(track, "15.9", "24J5040a").known
    assert compare(track, "15.7.9", "24G830").known
    assert compare(track, "15.7.8", None).known  # By version, if there is no build.


# Items


def test_macos_behind_with_an_exploited_cve_is_vulnerable(tmp_path):
    item = mac()
    coverage = run([item], tmp_path)
    assert coverage.state == "complete" and coverage.source_at == T1
    assert (item.state, item.latest_version, item.origin) == ("vulnerable", "15.8.2", "SOFA")
    assert item.note == "15.8.2 fixes 1 actively exploited CVE."
    a = item.attributes
    assert (a["sofaLatest"], a["sofaReleased"], a["sofaExploited"], a["sofaChecked"]) == (
        "15.8.2 (24H232)", "2026-10-26", "CVE-2026-86950", T1)
    assert "CVE-2026-86950" in a["sofaFixedCves"].split(", ")
    assert a["build"] == "24G830" and item.error is None


def test_macos_behind_without_an_exploited_cve_is_update_available(tmp_path):
    item = mac("15.8.1", "24H32")
    run([item], tmp_path)
    count = len(item.attributes["sofaFixedCves"].split(", "))
    assert item.state == "update_available"
    assert item.note == f"macOS 15.8.2 fixes {count} CVEs."
    assert "sofaExploited" not in item.attributes


def test_current_macos_is_up_to_date(tmp_path):
    item = mac("15.8.2", "24H232")
    run([item], tmp_path)
    assert (item.state, item.note) == ("up_to_date", None)
    assert "sofaFixedCves" not in item.attributes


def test_a_beta_build_is_unknown(tmp_path):
    item = mac("15.9", "24J5040a")
    run([item], tmp_path)
    assert (item.state, item.note) == ("unknown", NOTE_NOT_IN_FEED)


def test_a_major_version_that_is_not_in_the_feed_is_unknown(tmp_path):
    item = mac("12.7.6", "21H1320")  # The excerpt has 15 and 26 only.
    run([item], tmp_path)
    assert (item.state, item.note) == ("unknown", NOTE_NOT_IN_FEED)


def test_a_rapid_security_response_compares_by_its_version(tmp_path):
    item = mac("15.8.2 (a)", "24H232a")
    run([item], tmp_path)
    assert item.state == "up_to_date"


def test_safari_behind_is_update_available_within_its_major_version(tmp_path):
    item = safari("26.5.2")
    run([item], tmp_path)
    assert (item.state, item.latest_version, item.origin) == ("update_available", "26.6.1", "SOFA")
    assert item.note.startswith("Safari 26.6.1 fixes ")
    assert item.attributes["sofaLatest"] == "26.6.1"
    assert item.attributes["path"] == "/Applications/Safari.app"


def test_current_safari_is_up_to_date(tmp_path):
    item = safari("26.6.1")
    run([item], tmp_path)
    assert item.state == "up_to_date"


def test_other_items_are_not_changed(tmp_path):
    other = ItemRecord("com.apple.SafariTechnologyPreview", "apps", "Safari Technology Preview", "manual",
                       installed_version="230", attributes={"bundleId": "com.apple.SafariTechnologyPreview"})
    run([other], tmp_path)
    assert (other.state, other.origin, other.attributes) == ("manual", None,
                                                              {"bundleId": "com.apple.SafariTechnologyPreview"})


# Requests


def test_the_requests_send_nothing_about_this_mac(tmp_path):
    fetch = FakeFetch()
    run([mac(), safari()], tmp_path, fetch)
    assert [u for u, _ in fetch.calls] == [MACOS_URL, SAFARI_URL]
    for _, headers in fetch.calls:
        assert set(headers) == {"User-Agent", "Accept"}
        assert "15.7.9" not in json.dumps(headers) and "Safari.app" not in json.dumps(headers)


# Failure


def test_a_failed_feed_keeps_the_earlier_data_and_is_partial(tmp_path):
    run([mac()], tmp_path, now=T1)
    item = mac()
    fetch = FakeFetch({SAFARI_URL: Response(200, {}, SAFARI)})  # The macOS feed fails.
    coverage = run([item], tmp_path, fetch, now=T2)
    assert (coverage.state, coverage.source_at, coverage.error) == ("partial", T1, sofa.ERROR_SOME)
    assert "offline" in coverage.detail
    assert (item.state, item.latest_version) == ("vulnerable", "15.8.2")
    assert item.attributes["sofaChecked"] == T1 and item.source_at == T1
    assert item.error == ERROR_FAILED


def test_a_failed_feed_without_earlier_data_leaves_the_item_and_fails(tmp_path):
    item = mac()
    coverage = run([item], tmp_path, FakeFetch({}))
    assert coverage.state == "failed" and coverage.error == ERROR_FAILED
    assert (item.state, item.origin, item.latest_version) == ("manual", None, None)
    assert item.error == ERROR_FAILED


@pytest.mark.parametrize("response", [Response(500, {}, b""), Response(200, {}, b"<html>")])
def test_a_bad_answer_counts_as_a_failure(tmp_path, response):
    coverage = run([mac()], tmp_path, FakeFetch({MACOS_URL: response, SAFARI_URL: Response(200, {}, SAFARI)}))
    assert coverage.state == "partial"


def test_the_cache_file_is_private_and_a_corrupt_cache_is_ignored(tmp_path):
    run([mac()], tmp_path)
    path = tmp_path / "cache" / "sofa" / "feeds.json"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    path.write_text(json.dumps({"format": 1, "feeds": {"macos": {"fetched_at": T1, "tracks": {"15": 3}}}}))
    item = mac()
    assert run([item], tmp_path, FakeFetch({})).state == "failed"
    assert item.state == "manual"


# Refresh


def test_refresh_runs_sofa_after_the_macos_and_app_sources(tmp_path, monkeypatch):
    monkeypatch.setattr(macos, "collect",
                        lambda: SourceResult(CoverageRecord("macos", "macOS", "complete"), [mac()]))
    monkeypatch.setattr(apps, "collect_live",
                        lambda *a, **kw: SourceResult(CoverageRecord("apps", "Applications", "complete"),
                                                      [safari("26.5.2")]))
    real = sofa.check
    monkeypatch.setattr(sofa, "check", lambda items, data_dir: real(items, data_dir, fetch=FakeFetch(),
                                                                    now=lambda: T1))
    sources = [s for s in refresh.default_sources(tmp_path) if s.source in ("apps", "macos", "sofa")]
    with Store(tmp_path) as store:
        state = run_refresh(store, sources)
    by_source = {c["source"]: c["state"] for c in state["coverage"]}
    assert by_source == {"apps": "complete", "macos": "complete", "sofa": "complete"}
    items = {i["id"]: i for i in state["items"]}
    assert items["macos"]["state"] == "vulnerable"
    assert items["macos"]["attributes"]["sofaExploited"] == "CVE-2026-86950"
    assert items["com.apple.Safari"]["state"] == "update_available"
