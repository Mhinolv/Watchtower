"""Latest version for apps from the public Homebrew cask catalog (#55). Fixtures only, no network.

`fixtures/homebrew/cask-catalog.json` holds real entries of the public cask API.
"""
import json
from pathlib import Path

import pytest

from watchtower_engine.feeds.homebrew import URLS, Catalog, Response, cask_app_names, cask_bundle_ids, load_catalog
from watchtower_engine.inventory import apps, homebrew as hb
from watchtower_engine.inventory.apps import build_items, collect, collect_live, compare_versions, read_bundle

from test_apps import make_app

FIXTURE = Path(__file__).parent / "fixtures" / "homebrew" / "cask-catalog.json"
RAW = json.loads(FIXTURE.read_text())
T1 = "2026-10-29T08:02:00Z"
SELF = "This app updates itself. Watchtower compares the app version, not the Homebrew record."


class Fetch:
    def __init__(self, rows=None, error=None):
        self.rows, self.error, self.calls = RAW if rows is None else rows, error, []

    def __call__(self, url, headers):
        self.calls.append(url)
        assert url == URLS["cask"]
        if self.error:
            raise self.error
        return Response(200, {"etag": "abc"}, json.dumps(self.rows).encode())


@pytest.fixture
def catalog(tmp_path):
    return load_catalog("cask", tmp_path / "data", Fetch(), now=lambda: T1)


@pytest.fixture
def folder(tmp_path):
    root = tmp_path / "Applications"
    root.mkdir()
    return root


def items_for(root, catalog, casks=None, cask_items=None):
    bundles = [read_bundle(p) for p in sorted(root.glob("*.app"))]
    return {i.name: i for i in build_items(bundles, casks, cask_items, catalog)}


# The index reads the real catalog shape


def test_index_reads_app_names_and_bundle_ids_from_real_entries(catalog):
    rows = {r["name"]: r for r in catalog.rows}
    assert rows["t3-code"]["app_names"] == ["t3 code (beta).app"]
    assert "com.t3tools.t3code" in rows["t3-code"]["bundle_ids"]
    assert rows["zed"]["bundle_ids"] == ["dev.zed.zed"]
    assert rows["hopper-disassembler"]["bundle_ids"] == ["com.cryptic-apps.hopper-web-4"]
    assert rows["hopper-disassembler"]["homepage"] == "https://www.hopperapp.com/"
    assert rows["firefox@esr"]["app_names"] == ["firefox.app"]
    assert rows["t3-code"]["auto_updates"] is True


def test_cask_app_name_follows_a_target_rename_and_skips_other_artifacts():
    artifacts = [{"app": ["Original.app", {"target": "Renamed.app"}]}, {"pkg": ["x.pkg"]}, {"zap": [{"trash": "~/x"}]}]
    assert cask_app_names(artifacts) == ["renamed.app"]
    assert cask_bundle_ids(artifacts) == []


def test_bundle_ids_come_from_quit_and_library_zap_paths_only():
    artifacts = [{"uninstall": [{"quit": ["com.a.one", "not an id"]}]},
                 {"zap": [{"trash": ["~/Library/Caches/com.b.two", "~/Library/Preferences/com.c.three.plist",
                                     "~/Library/Application Support/com.d.four", "~/Library/Logs/Zed"]}]}]
    assert cask_bundle_ids(artifacts) == ["com.a.one", "com.b.two", "com.c.three"]


# Not installed by Homebrew: the catalog gives Latest


def test_an_app_with_a_matching_public_cask_shows_the_catalog_version(folder, catalog):
    # T3 Code 0.1.3, catalog 0.1.5. The app file name differs from the cask's, so the bundle id matches.
    make_app(folder, "T3 Code.app", "com.t3tools.t3code", "0.1.3")
    item = items_for(folder, catalog)["T3 Code"]
    assert (item.latest_version, item.state, item.origin) == ("0.1.5", "update_available", "Homebrew catalog")
    assert item.note == f"Homebrew did not install this app. Update it from the vendor. {SELF}"
    assert item.attributes["matchedBy"] == "Bundle ID" and item.attributes["cask"] == "t3-code"
    assert item.attributes["latestFrom"] == "Homebrew catalog, cask t3-code"
    assert item.attributes["homepage"] == "https://t3.codes/"
    assert item.source_at == T1 and item.error is None


def test_match_by_app_name_and_same_version_is_up_to_date(folder, catalog):
    make_app(folder, "Hopper Disassembler.app", "com.example.renamed", "6.6.1")
    item = items_for(folder, catalog)["Hopper Disassembler"]
    assert (item.latest_version, item.state, item.attributes["matchedBy"]) == ("6.6.1", "up_to_date", "App name")
    assert item.note == SELF


def test_an_app_newer_than_the_catalog_is_up_to_date_with_a_note(folder, catalog):
    make_app(folder, "Zed.app", "dev.zed.Zed", "1.30.0")
    item = items_for(folder, catalog)["Zed"]
    assert (item.state, item.latest_version) == ("up_to_date", "1.26.2")
    assert item.note == f"The app is newer than the Homebrew catalog (1.26.2). {SELF}"


def test_several_casks_for_one_app_stay_manual_and_never_guess(folder, catalog):
    # Real: zoom and zoom-for-it-admins both list us.zoom.xos, neither has an app artifact, no `@` suffix.
    make_app(folder, "zoom.us.app", "us.zoom.xos", "6.0.0")
    item = items_for(folder, catalog)["zoom.us"]
    assert (item.state, item.latest_version, item.origin) == ("manual", None, "Manual")
    assert item.note == "More than one cask matches. Watchtower does not guess."
    assert item.detail == "Casks that match: zoom, zoom-for-it-admins."
    assert "cask" not in item.attributes


def test_variants_with_an_at_suffix_do_not_make_a_match_ambiguous(folder, catalog):
    # Real: slack and slack@beta both install Slack.app and list the same bundle id. Take slack.
    make_app(folder, "Slack.app", "com.tinyspeck.slackmacgap", "4.40.0")
    make_app(folder, "iTerm.app", "com.googlecode.iterm2", "3.5.0")
    make_app(folder, "Firefox.app", "org.mozilla.firefox", "150.0")
    items = items_for(folder, catalog)
    assert [(items[n].attributes["cask"], items[n].state) for n in ("Slack", "iTerm", "Firefox")] == [
        ("slack", "update_available"), ("iterm2", "update_available"), ("firefox", "update_available")]
    assert items["Slack"].latest_version == "4.53.276" and items["Slack"].attributes["matchedBy"] == "Bundle ID"


def test_only_variants_stay_ambiguous(folder):
    rows = [{"name": n, "full_name": n, "version": "2.0", "auto_updates": False, "old_names": [], "homepage": None,
             "app_names": ["tool.app"], "bundle_ids": ["com.example.tool"]} for n in ("tool@beta", "tool@dev")]
    make_app(folder, "Tool.app", "com.example.tool", "1.0")
    item = items_for(folder, Catalog("cask", rows=rows, fetched_at=T1, fresh=True))["Tool"]
    assert item.state == "manual" and item.note == "More than one cask matches. Watchtower does not guess."


def test_a_bundle_id_in_another_casks_uninstall_list_does_not_win(folder, catalog):
    # Real: wondershare-uniconverter lists com.google.Chrome in `uninstall quit`.
    make_app(folder, "Google Chrome.app", "com.google.Chrome", "150.0.7000.1")
    item = items_for(folder, catalog)["Google Chrome"]
    assert (item.attributes["cask"], item.latest_version, item.state) == ("google-chrome", "156.0.8078.80",
                                                                         "update_available")


def test_a_bundle_id_in_another_casks_zap_path_does_not_win(folder, catalog):
    # Real: tidgi lists com.microsoft.VSCode in a zap trash path.
    make_app(folder, "Visual Studio Code.app", "com.microsoft.VSCode", "1.100.0")
    item = items_for(folder, catalog)["Visual Studio Code"]
    assert (item.attributes["cask"], item.latest_version) == ("visual-studio-code", "1.144.0")


def test_casks_that_share_a_bundle_id_are_told_apart_by_the_app_name(folder, catalog):
    # Real: chatgpt and codex-app both list com.openai.codex.
    make_app(folder, "ChatGPT.app", "com.openai.codex", "26.1000.1")
    make_app(folder, "Codex.app", "com.openai.codex", "26.600.1")
    items = items_for(folder, catalog)
    assert items["ChatGPT"].attributes["cask"] == "chatgpt"
    assert items["Codex"].attributes["cask"] == "codex-app"


def test_an_app_without_a_match_stays_manual(folder, catalog):
    make_app(folder, "Unknown.app", "com.example.unknown", "1.0")
    item = items_for(folder, catalog)["Unknown"]
    assert (item.state, item.latest_version, item.origin) == ("manual", None, "Manual")
    assert item.note == "Update this app from its vendor."


def test_a_cask_without_a_homepage_gives_no_vendor_link(folder):
    row = {"name": "nohome", "full_name": "nohome", "version": "2.0", "auto_updates": False, "old_names": [],
           "homepage": None, "app_names": ["nohome.app"], "bundle_ids": []}
    make_app(folder, "NoHome.app", "com.example.nohome", "1.0")
    item = items_for(folder, Catalog("cask", rows=[row], fetched_at=T1, fresh=True))["NoHome"]
    assert item.state == "update_available" and "homepage" not in item.attributes
    assert item.note == "Homebrew did not install this app. Update it from the vendor."


def test_a_cask_build_part_is_not_part_of_the_version(folder):
    row = {"name": "fluff", "full_name": "fluff", "version": "1.3,200", "auto_updates": False, "old_names": [],
           "homepage": None, "app_names": ["fluff.app"], "bundle_ids": []}
    make_app(folder, "Fluff.app", "com.example.fluff", "1.3")
    item = items_for(folder, Catalog("cask", rows=[row], fetched_at=T1, fresh=True))["Fluff"]
    assert (item.latest_version, item.state, item.note) == ("1.3", "up_to_date", None)


def test_formats_that_differ_are_unknown_not_a_guess(folder):
    row = {"name": "cal", "full_name": "cal", "version": "10.2", "auto_updates": False, "old_names": [],
           "homepage": None, "app_names": ["cal.app"], "bundle_ids": []}
    make_app(folder, "Cal.app", "com.example.cal", "2024.10")
    item = items_for(folder, Catalog("cask", rows=[row], fetched_at=T1, fresh=True))["Cal"]
    assert (item.state, item.note) == ("unknown", "Version formats differ: 2024.10 and 10.2.")


def test_two_copies_match_by_bundle_id_only(folder, tmp_path):
    other = tmp_path / "Other"
    other.mkdir()
    make_app(folder, "Hopper Disassembler.app", "com.cryptic-apps.hopper-web-4", "6.5.0")
    make_app(other, "Hopper Disassembler.app", "com.example.second", "6.5.0")
    bundles = [read_bundle(folder / "Hopper Disassembler.app"), read_bundle(other / "Hopper Disassembler.app")]
    items = build_items(bundles, None, None, load_catalog("cask", tmp_path / "d", Fetch(), now=lambda: T1))
    by_id = {i.id: i for i in items}
    assert by_id["com.cryptic-apps.hopper-web-4"].latest_version == "6.6.1"
    assert by_id["com.example.second"].latest_version is None


# Installed by Homebrew, self-updating: compare the app


def test_a_self_updating_installed_cask_compares_the_app_version(folder, catalog):
    # T3 Code 0.1.3 installed by Homebrew, catalog 0.1.5: the cask row says Unknown, the app row compares.
    make_app(folder, "T3 Code (Beta).app", "com.t3tools.t3code", "0.1.3")
    raw = next(r for r in RAW if r["token"] == "t3-code")
    installed = {**raw, "installed": "0.1.3"}
    cask_item = hb.cask_item(installed, catalog)
    assert cask_item.state == "unknown" and cask_item.note == hb.NOTE_SELF_UPDATE
    item = items_for(folder, catalog, [installed], [cask_item])["T3 Code (Beta)"]
    assert (item.state, item.latest_version, item.origin) == ("update_available", "0.1.5", "Homebrew cask")
    assert item.note == SELF


def test_a_self_updating_cask_with_a_current_app_is_up_to_date(folder, catalog):
    make_app(folder, "T3 Code (Beta).app", "com.t3tools.t3code", "0.1.5")
    raw = next(r for r in RAW if r["token"] == "t3-code")
    installed = {**raw, "installed": "0.1.3"}  # The receipt is old. The app updated itself.
    item = items_for(folder, catalog, [installed], [hb.cask_item(installed, catalog)])["T3 Code (Beta)"]
    assert (item.state, item.note) == ("up_to_date", SELF)


# Versions


@pytest.mark.parametrize("installed,latest,result", [
    ("0.1.3", "0.1.5", "newer"), ("1.0", "1.0.0", "same"), ("2.0", "1.9.9", "older"), ("1.10", "1.9", "older"),
    ("1.3", "1.3,200", "same"), ("2024.10", "10.2", "unknown"), ("1.0-beta", "1.0", "unknown"),
    ("1.0", "latest", "unknown"), (None, "1.0", "unknown"), ("5", "5", "same"),
    ("v2.8.2", "2.8.2", "same"), ("2.0.2+b72db03fb", "2.0.2", "same"), ("2.0.1", "v2.8.2", "newer"),
])
def test_compare_versions(installed, latest, result):
    assert compare_versions(installed, latest) == result


# Coverage and the live run


def test_a_failed_catalog_keeps_apps_manual_and_marks_coverage_partial(folder, tmp_path):
    make_app(folder, "T3 Code.app", "com.t3tools.t3code", "0.1.3")
    result = collect((str(folder),), catalog_loader=lambda: load_catalog("cask", tmp_path / "d", Fetch(error=OSError("down"))))
    [item] = result.items
    assert (item.state, item.latest_version, item.origin) == ("manual", None, "Manual")
    assert result.coverage.state == "partial" and result.coverage.error == "Homebrew catalog did not load."


def test_an_old_catalog_still_matches_and_shows_its_age(folder, tmp_path):
    make_app(folder, "T3 Code.app", "com.t3tools.t3code", "0.1.3")
    load_catalog("cask", tmp_path / "d", Fetch(), now=lambda: T1)
    result = collect((str(folder),), catalog_loader=lambda: load_catalog("cask", tmp_path / "d", Fetch(error=OSError("down"))))
    [item] = result.items
    assert (item.state, item.latest_version, item.source_at) == ("update_available", "0.1.5", T1)
    assert item.error == "Homebrew catalog did not load."
    assert result.coverage.state == "partial"


def test_the_live_run_matches_apps_without_brew(tmp_path, folder, monkeypatch):
    monkeypatch.setattr("watchtower_engine.inventory.homebrew.find_brew", lambda: None)
    make_app(folder, "T3 Code.app", "com.t3tools.t3code", "0.1.3")
    fetch = Fetch()
    result = collect_live(tmp_path / "data", (str(folder),), fetch=fetch, now=lambda: T1)
    assert fetch.calls == [URLS["cask"]]
    assert result.items[0].latest_version == "0.1.5" and result.coverage.state == "complete"
