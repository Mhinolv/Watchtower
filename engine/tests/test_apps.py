import json
import os
import plistlib
import struct
import subprocess
from pathlib import Path

import pytest

from watchtower_engine import cli
from watchtower_engine.feeds.homebrew import URLS, Response
from watchtower_engine.inventory import apps, macos
from watchtower_engine.inventory.apps import (
    Bundle, build_items, collect, collect_live, electron_runtimes, find_bundles,
    mach_o_architectures, read_bundle,
)
from watchtower_engine.models import ItemRecord

FIX = Path(__file__).parent / "fixtures" / "homebrew"
T1 = "2026-10-29T08:00:00Z"


# Fixture bundles. Nothing here is a real app, and nothing starts one.


def make_app(root, rel, bundle_id="com.example.app", version="1.0", build="100", executable=None,
             electron=None, name=None, extra=None, plist=True):
    app = Path(root) / rel
    (app / "Contents" / "MacOS").mkdir(parents=True)
    info = {"CFBundleName": name or app.stem}
    if bundle_id:
        info["CFBundleIdentifier"] = bundle_id
    if version:
        info["CFBundleShortVersionString"] = version
    if build:
        info["CFBundleVersion"] = build
    if executable:
        info["CFBundleExecutable"] = "main"
        (app / "Contents" / "MacOS" / "main").write_bytes(executable)
    info.update(extra or {})
    if plist:
        with open(app / "Contents" / "Info.plist", "wb") as f:
            plistlib.dump(info, f, fmt=plistlib.FMT_BINARY)
    if electron:
        res = app / "Contents" / "Frameworks" / "Electron Framework.framework" / "Resources"
        res.mkdir(parents=True)
        with open(res / "Info.plist", "wb") as f:
            plistlib.dump({"CFBundleShortVersionString": electron, "CFBundleVersion": electron}, f)
    return app


def fat(*cpu_types):
    head = b"\xca\xfe\xba\xbe" + struct.pack(">I", len(cpu_types))
    for t in cpu_types:
        head += struct.pack(">IIIII", t, 0, 4096, 100, 14)
    return head + b"\0" * 64


ARM64, X86_64 = 0x0100000C, 0x01000007
THIN_ARM64 = b"\xcf\xfa\xed\xfe" + struct.pack("<I", ARM64) + b"\0" * 64


@pytest.fixture
def folders(tmp_path):
    root = tmp_path / "home" / "Applications"
    system = tmp_path / "Applications"
    root.mkdir(parents=True)
    system.mkdir()
    return system, root, (str(system), str(root))


def cask(token, *apps_, installed="1.0", target=None):
    names = [{"app": [a] + ([{"target": target}] if target else [])} for a in apps_]
    return {"token": token, "installed": installed, "artifacts": names + [{"zap": [{"trash": "~/x"}]}]}


def by_name(items):
    return {i.name: i for i in items}


# Bundles


def test_reads_bundle_fields_from_info_plist(folders):
    system, _, roots = folders
    make_app(system, "Zed.app", "dev.zed.Zed", "0.158.2", "158002", executable=fat(ARM64, X86_64))
    result = collect(roots)
    assert result.coverage.state == "complete"
    [zed] = result.items
    assert (zed.id, zed.name, zed.kind, zed.installed_version) == ("dev.zed.Zed", "Zed", "app", "0.158.2")
    assert zed.attributes == {
        "path": str(system / "Zed.app"),
        "bundleId": "dev.zed.Zed",
        "build": "158002",
        "architecture": "arm64, x86_64",
    }
    assert (zed.state, zed.origin, zed.note) == ("manual", "Manual", "Update this app from its vendor.")


def test_display_name_is_preferred_and_build_equal_to_version_is_dropped(folders):
    system, _, roots = folders
    make_app(system, "x.app", version="2.0", build="2.0",
             extra={"CFBundleDisplayName": "Nice Name"})
    [item] = collect(roots).items
    assert item.name == "Nice Name"
    assert "build" not in item.attributes


def test_finds_apps_in_subfolders_but_not_inside_bundles(folders):
    system, root, roots = folders
    make_app(system, "Utilities/Tool.app", "com.example.tool")
    make_app(system, "Top.app", "com.example.top")
    make_app(system, "Top.app/Contents/Helpers/Helper.app", "com.example.helper")
    make_app(root, "Mine.app", "com.example.mine")
    make_app(system, ".Hidden.app", "com.example.hidden")
    make_app(system, "Deep/Two/Nope.app", "com.example.nope")
    paths, errors = find_bundles(roots)
    assert errors == []
    assert sorted(p.name for p in paths) == ["Mine.app", "Tool.app", "Top.app"]


def test_missing_user_applications_folder_is_not_an_error(tmp_path):
    system = tmp_path / "Applications"
    system.mkdir()
    result = collect((str(system), str(tmp_path / "nope")))
    assert result.coverage.state == "complete"


def test_symlink_to_a_bundle_is_one_app(folders):
    system, root, roots = folders
    app = make_app(system, "Zed.app", "dev.zed.Zed")
    os.symlink(app, root / "Zed.app")
    assert len(collect(roots).items) == 1


# Missing version, duplicates


def test_missing_version_is_unknown_with_a_note(folders):
    system, _, roots = folders
    make_app(system, "NoVersion.app", "com.example.nov", version=None, build=None)
    [item] = collect(roots).items
    assert (item.state, item.installed_version) == ("unknown", None)
    assert item.note == "This app has no version in Info.plist."
    assert item.error is None


def test_build_number_alone_is_used_as_version(folders):
    system, _, roots = folders
    make_app(system, "B.app", version=None, build="77")
    [item] = collect(roots).items
    assert (item.installed_version, item.state) == ("77", "manual")
    assert "build" not in item.attributes


def test_duplicate_bundle_ids_give_each_copy_its_own_item_and_note(folders):
    system, root, roots = folders
    make_app(system, "Thing.app", "com.example.thing", "1.0")
    make_app(root, "Thing.app", "com.example.thing", "2.0")
    make_app(system, "Other.app", "com.example.other")
    result = collect(roots)
    things = [i for i in result.items if i.name == "Thing"]
    assert len({i.id for i in things}) == 2
    assert {i.installed_version for i in things} == {"1.0", "2.0"}
    for i in things:
        assert i.attributes["copies"] == "2"
        assert i.note.startswith("2 copies of this app. Paths: ")
        assert str(system / "Thing.app") in i.note
        assert i.note.count("Thing.app") == 2
    [other] = [i for i in result.items if i.name == "Other"]
    assert "copies" not in other.attributes and other.id == "com.example.other"


def test_duplicate_note_shows_home_as_tilde(tmp_path, monkeypatch):
    home = tmp_path / "home"
    for folder in ("Applications", "Other"):
        make_app(home / folder, "Thing.app", "com.example.thing")
    items = build_items([read_bundle(home / "Applications" / "Thing.app"),
                         read_bundle(home / "Other" / "Thing.app")])
    assert items[0].note == "2 copies of this app. Paths: ~/Applications/Thing.app, ~/Other/Thing.app."


def test_bundle_id_case_does_not_hide_a_duplicate(folders):
    system, root, roots = folders
    make_app(system, "A.app", "com.Example.A")
    make_app(root, "B.app", "com.example.a")
    assert all("copies" in i.attributes for i in collect(roots).items)


def test_app_without_bundle_id_is_keyed_by_path(folders):
    system, _, roots = folders
    make_app(system, "Odd.app", bundle_id=None)
    [item] = collect(roots).items
    assert item.id == f"path:{system / 'Odd.app'}"
    assert "bundleId" not in item.attributes


def test_unreadable_info_plist_is_an_error_and_makes_coverage_partial(folders):
    system, _, roots = folders
    make_app(system, "Good.app", "com.example.good")
    bad = make_app(system, "Bad.app", "com.example.bad")
    (bad / "Contents" / "Info.plist").write_text("not a plist")
    make_app(system, "Empty.app", plist=False)
    result = collect(roots)
    assert result.coverage.state == "partial"
    assert result.coverage.error == "2 apps could not be read."
    items = by_name(result.items)
    assert items["Good"].state == "manual"
    assert (items["Bad"].state, items["Bad"].error) == ("error", "Info.plist could not be read.")
    assert items["Empty"].state == "error" and items["Empty"].installed_version is None


def test_unreadable_applications_folder_fails_or_partly_fails(tmp_path):
    system = tmp_path / "Applications"
    other = tmp_path / "Other"
    make_app(system, "A.app", "com.example.a")
    other.mkdir()
    other.chmod(0)
    try:
        if os.access(other, os.R_OK):
            pytest.skip("running as a user that ignores folder modes")
        partial = collect((str(system), str(other)))
        failed = collect((str(other),))
    finally:
        other.chmod(0o700)
    assert partial.coverage.state == "partial" and len(partial.items) == 1
    assert failed.coverage.state == "failed" and failed.items == []
    assert partial.coverage.error == f"Watchtower cannot read {other}."


def test_inventory_reads_only_plists_and_executable_headers(folders, monkeypatch):
    system, _, roots = folders
    app = make_app(system, "Zed.app", "dev.zed.Zed", executable=fat(ARM64), electron="30.1.2")
    (app / "Contents" / "Resources").mkdir()
    (app / "Contents" / "Resources" / "secret.txt").write_text("x")
    opened = []
    real_open = open

    def spy(file, *a, **kw):
        opened.append(str(file))
        return real_open(file, *a, **kw)

    def no_process(*a, **kw):
        raise AssertionError("a program was started")

    monkeypatch.setattr("builtins.open", spy)
    monkeypatch.setattr(subprocess, "run", no_process)
    monkeypatch.setattr(subprocess, "Popen", no_process)
    monkeypatch.setattr(os, "system", no_process)
    collect(roots)
    assert opened
    for f in opened:
        assert f.endswith(("Info.plist", "MacOS/main")), f


# Architecture


def test_architectures_from_mach_o_headers(tmp_path):
    cases = {
        "arm": (fat(ARM64), "arm64"),
        "uni": (fat(X86_64, ARM64), "arm64, x86_64"),
        "thin": (THIN_ARM64, "arm64"),
        "x86": (b"\xcf\xfa\xed\xfe" + struct.pack("<I", X86_64) + b"\0" * 8, "x86_64"),
        "script": (b"#!/bin/sh\necho hi\n", None),
        "empty": (b"", None),
        "java": (b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\0" * 64, None),
        "short": (b"\xca\xfe\xba\xbe", None),
    }
    for name, (data, expected) in cases.items():
        f = tmp_path / name
        f.write_bytes(data)
        assert mach_o_architectures(f) == expected, name
    assert mach_o_architectures(tmp_path / "missing") is None


# Electron


def test_electron_version_comes_from_the_framework_plist_without_launch(folders):
    system, _, roots = folders
    make_app(system, "Chatty.app", "com.example.chatty", electron="30.1.2")
    make_app(system, "Plain.app", "com.example.plain")
    items = by_name(collect(roots).items)
    assert items["Chatty"].attributes["electron"] == "30.1.2"
    assert items["Chatty"].attributes["chromium"] == "124"
    assert items["Chatty"].attributes["node"] == "20"
    assert "electron" not in items["Plain"].attributes


def test_unknown_electron_major_has_version_but_no_inferred_runtimes(folders):
    system, _, roots = folders
    make_app(system, "Future.app", "com.example.future", electron="99.0.0")
    [item] = collect(roots).items
    assert item.attributes["electron"] == "99.0.0"
    assert "node" not in item.attributes and "chromium" not in item.attributes
    assert electron_runtimes("30.1.2") == ("124", "20")
    assert electron_runtimes("nonsense") is None


def test_broken_electron_plist_is_ignored(folders):
    system, _, roots = folders
    app = make_app(system, "E.app", "com.example.e", electron="30.0.0")
    plist = next(app.rglob("Electron Framework.framework/Resources/Info.plist"))
    plist.write_text("junk")
    [item] = collect(roots).items
    assert "electron" not in item.attributes and item.state == "manual"


# Cask links


def cask_item(token, state="up_to_date", latest="2.0"):
    return ItemRecord(f"cask:{token}", "homebrew", token, state, kind="cask", latest_version=latest,
                      source_at=T1)


def test_one_cask_for_one_app_links_and_takes_the_cask_state(folders):
    system, _, roots = folders
    make_app(system, "Zed.app", "dev.zed.Zed", "1.0")
    result = collect(roots, [cask("zed", "Zed.app")], [cask_item("zed", "update_available", "2.0")])
    [zed] = result.items
    assert (zed.state, zed.latest_version, zed.source_at) == ("update_available", "2.0", T1)
    assert (zed.origin, zed.note) == ("Homebrew cask", "Linked to cask zed.")
    assert zed.attributes["cask"] == "zed"


def test_link_without_cask_state_is_unknown_not_up_to_date(folders):
    system, _, roots = folders
    make_app(system, "Zed.app", "dev.zed.Zed")
    [zed] = collect(roots, [cask("zed", "Zed.app")], []).items
    assert (zed.state, zed.origin) == ("unknown", "Homebrew cask")


def test_two_casks_for_one_app_stay_unlinked(folders):
    system, _, roots = folders
    make_app(system, "Firefox.app", "org.mozilla.firefox")
    casks = [cask("firefox", "Firefox.app"), cask("firefox@esr", "Firefox.app")]
    [item] = collect(roots, casks, [cask_item("firefox"), cask_item("firefox@esr")]).items
    assert (item.state, item.origin, item.note) == ("manual", "Manual", "Update this app from its vendor.")
    assert "cask" not in item.attributes
    assert item.detail == "Casks that claim this app: firefox, firefox@esr."


def test_two_copies_of_a_cask_app_stay_unlinked(folders):
    system, root, roots = folders
    make_app(system, "Zed.app", "dev.zed.Zed")
    make_app(root, "Zed.app", "dev.zed.Zed")
    items = collect(roots, [cask("zed", "Zed.app")], [cask_item("zed")]).items
    assert len(items) == 2
    for i in items:
        assert (i.state, i.origin) == ("manual", "Manual")
        assert i.detail == "Cask zed matches more than one copy of this app."


def test_cask_target_rename_and_case_insensitive_match(folders):
    system, _, roots = folders
    make_app(system, "Renamed Name.app", "com.example.r")
    make_app(system, "ZED.app", "dev.zed.Zed")
    casks = [cask("renamer", "Original.app", target="Renamed Name.app"), cask("zed", "zed.app")]
    items = by_name(collect(roots, casks, [cask_item("renamer"), cask_item("zed")]).items)
    assert items["Renamed Name"].attributes["cask"] == "renamer"
    assert items["ZED"].attributes["cask"] == "zed"


def test_cask_that_is_not_installed_or_has_no_app_artifact_does_not_link(folders):
    system, _, roots = folders
    make_app(system, "Zed.app", "dev.zed.Zed")
    casks = [cask("zed", "Zed.app", installed=None), {"token": "pkg", "installed": "1", "artifacts": [{"pkg": ["x.pkg"]}]},
             {"token": "odd", "installed": "1", "artifacts": "bad"}, {"installed": "1"}]
    [item] = collect(roots, casks, []).items
    assert item.origin == "Manual"


def test_linked_app_copies_the_cask_error(folders):
    system, _, roots = folders
    make_app(system, "Zed.app", "dev.zed.Zed")
    broken = cask_item("zed", "error", None)
    broken.error = "Homebrew catalog did not load."
    [item] = collect(roots, [cask("zed", "Zed.app")], [broken]).items
    assert (item.state, item.error) == ("error", "Homebrew catalog did not load.")


def test_failed_cask_list_marks_coverage_partial(folders):
    system, _, roots = folders
    make_app(system, "Zed.app", "dev.zed.Zed")
    result = collect(roots, casks_error=apps.ERROR_CASKS, casks_detail="brew exploded")
    assert result.coverage.state == "partial"
    assert result.coverage.error == "Homebrew casks did not load. Apps show as manual."
    assert result.coverage.detail == "brew exploded"


# Live collection with a fake brew


BREW_INFO = {
    "formulae": [],
    "casks": [
        {"token": "zed", "full_token": "zed", "tap": "homebrew/cask", "installed": "0.100.0",
         "auto_updates": False, "name": ["Zed"], "version": "0.100.0",
         "artifacts": [{"app": ["Zed.app"]}]},
    ],
}


class FakeRun:
    def __init__(self, info=BREW_INFO, returncode=0):
        self.info, self.returncode, self.calls = info, returncode, []

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, self.returncode, json.dumps(self.info), "boom")


class FakeFetch:
    def __init__(self, latest="0.158.2"):
        body = json.dumps([{"token": "zed", "full_token": "zed", "tap": "homebrew/cask",
                            "version": latest, "auto_updates": False}]).encode()
        self.body, self.calls = body, []

    def __call__(self, url, headers):
        self.calls.append(url)
        assert url == URLS["cask"]
        return Response(200, {}, self.body)


def test_live_run_links_apps_and_runs_brew_info_once(tmp_path, folders):
    system, _, roots = folders
    make_app(system, "Zed.app", "dev.zed.Zed", "0.100.0")
    make_app(system, "Manual.app", "com.example.manual")
    run, fetch = FakeRun(), FakeFetch()
    result = collect_live(tmp_path / "data", roots, brew="/fake/brew", run=run, fetch=fetch, now=lambda: T1)
    assert len(run.calls) == 1 and run.calls[0][1:3] == ["info", "--json=v2"]
    items = by_name(result.items)
    assert (items["Zed"].state, items["Zed"].latest_version) == ("update_available", "0.158.2")
    assert items["Manual"].origin == "Manual"
    assert result.coverage.state == "complete"


def test_live_run_without_brew_links_nothing(tmp_path, folders, monkeypatch):
    system, _, roots = folders
    make_app(system, "Zed.app", "dev.zed.Zed")
    monkeypatch.setattr("watchtower_engine.inventory.homebrew.find_brew", lambda: None)
    result = collect_live(tmp_path / "data", roots)
    assert result.coverage.state == "complete"
    assert result.items[0].origin == "Manual"


def test_live_run_with_failing_brew_is_partial(tmp_path, folders):
    system, _, roots = folders
    make_app(system, "Zed.app", "dev.zed.Zed")
    result = collect_live(tmp_path / "data", roots, brew="/fake/brew", run=FakeRun(returncode=1),
                          fetch=FakeFetch())
    assert result.coverage.state == "partial"
    assert result.items[0].origin == "Manual"


def test_live_run_with_no_casks_does_not_fetch_the_catalog(tmp_path, folders):
    system, _, roots = folders
    make_app(system, "Zed.app", "dev.zed.Zed")
    fetch = FakeFetch()
    collect_live(tmp_path / "data", roots, brew="/fake/brew",
                 run=FakeRun({"formulae": [], "casks": []}), fetch=fetch)
    assert fetch.calls == []


# macOS


def write_system_version(path, **kw):
    info = {"ProductName": "macOS", "ProductVersion": "15.1", "ProductBuildVersion": "24B83"}
    info.update(kw)
    with open(path, "wb") as f:
        plistlib.dump(info, f)
    return path


def test_macos_item_has_version_build_and_manual_update(tmp_path):
    result = macos.collect(write_system_version(tmp_path / "SystemVersion.plist"))
    assert result.coverage.state == "complete"
    [item] = result.items
    assert (item.id, item.source, item.name, item.kind) == ("macos", "macos", "macOS", "os")
    assert item.installed_version == "15.1"
    assert item.attributes == {"build": "24B83"}
    assert (item.state, item.note) == ("manual", "Update macOS in System Settings.")


def test_macos_rapid_security_response_extra(tmp_path):
    result = macos.collect(write_system_version(tmp_path / "s.plist", ProductVersionExtra="(a)"))
    [item] = result.items
    assert item.installed_version == "15.1 (a)" and item.attributes["extra"] == "(a)"


def test_macos_unreadable_plist_fails(tmp_path):
    bad = tmp_path / "s.plist"
    bad.write_text("junk")
    for path in (bad, tmp_path / "missing.plist"):
        result = macos.collect(path)
        assert result.coverage.state == "failed" and result.items == []
        assert result.coverage.error == "macOS version could not be read."
    no_version = tmp_path / "v.plist"
    with open(no_version, "wb") as f:
        plistlib.dump({"ProductName": "macOS"}, f)
    assert macos.collect(no_version).coverage.state == "failed"



# Contract and CLI


def test_items_survive_the_store_with_attributes(tmp_path, folders):
    from watchtower_engine.store import Store

    system, _, roots = folders
    make_app(system, "Zed.app", "dev.zed.Zed", executable=fat(ARM64), electron="30.1.2")
    result = collect(roots)
    with Store(tmp_path / "data") as store:
        r = store.begin_refresh()
        store.finish_refresh(r.id, "complete", coverage=[result.coverage], items=result.items)
        saved = store.items()
    assert saved[0].attributes == result.items[0].attributes
    assert saved[0].attributes["node"] == "20"


def test_apps_command_prints_coverage_and_items(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    make_app(home / "Applications", "Mine.app", "com.example.mine")
    monkeypatch.setattr(apps, "APP_ROOTS", (str(tmp_path / "none"), "~/Applications"))
    monkeypatch.setattr("watchtower_engine.inventory.homebrew.find_brew", lambda: None)
    real = apps.collect_live
    monkeypatch.setattr(apps, "collect_live", lambda data_dir: real(data_dir, apps.APP_ROOTS))
    assert cli.main(["--data-dir", str(tmp_path / "data"), "apps"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["coverage"]["source"] == "apps" and out["coverage"]["state"] == "complete"
    assert [i["name"] for i in out["items"]] == ["Mine"]
    assert out["items"][0]["attributes"]["bundleId"] == "com.example.mine"


def test_macos_command_prints_one_item(tmp_path, capsys, monkeypatch):
    plist = write_system_version(tmp_path / "SystemVersion.plist")
    real = macos.collect
    monkeypatch.setattr(macos, "collect", lambda: real(plist))
    assert cli.main(["macos"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["coverage"]["source"] == "macos"
    assert [(i["id"], i["installed_version"], i["attributes"]) for i in out["items"]] == [
        ("macos", "15.1", {"build": "24B83"})
    ]
