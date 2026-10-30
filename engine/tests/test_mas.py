"""Mac App Store updates through mas (#13). Fixtures only: no mas, no network, no real apps.

The fixtures follow the documented mas 7.0.0 output (see fixtures/mas/README.md).
"""
import plistlib
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from watchtower_engine import updater
from watchtower_engine.inventory import apps
from watchtower_engine.inventory import mas as inv
from watchtower_engine.models import CoverageRecord as C
from watchtower_engine.models import ItemRecord as I
from watchtower_engine.store import Store
from watchtower_engine.update_log import UpdateLog
from watchtower_engine.updater import run_update
from watchtower_engine.updates import mas as upd

from contract import Clock
from test_apps import make_app

FIX = Path(__file__).parent / "fixtures" / "mas"
LIST = (FIX / "list.jsonl").read_text()
OUTDATED = (FIX / "outdated.jsonl").read_text()
VERSION = (FIX / "version.txt").read_text()
MAS = "/fake/mas"
KEYNOTE = "409183694"


class FakeMas:
    """Answers mas calls from fixtures and records them. Never starts a process."""

    def __init__(self, version=VERSION, listing=LIST, outdated=OUTDATED, list_code=0, outdated_code=0,
                 list_err="", outdated_err=""):
        self.version, self.listing, self.outdated = version, listing, outdated
        self.codes = {"list": list_code, "outdated": outdated_code}
        self.errs = {"list": list_err, "outdated": outdated_err}
        self.calls = []

    def __call__(self, args, **kwargs):
        assert args[0] == MAS
        self.calls.append(args[1:])
        sub = args[1]
        assert kwargs.get("stdin") == subprocess.DEVNULL
        if sub == "version":
            return SimpleNamespace(returncode=0, stdout=self.version, stderr="")
        out = {"list": self.listing, "outdated": self.outdated}[sub]
        return SimpleNamespace(returncode=self.codes[sub], stdout=out if not self.codes[sub] else "",
                               stderr=self.errs[sub])


# Parsing


def test_list_json_stream_is_read():
    parsed = inv.parse_list(LIST)
    assert [(a.adam_id, a.bundle_id, a.name, a.version) for a in parsed] == [
        ("1569813296", "com.1password.1password-safari", "1Password for Safari", "2.3.5"),
        ("1295203466", "com.microsoft.rdc.macos", "Microsoft Remote Desktop", "10.7.6"),
        ("409183694", "com.apple.iWork.Keynote", "Keynote", "12.0"),
    ]


def test_outdated_json_stream_is_read():
    parsed = inv.parse_outdated(OUTDATED)
    assert [(o.adam_id, o.name, o.version, o.new_version) for o in parsed] == [
        ("409183694", "Keynote", "11.0", "12.0"), ("1176895641", "Spark", "2.11.20", "2.11.21")]


def test_an_array_and_an_empty_answer_are_read_too():
    assert len(inv.parse_list('[{"adamID": 1, "bundleID": "a.b", "name": "A", "version": "1"}]')) == 1
    assert inv.parse_list("") == [] and inv.parse_outdated("\n") == []


@pytest.mark.parametrize("text", ["not json", '{"adamID": 1, "name": "A"}', '{"adamID": 1, "bundleID": "a",'
                                  ' "name": "A", "version": ""}', "[1, 2]"])
def test_output_in_another_format_is_refused(text):
    with pytest.raises(ValueError):
        inv.parse_list(text)


@pytest.mark.parametrize("version,ok", [("7.0.0", True), ("7.3.1", True), ("6.9.9", False), ("1.6.0", False),
                                        ("8.0.0", False), ("", False)])
def test_only_mas_7_from_the_pinned_version_is_supported(version, ok):
    assert inv.is_supported(version) is ok
    assert inv.PINNED_VERSION == "7.0.0"


def test_limits_are_named_from_mas_text():
    assert inv.classify("Error: Spotlight Metadata Service returned nothing") == "spotlight"
    assert inv.classify("Error: Not signed in to the App Store") == "signed_out"
    assert inv.classify("Error: update requires root privileges") == "admin"
    assert inv.classify("something else") is None


# Inventory runs `mas list --json` only


def test_inventory_runs_version_and_list_json_and_nothing_else():
    fake = FakeMas()
    result = inv.read_inventory(MAS, fake)
    assert result.status == "ok" and result.version == "7.0.0"
    assert fake.calls == [["version"], ["list", "--json"]]
    assert result.apps["com.apple.iwork.keynote"].adam_id == KEYNOTE


@pytest.mark.parametrize("fake,mas,status", [
    (FakeMas(version="1.6.0\n"), MAS, "unsupported"),
    (FakeMas(listing="garbage"), MAS, "failed"),
    (FakeMas(list_code=1, list_err="Spotlight index is missing"), MAS, "spotlight"),
    (FakeMas(list_code=1, list_err="boom"), MAS, "failed"),
    (FakeMas(version="no version here"), MAS, "failed"),
    (FakeMas(), None, "not_installed"),
])
def test_inventory_states(fake, mas, status):
    result = inv.read_inventory(mas, fake)
    assert result.status == status
    assert all(call[0] != "outdated" for call in fake.calls)
    if status == "unsupported":
        assert result.message == "mas 1.6.0 is not supported. Watchtower needs mas 7.0.0 or a newer 7.x."


# Apps in the inventory


def receipt_app(root, rel, bundle_id, version="11.0"):
    app = make_app(root, rel, bundle_id=bundle_id, version=version)
    (app / "Contents" / "_MASReceipt").mkdir()
    (app / "Contents" / "_MASReceipt" / "receipt").write_bytes(b"\0")
    return app


def collect_apps(tmp_path, mas_reader, with_receipt=True):
    make = receipt_app if with_receipt else make_app
    app = make(tmp_path, "Keynote.app", "com.apple.iWork.Keynote")
    make_app(tmp_path, "Manual.app", bundle_id="com.example.manual")
    return app, apps.collect((str(tmp_path),), mas_reader=mas_reader)


def test_an_app_with_a_receipt_is_an_app_store_app(tmp_path):
    fake = FakeMas()
    app, result = collect_apps(tmp_path, lambda: inv.read_inventory(MAS, fake))
    item = next(i for i in result.items if i.name == "Keynote")
    assert (item.origin, item.state, item.latest_version) == ("App Store", "unknown", None)
    assert item.attributes["adamId"] == KEYNOTE and item.attributes["path"] == str(app)
    assert item.note == "Watchtower checks App Store versions only when you click Check for Update…"
    other = next(i for i in result.items if i.name == "Manual")
    assert other.origin == "Manual" and "adamId" not in other.attributes
    assert result.coverage.state == "complete"
    assert fake.calls == [["version"], ["list", "--json"]]


def test_mas_does_not_run_if_no_app_has_a_receipt(tmp_path):
    def reader():
        raise AssertionError("mas must not run")
    _, result = collect_apps(tmp_path, reader, with_receipt=False)
    assert result.coverage.state == "complete"


def test_without_mas_the_row_says_how_to_install_it(tmp_path):
    _, result = collect_apps(tmp_path, lambda: inv.read_inventory(None))
    item = next(i for i in result.items if i.name == "Keynote")
    assert (item.origin, item.state, item.note) == ("App Store", "manual",
                                                    "Install mas with Homebrew to update App Store apps here.")
    assert result.coverage.state == "complete"


def test_unsupported_mas_is_an_error_state(tmp_path):
    _, result = collect_apps(tmp_path, lambda: inv.read_inventory(MAS, FakeMas(version="1.6.0")))
    item = next(i for i in result.items if i.name == "Keynote")
    assert item.state == "error" and item.error.startswith("mas 1.6.0 is not supported.")
    assert result.coverage.state == "partial" and "App Store: partial." in result.coverage.error


def test_a_missing_spotlight_index_is_partial_coverage(tmp_path):
    fake = FakeMas(list_code=1, list_err="Spotlight index is missing")
    _, result = collect_apps(tmp_path, lambda: inv.read_inventory(MAS, fake))
    item = next(i for i in result.items if i.name == "Keynote")
    assert item.state == "unknown" and item.note == "Spotlight cannot find App Store apps. App list can be incomplete."
    assert result.coverage.state == "partial"
    assert result.coverage.error.startswith("App Store: partial. Spotlight cannot find App Store apps.")


def test_an_app_that_mas_does_not_list_says_so(tmp_path):
    fake = FakeMas(listing='{"adamID":1,"bundleID":"other.app","name":"Other","version":"1"}\n')
    _, result = collect_apps(tmp_path, lambda: inv.read_inventory(MAS, fake))
    item = next(i for i in result.items if i.name == "Keynote")
    assert "adamId" not in item.attributes and item.note == inv.NOTE_NOT_LISTED


# Plan: the outdated check runs here


def test_plan_runs_outdated_for_one_app_and_shows_the_command():
    fake = FakeMas()
    plan = upd.make_plan("apps/com.apple.iWork.Keynote", "Keynote", KEYNOTE, "11.0", MAS, fake)
    assert fake.calls == [["version"], ["outdated", "--json", KEYNOTE]]
    assert plan.refusal is None and plan.kind == "mas"
    assert (plan.installed_version, plan.target_version) == ("11.0", "12.0")
    assert plan.command_text == f"{MAS} update {KEYNOTE}"
    assert plan.major_change is True and plan.scripts == []
    assert plan.rows == [{"label": "Scripts", "value": "Not used by App Store updates."}]


def test_a_minor_update_is_not_a_major_change():
    out = '{"adamID":1,"name":"A","newVersion":"2.1","version":"2.0"}\n'
    plan = upd.make_plan("apps/a", "A", "1", "2.0", MAS, FakeMas(outdated=out))
    assert plan.refusal is None and plan.major_change is False


def test_a_current_app_gets_the_up_to_date_text():
    plan = upd.make_plan("apps/a", "Numbers", "999", "5.2", MAS, FakeMas())
    assert plan.refusal == "Numbers is up to date (5.2)."


@pytest.mark.parametrize("fake,mas,refusal", [
    (FakeMas(), None, "Install mas with Homebrew to update App Store apps here."),
    (FakeMas(version="1.6.0"), MAS, "mas 1.6.0 is not supported. Watchtower needs mas 7.0.0 or a newer 7.x."),
    (FakeMas(outdated_code=1, outdated_err="Error: Not signed in to the App Store"), MAS,
     "Sign in to the App Store, then try again."),
    (FakeMas(outdated_code=1, outdated_err="Error: update requires root privileges"), MAS,
     "This update needs an administrator. Use the App Store app."),
    (FakeMas(outdated_code=1, outdated_err="Spotlight is off"), MAS,
     "Spotlight cannot find App Store apps. App list can be incomplete."),
    (FakeMas(outdated_code=1, outdated_err="boom"), MAS, "Watchtower cannot read the output of mas."),
    (FakeMas(outdated="not json"), MAS, "Watchtower cannot read the output of mas."),
])
def test_plan_states(fake, mas, refusal):
    plan = upd.make_plan("apps/k", "Keynote", KEYNOTE, "11.0", mas, fake)
    assert plan.refusal == refusal


def test_an_app_without_an_id_is_refused():
    plan = upd.make_plan("apps/k", "Keynote", None, "11.0", MAS, FakeMas())
    assert plan.refusal == "Watchtower does not know the App Store ID of Keynote."


# Confirmed update


class FakeRunner:
    def __init__(self, app=None, new_version=None, code=0, lines=("Downloading Keynote", "Installed")):
        self.app, self.new_version, self.code, self.lines, self.calls = app, new_version, code, lines, []

    def __call__(self, args, env, on_line):
        self.calls.append(list(args))
        for line in self.lines:
            on_line(line)
        if self.new_version:
            plist = self.app / "Contents" / "Info.plist"
            with open(plist, "wb") as f:
                plistlib.dump({"CFBundleIdentifier": "com.apple.iWork.Keynote",
                               "CFBundleShortVersionString": self.new_version}, f)
        return self.code


def seeded_store(tmp_path, app):
    store = Store(tmp_path / "data", clock=Clock(*[f"2026-10-29T10:{m:02d}:00Z" for m in range(60)]))
    r = store.begin_refresh()
    item = I("com.apple.iWork.Keynote", "apps", "Keynote", "unknown", kind="app", installed_version="11.0",
             origin="App Store", attributes={"adamId": KEYNOTE, "path": str(app)})
    store.finish_refresh(r.id, "complete", coverage=[C("apps", "Applications", "complete")], items=[item])
    return store


KEY = "apps/com.apple.iWork.Keynote"


def update(store, plan_id, runner, fake, **kw):
    return run_update(store, KEY, plan_id, mas=MAS, run=fake, runner=runner, **kw)


def test_plan_update_picks_mas_for_an_app_store_item(tmp_path):
    app = receipt_app(tmp_path, "Keynote.app", "com.apple.iWork.Keynote")
    store = seeded_store(tmp_path, app)
    fake = FakeMas()
    plan = updater.plan_update(store, KEY, mas=MAS, run=fake)
    assert plan.kind == "mas" and plan.command == [MAS, "update", KEYNOTE] and plan.target_version == "12.0"


def test_a_confirmed_update_is_verified_by_reading_the_version_again(tmp_path):
    app = receipt_app(tmp_path, "Keynote.app", "com.apple.iWork.Keynote")
    store, fake = seeded_store(tmp_path, app), FakeMas()
    plan = updater.plan_update(store, KEY, mas=MAS, run=fake)
    runner = FakeRunner(app, new_version="12.0")
    attempt, _ = update(store, plan.id, runner, fake, confirm_major=True)
    assert runner.calls == [[MAS, "update", KEYNOTE]]
    assert (attempt.status, attempt.before_version, attempt.after_version) == ("verified", "11.0", "12.0")
    assert attempt.command == [MAS, "update", KEYNOTE] and "Installed" in attempt.output
    assert [a.id for a in UpdateLog(store).attempts()] == [attempt.id]
    assert next(i for i in store.items() if i.source == "apps").installed_version == "12.0"


def test_exit_zero_without_the_new_version_is_not_verified(tmp_path):
    app = receipt_app(tmp_path, "Keynote.app", "com.apple.iWork.Keynote")
    store, fake = seeded_store(tmp_path, app), FakeMas()
    plan = updater.plan_update(store, KEY, mas=MAS, run=fake)
    attempt, _ = update(store, plan.id, FakeRunner(app), fake, confirm_major=True)
    assert attempt.status == "not_verified" and "still 11.0" in attempt.error


def test_a_major_version_needs_its_own_confirmation(tmp_path):
    app = receipt_app(tmp_path, "Keynote.app", "com.apple.iWork.Keynote")
    store, fake = seeded_store(tmp_path, app), FakeMas()
    plan = updater.plan_update(store, KEY, mas=MAS, run=fake)
    runner = FakeRunner(app, new_version="12.0")
    attempt, _ = update(store, plan.id, runner, fake)
    assert attempt.status == "refused" and runner.calls == []


def test_an_admin_failure_shows_the_admin_state(tmp_path):
    app = receipt_app(tmp_path, "Keynote.app", "com.apple.iWork.Keynote")
    store, fake = seeded_store(tmp_path, app), FakeMas()
    plan = updater.plan_update(store, KEY, mas=MAS, run=fake)
    runner = FakeRunner(app, code=1, lines=("Error: update requires root privileges",))
    attempt, _ = update(store, plan.id, runner, fake, confirm_major=True)
    assert attempt.status == "failed" and attempt.error == "This update needs an administrator. Use the App Store app."


def test_a_signed_out_failure_shows_the_sign_in_state(tmp_path):
    app = receipt_app(tmp_path, "Keynote.app", "com.apple.iWork.Keynote")
    store, fake = seeded_store(tmp_path, app), FakeMas()
    plan = updater.plan_update(store, KEY, mas=MAS, run=fake)
    runner = FakeRunner(app, code=1, lines=("Error: Not signed in to the App Store",))
    attempt, _ = update(store, plan.id, runner, fake, confirm_major=True)
    assert attempt.status == "failed" and attempt.error == "Sign in to the App Store, then try again."


def test_a_changed_plan_is_not_run(tmp_path):
    app = receipt_app(tmp_path, "Keynote.app", "com.apple.iWork.Keynote")
    store, fake = seeded_store(tmp_path, app), FakeMas()
    runner = FakeRunner(app, new_version="12.0")
    attempt, _ = update(store, "stale-plan-id", runner, fake, confirm_major=True)
    assert attempt.status == "plan_changed" and runner.calls == []
