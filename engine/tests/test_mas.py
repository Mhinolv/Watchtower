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
WARNING = (FIX / "stderr.txt").read_text()  # Real: mas warns about Spotlight and still exits 0 with full output.
MAS = "/fake/mas"
BEAR = "1091189122"


class FakeMas:
    """Answers mas calls from fixtures and records them. Never starts a process."""

    def __init__(self, version=VERSION, listing=LIST, outdated=OUTDATED, list_code=0, outdated_code=0,
                 list_err=WARNING, outdated_err=WARNING):
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


def test_the_real_list_is_read_and_the_record_without_ids_is_skipped():
    # Real mas 7.0.0 output: the first record is {"name":""}.
    assert LIST.splitlines()[0] == '{"name":""}'
    parsed = inv.parse_list(LIST)
    assert [(a.adam_id, a.bundle_id, a.name, a.version) for a in parsed] == [
        ("1091189122", "net.shinyfrog.bear", "Bear", "2.9.4"),
        ("1056643111", "com.abhishek.Clocker", "Clocker", "26.16"),
        ("634148309", "com.apple.logic10", "Logic Pro", "12.3.1"),
        ("1183407767", "com.coderforart.iOS.MWeb", "MWeb", "4.8.2"),
        ("409203825", "com.apple.iWork.Numbers", "Numbers", "14.5"),
        ("490179405", "com.okta.mobile", "Okta Verify", "9.69.0"),
    ]


def test_the_real_outdated_list_is_read():
    parsed = inv.parse_outdated(OUTDATED)
    assert [(o.adam_id, o.name, o.version, o.new_version) for o in parsed] == [
        ("1091189122", "Bear", "2.9.4", "3.0.3"), ("1056643111", "Clocker", "26.16", "26.19"),
        ("634148309", "Logic Pro", "12.3.1", "12.4"), ("1183407767", "MWeb", "4.8.2", "4.8.3"),
        ("490179405", "Okta Verify", "9.69.0", "9.73.0")]


def test_only_the_blank_record_of_real_mas_is_skipped():
    blank = '{"name":""}\n'
    good = '{"adamID":2,"bundleID":"c.d","name":"Z","version":"3"}\n'
    assert [a.adam_id for a in inv.parse_list(blank + good)] == ["2"]
    assert inv.parse_outdated(blank + '{"adamID":2,"name":"Z","version":"3","newVersion":"4"}\n')[0].adam_id == "2"
    assert inv.parse_list(blank) == [] and inv.parse_outdated(blank) == []


@pytest.mark.parametrize("record", [
    '{"error":"x"}', '{"name":"Bear"}', '{"name":"","extra":1}', '{"name":null}', '{}',
    '{"adamID":"--help","bundleID":"a.b","name":"X","version":"1"}',
    '{"adamID":1,"bundleID":"","name":"Y","version":"1"}', '{"adamID":"","bundleID":"a.b","name":"Y","version":"1"}'])
def test_any_other_record_without_a_valid_id_makes_the_parse_fail(record):
    with pytest.raises(ValueError):
        inv.parse_list(record)
    with pytest.raises(ValueError):
        inv.parse_outdated(record)


def test_an_error_object_with_exit_zero_is_not_up_to_date_and_not_an_empty_inventory():
    error = '{"error":"x"}\n'
    plan = upd.make_plan("apps/b", "Bear", BEAR, "2.9.4", MAS, FakeMas(outdated=error))
    assert plan.refusal == "Watchtower cannot read the output of mas."
    result = inv.read_inventory(MAS, FakeMas(listing=error))
    assert result.status == "failed" and result.apps == {}


def test_an_array_and_an_empty_answer_are_read_too():
    assert len(inv.parse_list('[{"adamID": 1, "bundleID": "a.b", "name": "A", "version": "1"}]')) == 1
    assert inv.parse_list("") == [] and inv.parse_outdated("\n") == []


@pytest.mark.parametrize("text", ["not json", '{"adamID": 1, "bundleID": "a.b", "name": "A"}', '{"adamID": 1, "bundleID": "a",'
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
    assert result.apps["net.shinyfrog.bear"].adam_id == BEAR


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


def receipt_app(root, rel, bundle_id, version="2.9.4"):
    app = make_app(root, rel, bundle_id=bundle_id, version=version)
    (app / "Contents" / "_MASReceipt").mkdir()
    (app / "Contents" / "_MASReceipt" / "receipt").write_bytes(b"\0")
    return app


def collect_apps(tmp_path, mas_reader, with_receipt=True):
    make = receipt_app if with_receipt else make_app
    app = make(tmp_path, "Bear.app", "net.shinyfrog.bear")
    make_app(tmp_path, "Manual.app", bundle_id="com.example.manual")
    return app, apps.collect((str(tmp_path),), mas_reader=mas_reader)


def test_an_app_with_a_receipt_is_an_app_store_app(tmp_path):
    fake = FakeMas()
    app, result = collect_apps(tmp_path, lambda: inv.read_inventory(MAS, fake))
    item = next(i for i in result.items if i.name == "Bear")
    assert (item.origin, item.state, item.latest_version) == ("App Store", "unknown", None)
    assert item.attributes["adamId"] == BEAR and item.attributes["path"] == str(app)
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
    item = next(i for i in result.items if i.name == "Bear")
    assert (item.origin, item.state, item.note) == ("App Store", "manual",
                                                    "Install mas with Homebrew to update App Store apps here.")
    assert result.coverage.state == "complete"


def test_unsupported_mas_is_an_error_state(tmp_path):
    _, result = collect_apps(tmp_path, lambda: inv.read_inventory(MAS, FakeMas(version="1.6.0")))
    item = next(i for i in result.items if i.name == "Bear")
    assert item.state == "error" and item.error.startswith("mas 1.6.0 is not supported.")
    assert result.coverage.state == "partial" and "App Store: partial." in result.coverage.error


def test_a_missing_spotlight_index_is_partial_coverage(tmp_path):
    fake = FakeMas(list_code=1, list_err="Spotlight index is missing")
    _, result = collect_apps(tmp_path, lambda: inv.read_inventory(MAS, fake))
    item = next(i for i in result.items if i.name == "Bear")
    assert item.state == "unknown" and item.note == "Spotlight cannot find App Store apps. App list can be incomplete."
    assert result.coverage.state == "partial"
    assert result.coverage.error.startswith("App Store: partial. Spotlight cannot find App Store apps.")


def test_an_app_that_mas_does_not_list_says_so(tmp_path):
    fake = FakeMas(listing='{"adamID":1,"bundleID":"other.app","name":"Other","version":"1"}\n')
    _, result = collect_apps(tmp_path, lambda: inv.read_inventory(MAS, fake))
    item = next(i for i in result.items if i.name == "Bear")
    assert "adamId" not in item.attributes and item.note == inv.NOTE_NOT_LISTED


# Plan: the outdated check runs here


def test_plan_runs_outdated_for_one_app_and_shows_the_command():
    fake = FakeMas()
    plan = upd.make_plan("apps/net.shinyfrog.bear", "Bear", BEAR, "2.9.4", MAS, fake)
    assert fake.calls == [["version"], ["outdated", "--json", BEAR]]
    assert plan.refusal is None and plan.kind == "mas"
    assert (plan.installed_version, plan.target_version) == ("2.9.4", "3.0.3")
    assert plan.command_text == f"{MAS} update {BEAR}"
    assert plan.major_change is True and plan.scripts == []
    assert plan.rows == [{"label": "Scripts", "value": "Not used by App Store updates."}]


def test_a_minor_update_is_not_a_major_change():
    out = '{"adamID":1,"name":"A","newVersion":"2.1","version":"2.0"}\n'
    plan = upd.make_plan("apps/a", "A", "1", "2.0", MAS, FakeMas(outdated=out))
    assert plan.refusal is None and plan.major_change is False


def test_a_current_app_gets_the_up_to_date_text():
    plan = upd.make_plan("apps/a", "Numbers", "409203825", "14.5", MAS, FakeMas())
    assert plan.refusal == "Numbers is up to date (14.5)."


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
    plan = upd.make_plan("apps/k", "Bear", BEAR, "2.9.4", mas, fake)
    assert plan.refusal == refusal


def test_an_app_without_an_id_is_refused():
    plan = upd.make_plan("apps/k", "Bear", None, "2.9.4", MAS, FakeMas())
    assert plan.refusal == "Watchtower does not know the App Store ID of Bear."


# Confirmed update


class FakeRunner:
    def __init__(self, app=None, new_version=None, code=0, lines=("Downloading Bear", "Installed")):
        self.app, self.new_version, self.code, self.lines, self.calls = app, new_version, code, lines, []

    def __call__(self, args, env, on_line):
        self.calls.append(list(args))
        for line in self.lines:
            on_line(line)
        if self.new_version:
            plist = self.app / "Contents" / "Info.plist"
            with open(plist, "wb") as f:
                plistlib.dump({"CFBundleIdentifier": "net.shinyfrog.bear",
                               "CFBundleShortVersionString": self.new_version}, f)
        return self.code


def seeded_store(tmp_path, app):
    store = Store(tmp_path / "data", clock=Clock(*[f"2026-10-29T10:{m:02d}:00Z" for m in range(60)]))
    r = store.begin_refresh()
    item = I("net.shinyfrog.bear", "apps", "Bear", "unknown", kind="app", installed_version="2.9.4",
             origin="App Store", attributes={"adamId": BEAR, "path": str(app)})
    store.finish_refresh(r.id, "complete", coverage=[C("apps", "Applications", "complete")], items=[item])
    return store


KEY = "apps/net.shinyfrog.bear"


def update(store, plan_id, runner, fake, **kw):
    return run_update(store, KEY, plan_id, mas=MAS, run=fake, runner=runner, **kw)


def test_plan_update_picks_mas_for_an_app_store_item(tmp_path):
    app = receipt_app(tmp_path, "Bear.app", "net.shinyfrog.bear")
    store = seeded_store(tmp_path, app)
    fake = FakeMas()
    plan = updater.plan_update(store, KEY, mas=MAS, run=fake)
    assert plan.kind == "mas" and plan.command == [MAS, "update", BEAR] and plan.target_version == "3.0.3"


def test_a_confirmed_update_is_verified_by_reading_the_version_again(tmp_path):
    app = receipt_app(tmp_path, "Bear.app", "net.shinyfrog.bear")
    store, fake = seeded_store(tmp_path, app), FakeMas()
    plan = updater.plan_update(store, KEY, mas=MAS, run=fake)
    runner = FakeRunner(app, new_version="3.0.3")
    attempt, _ = update(store, plan.id, runner, fake, confirm_major=True)
    assert runner.calls == [[MAS, "update", BEAR]]
    assert (attempt.status, attempt.before_version, attempt.after_version) == ("verified", "2.9.4", "3.0.3")
    assert attempt.command == [MAS, "update", BEAR] and "Installed" in attempt.output
    assert [a.id for a in UpdateLog(store).attempts()] == [attempt.id]
    assert next(i for i in store.items() if i.source == "apps").installed_version == "3.0.3"


def test_exit_zero_without_the_new_version_is_not_verified(tmp_path):
    app = receipt_app(tmp_path, "Bear.app", "net.shinyfrog.bear")
    store, fake = seeded_store(tmp_path, app), FakeMas()
    plan = updater.plan_update(store, KEY, mas=MAS, run=fake)
    attempt, _ = update(store, plan.id, FakeRunner(app), fake, confirm_major=True)
    assert attempt.status == "not_verified" and "still 2.9.4" in attempt.error


def test_a_major_version_needs_its_own_confirmation(tmp_path):
    app = receipt_app(tmp_path, "Bear.app", "net.shinyfrog.bear")
    store, fake = seeded_store(tmp_path, app), FakeMas()
    plan = updater.plan_update(store, KEY, mas=MAS, run=fake)
    runner = FakeRunner(app, new_version="3.0.3")
    attempt, _ = update(store, plan.id, runner, fake)
    assert attempt.status == "refused" and runner.calls == []


def test_an_admin_failure_shows_the_admin_state(tmp_path):
    app = receipt_app(tmp_path, "Bear.app", "net.shinyfrog.bear")
    store, fake = seeded_store(tmp_path, app), FakeMas()
    plan = updater.plan_update(store, KEY, mas=MAS, run=fake)
    runner = FakeRunner(app, code=1, lines=("Error: update requires root privileges",))
    attempt, _ = update(store, plan.id, runner, fake, confirm_major=True)
    assert attempt.status == "failed" and attempt.error == "This update needs an administrator. Use the App Store app."


def test_a_signed_out_failure_shows_the_sign_in_state(tmp_path):
    app = receipt_app(tmp_path, "Bear.app", "net.shinyfrog.bear")
    store, fake = seeded_store(tmp_path, app), FakeMas()
    plan = updater.plan_update(store, KEY, mas=MAS, run=fake)
    runner = FakeRunner(app, code=1, lines=("Error: Not signed in to the App Store",))
    attempt, _ = update(store, plan.id, runner, fake, confirm_major=True)
    assert attempt.status == "failed" and attempt.error == "Sign in to the App Store, then try again."


def test_a_changed_plan_is_not_run(tmp_path):
    app = receipt_app(tmp_path, "Bear.app", "net.shinyfrog.bear")
    store, fake = seeded_store(tmp_path, app), FakeMas()
    runner = FakeRunner(app, new_version="3.0.3")
    attempt, _ = update(store, "stale-plan-id", runner, fake, confirm_major=True)
    assert attempt.status == "plan_changed" and runner.calls == []


# Real mas output (#13 round 2): a warning on stderr, exit 0, full output


def test_the_real_spotlight_warning_is_not_a_limit():
    assert inv.classify(WARNING) is None


def test_a_warning_with_exit_zero_and_full_output_is_not_an_error():
    fake = FakeMas()
    result = inv.read_inventory(MAS, fake)
    assert result.status == "ok" and len(result.apps) == 6
    plan = upd.make_plan("apps/b", "Bear", BEAR, "2.9.4", MAS, fake)
    assert plan.refusal is None and plan.target_version == "3.0.3"


def test_the_real_list_gives_every_app_an_id(tmp_path):
    app = receipt_app(tmp_path, "Bear.app", "net.shinyfrog.bear")
    result = apps.collect((str(tmp_path),), mas_reader=lambda: inv.read_inventory(MAS, FakeMas()))
    [item] = result.items
    assert item.attributes["adamId"] == BEAR and item.state == "unknown" and result.coverage.state == "complete"


@pytest.mark.parametrize("text,state", [
    (WARNING + "\nError: Not signed in to the App Store", "signed_out"),
    (WARNING + "\nError: update requires root privileges", "admin"),
    (WARNING + "\nError: something else", None),
    ("Error: Spotlight Metadata Service returned nothing", "spotlight"),
])
def test_the_warning_does_not_hide_a_real_failure(text, state):
    assert inv.classify(text) == state


def test_a_failed_outdated_with_the_warning_shows_the_sign_in_state():
    fake = FakeMas(outdated_code=1, outdated_err=WARNING + "\nError: Not signed in to the App Store")
    plan = upd.make_plan("apps/b", "Bear", BEAR, "2.9.4", MAS, fake)
    assert plan.refusal == "Sign in to the App Store, then try again."
    assert upd.failure_message(WARNING + "\nError: Not signed in to the App Store") == plan.refusal


def test_exit_zero_with_no_output_and_a_sign_in_limit_is_not_up_to_date():
    fake = FakeMas(outdated="", outdated_err=WARNING + "\nNot signed in to the App Store")
    plan = upd.make_plan("apps/b", "Bear", BEAR, "2.9.4", MAS, fake)
    assert plan.refusal == "Sign in to the App Store, then try again."
    # With only the real warning, an empty answer is still "up to date".
    ok = upd.make_plan("apps/b", "Bear", BEAR, "2.9.4", MAS, FakeMas(outdated=""))
    assert ok.refusal == "Bear is up to date (2.9.4)."


@pytest.mark.parametrize("bad", ["--help", "12a", "", "1 2"])
def test_an_id_that_is_not_digits_never_becomes_a_command(bad):
    fake = FakeMas()
    plan = upd.make_plan("apps/b", "Bear", bad or None, "2.9.4", MAS, fake)
    assert plan.refusal == "Watchtower does not know the App Store ID of Bear."
    assert fake.calls == []
