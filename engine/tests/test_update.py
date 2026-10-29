import json
import os
import subprocess
import sys

import pytest

from watchtower_engine import cli, updater
from watchtower_engine.models import CoverageRecord as C
from watchtower_engine.models import ItemRecord as I
from watchtower_engine.store import Store
from watchtower_engine.update_log import UpdateLog
from watchtower_engine.updater import Interrupted, UpdateError, plan_update, run_update
from watchtower_engine.updates import homebrew as hb

from contract import Clock

BREW = "/fake/brew"
MAC = {"machine": "arm64", "macos": 15}


def formula(version="2.46.0", stable="2.47.1", **extra):
    entry = {
        "name": "git", "full_name": "git", "tap": "homebrew/core", "versions": {"stable": stable},
        "revision": 0, "installed": [{"version": version}], "linked_keg": version, "pinned": False,
        "bottle": {"stable": {"files": {"arm64_sequoia": {}, "sonoma": {}}}}, "post_install_defined": False,
        "service": None,
    }
    entry.update(extra)
    return entry


def cask(installed="1.2", version="1.3", **extra):
    entry = {"token": "fluff", "full_token": "fluff", "tap": "homebrew/cask", "name": ["Fluff"],
             "version": version, "installed": installed, "auto_updates": False, "artifacts": [{"app": ["Fluff.app"]}]}
    entry.update(extra)
    return entry


class FakeBrew:
    """Answers `brew info` and `brew upgrade --dry-run`. Never starts a process."""

    def __init__(self, entry, kind="formula", dry_run=None, dry_code=0):
        self.entry, self.kind = entry, kind
        name = entry.get("name") if kind == "formula" else entry.get("token")
        target = hb.candidate_version(kind, entry)
        self.dry_run = dry_run if dry_run is not None else (
            f"==> Would upgrade 1 outdated package:\n{name} {hb.installed_version(kind, entry)} -> {target}\n")
        self.dry_code = dry_code
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        assert kwargs["env"]["HOMEBREW_NO_AUTO_UPDATE"] == "1"
        if args[1] == "info":
            key = "formulae" if self.kind == "formula" else "casks"
            return subprocess.CompletedProcess(args, 0, json.dumps({key: [self.entry]}), "")
        if args[1:3] == ["upgrade", "--dry-run"]:
            return subprocess.CompletedProcess(args, self.dry_code, self.dry_run, "")
        raise AssertionError(f"unexpected brew call {args}")

    def install(self, version):
        """What a real upgrade would leave behind."""
        if self.kind == "formula":
            self.entry["installed"] = [{"version": version}]
            self.entry["linked_keg"] = version
        else:
            self.entry["installed"] = version


class FakeRunner:
    def __init__(self, brew=None, new_version=None, code=0, lines=("==> Upgrading git", "done"), raise_exc=None):
        self.brew, self.new_version, self.code, self.lines, self.raise_exc = brew, new_version, code, lines, raise_exc
        self.calls = []

    def __call__(self, args, env, on_line):
        self.calls.append((list(args), env))
        for line in self.lines:
            on_line(line)
        if self.raise_exc:
            raise self.raise_exc
        if self.new_version and self.brew:
            self.brew.install(self.new_version)
        return self.code


def seeded(tmp_path, key="formula:git", latest="2.47.1", installed="2.46.0", kind="formula"):
    store = Store(tmp_path, clock=Clock(*[f"2026-10-29T10:{m:02d}:00Z" for m in range(60)]))
    r = store.begin_refresh()
    store.finish_refresh(r.id, "complete", coverage=[C("homebrew", "Homebrew", "complete")],
                         items=[I(key, "homebrew", key.split(":")[1], "update_available", kind=kind,
                                  installed_version=installed, latest_version=latest)])
    return store


def plan(store, brew, key="homebrew/formula:git", **kw):
    return plan_update(store, key, brew=BREW, run=brew, **{**MAC, **kw})


def run(store, brew, runner, plan_id, key="homebrew/formula:git", **kw):
    return run_update(store, key, plan_id, brew=BREW, run=brew, runner=runner, **{**MAC, **kw})


# Plan


def test_plan_shows_exact_command_and_dependency_scope(tmp_path):
    brew = FakeBrew(formula(), dry_run=(
        "==> Would upgrade 1 outdated package:\ngit 2.46.0 -> 2.47.1\n"
        "==> Would install 1 new dependency for git:\npcre2 10.44\n"
        "==> Would upgrade 1 dependent of upgraded formulae:\n"
        "Disable this behaviour by setting HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK.\n"
        "git-lfs 3.5.1 -> 3.5.1_1\n"))
    p = plan(seeded(tmp_path), brew)
    d = p.to_dict()
    assert d["command"] == ["/fake/brew", "upgrade", "--formula", "git"]
    assert d["command_text"] == "/fake/brew upgrade --formula git"
    assert (d["installed_version"], d["target_version"]) == ("2.46.0", "2.47.1")
    assert d["also_changes"] == [
        {"name": "pcre2", "before": None, "after": "10.44", "change": "install"},
        {"name": "git-lfs", "before": "3.5.1", "after": "3.5.1_1", "change": "upgrade"},
    ]
    assert d["refusal"] is None and d["scripts"] == [] and d["major_change"] is False
    assert len(d["id"]) == 16 and d["id"] == p.id
    assert ["/fake/brew", "upgrade", "--dry-run", "--formula", "git"] in brew.calls
    assert not any(c[1:3] == ["upgrade", "--formula"] for c in brew.calls)  # planning never upgrades


def test_plan_never_names_more_than_one_package(tmp_path):
    p = plan(seeded(tmp_path), FakeBrew(formula()))
    assert p.command[-1] == "git" and "--greedy" not in p.command and len(p.command) == 4


def test_major_version_is_marked(tmp_path):
    brew = FakeBrew(formula(stable="3.0.0"))
    p = plan(seeded(tmp_path, latest="3.0.0"), brew)
    assert p.major_change and p.refusal is None


@pytest.mark.parametrize("entry,kind,reasons", [
    (formula(bottle={"stable": {"files": {"arm64_ventura": {}}}}), "formula", []),  # older macOS bottle fits
    (formula(bottle={"stable": {"files": {"all": {}}}}), "formula", []),
    (formula(bottle={"stable": {"files": {"sonoma": {}}}}), "formula", [hb.SCRIPT_BUILD]),  # Intel only
    (formula(bottle={}), "formula", [hb.SCRIPT_BUILD]),
    (formula(post_install_defined=True), "formula", [hb.SCRIPT_POST_INSTALL]),
    (cask(artifacts=[{"pkg": ["x.pkg"]}, {"installer": [{"script": "x"}]}]), "cask", [hb.SCRIPT_PKG, hb.SCRIPT_INSTALLER]),
])
def test_scripts_and_builds_are_found(entry, kind, reasons):
    assert hb.script_reasons(kind, entry, machine="arm64", macos=15) == reasons


@pytest.mark.parametrize("entry,latest,dry_run,refusal", [
    (formula(pinned=True), "2.47.1", None, hb.REFUSE_PINNED),
    (formula(tap="acme/tools"), "2.47.1", None, "Watchtower cannot check tap acme/tools."),
    (formula(installed=[], linked_keg=None), "2.47.1", None, "Homebrew does not list git as installed."),
    (formula(stable="2.46.0"), "2.46.0", None, "Homebrew has no newer version of git."),
    (formula(stable="2.46.0"), "2.47.1", None, hb.REFUSE_BEHIND),
    (formula(stable="2.47.0"), "2.47.1", None, hb.REFUSE_BEHIND),
    (formula(), "2.47.1", "==> Would upgrade:\nsomething strange happened\n", hb.REFUSE_UNREADABLE),
    (formula(), "2.47.1", "git 2.46.0 -> 2.48.0\n", hb.REFUSE_UNREADABLE),
])
def test_plan_refusals(tmp_path, entry, latest, dry_run, refusal):
    p = plan(seeded(tmp_path, latest=latest), FakeBrew(entry, dry_run=dry_run))
    assert p.refusal == refusal


def test_cask_plan_and_self_updating_cask(tmp_path):
    store = seeded(tmp_path, key="cask:fluff", latest="1.3", installed="1.2", kind="cask")
    p = plan(store, FakeBrew(cask(), kind="cask"), key="homebrew/cask:fluff")
    assert p.command == ["/fake/brew", "upgrade", "--cask", "fluff"]
    assert p.manual_steps == ["Quit and reopen Fluff if it is open."]
    auto = plan(store, FakeBrew(cask(auto_updates=True), kind="cask"), key="homebrew/cask:fluff")
    assert auto.refusal == hb.REFUSE_AUTO_UPDATES


def test_only_homebrew_items_can_update(tmp_path):
    store = seeded(tmp_path)
    with pytest.raises(UpdateError):
        plan_update(store, "apps/com.example.legacy", brew=BREW, run=FakeBrew(formula()))
    with pytest.raises(UpdateError):
        plan_update(store, "homebrew/formula:missing", brew=BREW, run=FakeBrew(formula()))


# Run and verify


def test_verified_update_logs_everything_and_updates_the_item(tmp_path):
    store = seeded(tmp_path)
    brew = FakeBrew(formula())
    runner = FakeRunner(brew, new_version="2.47.1")
    seen = []
    attempt, _ = run_update(store, "homebrew/formula:git", plan(store, brew).id, brew=BREW, run=brew,
                            runner=runner, on_line=seen.append, **MAC)
    assert attempt.status == "verified"
    assert (attempt.before_version, attempt.target_version, attempt.after_version) == ("2.46.0", "2.47.1", "2.47.1")
    assert attempt.command == ["/fake/brew", "upgrade", "--formula", "git"]
    assert attempt.output == "==> Upgrading git\ndone" and seen == ["==> Upgrading git", "done"]
    assert attempt.exit_code == 0 and attempt.error is None and attempt.finished_at
    assert runner.calls[0][0] == attempt.command
    assert runner.calls[0][1]["HOMEBREW_NO_AUTO_UPDATE"] == "1"
    git = next(i for i in store.items() if i.id == "formula:git")
    assert (git.installed_version, git.state) == ("2.47.1", "up_to_date")


def test_exit_zero_with_unchanged_version_is_not_verified(tmp_path):
    store = seeded(tmp_path)
    brew = FakeBrew(formula())
    attempt, _ = run(store, brew, FakeRunner(brew, new_version=None), plan(store, brew).id)
    assert attempt.status == "not_verified" and attempt.exit_code == 0
    assert attempt.after_version == "2.46.0"
    assert attempt.error == "The command finished, but the installed version is still 2.46.0."
    assert next(i for i in store.items() if i.id == "formula:git").state == "update_available"


def test_other_version_after_the_run_is_not_verified(tmp_path):
    store = seeded(tmp_path)
    brew = FakeBrew(formula())
    attempt, _ = run(store, brew, FakeRunner(brew, new_version="2.47.0"), plan(store, brew).id)
    assert attempt.status == "not_verified"


def test_non_zero_exit_fails(tmp_path):
    store = seeded(tmp_path)
    brew = FakeBrew(formula())
    attempt, _ = run(store, brew, FakeRunner(brew, code=1), plan(store, brew).id)
    assert attempt.status == "failed" and attempt.exit_code == 1
    assert attempt.error == "The update failed (exit code 1)."


def test_changed_plan_does_not_run(tmp_path):
    store = seeded(tmp_path)
    brew = FakeBrew(formula())
    confirmed = plan(store, brew)
    # Homebrew data changes after the owner saw the plan: a newer target.
    brew.entry["versions"]["stable"] = "2.47.2"
    brew.dry_run = "git 2.46.0 -> 2.47.2\n"
    runner = FakeRunner(brew, new_version="2.47.2")
    attempt, new_plan = run(store, brew, runner, confirmed.id)
    assert attempt.status == "plan_changed"
    assert attempt.error == "The plan changed. Review the new plan."
    assert runner.calls == []
    assert new_plan["target_version"] == "2.47.2" and new_plan["id"] != confirmed.id


def test_major_and_scripts_need_their_own_confirmation(tmp_path):
    store = seeded(tmp_path, latest="3.0.0")
    brew = FakeBrew(formula(stable="3.0.0", post_install_defined=True))
    p = plan(store, brew)
    runner = FakeRunner(brew, new_version="3.0.0")
    first, _ = run(store, brew, runner, p.id)
    assert (first.status, first.error) == ("refused", "A new major version needs its own confirmation.")
    second, _ = run(store, brew, runner, p.id, confirm_major=True)
    assert (second.status, second.error) == ("refused", "This update needs install scripts. Confirm them first.")
    assert runner.calls == []
    third, _ = run(store, brew, runner, p.id, confirm_major=True, confirm_scripts=True)
    assert third.status == "verified" and third.confirmed_major and third.confirmed_scripts


def test_refused_plan_is_logged_and_not_run(tmp_path):
    store = seeded(tmp_path)
    brew = FakeBrew(formula(pinned=True))
    runner = FakeRunner(brew)
    attempt, _ = run(store, brew, runner, plan(store, brew).id)
    assert attempt.status == "refused" and attempt.error == hb.REFUSE_PINNED
    assert runner.calls == []


def test_interrupted_update_is_logged(tmp_path):
    store = seeded(tmp_path)
    brew = FakeBrew(formula())
    with pytest.raises(Interrupted):
        run(store, brew, FakeRunner(brew, raise_exc=Interrupted()), plan(store, brew).id)
    (attempt,) = UpdateLog(store).attempts()
    assert attempt.status == "interrupted" and attempt.output == "==> Upgrading git\ndone"


def test_running_row_of_a_dead_engine_reads_interrupted(tmp_path):
    store = seeded(tmp_path)
    brew = FakeBrew(formula())
    log = UpdateLog(store)
    attempt_id = log.begin(plan(store, brew), False, False)
    store.db.execute("UPDATE update_attempts SET pid = 999999 WHERE id = ?", (attempt_id,))
    assert log.attempts()[0].status == "interrupted"
    store.db.execute("UPDATE update_attempts SET pid = ? WHERE id = ?", (os.getpid(), attempt_id))
    assert log.attempts()[0].status == "running"


def test_every_attempt_is_logged_newest_first(tmp_path):
    store = seeded(tmp_path)
    brew = FakeBrew(formula())
    p = plan(store, brew)
    run(store, brew, FakeRunner(brew, code=1), p.id)
    run(store, brew, FakeRunner(brew, new_version=None), p.id)
    run(store, brew, FakeRunner(brew, new_version="2.47.1"), p.id)
    assert [a.status for a in UpdateLog(store).attempts()] == ["verified", "not_verified", "failed"]


def test_log_keeps_the_end_of_long_output(tmp_path, monkeypatch):
    monkeypatch.setattr("watchtower_engine.update_log.OUTPUT_MAX_CHARS", 10)
    store = seeded(tmp_path)
    brew = FakeBrew(formula())
    attempt, _ = run(store, brew, FakeRunner(brew, lines=["a" * 50, "the end"]), plan(store, brew).id)
    assert attempt.output == ("a" * 50 + "\nthe end")[-10:]


# Streaming runner (real, /bin/sh only)


def test_run_streaming_reports_lines_and_exit_code():
    lines = []
    code = hb.run_streaming(["/bin/sh", "-c", "echo one; echo two >&2; printf last; exit 3"], dict(os.environ),
                            lines.append, poll=0.01)
    assert code == 3 and lines == ["one", "two", "last"]


def test_parse_dry_run_reads_install_lists():
    changes = hb.parse_dry_run("==> Would install 2 new dependencies:\npcre2, zstd 1.5\n")
    assert [(c.name, c.after, c.change) for c in changes] == [("pcre2", None, "install"), ("zstd", "1.5", "install")]


# CLI


@pytest.fixture
def fake_cli(tmp_path, monkeypatch):
    store = seeded(tmp_path)
    store.close()
    brew = FakeBrew(formula())
    runner = FakeRunner(brew, new_version="2.47.1")
    real_plan = updater.plan_update
    monkeypatch.setattr(updater, "plan_update",
                        lambda store, item, *a, **k: real_plan(store, item, brew=BREW, run=brew, **MAC))
    real_run = updater.run_update
    monkeypatch.setattr(updater, "run_update", lambda store, item, plan_id, cm, cs, out: real_run(
        store, item, plan_id, cm, cs, out, brew=BREW, run=brew, runner=runner, **MAC))
    return tmp_path


def test_cli_plan_run_and_log(fake_cli, capsys):
    data = str(fake_cli)
    assert cli.main(["--data-dir", data, "update-plan", "homebrew/formula:git"]) == 0
    p = json.loads(capsys.readouterr().out)["plan"]
    assert p["command_text"] == "/fake/brew upgrade --formula git"
    assert cli.main(["--data-dir", data, "update-run", "homebrew/formula:git", "--plan-id", p["id"]]) == 0
    captured = capsys.readouterr()
    out = json.loads(captured.out)
    assert out["attempt"]["status"] == "verified" and out["plan"]["id"] == p["id"]
    assert [json.loads(l)["output"] for l in captured.err.splitlines()] == ["==> Upgrading git", "done"]
    assert cli.main(["--data-dir", data, "update-log"]) == 0
    log = json.loads(capsys.readouterr().out)["attempts"]
    assert [a["status"] for a in log] == ["verified"]


def test_cli_rejects_items_that_cannot_update(fake_cli, capsys):
    assert cli.main(["--data-dir", str(fake_cli), "update-plan", "apps/com.example.x"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err)["error"] == "Watchtower can update Homebrew formulae and casks only."


# Fix round 2 (QA non-blocking items, main answer 109)


@pytest.mark.parametrize("artifact", [
    {"preflight": None}, {"postflight": None}, {"uninstall_preflight": None}, {"uninstall_postflight": None},
])
def test_cask_preflight_and_postflight_are_scripts(artifact):
    entry = cask(artifacts=[{"app": ["Fluff.app"]}, artifact])
    assert hb.script_reasons("cask", entry, machine="arm64", macos=15) == [hb.SCRIPT_FLIGHT]


def test_cask_with_postflight_needs_scripts_confirmation(tmp_path):
    store = seeded(tmp_path, key="cask:fluff", latest="1.3", installed="1.2", kind="cask")
    brew = FakeBrew(cask(artifacts=[{"app": ["Fluff.app"]}, {"postflight": None}]), kind="cask")
    p = plan(store, brew, key="homebrew/cask:fluff")
    assert p.scripts == [hb.SCRIPT_FLIGHT]
    runner = FakeRunner(brew, new_version="1.3")
    attempt, _ = run(store, brew, runner, p.id, key="homebrew/cask:fluff")
    assert attempt.status == "refused" and runner.calls == []


def test_moved_to_another_version_does_not_say_still(tmp_path):
    store = seeded(tmp_path)
    brew = FakeBrew(formula())
    attempt, _ = run(store, brew, FakeRunner(brew, new_version="2.47.0"), plan(store, brew).id)
    assert attempt.status == "not_verified"
    assert attempt.error == "The command finished, but the installed version is 2.47.0, not 2.47.1."
