"""#15: the Cargo update adapter. Real cargo 1.98 output (fixtures/cargo/README.md), no network."""
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from watchtower_engine import findings
from watchtower_engine.models import CoverageRecord as C
from watchtower_engine.scanners import osv
from watchtower_engine.scanners.osv import Lockfile, Match, OsvResult, ProjectScan
from watchtower_engine.scope import list_projects
from watchtower_engine.store import Store
from watchtower_engine.update_log import UpdateLog
from watchtower_engine.updater import ERROR_NEEDS_MAJOR, plan_update, run_update
from watchtower_engine.updates import cargo

from contract import Clock

FIX = Path(__file__).parent / "fixtures" / "cargo"
CARGO = "/fake/cargo"
DRY_RUN = (FIX / "update-dry-run.stderr").read_text()
RUN_OUT = (FIX / "update-run.stderr").read_text()
LOCK_AFTER = (FIX / "tool-Cargo.lock.after").read_text()
KEY = cargo.make_key("serde", "1.0.210", "~/Projects/tool", "Cargo.lock")


def make_project(tmp_path, name="tool", source="tool", toml=None, lock=None):
    root = tmp_path / "home" / "Projects" / name
    shutil.copytree(FIX / source, root)
    (root / "src").mkdir(exist_ok=True)
    (root / "src" / "main.rs").write_text("fn main() {}\n")
    if toml is not None:
        (root / "Cargo.toml").write_text(toml)
    if lock is not None:
        (root / "Cargo.lock").write_text(lock)
    return root


class FakeCargo:
    """Answers `cargo update --dry-run` with real cargo output. Never starts a process."""

    def __init__(self, err=DRY_RUN, code=0):
        self.err, self.code, self.calls = err, code, []

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), kwargs))
        assert "--dry-run" in args and args[1] == "update"
        assert kwargs["env"]["CARGO_TERM_COLOR"] == "never"
        assert not [k for k in kwargs["env"] if k.startswith("CARGO_") and k not in ("CARGO_TERM_COLOR", "CARGO_TERM_PROGRESS_WHEN")]
        return subprocess.CompletedProcess(args, self.code, "", self.err)


class FakeUpdate:
    """Stands in for the cargo process. `mode` says what it leaves behind."""

    def __init__(self, root, mode="ok", code=0):
        self.root, self.mode, self.code, self.calls = root, mode, code, []

    def __call__(self, args, env, on_line):
        self.calls.append((list(args), dict(env)))
        for line in RUN_OUT.splitlines():
            on_line(line)
        if self.mode in ("ok", "stray"):
            (self.root / "Cargo.lock").write_text(LOCK_AFTER)
        if self.mode == "stray":
            (self.root / "Cargo.toml").write_text((self.root / "Cargo.toml").read_text() + "# edited\n")
        return self.code


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "data", clock=Clock(*[f"2026-10-29T10:{m:02d}:00Z" for m in range(60)])) as s:
        yield s


def plan(store, run=None, key=KEY, cargo_path=CARGO):
    return plan_update(store, key, run=run or FakeCargo(), cargo=cargo_path)


def rows(p):
    return {r["label"]: r for r in p.rows}


# Key


def test_key_round_trip_and_bad_keys():
    req = cargo.parse_key(KEY)
    assert (req.name, req.target, req.project_path, req.lockfile) == ("serde", "1.0.210", "~/Projects/tool", "Cargo.lock")
    for bad in ("cargo/serde@1.0|~/p|Cargo.lock", "cargo/serde@1.0.1|~/p|../Cargo.lock", "cargo/serde@1.0.1|~/p|uv.lock",
                "cargo/se rde@1.0.1|~/p|Cargo.lock", "npm/serde@1.0.1|~/p|Cargo.lock", "cargo/serde@1.0.1|~/p"):
        assert cargo.parse_key(bad) is None


# Evidence: exact pins and ranges stay separate


def test_dependencies_table_keeps_exact_pins_and_ranges_apart(tmp_path):
    root = make_project(tmp_path)
    table, note = cargo.dependencies(root)
    assert note is None
    by_name = {r["package"]: r for r in table}
    assert by_name["itoa"] == {"package": "itoa", "declared": "=1.0.9", "locked": "1.0.9", "evidence": "exact_pin",
                               "ecosystem": "crates.io", "table": None}
    assert by_name["serde"]["evidence"] == "range" and by_name["serde"]["declared"] == "1.0.190"
    assert by_name["serde"]["locked"] == "1.0.190"
    assert by_name["memchr"]["table"] == "dev-dependencies" and by_name["memchr"]["evidence"] == "range"
    assert [r["package"] for r in table] == ["itoa", "memchr", "serde", "smallvec"]


@pytest.mark.parametrize("spec,exact", [("=1.0.9", True), ("= 1.0.9", True), ("1.0.9", False), ("^1.0.9", False),
                                        ("~1.0", False), ("=1.0", False), (">=1, <2", False), ("=1.0.9, <2", False)])
def test_exact_pin_rule(spec, exact):
    assert cargo.is_exact_pin(spec) is exact


@pytest.mark.parametrize("spec,version,ok", [
    ("1.0.190", "1.0.210", True), ("1.0.190", "2.0.0", False), ("1.0.190", "1.0.100", False),
    ("0.2.3", "0.2.9", True), ("0.2.3", "0.3.0", False), ("0.0.3", "0.0.4", False), ("^0.0", "0.0.9", True),
    ("~1.2.3", "1.2.9", True), ("~1.2.3", "1.3.0", False), ("~1", "1.9.0", True),
    ("=1.0.9", "1.0.9", True), ("=1.0.9", "1.0.11", False), ("=1.2", "1.2.7", True),
    ("*", "9.9.9", True), ("1.*", "1.7.0", True), ("1.2.*", "1.3.0", False),
    (">=1.2, <1.5", "1.4.9", True), (">=1.2, <1.5", "1.5.0", False), ("1.6.0", "1.6.1", True), ("nonsense", "1.0.0", False),
])
def test_cargo_requirements(spec, version, ok):
    assert cargo.spec_allows(spec, version) is ok


@pytest.mark.parametrize("before,after,major", [("1.0.190", "1.0.210", False), ("1.9.0", "2.0.0", True),
                                                ("0.2.3", "0.3.0", True), ("0.2.3", "0.2.9", False),
                                                ("0.0.3", "0.0.4", True)])
def test_major_change_follows_cargo_semver(before, after, major):
    assert cargo.is_major_change(before, after) is major


def test_parse_lock_changes_reads_real_cargo_output():
    changes = cargo.parse_lock_changes(DRY_RUN)
    assert [(c.name, c.before, c.after, c.change) for c in changes] == [
        ("serde", "1.0.190", "1.0.210", "upgrade"), ("serde_derive", "1.0.190", "1.0.210", "upgrade")]
    text = "     Locking 7 packages\n      Adding itoa v1.0.9 (available: v1.0.18)\n    Removing serde_core v1.0.229\n" \
           " Downgrading syn v3.0.9 -> v2.0.119\n"
    assert [(c.name, c.change) for c in cargo.parse_lock_changes(text)] == [
        ("itoa", "install"), ("serde_core", "remove"), ("syn", "upgrade")]


# Plan


def test_plan_shows_rows_command_and_no_build(tmp_path, store):
    root = make_project(tmp_path)
    fake = FakeCargo()
    p = plan(store, fake)
    assert p.refusal is None and p.kind == "cargo"
    r = rows(p)
    assert [x["label"] for x in p.rows] == ["Project", "Cargo.toml", "Cargo.lock", "Other packages", "Build"]
    assert r["Project"]["value"] == "~/Projects/tool"
    assert r["Cargo.toml"]["value"] == "No change"
    assert r["Cargo.lock"]["value"] == "serde 1.0.190 → 1.0.210"
    assert (r["Other packages"]["value"], r["Other packages"]["items"]) == ("1 package changes",
                                                                            ["serde_derive 1.0.190 → 1.0.210"])
    assert r["Build"]["value"] == "Not run. Cargo builds on next use."
    assert p.command == [CARGO, "update", "--manifest-path", str(root / "Cargo.toml"), "-p", "serde@1.0.190",
                         "--precise", "1.0.210"]
    assert (p.installed_version, p.target_version, p.major_change, p.scripts) == ("1.0.190", "1.0.210", False, [])
    assert p.manual_steps == ["Build or test the project to use the new version."]
    # Planning ran only the dry run: no build, no test, nothing written.
    assert [c[0][-1] for c in fake.calls] == ["--dry-run"]
    assert not any(word in c[0] for c in fake.calls for word in ("build", "test", "run", "check"))
    assert not (root / "target").exists()


def test_a_workspace_is_refused(tmp_path, store):
    make_project(tmp_path, "ws", "workspace")
    fake = FakeCargo()
    p = plan(store, fake, cargo.make_key("serde", "1.0.210", "~/Projects/ws", "Cargo.lock"))
    assert p.refusal == "Cargo workspaces are not supported yet."
    assert fake.calls == []
    assert cargo.block_reason("~/Projects/ws", "Cargo.lock") == "Cargo workspaces are not supported yet."
    table, note = cargo.dependencies(tmp_path / "home" / "Projects" / "ws")
    assert (table, note) == (None, "Cargo workspaces are not supported yet.")


def test_a_workspace_member_is_refused(tmp_path, store):
    make_project(tmp_path, "ws", "workspace")
    p = plan(store, key=cargo.make_key("serde", "1.0.210", "~/Projects/ws/member", "Cargo.lock"))
    assert p.refusal == "Cargo workspaces are not supported yet."


def test_an_exact_pin_that_does_not_allow_the_target_is_refused(tmp_path, store):
    make_project(tmp_path)
    p = plan(store, key=cargo.make_key("itoa", "1.0.11", "~/Projects/tool", "Cargo.lock"))
    assert p.refusal == 'Cargo.toml requires itoa "=1.0.9". That does not allow 1.0.11. Change it there first.'


@pytest.mark.parametrize("dep", ['serde = { git = "https://github.com/serde-rs/serde" }', 'serde = { path = "../serde" }'])
def test_git_and_path_dependencies_are_refused(tmp_path, store, dep):
    toml = (FIX / "tool" / "Cargo.toml").read_text().replace('serde = { version = "1.0.190", features = ["derive"] }', dep)
    make_project(tmp_path, toml=toml)
    assert plan(store).refusal == "Git and path dependencies are not supported."


def test_git_dependency_with_a_matching_lock_is_refused_as_a_source(tmp_path, store):
    lock = (FIX / "tool" / "Cargo.lock").read_text().replace(
        'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "91d3c334ca1ee894a2c6f6ad698fe8c435b76d504b13d436f0685d648d6d96f7"',
        'source = "git+https://github.com/serde-rs/serde#abc"')
    toml = (FIX / "tool" / "Cargo.toml").read_text().replace(
        'serde = { version = "1.0.190", features = ["derive"] }', 'serde = { git = "https://github.com/serde-rs/serde" }')
    make_project(tmp_path, toml=toml, lock=lock)
    assert plan(store).refusal == "Git and path dependencies are not supported."


@pytest.mark.parametrize("lock", [None, "", "version = 1\n", "this is not toml ["])
def test_a_missing_or_unknown_lock_is_refused(tmp_path, store, lock):
    root = make_project(tmp_path)
    if lock is None:
        (root / "Cargo.lock").unlink()
    else:
        (root / "Cargo.lock").write_text(lock)
    assert plan(store).refusal == "Cargo.lock is missing or out of date. Run cargo yourself first."
    assert cargo.block_reason("~/Projects/tool", "Cargo.lock") == cargo.REFUSE_LOCK


def test_a_lock_that_does_not_match_cargo_toml_is_refused(tmp_path, store):
    toml = (FIX / "tool" / "Cargo.toml").read_text() + '\n[build-dependencies]\ncc = "1.0"\n'
    make_project(tmp_path, toml=toml)
    assert plan(store).refusal == "Cargo.lock is missing or out of date. Run cargo yourself first."


def test_other_refusals(tmp_path, store):
    make_project(tmp_path)
    assert plan(store, key=cargo.make_key("syn", "2.0.200", "~/Projects/tool", "Cargo.lock")).refusal == \
        "syn is not a direct dependency of this project. Watchtower updates direct dependencies only."
    assert plan(store, key=cargo.make_key("serde", "1.0.190", "~/Projects/tool", "Cargo.lock")).refusal == \
        "Cargo.lock already has serde 1.0.190 or newer."
    assert plan(store, key=cargo.make_key("serde", "1.0.210", "~/Elsewhere/tool", "Cargo.lock")).refusal == \
        "Watchtower cannot find this Cargo project in the project folders."


def test_cargo_not_installed(tmp_path, monkeypatch):
    make_project(tmp_path)
    monkeypatch.setattr(cargo, "find_cargo", lambda: None)
    assert cargo.make_plan(KEY, None, FakeCargo()).refusal == "cargo is not installed."


def test_a_failed_or_unexpected_dry_run_is_unreadable(tmp_path, store):
    make_project(tmp_path)
    err = (FIX / "update-exact-pin-error.stderr").read_text()
    assert plan(store, FakeCargo(err, 101)).refusal == "Watchtower cannot read the Cargo plan."
    assert plan(store, FakeCargo("    Updating crates.io index\n")).refusal == "Watchtower cannot read the Cargo plan."


# Run


def test_a_successful_update_is_lockfile_updated_not_verified(tmp_path, store):
    root = make_project(tmp_path)
    p = plan(store)
    runner = FakeUpdate(root)
    attempt, _ = run_update(store, KEY, p.id, run=FakeCargo(), cargo=CARGO, runner=runner)
    assert attempt.status == "lockfile_updated" and attempt.error is None
    assert (attempt.before_version, attempt.after_version, attempt.exit_code) == ("1.0.190", "1.0.210", 0)
    assert attempt.result_rows == [{"label": "Lockfile", "value": "serde 1.0.210", "ok": True},
                                   {"label": "Installed", "value": "not checked. Cargo builds crates on next use."}]
    assert runner.calls[0][0] == p.command
    assert "Updating serde v1.0.190 -> v1.0.210" in attempt.output
    assert UpdateLog(store).attempts()[0].status == "lockfile_updated"
    assert not (root / "target").exists()


def test_a_lock_that_did_not_move_is_not_verified(tmp_path, store):
    root = make_project(tmp_path)
    attempt, _ = run_update(store, KEY, plan(store).id, run=FakeCargo(), cargo=CARGO, runner=FakeUpdate(root, "none"))
    assert (attempt.status, attempt.error) == ("not_verified", "The command finished, but Cargo.lock still has 1.0.190.")
    assert attempt.result_rows[0]["ok"] is False


def test_a_changed_cargo_toml_is_flagged(tmp_path, store):
    root = make_project(tmp_path)
    attempt, _ = run_update(store, KEY, plan(store).id, run=FakeCargo(), cargo=CARGO, runner=FakeUpdate(root, "stray"))
    assert (attempt.status, attempt.error) == ("not_verified", "cargo changed files that Watchtower did not plan: Cargo.toml.")


def test_a_failed_command_is_failed(tmp_path, store):
    root = make_project(tmp_path)
    attempt, _ = run_update(store, KEY, plan(store).id, run=FakeCargo(), cargo=CARGO, runner=FakeUpdate(root, "none", 101))
    assert (attempt.status, attempt.error) == ("failed", "The update failed (exit code 101).")


def test_files_are_backed_up_privately_before_the_run(tmp_path, store):
    root = make_project(tmp_path)
    before = (root / "Cargo.lock").read_text()
    attempt, _ = run_update(store, KEY, plan(store).id, run=FakeCargo(), cargo=CARGO, runner=FakeUpdate(root))
    folder = store.data_dir / "update-backups" / f"attempt-{attempt.id}"
    assert (folder / "Cargo.lock").read_text() == before
    assert stat.S_IMODE(os.stat(folder).st_mode) == 0o700
    assert {stat.S_IMODE(os.stat(f).st_mode) for f in folder.iterdir()} == {0o600}


def test_a_changed_project_invalidates_the_plan(tmp_path, store):
    root = make_project(tmp_path)
    p = plan(store)
    (root / "Cargo.lock").write_text((root / "Cargo.lock").read_text() + "\n")
    runner = FakeUpdate(root)
    attempt, _ = run_update(store, KEY, p.id, run=FakeCargo(), cargo=CARGO, runner=runner)
    assert attempt.status == "plan_changed" and runner.calls == []


def test_a_major_jump_needs_its_own_confirmation(tmp_path, store):
    toml = (FIX / "tool" / "Cargo.toml").read_text().replace('smallvec = "1.11"', 'smallvec = "*"')
    root = make_project(tmp_path, toml=toml)
    key = cargo.make_key("smallvec", "2.0.0", "~/Projects/tool", "Cargo.lock")
    fake = FakeCargo("    Updating crates.io index\n    Updating smallvec v1.11.0 -> v2.0.0\n")
    p = plan(store, fake, key)
    assert p.refusal is None and p.major_change
    runner = FakeUpdate(root)
    attempt, _ = run_update(store, key, p.id, run=fake, cargo=CARGO, runner=runner)
    assert (attempt.status, attempt.error) == ("refused", ERROR_NEEDS_MAJOR) and runner.calls == []


# Findings and OSV


def test_the_real_scanner_output_for_cargo_lock_is_read():
    text = (FIX / "osv-scan-output.json").read_text().replace("__CARGO_LOCK__", "/p/tool/Cargo.lock")
    parsed = osv.parse_output(text)
    (pkg,) = parsed["/p/tool/Cargo.lock"]
    assert (pkg["name"], pkg["ecosystem"], pkg["version"]) == ("smallvec", "crates.io", "1.6.0")
    assert {"RUSTSEC-2021-0003", "GHSA-43w2-9j62-hq99"} <= set(pkg["advisory_ids"] if "advisory_ids" in pkg else
                                                                 [i for g in pkg["groups"] for i in g["ids"]])


def test_cargo_lock_is_scanned_with_the_crates_io_database(tmp_path):
    root = make_project(tmp_path, "vuln", "vuln")
    scans = osv.plan(list_projects(tmp_path / "data", roots=(str(tmp_path / "home" / "Projects"),)).projects)
    lockfiles = {lf.path: lf for s in scans for lf in s.lockfiles}
    assert lockfiles["Cargo.lock"].ecosystem == "crates.io" and lockfiles["Cargo.lock"].status == "not_scanned"
    assert root.is_dir()


def test_a_cargo_finding_path_carries_the_workspace_block(tmp_path, store):
    make_project(tmp_path, "ws", "workspace")
    make_project(tmp_path)
    adv = {"ids": ["RUSTSEC-2021-0003", "GHSA-43w2-9j62-hq99"], "title": "t", "severity": "high", "fixed_in": ["1.6.1"]}
    matches = [Match(name, f"~/Projects/{name}", "Cargo.lock", "smallvec", "crates.io", "1.6.0", None,
                     ["RUSTSEC-2021-0003"], ["GHSA-43w2-9j62-hq99"], [adv]) for name in ("ws", "tool")]
    scan = OsvResult(C("osv", "OSV", "complete"),
                     [ProjectScan(n, f"~/Projects/{n}", [Lockfile("Cargo.lock", "crates.io", "scanned")]) for n in ("ws", "tool")],
                     matches, [])
    r = store.begin_refresh()
    store.finish_refresh(r.id, "complete", coverage=[scan.coverage], scan=scan)
    (finding,) = store.state()["findings"]
    blocks = {p["project"]: p["update_block"] for p in finding["paths"]}
    assert blocks == {"ws": "Cargo workspaces are not supported yet.", "tool": None}
    assert finding["ecosystem"] == "crates.io" and finding["fixed_in"] == "1.6.1"


# Projects list


def test_the_project_list_has_the_dependencies_table(tmp_path):
    make_project(tmp_path)
    make_project(tmp_path, "ws", "workspace")
    found = list_projects(tmp_path / "data", roots=(str(tmp_path / "home" / "Projects"),))
    by_name = {p.name: p.to_dict() for p in found.projects}
    assert by_name["tool"]["dependency_note"] is None
    assert {r["evidence"] for r in by_name["tool"]["dependencies"]} == {"exact_pin", "range"}
    assert by_name["ws"]["dependencies"] is None
    assert by_name["ws"]["dependency_note"] == "Cargo workspaces are not supported yet."
    assert json.loads(json.dumps(by_name["tool"]))["dependencies"][0]["ecosystem"] == "crates.io"
