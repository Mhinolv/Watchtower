import json
import os
import subprocess
from pathlib import Path

import pytest

from watchtower_engine import cli, updater
from watchtower_engine.feeds import npm_registry
from watchtower_engine.store import Store
from watchtower_engine.update_log import UpdateLog
from watchtower_engine.updater import plan_update, run_update
from watchtower_engine.updates import npm

NPM = "/fake/bin/npm"
URL = npm_registry.package_url


# A small project: express is direct, its deps are transitive.


def lock(express="4.17.1", extra=None, esbuild=None):
    packages = {
        "": {"name": "web", "dependencies": {"express": f"^{express}"}},
        "node_modules/express": {"version": express},
        "node_modules/path-to-regexp": {"version": "0.1.7" if express == "4.17.1" else "0.1.10"},
        "node_modules/cookie": {"version": "0.5.0" if express == "4.17.1" else "0.6.0"},
        "node_modules/send": {"version": "0.18.0" if express == "4.17.1" else "0.19.0"},
        "node_modules/lodash": {"version": "4.17.21"},
    }
    if esbuild:
        packages["node_modules/esbuild"] = {"version": esbuild, "hasInstallScript": True}
    packages.update(extra or {})
    return {"name": "web", "lockfileVersion": 3, "requires": True, "packages": packages}


def make_project(root: Path, spec="^4.17.1", section="dependencies", lockdata=None, pkg_extra=None,
                 installed="4.17.1") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    pkg = {"name": "web", "version": "1.0.0", section: {"express": spec}, "scripts": {"test": "node test.js"}}
    pkg.update(pkg_extra or {})
    (root / "package.json").write_text(json.dumps(pkg, indent=2) + "\n")
    (root / "package-lock.json").write_text(json.dumps(lockdata or lock(), indent=2) + "\n")
    if installed:
        mod = root / "node_modules" / "express"
        mod.mkdir(parents=True, exist_ok=True)
        (mod / "package.json").write_text(json.dumps({"name": "express", "version": installed}))
    return root


class FakeRegistry:
    def __init__(self, versions=("4.17.1", "4.18.2", "4.19.2", "5.0.0-beta.1", "5.1.0"), latest="5.1.0",
                 scripts=None, down=False):
        self.versions, self.latest, self.scripts, self.down = list(versions), latest, scripts or {}, down
        self.calls = []

    def __call__(self, url, accept):
        self.calls.append(url)
        if self.down:
            raise OSError("network is disabled")
        if url == URL("express"):
            return {"versions": {v: {} for v in self.versions}, "dist-tags": {"latest": self.latest}}
        for (name, version), scripts in self.scripts.items():
            if url == URL(name, version):
                if scripts is None:
                    raise OSError("down")
                return {"name": name, "version": version, "scripts": {s: "node x" for s in scripts}}
        raise AssertionError(f"unexpected registry call {url}")


class FakeNpm:
    """Stands in for `npm install --package-lock-only` during planning. Never runs npm."""

    def __init__(self, new_lock, code=0):
        self.new_lock, self.code = new_lock, code
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        assert "--package-lock-only" in args and "--ignore-scripts" in args
        prefix = Path(args[args.index("--prefix") + 1])
        if self.code == 0:
            (prefix / "package-lock.json").write_text(json.dumps(self.new_lock))
        return subprocess.CompletedProcess(args, self.code, "", "npm ERR! boom" if self.code else "")


class FakeInstall:
    """Stands in for the real install run. Writes what npm would write, or less."""

    def __init__(self, project, target="4.19.2", spec="^4.19.2", lock_only=False, code=0, rebuild_code=0):
        self.project, self.target, self.spec = project, target, spec
        self.lock_only, self.code, self.rebuild_code = lock_only, code, rebuild_code
        self.calls = []

    def __call__(self, args, env, on_line):
        self.calls.append(list(args))
        if args[1] == "rebuild":
            on_line("rebuilt")
            return self.rebuild_code
        on_line("added 1 package")
        pj = json.loads((self.project / "package.json").read_text())
        pj["dependencies"]["express"] = self.spec
        (self.project / "package.json").write_text(json.dumps(pj))
        (self.project / "package-lock.json").write_text(json.dumps(lock(self.target)))
        if not self.lock_only and self.code == 0:
            (self.project / "node_modules" / "express" / "package.json").write_text(
                json.dumps({"name": "express", "version": self.target}))
        return self.code


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "data") as s:
        yield s


def key(project, fixed="4.19.0"):
    return npm.make_key(str(project), "express", fixed)


def plan_for(store, project, registry=None, new_lock=None, fixed="4.19.0", npm_run=None):
    return plan_update(store, key(project, fixed), npm=NPM, run=npm_run or FakeNpm(new_lock or lock("4.19.2")),
                       get=registry or FakeRegistry())


def run_for(store, project, plan, installer, registry=None, new_lock=None, fixed="4.19.0", **kw):
    return run_update(store, key(project, fixed), plan.id, npm=NPM, run=FakeNpm(new_lock or lock("4.19.2")),
                      get=registry or FakeRegistry(), runner=installer, **kw)


# Plan


def test_plan_shows_command_rows_and_three_other_packages(store, tmp_path):
    project = make_project(tmp_path / "home" / "Projects" / "web")
    p = plan_for(store, project).to_dict()
    assert p["refusal"] is None
    assert p["command"] == [NPM, "install", "express@^4.19.2", "--save-prod", "--ignore-scripts", "--no-audit",
                            "--no-fund", "--prefix", str(project)]
    assert (p["installed_version"], p["target_version"], p["major_change"]) == ("4.17.1", "4.19.2", False)
    assert p["rows"] == [
        {"label": "Project", "value": "~/Projects/web"},
        {"label": "package.json", "value": '"express": "^4.17.1" → "^4.19.2"'},
        {"label": "package-lock.json", "value": "express 4.17.1 → 4.19.2"},
    ]
    assert p["changes_title"] == "Other packages"
    assert [(c["name"], c["before"], c["after"]) for c in p["also_changes"]] == [
        ("cookie", "0.5.0", "0.6.0"), ("path-to-regexp", "0.1.7", "0.1.10"), ("send", "0.18.0", "0.19.0"),
    ]
    assert p["scripts"] == [] and p["scripts_off_text"] == "Disabled (--ignore-scripts)"
    assert p["manual_steps"][0] == "Run the project tests: npm test"


def test_planning_never_changes_the_project(store, tmp_path):
    project = make_project(tmp_path / "web")
    before = {f: (project / f).read_bytes() for f in ("package.json", "package-lock.json")}
    fake = FakeNpm(lock("4.19.2"))
    plan_for(store, project, npm_run=fake)
    assert {f: (project / f).read_bytes() for f in before} == before
    prefix = fake.calls[0][fake.calls[0].index("--prefix") + 1]
    assert Path(prefix) != project and not Path(prefix).exists()  # a temp copy, removed after


def test_registry_gets_only_the_package_name(store, tmp_path):
    project = make_project(tmp_path / "web")
    registry = FakeRegistry()
    plan_for(store, project, registry=registry)
    assert registry.calls == ["https://registry.npmjs.org/express"]
    assert URL("@scope/pkg") == "https://registry.npmjs.org/@scope%2Fpkg"


def test_dev_dependency_keeps_its_section_and_exact_spec_stays_exact(store, tmp_path):
    project = make_project(tmp_path / "web", spec="4.17.1", section="devDependencies")
    p = plan_for(store, project)
    assert p.command[2:4] == ["express@4.19.2", "--save-dev"]


def test_major_version_needs_its_own_confirmation(store, tmp_path):
    project = make_project(tmp_path / "web")
    registry = FakeRegistry(versions=("4.17.1", "4.18.2", "5.1.0"))
    p = plan_for(store, project, registry=registry, new_lock=lock("5.1.0"), fixed="5.0.0")
    assert (p.target_version, p.major_change) == ("5.1.0", True)
    installer = FakeInstall(project, target="5.1.0", spec="^5.1.0")
    first, _ = run_for(store, project, p, installer, registry=registry, new_lock=lock("5.1.0"), fixed="5.0.0")
    assert first.status == "refused" and installer.calls == []
    second, _ = run_for(store, project, p, installer, registry=registry, new_lock=lock("5.1.0"), fixed="5.0.0",
                        confirm_major=True)
    assert second.status == "verified"


@pytest.mark.parametrize("versions,latest,fixed,target", [
    (["4.17.1", "4.18.2", "4.19.2", "5.0.0"], "5.0.0", "4.19.0", "4.19.2"),   # stay in the major
    (["4.17.1", "4.18.2", "5.0.0"], "5.0.0", "4.19.0", "5.0.0"),              # fix only in 5.x
    (["4.17.1", "4.19.2", "4.20.0-rc.1"], "4.19.2", None, "4.19.2"),          # no prerelease
    (["4.17.1"], "4.17.1", None, None),                                        # nothing newer
])
def test_choose_target(versions, latest, fixed, target):
    assert npm.choose_target("4.17.1", versions, latest, fixed) == target


def test_new_spec_keeps_the_range_style():
    assert npm.new_spec("^4.17.1", "4.19.2") == "^4.19.2"
    assert npm.new_spec("~4.17.1", "4.17.3") == "~4.17.3"
    assert npm.new_spec("4.17.1", "4.19.2") == "4.19.2"
    assert npm.new_spec(">=4 <5", "4.19.2") is None


# Scripts


def scripts_lock():
    return lock("4.19.2", esbuild="0.21.5")


def test_install_scripts_need_a_second_confirmation(store, tmp_path):
    project = make_project(tmp_path / "web")
    registry = FakeRegistry(scripts={("esbuild", "0.21.5"): ["postinstall"]})
    p = plan_for(store, project, registry=registry, new_lock=scripts_lock())
    assert p.scripts == ["esbuild needs its postinstall script"]
    assert p.script_details == [{"package": "esbuild", "version": "0.21.5", "script": "postinstall"}]
    assert {"label": "Scripts command",
            "value": f"{NPM} rebuild esbuild --ignore-scripts=false --prefix {project}"} in p.rows
    installer = FakeInstall(project)
    refused, _ = run_for(store, project, p, installer, registry=registry, new_lock=scripts_lock())
    assert refused.status == "refused" and installer.calls == []
    done, _ = run_for(store, project, p, installer, registry=registry, new_lock=scripts_lock(),
                      confirm_scripts=True)
    assert done.status == "verified" and done.confirmed_scripts
    assert "--ignore-scripts" in installer.calls[0]  # the install itself never runs scripts
    assert installer.calls[1][1:3] == ["rebuild", "esbuild"]


def test_failed_scripts_are_reported(store, tmp_path):
    project = make_project(tmp_path / "web")
    registry = FakeRegistry(scripts={("esbuild", "0.21.5"): ["install"]})
    p = plan_for(store, project, registry=registry, new_lock=scripts_lock())
    a, _ = run_for(store, project, p, FakeInstall(project, rebuild_code=1), registry=registry,
                   new_lock=scripts_lock(), confirm_scripts=True)
    assert (a.status, a.error) == ("failed", "The install scripts failed (exit code 1).")


def test_unknown_scripts_refuse_the_plan(store, tmp_path):
    project = make_project(tmp_path / "web")
    registry = FakeRegistry(scripts={("esbuild", "0.21.5"): None})
    p = plan_for(store, project, registry=registry, new_lock=scripts_lock())
    assert p.refusal == "This package needs scripts that Watchtower cannot check."


def test_unchanged_package_with_scripts_needs_no_confirmation(store, tmp_path):
    project = make_project(tmp_path / "web", lockdata=lock(esbuild="0.21.5"))
    p = plan_for(store, project, new_lock=scripts_lock())
    assert p.scripts == [] and p.refusal is None


# Refusals


@pytest.mark.parametrize("kwargs,refusal", [
    ({"pkg_extra": {"workspaces": ["packages/*"]}}, npm.REFUSE_WORKSPACE),
    ({"lockdata": lock(extra={"packages/a": {"name": "a"}})}, npm.REFUSE_WORKSPACE),
    ({"spec": "github:expressjs/express"}, npm.REFUSE_GIT),
    ({"spec": "git+https://github.com/expressjs/express.git"}, npm.REFUSE_GIT),
    ({"spec": "expressjs/express#v4"}, npm.REFUSE_GIT),
    ({"spec": "file:../express"}, npm.REFUSE_OTHER_SOURCE),
    ({"spec": ">=4 <5"}, "Watchtower cannot update the version range >=4 <5."),
    ({"lockdata": {"lockfileVersion": 1, "dependencies": {}}}, npm.REFUSE_LOCK_VERSION),
])
def test_plan_refusals(store, tmp_path, kwargs, refusal):
    project = make_project(tmp_path / "web", **kwargs)
    assert plan_for(store, project).refusal == refusal


def test_transitive_package_is_refused(store, tmp_path):
    project = make_project(tmp_path / "web")
    p = plan_update(store, npm.make_key(str(project), "cookie"), npm=NPM, run=FakeNpm(lock()), get=FakeRegistry())
    assert p.refusal == "Watchtower updates direct dependencies only. cookie comes in through another package."


def test_registry_down_and_no_newer_version(store, tmp_path):
    project = make_project(tmp_path / "web")
    assert plan_for(store, project, registry=FakeRegistry(down=True)).refusal == npm.REFUSE_REGISTRY
    old = FakeRegistry(versions=("4.17.1",), latest="4.17.1")
    assert plan_for(store, project, registry=old).refusal == "npm has no newer version of express."
    missing = tmp_path / "empty"
    missing.mkdir()
    assert plan_for(store, missing).refusal == npm.REFUSE_NO_PROJECT


def test_lock_resolution_failure_refuses(store, tmp_path):
    project = make_project(tmp_path / "web")
    assert plan_for(store, project, npm_run=FakeNpm(lock(), code=1)).refusal == npm.REFUSE_RESOLVE
    # npm resolved another version than the plan says.
    assert plan_for(store, project, new_lock=lock("4.18.2")).refusal == npm.REFUSE_RESOLVE


# Run and verify


def test_verified_update_checks_lockfile_and_node_modules(store, tmp_path):
    project = make_project(tmp_path / "web")
    p = plan_for(store, project)
    installer = FakeInstall(project)
    a, _ = run_for(store, project, p, installer)
    assert a.status == "verified" and a.after_version == "4.19.2"
    assert a.checks == [
        {"label": "Lockfile", "value": "express 4.19.2", "ok": True},
        {"label": "Installed (node_modules)", "value": "express 4.19.2", "ok": True},
    ]
    assert installer.calls == [p.command]
    assert UpdateLog(store).attempts()[0].checks == a.checks


def test_lockfile_only_is_not_verified(store, tmp_path):
    project = make_project(tmp_path / "web")
    p = plan_for(store, project)
    a, _ = run_for(store, project, p, FakeInstall(project, lock_only=True))
    assert a.status == "not_verified" and a.exit_code == 0
    assert a.error == "Not verified: the installed package is still 4.17.1."
    assert [c["ok"] for c in a.checks] == [True, False]


def test_failed_install_restores_the_project_files(store, tmp_path):
    project = make_project(tmp_path / "web")
    before = {f: (project / f).read_bytes() for f in ("package.json", "package-lock.json")}
    p = plan_for(store, project)
    a, _ = run_for(store, project, p, FakeInstall(project, code=1))
    assert (a.status, a.exit_code) == ("failed", 1)
    assert {f: (project / f).read_bytes() for f in before} == before
    assert "Watchtower restored package.json." in a.output


def test_edit_after_the_plan_changes_the_plan(store, tmp_path):
    project = make_project(tmp_path / "web")
    p = plan_for(store, project)
    pj = json.loads((project / "package.json").read_text())
    pj["scripts"]["lint"] = "eslint ."  # the owner edits the project after the plan
    (project / "package.json").write_text(json.dumps(pj))
    installer = FakeInstall(project)
    a, _ = run_for(store, project, p, installer)
    assert a.status == "plan_changed" and installer.calls == []


def test_old_log_table_gets_the_checks_column(store, tmp_path):
    store.db.executescript("""
        CREATE TABLE update_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, item_key TEXT NOT NULL,
            name TEXT NOT NULL, kind TEXT, command TEXT NOT NULL, before_version TEXT, target_version TEXT,
            after_version TEXT, status TEXT NOT NULL, exit_code INTEGER, output TEXT NOT NULL DEFAULT '',
            error TEXT, manual_steps TEXT NOT NULL DEFAULT '[]', confirmed_major INTEGER NOT NULL DEFAULT 0,
            confirmed_scripts INTEGER NOT NULL DEFAULT 0, plan_id TEXT, pid INTEGER, started_at TEXT NOT NULL,
            finished_at TEXT);
        INSERT INTO update_attempts (item_key, name, command, status, started_at)
            VALUES ('homebrew/formula:git', 'git', '["brew"]', 'verified', '2026-10-29T10:00:00Z');
    """)
    assert UpdateLog(store).attempts()[0].checks == []


# CLI


def test_cli_plan_for_an_npm_key(tmp_path, monkeypatch, capsys):
    project = make_project(tmp_path / "web")
    real = updater.plan_update
    monkeypatch.setattr(updater, "plan_update", lambda store, item, *a, **k: real(
        store, item, npm=NPM, run=FakeNpm(lock("4.19.2")), get=FakeRegistry()))
    assert cli.main(["--data-dir", str(tmp_path / "data"), "update-plan", key(project)]) == 0
    plan = json.loads(capsys.readouterr().out)["plan"]
    assert plan["kind"] == "npm" and plan["target_version"] == "4.19.2" and len(plan["also_changes"]) == 3
