import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from watchtower_engine import findings
from watchtower_engine.feeds.homebrew import Response
from watchtower_engine.models import CoverageRecord as C
from watchtower_engine.scanners.osv import Lockfile, Match, OsvResult, ProjectScan
from watchtower_engine.store import Store
from watchtower_engine.update_log import UpdateLog
from watchtower_engine.updater import Interrupted, plan_update, run_update
from watchtower_engine.updates import uv as uvu

from contract import Clock

UV = "/fake/uv"
MAC = {"machine": "arm64", "mac": (15, 1), "system": "Darwin"}
LOCK_OUT = ("Resolved 12 packages in 1ms\nUpdate httpx v0.26.0 -> v0.27.2\n"
            "Update anyio v4.2.0 -> v4.3.0\nAdd sniffio v1.3.1\nRemove h11 v0.13.0\n")
WHEEL = "httpx-0.27.2-py3-none-any.whl"
PYPI_OK = {"urls": [{"filename": WHEEL, "packagetype": "bdist_wheel"},
                    {"filename": "httpx-0.27.2.tar.gz", "packagetype": "sdist"}]}
PYPROJECT = """[project]
name = "tool"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = ["httpx>=0.26"]

[project.optional-dependencies]
web = ["uvicorn>=0.20"]

[dependency-groups]
dev = ["pytest>=8"]
"""


def lock_text(version="0.26.0", source='{ registry = "https://pypi.org/simple" }', name="httpx"):
    return (f'version = 1\nrequires-python = ">=3.12"\n\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
            f'source = {source}\n\n[[package]]\nname = "tool"\nversion = "0.1.0"\nsource = {{ editable = "." }}\n')


def make_project(tmp_path, pyproject=PYPROJECT, lock=None, env=True, installed="0.26.0", where="Real", sub="tool"):
    home = tmp_path / "home"
    root = home / where / sub
    root.mkdir(parents=True)
    (root / "pyproject.toml").write_text(pyproject)
    (root / "uv.lock").write_text(lock if lock is not None else lock_text())
    (root / "README.md").write_text("hello")
    if env:
        site = root / ".venv" / "lib" / "python3.12" / "site-packages"
        (site / f"httpx-{installed}.dist-info").mkdir(parents=True)
        (site / f"httpx-{installed}.dist-info" / "METADATA").write_text(f"Metadata-Version: 2.1\nName: httpx\nVersion: {installed}\n\nbody")
        (root / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\nversion_info = 3.12.4\n")
    return root


class FakeUv:
    """Answers `uv lock --dry-run`. Never starts a process."""

    def __init__(self, out=LOCK_OUT, code=0):
        self.out, self.code, self.calls = out, code, []

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), kwargs))
        assert kwargs["env"]["UV_PYTHON_DOWNLOADS"] == "never" and "UV_PROJECT_ENVIRONMENT" not in kwargs["env"]
        assert args[3] == "lock" and "--dry-run" in args
        return subprocess.CompletedProcess(args, self.code, self.out, "boom" if self.code else "")


class FakePyPI:
    def __init__(self, data=PYPI_OK, status=200, error=None):
        self.data, self.status, self.error, self.calls = data, status, error, []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        if self.error:
            raise self.error
        return Response(self.status, {}, json.dumps(self.data).encode())


class FakeSync:
    """Stands in for the uv process. `mode` says what it leaves behind."""

    def __init__(self, root, mode="both", code=0, target="0.27.2"):
        self.root, self.mode, self.code, self.target = root, mode, code, target
        self.calls = []

    def __call__(self, args, env, on_line):
        self.calls.append((list(args), dict(env)))
        on_line("Resolved 12 packages in 1ms")
        if self.mode in ("both", "lock_only", "stray", "env_replaced"):
            (self.root / "uv.lock").write_text(lock_text(self.target))
        if self.mode in ("both", "stray", "env_replaced"):
            site = self.root / ".venv" / "lib" / "python3.12" / "site-packages"
            old = next(site.glob("httpx-*.dist-info"))
            new = site / f"httpx-{self.target}.dist-info"
            old.rename(new)
            (new / "METADATA").write_text(f"Name: httpx\nVersion: {self.target}\n")
        if self.mode == "stray":
            (self.root / "README.md").write_text("changed by uv")
            (self.root / "new.txt").write_text("x")
        if self.mode == "env_replaced":
            (self.root / ".venv" / "pyvenv.cfg").write_text("home = /usr/local/bin\nversion_info = 3.13.0\n")
        return self.code


KEY = uvu.make_key("httpx", "0.27.2", "~/Real/tool", "uv.lock")


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "data", clock=Clock(*[f"2026-10-29T10:{m:02d}:00Z" for m in range(60)])) as s:
        yield s


def plan(store, uv=None, pypi=None, key=KEY, **kw):
    return plan_update(store, key, uv=UV, run=uv or FakeUv(), fetch=pypi or FakePyPI(), uv_options={**MAC, **kw})


def run(store, runner, plan_id, key=KEY, uv=None, pypi=None, **kw):
    options = {**MAC, **kw.pop("uv_options", {})}
    return run_update(store, key, plan_id, uv=UV, run=uv or FakeUv(), fetch=pypi or FakePyPI(), runner=runner,
                      uv_options=options, **kw)


def rows(p):
    return {r["label"]: r for r in p.rows}


# Plan


def test_plan_shows_the_exact_command_and_every_row_of_the_design(tmp_path, store):
    make_project(tmp_path)
    p = plan(store)
    assert p.refusal is None and p.kind == "uv" and p.name == "httpx"
    assert (p.installed_version, p.target_version, p.major_change) == ("0.26.0", "0.27.2", False)
    root = tmp_path / "home" / "Real" / "tool"
    assert p.command == [UV, "--project", str(root), "sync", "--upgrade-package", "httpx==0.27.2", "--inexact",
                         "--no-build"]
    r = rows(p)
    assert [x["label"] for x in p.rows] == ["Project", "Environment", "pyproject.toml", "uv.lock", "Groups and extras",
                                            "Other packages", "Build"]
    assert r["Project"]["value"] == "~/Real/tool"
    assert r["Environment"]["value"] == ".venv (exists)"
    assert r["pyproject.toml"]["value"] == "No change"
    assert r["uv.lock"]["value"] == "httpx 0.26.0 → 0.27.2"
    assert r["Groups and extras"]["value"] == "Groups: none. Extras: none."
    assert r["Other packages"]["value"] == "3 packages"
    assert r["Other packages"]["items"] == ["anyio 4.2.0 → 4.3.0", "sniffio 1.3.1 (new)", "h11 0.13.0 (removed)"]
    assert r["Build"]["value"] == "Disabled"
    assert p.scripts == [] and p.scripts_command is None and p.also_changes == []
    assert p.manual_steps == ["Restart the dev server after the update."]
    assert p.to_dict()["rows"][0] == {"label": "Project", "value": "~/Real/tool"}


def test_no_other_package_change_has_its_own_text(tmp_path, store):
    make_project(tmp_path)
    p = plan(store, uv=FakeUv("Resolved 1 package in 1ms\nUpdate httpx v0.26.0 -> v0.27.2\n"))
    assert rows(p)["Other packages"] == {"label": "Other packages", "value": "No other packages change."}


def test_the_command_names_one_package_and_never_updates_all(tmp_path, store):
    make_project(tmp_path)
    p = plan(store)
    flat = " ".join(p.command)
    assert flat.count("--upgrade-package") == 1 and "httpx==0.27.2" in p.command
    for forbidden in ("add", "remove", "--upgrade", "-U", "lock", "pip", "--reinstall", "--refresh", "venv"):
        assert forbidden not in p.command, forbidden
    assert p.command[3] == "sync" and "--inexact" in p.command


@pytest.mark.parametrize("pyproject,groups,flags", [
    (PYPROJECT, "Groups: none. Extras: none.", []),
    (PYPROJECT.replace('dev = ["pytest>=8"]', 'dev = ["pytest>=8", "httpx>=0.26"]'),
     "Groups: dev. Extras: none.", ["--group", "dev"]),
    (PYPROJECT.replace('web = ["uvicorn>=0.20"]', 'web = ["uvicorn>=0.20", "httpx>=0.26"]'),
     "Groups: none. Extras: web.", ["--extra", "web"]),
    (PYPROJECT.replace('dependencies = ["httpx>=0.26"]', "dependencies = []").replace(
        'dev = ["pytest>=8"]', 'dev = ["httpx>=0.26"]\ndocs = ["HTTPX>=0.1"]').replace(
        'web = ["uvicorn>=0.20"]', 'web = ["httpx"]\nzzz = ["httpx[http2]>=0.20"]'),
     "Groups: dev, docs. Extras: web, zzz.", ["--group", "dev", "--group", "docs", "--extra", "web", "--extra", "zzz"]),
])
def test_groups_and_extras_are_explicit_in_the_row_and_the_command(tmp_path, store, pyproject, groups, flags):
    make_project(tmp_path, pyproject=pyproject)
    p = plan(store)
    assert p.refusal is None
    assert rows(p)["Groups and extras"]["value"] == groups  # Shown even when both are empty.
    assert p.command[8:] == flags


def test_uv_tool_dev_dependencies_count_as_the_dev_group(tmp_path, store):
    make_project(tmp_path, pyproject=PYPROJECT.replace('dependencies = ["httpx>=0.26"]', "dependencies = []")
                 + '\n[tool.uv]\ndev-dependencies = ["httpx>=0.26"]\n')
    assert rows(plan(store))["Groups and extras"]["value"] == "Groups: dev. Extras: none."


def test_major_change_is_marked(tmp_path, store):
    make_project(tmp_path)
    p = plan(store, key=uvu.make_key("httpx", "1.0.0", "~/Real/tool", "uv.lock"),
             uv=FakeUv("Update httpx v0.26.0 -> v1.0.0\n"), pypi=FakePyPI({"urls": [{"filename": "httpx-1.0.0-py3-none-any.whl"}]}))
    assert p.refusal is None and p.major_change is True


# Build step


@pytest.mark.parametrize("files", [
    [{"filename": "httpx-0.27.2.tar.gz"}],
    [{"filename": "httpx-0.27.2-cp312-cp312-manylinux_2_17_x86_64.whl"}],
    [{"filename": "httpx-0.27.2-cp311-cp311-macosx_11_0_arm64.whl"}],
    [{"filename": "httpx-0.27.2-py3-none-any.whl", "yanked": True}, {"filename": "httpx-0.27.2.tar.gz"}],
])
def test_a_target_without_a_fitting_wheel_needs_the_scripts_step(tmp_path, store, files):
    make_project(tmp_path)
    p = plan(store, pypi=FakePyPI({"urls": files}))
    assert p.refusal is None
    assert p.scripts == ["httpx needs a source build: no wheel for this platform."]
    assert p.scripts_message == "httpx needs a source build: no wheel for this platform."
    assert "--no-build" in p.command and "--no-build" not in p.scripts_command
    assert p.scripts_command == [c for c in p.command if c != "--no-build"]
    assert rows(p)["Build"]["value"] == "Disabled"  # The first run never builds.


def test_build_runs_only_after_the_second_confirmation(tmp_path, store):
    root = make_project(tmp_path)
    pypi = FakePyPI({"urls": [{"filename": "httpx-0.27.2.tar.gz"}]})
    p = plan(store, pypi=pypi)
    runner = FakeSync(root)
    attempt, _ = run(store, runner, p.id, pypi=pypi)
    assert (attempt.status, attempt.error) == ("refused", "This update needs install scripts. Confirm them first.")
    assert runner.calls == []
    attempt, _ = run(store, runner, p.id, pypi=pypi, confirm_scripts=True)
    assert attempt.status == "verified" and attempt.confirmed_scripts
    assert "--no-build" not in runner.calls[0][0]


def test_the_first_run_always_has_no_build(tmp_path, store):
    root = make_project(tmp_path)
    p = plan(store)
    runner = FakeSync(root)
    run(store, runner, p.id)
    assert "--no-build" in runner.calls[0][0]


def test_wheel_tags():
    def fits(name, minor=12, machine="arm64", mac=(15, 1), system="Darwin"):
        return uvu.wheel_fits(name, minor, machine, mac, system)

    assert fits("a-1-py3-none-any.whl")
    assert fits("a-1-py2.py3-none-any.whl")
    assert fits("a-1-cp312-cp312-macosx_11_0_arm64.whl")
    assert fits("a-1-cp39-abi3-macosx_10_9_universal2.whl")
    assert fits("a-1-cp312-cp312-macosx_14_0_universal2.whl")
    assert not fits("a-1-cp312-cp312-macosx_16_0_arm64.whl")  # Needs a newer macOS.
    assert not fits("a-1-cp312-cp312-macosx_11_0_x86_64.whl")
    assert not fits("a-1-cp313-cp313-macosx_11_0_arm64.whl")
    assert not fits("a-1-cp311-cp311-macosx_11_0_arm64.whl")
    assert not fits("a-1-cp312-cp312-manylinux_2_17_aarch64.whl")
    assert not fits("a-1.tar.gz") and not fits("a-1.whl")
    assert fits("a-1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", machine="x86_64", system="Linux")
    assert fits("a-1-py3-none-any.whl", minor=None)  # A pure wheel fits if the Python version is unknown.
    assert not fits("a-1-cp312-cp312-macosx_11_0_arm64.whl", minor=None)


# Refusals


def refusal(store, **kw):
    p = plan(store, **kw)
    assert p.refusal, "the plan was not refused"
    return p.refusal


def test_no_environment_is_refused_and_nothing_creates_one(tmp_path, store):
    root = make_project(tmp_path, env=False)
    uv = FakeUv()
    assert refusal(store, uv=uv) == "No environment found. Watchtower does not create environments."
    assert uv.calls == [] and not (root / ".venv").exists()
    assert uvu.block_reason("~/Real/tool", "uv.lock") == "No environment found. Watchtower does not create environments."


def test_a_folder_named_venv_without_a_config_is_no_environment(tmp_path, store):
    root = make_project(tmp_path, env=False)
    (root / ".venv").mkdir()
    assert refusal(store).startswith("No environment found")


def test_workspace_projects_are_refused(tmp_path, store):
    make_project(tmp_path, pyproject=PYPROJECT + '\n[tool.uv.workspace]\nmembers = ["packages/*"]\n')
    assert refusal(store) == "Watchtower cannot update workspace projects yet."
    assert uvu.block_reason("~/Real/tool", "uv.lock") == "Watchtower cannot update workspace projects yet."


def test_a_member_of_a_workspace_is_refused(tmp_path, store):
    home = tmp_path / "home"
    (home / "Real" / "ws").mkdir(parents=True)
    (home / "Real" / "ws" / "pyproject.toml").write_text('[tool.uv.workspace]\nmembers = ["tool"]\n')
    make_project(tmp_path, sub="ws/tool")
    key = uvu.make_key("httpx", "0.27.2", "~/Real/ws", "tool/uv.lock")
    assert refusal(store, key=key) == "Watchtower cannot update workspace projects yet."


def test_a_package_that_is_not_a_direct_dependency_is_refused(tmp_path, store):
    make_project(tmp_path, lock=lock_text() + '\n[[package]]\nname = "anyio"\nversion = "4.2.0"\nsource = { registry = "https://pypi.org/simple" }\n')
    key = uvu.make_key("anyio", "4.3.0", "~/Real/tool", "uv.lock")
    assert refusal(store, key=key) == ("anyio is not a direct dependency of this project. "
                                       "Watchtower updates direct dependencies only.")


@pytest.mark.parametrize("lock,pyproject", [
    (lock_text(source='{ git = "https://example.com/httpx" }'), PYPROJECT),
    (lock_text(source='{ path = "../httpx" }'), PYPROJECT),
    (lock_text(), PYPROJECT + '\n[tool.uv.sources]\nhttpx = { git = "https://example.com/httpx" }\n'),
])
def test_git_and_path_dependencies_are_refused(tmp_path, store, lock, pyproject):
    make_project(tmp_path, lock=lock, pyproject=pyproject)
    assert refusal(store).startswith("httpx does not come from a package index.")


def test_a_package_locked_at_two_versions_is_refused(tmp_path, store):
    make_project(tmp_path, lock=lock_text() + lock_text("0.25.0").split("\n\n[[package]]\nname = \"tool\"")[0].split("requires-python = \">=3.12\"\n", 1)[1])
    assert refusal(store) == "uv.lock has no single version of httpx."


def test_a_target_that_the_lock_already_has_is_refused(tmp_path, store):
    make_project(tmp_path, lock=lock_text("0.27.2"))
    assert refusal(store) == "uv.lock already has httpx 0.27.2 or newer."


@pytest.mark.parametrize("requirement,shown", [
    ("httpx==0.26.0", "httpx==0.26.0"), ("httpx>=0.26,<0.27", "httpx>=0.26,<0.27"), ("httpx~=0.26.0", "httpx~=0.26.0"),
])
def test_a_requirement_that_excludes_the_target_is_refused_and_pyproject_stays(tmp_path, store, requirement, shown):
    root = make_project(tmp_path, pyproject=PYPROJECT.replace("httpx>=0.26", requirement))
    before = (root / "pyproject.toml").read_bytes()
    text = refusal(store)
    assert text == f'pyproject.toml requires "{shown}". That does not allow 0.27.2. Change it there first.'
    assert (root / "pyproject.toml").read_bytes() == before


def test_spec_allows():
    ok = uvu.spec_allows
    assert ok("", "1.0") and ok(">=0.26", "0.27.2") and ok(">=0.26,<1", "0.27.2") and ok("==0.27.*", "0.27.2")
    assert ok("~=0.27.1", "0.27.2") and ok("~=0.27", "0.99") and ok("!=0.26.1", "0.27.2") and ok("(>=1)", "1.0")
    assert not ok("==0.26.0", "0.27.2") and not ok("<0.27", "0.27.2") and not ok("~=0.26.0", "0.27.2")
    assert not ok("~=0.27.3", "0.27.2") and not ok("==0.26.*", "0.27.2") and not ok("!=0.27.*", "0.27.2")
    assert not ok(">=2", "1.9") and not ok("garbage", "1.0") and not ok(">0.27.2", "0.27.2")
    assert ok("<=0.27.2", "0.27.2") and ok("===0.27.2", "0.27.2") and ok(">=0.27.2.0", "0.27.2")


@pytest.mark.parametrize("key", [
    "homebrew/formula:git", "uv/", "uv/httpx|~/Real/tool|uv.lock", "uv/httpx@0.27.2|~/Real/tool",
    "uv/ht tp@0.27.2|~/Real/tool|uv.lock", "uv/httpx@0.27.2;ls|~/Real/tool|uv.lock",
    "uv/httpx@0.27.2|~/Real/tool|../uv.lock", "uv/httpx@0.27.2|~/Real/tool|/etc/uv.lock",
    "uv/httpx@0.27.2|~/Real/tool|requirements.txt", "uv/httpx@0.27.2||uv.lock",
])
def test_bad_keys_are_refused(tmp_path, store, key):
    make_project(tmp_path)
    if key.startswith("uv/"):
        p = plan_update(store, key, uv=UV, run=FakeUv(), fetch=FakePyPI(), uv_options=MAC)
        assert p.refusal == "Watchtower cannot read this update request."
    else:
        assert uvu.parse_key(key) is None


def test_a_project_outside_the_project_folders_is_refused(tmp_path, store):
    elsewhere = tmp_path / "elsewhere" / "tool"
    elsewhere.mkdir(parents=True)
    (elsewhere / "pyproject.toml").write_text(PYPROJECT)
    (elsewhere / "uv.lock").write_text(lock_text())
    uv = FakeUv()
    key = uvu.make_key("httpx", "0.27.2", str(elsewhere), "uv.lock")
    assert refusal(store, key=key, uv=uv) == "Watchtower cannot find this uv project in the project folders."
    assert uv.calls == []


def test_a_lockfile_path_that_leaves_the_project_is_refused(tmp_path, store):
    make_project(tmp_path)
    (tmp_path / "home" / "Real" / "tool" / "link").symlink_to(tmp_path)
    key = uvu.make_key("httpx", "0.27.2", "~/Real/tool", "link/uv.lock")
    assert refusal(store, key=key).startswith("Watchtower cannot find")


def test_uv_missing_is_refused(tmp_path, store, monkeypatch):
    make_project(tmp_path)
    monkeypatch.setattr(uvu, "find_uv", lambda: None)
    p = plan_update(store, KEY, uv=None, run=FakeUv(), fetch=FakePyPI(), uv_options=MAC)
    assert p.refusal == "uv is not installed."


def test_a_failed_or_odd_dry_run_is_refused(tmp_path, store):
    make_project(tmp_path)
    assert refusal(store, uv=FakeUv(code=2)) == "Watchtower cannot read the uv plan."
    assert refusal(store, uv=FakeUv("Resolved 1 package\n")) == "Watchtower cannot read the uv plan."
    assert refusal(store, uv=FakeUv("Update httpx v0.26.0 -> v0.28.0\n")) == "Watchtower cannot read the uv plan."


@pytest.mark.parametrize("pypi", [FakePyPI(error=OSError("down")), FakePyPI(status=404), FakePyPI({"urls": "x"}),
                                  FakePyPI({})])
def test_unknown_build_need_is_refused(tmp_path, store, pypi):
    make_project(tmp_path)
    assert refusal(store, pypi=pypi) == "Watchtower cannot check whether httpx 0.27.2 needs a source build."


def test_pypi_with_no_files_is_refused(tmp_path, store):
    make_project(tmp_path)
    assert refusal(store, pypi=FakePyPI({"urls": []})) == "PyPI has no files for httpx 0.27.2."


def test_pypi_request_holds_only_the_package_and_version(tmp_path, store):
    make_project(tmp_path)
    pypi = FakePyPI()
    plan(store, pypi=pypi)
    assert [u for u, _ in pypi.calls] == ["https://pypi.org/pypi/httpx/0.27.2/json"]
    assert set(pypi.calls[0][1]) == {"Accept"}


# Run and verify


def test_verified_needs_the_lockfile_and_the_environment(tmp_path, store):
    root = make_project(tmp_path)
    p = plan(store)
    runner = FakeSync(root, "both")
    attempt, checked = run(store, runner, p.id)
    assert attempt.status == "verified" and attempt.error is None
    assert (attempt.before_version, attempt.target_version, attempt.after_version) == ("0.26.0", "0.27.2", "0.27.2")
    assert attempt.result_rows == [{"label": "Lockfile", "value": "httpx 0.27.2"},
                                   {"label": "Installed (.venv)", "value": "httpx 0.27.2"}]
    assert attempt.command == runner.calls[0][0] and attempt.exit_code == 0
    assert "Resolved 12 packages" in attempt.output
    assert checked["rows"][0]["label"] == "Project"
    env = runner.calls[0][1]
    assert env["UV_PYTHON_DOWNLOADS"] == "never" and "UV_PROJECT_ENVIRONMENT" not in env


def test_lock_change_without_the_installed_target_stays_unverified(tmp_path, store):
    root = make_project(tmp_path)
    p = plan(store)
    attempt, _ = run(store, FakeSync(root, "lock_only"), p.id)
    assert attempt.status == "not_verified"
    assert attempt.error == "Not verified: the environment still has 0.26.0."
    assert attempt.after_version == "0.26.0"
    assert attempt.result_rows == [{"label": "Lockfile", "value": "httpx 0.27.2"},
                                   {"label": "Installed (.venv)", "value": "httpx 0.26.0"}]


def test_exit_zero_with_nothing_changed_is_not_verified(tmp_path, store):
    root = make_project(tmp_path)
    attempt, _ = run(store, FakeSync(root, "none"), plan(store).id)
    assert attempt.status == "not_verified"
    assert attempt.error == "The command finished, but uv.lock still has 0.26.0."


def test_a_failed_command_is_failed_and_the_rows_show_what_is_there(tmp_path, store):
    root = make_project(tmp_path)
    attempt, _ = run(store, FakeSync(root, "none", code=2), plan(store).id)
    assert (attempt.status, attempt.exit_code, attempt.error) == ("failed", 2, "The update failed (exit code 2).")
    assert attempt.result_rows[1]["value"] == "httpx 0.26.0"


def test_files_that_uv_changed_beside_the_lockfile_are_not_verified(tmp_path, store):
    root = make_project(tmp_path)
    attempt, _ = run(store, FakeSync(root, "stray"), plan(store).id)
    assert attempt.status == "not_verified"
    assert attempt.error == "uv changed files that Watchtower did not plan: README.md, new.txt."


def test_a_replaced_environment_is_not_verified(tmp_path, store):
    root = make_project(tmp_path)
    attempt, _ = run(store, FakeSync(root, "env_replaced"), plan(store).id)
    assert (attempt.status, attempt.error) == ("not_verified", "uv replaced the environment. Watchtower did not plan that.")


def test_pyproject_changed_by_the_run_is_flagged(tmp_path, store):
    root = make_project(tmp_path)

    def runner(args, env, on_line):
        (root / "uv.lock").write_text(lock_text("0.27.2"))
        (root / "pyproject.toml").write_text(PYPROJECT + "# edited\n")
        return 0

    attempt, _ = run(store, runner, plan(store).id)
    assert attempt.status == "not_verified" and "pyproject.toml" in attempt.error


def test_files_are_backed_up_privately_before_the_run(tmp_path, store):
    root = make_project(tmp_path)
    old = os.umask(0o022)
    try:
        attempt, _ = run(store, FakeSync(root), plan(store).id)
    finally:
        os.umask(old)
    folder = store.data_dir / "update-backups" / f"attempt-{attempt.id}"
    assert (folder / "uv.lock").read_text() == lock_text()  # The lock before the run.
    assert (folder / "pyproject.toml").read_text() == PYPROJECT
    assert stat.S_IMODE(os.stat(folder).st_mode) == 0o700
    assert {stat.S_IMODE(os.stat(f).st_mode) for f in folder.iterdir()} == {0o600}
    assert f"Backup of pyproject.toml and uv.lock: {folder}" in attempt.output


def test_a_changed_project_invalidates_the_plan(tmp_path, store):
    root = make_project(tmp_path)
    p = plan(store)
    (root / "uv.lock").write_text(lock_text() + "# edited by the owner\n")
    runner = FakeSync(root)
    attempt, _ = run(store, runner, p.id)
    assert (attempt.status, attempt.error) == ("plan_changed", "The plan changed. Review the new plan.")
    assert runner.calls == []
    (root / "README.md").write_text("only an unrelated file")  # Not part of the plan.
    assert plan(store).id == plan(store).id


def test_an_environment_that_changed_invalidates_the_plan(tmp_path, store):
    root = make_project(tmp_path)
    p = plan(store)
    (root / ".venv" / "pyvenv.cfg").write_text("home = /opt/python\nversion_info = 3.12.5\n")
    attempt, _ = run(store, FakeSync(root), p.id)
    assert attempt.status == "plan_changed"


def test_a_refused_plan_is_logged_and_not_run(tmp_path, store):
    root = make_project(tmp_path, env=False)
    p = plan(store)
    runner = FakeSync(root)
    attempt, _ = run(store, runner, p.id)
    assert attempt.status == "refused" and "No environment" in attempt.error and runner.calls == []
    assert [a.status for a in UpdateLog(store).attempts()] == ["refused"]


def test_a_major_change_needs_its_own_confirmation(tmp_path, store):
    root = make_project(tmp_path)
    key = uvu.make_key("httpx", "1.0.0", "~/Real/tool", "uv.lock")
    kw = dict(key=key, uv=FakeUv("Update httpx v0.26.0 -> v1.0.0\n"), pypi=FakePyPI({"urls": [{"filename": "httpx-1.0.0-py3-none-any.whl"}]}))
    p = plan(store, **kw)
    runner = FakeSync(root, target="1.0.0")
    attempt, _ = run(store, runner, p.id, key=key, uv=kw["uv"], pypi=kw["pypi"])
    assert attempt.status == "refused" and runner.calls == []
    attempt, _ = run(store, runner, p.id, key=key, uv=kw["uv"], pypi=kw["pypi"], confirm_major=True)
    assert attempt.status == "verified"


def test_interrupted_run_is_logged(tmp_path, store):
    root = make_project(tmp_path)

    def runner(args, env, on_line):
        on_line("starting")
        raise Interrupted()

    with pytest.raises(Interrupted):
        run(store, runner, plan(store).id)
    [a] = UpdateLog(store).attempts()
    assert a.status == "interrupted" and "starting" in a.output


def test_a_crashing_runner_is_a_failed_attempt(tmp_path, store):
    make_project(tmp_path)

    def runner(args, env, on_line):
        raise RuntimeError("no uv")

    attempt, _ = run(store, runner, plan(store).id)
    assert attempt.status == "failed"


def test_the_update_log_keeps_the_result_rows_and_old_logs_open(tmp_path, store):
    root = make_project(tmp_path)
    run(store, FakeSync(root), plan(store).id)
    store.db.execute("ALTER TABLE update_attempts DROP COLUMN result_rows")
    [a] = UpdateLog(store).attempts()  # The column comes back.
    assert a.result_rows == []


# Installed version and files


def test_installed_version_reads_dist_info_without_a_process(tmp_path):
    root = make_project(tmp_path, installed="0.26.0")
    assert uvu.installed_version(root, "httpx") == "0.26.0"
    assert uvu.installed_version(root, "HTTPX") == "0.26.0"
    assert uvu.installed_version(root, "other") is None
    site = root / ".venv" / "lib" / "python3.12" / "site-packages"
    (site / "My_Pkg-1.2.3.dist-info").mkdir()
    assert uvu.installed_version(root, "my.pkg") == "1.2.3"  # The folder name, if METADATA is missing.
    (site / "My_Pkg-1.2.3.dist-info" / "METADATA").write_text("Version: 1.2.4\n")
    assert uvu.installed_version(root, "my-pkg") == "1.2.4"


def test_parse_lock_changes_reads_only_known_lines():
    out = "Using CPython 3.12\nResolved 5 packages in 2ms\nUpdate a v1 -> v2\nUpdated b v1.0 -> v1.1\nAdd c v3\nRemoved d v4\nnoise\n"
    assert [(c.name, c.before, c.after, c.change) for c in uvu.parse_lock_changes(out)] == [
        ("a", "1", "2", "upgrade"), ("b", "1.0", "1.1", "upgrade"), ("c", None, "3", "install"), ("d", "4", None, "remove")]


def test_block_reason_is_none_for_a_ready_project_and_other_lockfiles(tmp_path):
    make_project(tmp_path)
    assert uvu.block_reason("~/Real/tool", "uv.lock") is None
    assert uvu.block_reason("~/Real/tool", "package-lock.json") is None
    assert uvu.block_reason("~/Real/gone", "uv.lock") is None


def test_findings_carry_the_reason_that_update_is_off(tmp_path):
    make_project(tmp_path, env=False)
    adv = {"ids": ["CVE-2024-1", "GHSA-aaaa-bbbb-cccc"], "title": "t", "severity": "high", "fixed_in": ["0.27.2"]}
    m = Match("tool", "~/Real/tool", "uv.lock", "httpx", "PyPI", "0.26.0", None, ["GHSA-aaaa-bbbb-cccc"], [], [adv])
    m2 = Match("web", "~/Projects/web", "package-lock.json", "lodash", "npm", "1", None, ["GHSA-1"], [],
               [{"ids": ["GHSA-1"], "title": "t", "severity": "low", "fixed_in": []}])
    scan = OsvResult(C("osv", "OSV", "complete"), [ProjectScan("tool", "~/Real/tool", [Lockfile("uv.lock", "PyPI", "scanned")])],
                     [m, m2], [])
    with Store(tmp_path / "data", clock=Clock(*[f"2026-10-29T10:{m:02d}:00Z" for m in range(20)])) as s:
        r = s.begin_refresh()
        s.finish_refresh(r.id, "complete", coverage=[scan.coverage], scan=scan)
        state = s.state()
    blocks = {f["package"]: f["paths"][0]["update_block"] for f in state["findings"]}
    assert blocks == {"httpx": "No environment found. Watchtower does not create environments.", "lodash": None}
