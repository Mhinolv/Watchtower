"""Requirements-only project update (#30). Fixtures only: no pip, no network, no real project."""
import copy
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from watchtower_engine.feeds.homebrew import Response
from watchtower_engine.store import Store
from watchtower_engine.update_log import UpdateLog
from watchtower_engine.updater import Interrupted, plan_update, run_update
from watchtower_engine.updates import requirements as ru

from contract import Clock

FIX = Path(__file__).parent / "fixtures" / "requirements"
SIMPLE = (FIX / "simple.txt").read_text()
REPORT = json.loads((FIX / "pip-report-requests-2.32.3.json").read_text())
PYPI_REQUESTS = json.loads((FIX / "pypi-requests-2.32.3.json").read_text())
PYPI_PYCRYPTO = json.loads((FIX / "pypi-pycrypto-2.6.1.json").read_text())
MAC = {"machine": "arm64", "mac": (15, 1), "system": "Darwin"}
# What the environment has before the update: requests is behind, two of its dependencies are old, two are missing.
INSTALLED = {"requests": "2.31.0", "urllib3": "1.26.18", "certifi": "2023.7.22", "click": "8.1.7", "rich": "13.7.1",
             "PyYAML": "6.0.1", "pytest": "7.4.4"}
KEY = ru.make_key("requests", "2.32.3", "~/Real/script")


def make_project(tmp_path, text=SIMPLE, installed=None, env=True, pip=True, name="script", where="Real"):
    root = tmp_path / "home" / where / name
    root.mkdir(parents=True)
    (root / "requirements.txt").write_text(text)
    (root / "README.md").write_text("hello")
    if env:
        (root / ".venv" / "bin").mkdir(parents=True)
        python = root / ".venv" / "bin" / "python"
        python.write_text("#!/bin/sh\n")
        python.chmod(0o755)
        (root / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\nversion_info = 3.12.4\n")
        site = root / ".venv" / "lib" / "python3.12" / "site-packages"
        for pkg, version in (installed or INSTALLED).items():
            put_dist(root, pkg, version)
        if pip:
            (site / "pip").mkdir(parents=True, exist_ok=True)
    return root


def put_dist(root, pkg, version):
    site = root / ".venv" / "lib" / "python3.12" / "site-packages"
    for old in site.glob(f"{pkg.replace('-', '_')}-*.dist-info"):
        old.rename(site / f"{pkg.replace('-', '_')}-{version}.dist-info")
        break
    else:
        (site / f"{pkg.replace('-', '_')}-{version}.dist-info").mkdir(parents=True)
    (site / f"{pkg.replace('-', '_')}-{version}.dist-info" / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {pkg}\nVersion: {version}\n\nbody")


def report_for(name, version, others=()):
    """A pip report in the real shape, for another package. The first entry of the real report is the template."""
    data = copy.deepcopy(REPORT)
    template = data["install"][0]
    items = []
    for n, v in ((name, version), *others):
        item = copy.deepcopy(template)
        item["metadata"]["name"], item["metadata"]["version"] = n, v
        items.append(item)
    data["install"] = items
    return json.dumps(data)


class FakeDry:
    """Answers `pip install --dry-run --report -`. Never starts a process."""

    def __init__(self, out=None, code=0):
        self.out, self.code, self.calls = json.dumps(REPORT) if out is None else out, code, []

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), kwargs))
        assert args[1:4] == ["-m", "pip", "install"] and "--dry-run" in args and args[args.index("--report") + 1] == "-"
        assert "--only-binary=:all:" in args  # Planning builds nothing: no setup.py, no build hook.
        assert not any(a.startswith("--no-binary") for a in args)
        assert not {k for k in kwargs["env"] if k.startswith("PIP_")} - {
            "PIP_DISABLE_PIP_VERSION_CHECK", "PIP_NO_INPUT", "PIP_PROGRESS_BAR", "PIP_REQUIRE_VIRTUALENV"}
        return subprocess.CompletedProcess(args, self.code, self.out, "boom" if self.code else "")


class FakePyPI:
    def __init__(self, data=PYPI_REQUESTS, status=200, error=None):
        self.data, self.status, self.error, self.calls = data, status, error, []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        if self.error:
            raise self.error
        return Response(self.status, {}, json.dumps(self.data).encode())


def wheel_page(name, version):
    return {"urls": [{"filename": f"{name}-{version}-py3-none-any.whl", "packagetype": "bdist_wheel"}]}


class FakePip:
    """Stands in for the pip process. `mode` says what it leaves behind."""

    def __init__(self, root, mode="ok", code=0, name="requests", target="2.32.3"):
        self.root, self.mode, self.code, self.name, self.target = root, mode, code, name, target
        self.calls = []

    def __call__(self, args, env, on_line):
        self.calls.append((list(args), dict(env)))
        on_line(f"Collecting {self.name}=={self.target}")
        if self.mode in ("ok", "stray", "env_replaced", "edit_blocked") and self.code == 0:
            put_dist(self.root, self.name, self.target)
        if self.mode == "stray":
            (self.root / "README.md").write_text("changed by pip")
        if self.mode == "env_replaced":
            (self.root / ".venv" / "pyvenv.cfg").write_text("home = /usr/local/bin\nversion_info = 3.13.0\n")
        if self.mode == "edit_blocked":  # The owner's editor rewrote the line while pip ran.
            (self.root / "requirements.txt").write_text(f"{self.name}==2.31.0 \\\n    ; python_version >= '3.8'\n")
        if self.code:
            on_line("ERROR: Could not install packages")
        return self.code


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "data", clock=Clock(*[f"2026-10-29T10:{m:02d}:00Z" for m in range(60)])) as s:
        yield s


def plan(store, dry=None, pypi=None, key=KEY, **kw):
    return plan_update(store, key, run=dry or FakeDry(), fetch=pypi or FakePyPI(), uv_options={**MAC, **kw})


def run(store, runner, plan_id, key=KEY, dry=None, pypi=None, **kw):
    return run_update(store, key, plan_id, run=dry or FakeDry(), fetch=pypi or FakePyPI(), runner=runner,
                      uv_options=MAC, **kw)


def rows(p):
    return {r["label"]: r for r in p.rows}


# Evidence and the file


def test_exact_pins_ranges_and_unpinned_lines_are_distinct_evidence():
    parsed = ru.parse_file(SIMPLE)
    found = {e.name: e.evidence for e in parsed.entries}
    assert found == {"requests": "Exact pin", "urllib3": "Exact pin", "click": "Range", "rich": "Range",
                     "PyYAML": "Unpinned", "Flask": "Exact pin", "pytest": "Range"}
    assert [ru.evidence(s) for s in ("==1.2.3", ">=1.2", "~=1.2", "==1.*", ">=1,<2", "", "===1.0")] == [
        "Exact pin", "Range", "Range", "Range", "Range", "Unpinned", "Range"]


def test_the_parser_reads_comments_extras_markers_and_other_lines_as_text():
    parsed = ru.parse_file(SIMPLE)
    by = {e.name: e for e in parsed.entries}
    assert by["urllib3"].extras == "[socks]" and by["urllib3"].marker == 'python_version < "3.10"'
    assert by["urllib3"].text == "urllib3[socks]==1.26.18"  # The comment is gone.
    assert by["rich"].spec == "~=13.7" and by["pytest"].spec == ">=7.4,!=8.0.0"
    assert parsed.sources == {"tool", "tomli"}  # An editable line and a URL requirement.
    assert not (parsed.includes or parsed.hashes or parsed.index)


@pytest.mark.parametrize("name,flag", [("with-include.txt", "includes"), ("with-constraint.txt", "includes"),
                                       ("with-hashes.txt", "hashes"), ("with-index.txt", "index")])
def test_includes_hashes_and_index_options_are_found(name, flag):
    parsed = ru.parse_file((FIX / name).read_text())
    assert getattr(parsed, flag) is True


def test_a_continued_line_is_one_entry_over_two_physical_lines():
    [entry] = ru.parse_file((FIX / "continued.txt").read_text()).entries
    assert (entry.first, entry.last, entry.marker) == (0, 1, 'python_version >= "3.8"')


def test_the_edit_changes_the_pin_only_and_keeps_everything_else(tmp_path):
    root = make_project(tmp_path)
    assert ru.apply_edit(root / "requirements.txt", "requests", "2.32.3") is True
    assert (root / "requirements.txt").read_text() == SIMPLE.replace("requests==2.31.0", "requests==2.32.3")
    parsed = ru.parse_file(SIMPLE)
    entry = next(e for e in parsed.entries if e.name == "urllib3")
    assert ru.edit_line(parsed.lines[entry.first], entry, "1.26.19") == (
        'urllib3[socks]==1.26.19 ; python_version < "3.10"   # pinned for old Pythons\n')


def test_the_edit_keeps_the_file_mode_and_leaves_no_temp_file(tmp_path):
    root = make_project(tmp_path)
    os.chmod(root / "requirements.txt", 0o640)
    ru.apply_edit(root / "requirements.txt", "requests", "2.32.3")
    assert stat.S_IMODE(os.stat(root / "requirements.txt").st_mode) == 0o640
    assert sorted(p.name for p in root.iterdir() if p.is_file()) == ["README.md", "requirements.txt"]


def test_a_range_that_allows_the_target_stays_as_it_is(tmp_path):
    root = make_project(tmp_path)
    assert ru.apply_edit(root / "requirements.txt", "click", "8.2.1") is True
    assert (root / "requirements.txt").read_text() == SIMPLE
    assert ru.apply_edit(root / "requirements.txt", "rich", "14.0.0") is False  # `~=13.7` does not allow 14.


# Plan


def test_plan_shows_the_exact_command_the_exact_edit_and_every_row(tmp_path, store):
    make_project(tmp_path)
    dry = FakeDry()
    p = plan(store, dry)
    assert p.refusal is None and p.kind == "requirements" and p.name == "requests"
    assert (p.installed_version, p.target_version, p.major_change) == ("2.31.0", "2.32.3", False)
    root = tmp_path / "home" / "Real" / "script"
    assert p.command == [str(root / ".venv" / "bin" / "python"), "-m", "pip", "install", "--only-binary=:all:",
                         "--disable-pip-version-check", "--no-input", "requests==2.32.3"]
    assert [x["label"] for x in p.rows] == ["Project", "Environment", "requirements.txt", "Evidence", "Lockfile",
                                            "Other packages", "Build"]
    r = rows(p)
    assert r["Project"]["value"] == "~/Real/script" and r["Environment"]["value"] == ".venv (exists)"
    assert r["requirements.txt"]["value"] == "requests==2.31.0 → requests==2.32.3"
    assert r["Evidence"]["value"] == "Exact pin (==2.31.0)"
    assert r["Lockfile"]["value"] == "No lockfile."
    assert r["Other packages"]["value"] == "4 packages change"
    assert r["Other packages"]["items"] == ["charset-normalizer 3.5.2 (new)", "idna 3.20 (new)",
                                            "urllib3 1.26.18 → 2.8.0", "certifi 2023.7.22 → 2026.10.23"]
    assert r["Build"]["value"] == "Disabled (wheels only)"
    assert p.scripts == [] and p.scripts_command is None and p.also_changes == []
    assert p.manual_steps == ["Restart the dev server after the update."]
    assert len(dry.calls) == 1  # One dry run, wheels only.


def test_the_file_is_not_changed_by_planning(tmp_path, store):
    root = make_project(tmp_path)
    plan(store)
    assert (root / "requirements.txt").read_text() == SIMPLE


def test_extras_and_markers_stay_in_the_edit_and_the_command(tmp_path, store):
    make_project(tmp_path, installed={**INSTALLED, "urllib3": "1.26.18"})
    key = ru.make_key("urllib3", "1.26.19", "~/Real/script")
    p = plan(store, FakeDry(report_for("urllib3", "1.26.19")), FakePyPI(wheel_page("urllib3", "1.26.19")), key)
    assert p.refusal is None
    assert rows(p)["requirements.txt"]["value"] == "urllib3[socks]==1.26.18 → urllib3[socks]==1.26.19"
    assert p.command[-1] == "urllib3[socks]==1.26.19"
    assert rows(p)["Other packages"]["value"] == "No other packages change."


def test_a_range_that_allows_the_target_needs_no_file_edit(tmp_path, store):
    make_project(tmp_path)
    key = ru.make_key("click", "8.2.1", "~/Real/script")
    p = plan(store, FakeDry(report_for("click", "8.2.1")), FakePyPI(wheel_page("click", "8.2.1")), key)
    assert p.refusal is None
    r = rows(p)
    assert r["requirements.txt"]["value"] == "No change" and r["Evidence"]["value"] == "Range (>=8.0,<9)"
    assert p.command[-1] == "click==8.2.1"


def test_an_unpinned_line_needs_no_file_edit_and_has_its_own_evidence(tmp_path, store):
    make_project(tmp_path)
    key = ru.make_key("PyYAML", "6.0.2", "~/Real/script")
    p = plan(store, FakeDry(report_for("PyYAML", "6.0.2")), FakePyPI(wheel_page("PyYAML", "6.0.2")), key)
    assert (rows(p)["Evidence"]["value"], rows(p)["requirements.txt"]["value"]) == ("Unpinned", "No change")


def test_a_range_that_excludes_the_target_is_refused_and_the_file_stays(tmp_path, store):
    root = make_project(tmp_path)
    key = ru.make_key("rich", "14.0.0", "~/Real/script")
    p = plan(store, FakeDry(report_for("rich", "14.0.0")), FakePyPI(wheel_page("rich", "14.0.0")), key)
    assert p.refusal == 'requirements.txt requires "rich~=13.7". That does not allow 14.0.0. Change it there first.'
    assert (root / "requirements.txt").read_text() == SIMPLE


def test_a_major_change_is_marked(tmp_path, store):
    make_project(tmp_path, text="requests==2.31.0\n")
    key = ru.make_key("requests", "3.0.0", "~/Real/script")
    p = plan(store, FakeDry(report_for("requests", "3.0.0")), FakePyPI(wheel_page("requests", "3.0.0")), key)
    assert p.major_change is True


def test_a_target_without_a_wheel_needs_the_scripts_step_and_no_dry_run_runs(tmp_path, store):
    make_project(tmp_path, text="pycrypto==2.6.0\n", installed={"pycrypto": "2.6.0"})
    key = ru.make_key("pycrypto", "2.6.1", "~/Real/script")
    dry = FakeDry()
    p = plan(store, dry, FakePyPI(PYPI_PYCRYPTO), key)
    assert p.refusal is None and dry.calls == []  # A dry run of a source archive would run its build hook.
    assert p.scripts == ["pycrypto needs a source build: no wheel for this platform."]
    assert p.scripts_message == p.scripts[0]
    assert "--no-binary=pycrypto" not in p.command and "--only-binary=:all:" in p.command
    assert p.scripts_command[-3:] == ["--disable-pip-version-check", "--no-input", "pycrypto==2.6.1"]
    assert p.scripts_command[4:6] == ["--only-binary=:all:", "--no-binary=pycrypto"]
    assert rows(p)["Other packages"]["value"] == "Not known before the build step"


def test_the_pypi_request_holds_only_the_package_and_version(tmp_path, store):
    make_project(tmp_path)
    pypi = FakePyPI()
    plan(store, pypi=pypi)
    assert pypi.calls == [("https://pypi.org/pypi/requests/2.32.3/json", {"Accept": "application/json"})]


# Refusals


@pytest.mark.parametrize("fixture", ["with-include.txt", "with-constraint.txt", "with-hashes.txt"])
def test_includes_and_hash_pins_are_refused_with_one_explicit_message(tmp_path, store, fixture):
    root = make_project(tmp_path, text=(FIX / fixture).read_text())
    dry = FakeDry()
    p = plan(store, dry)
    assert p.refusal == "requirements.txt with -r includes or hashes is not supported."
    assert dry.calls == [] and (root / "requirements.txt").read_text() == (FIX / fixture).read_text()


def test_a_refused_include_is_logged_and_nothing_runs(tmp_path, store):
    root = make_project(tmp_path, text=(FIX / "with-include.txt").read_text())
    p = plan(store)
    runner = FakePip(root)
    attempt, _ = run(store, runner, p.id)
    assert attempt.status == "refused" and "-r includes or hashes" in attempt.error and runner.calls == []
    assert [a.status for a in UpdateLog(store).attempts()] == ["refused"]


def test_a_package_index_option_is_refused(tmp_path, store):
    make_project(tmp_path, text=(FIX / "with-index.txt").read_text())
    assert plan(store).refusal == "requirements.txt sets a package index. Watchtower cannot update it."


@pytest.mark.parametrize("env,pip,refusal", [
    (False, True, "No environment found. Watchtower does not create environments."),
    (True, False, "The environment has no pip. Watchtower does not install tools into it."),
])
def test_no_environment_and_no_pip_are_refused_and_nothing_creates_one(tmp_path, store, env, pip, refusal, monkeypatch):
    monkeypatch.setattr(ru, "find_uv", lambda: None, raising=False)  # No uv on this Mac.
    root = make_project(tmp_path, env=env, pip=pip)
    p = plan(store)
    assert p.refusal == refusal
    assert (root / ".venv").exists() == env  # Nothing created an environment.


def test_a_folder_named_venv_without_a_config_is_no_environment(tmp_path, store):
    root = make_project(tmp_path)
    (root / ".venv" / "pyvenv.cfg").unlink()
    assert plan(store).refusal.startswith("No environment found")


@pytest.mark.parametrize("name,text,refusal", [
    ("idna", None, "idna is not a requirement of this file. Watchtower updates direct requirements only."),
    ("tool", None, "tool does not come from a package index. Watchtower cannot update editable, git or URL requirements."),
    ("tomli", None, "tomli does not come from a package index. Watchtower cannot update editable, git or URL requirements."),
    ("numpy", (FIX / "duplicate.txt").read_text(), "requirements.txt names numpy more than once. Watchtower cannot choose one."),
    ("requests", (FIX / "continued.txt").read_text(),
     "The line of requests continues on the next line. Watchtower cannot edit it."),
])
def test_other_requirements_are_refused(tmp_path, store, name, text, refusal):
    make_project(tmp_path, text=text or SIMPLE, installed={**INSTALLED, "idna": "3.4", "tool": "1.0", "tomli": "2.0.1",
                                                           "numpy": "1.26.4"})
    key = ru.make_key(name, "9.9.9", "~/Real/script")
    assert plan(store, key=key).refusal == refusal


def test_a_range_that_is_not_installed_is_refused(tmp_path, store):
    make_project(tmp_path, installed={"requests": "2.31.0"})
    key = ru.make_key("click", "8.5.0", "~/Real/script")
    assert plan(store, key=key).refusal == "The environment has no click. Watchtower does not install new packages."


def test_a_target_that_the_environment_already_has_is_refused(tmp_path, store):
    make_project(tmp_path, installed={**INSTALLED, "requests": "2.32.3"})
    assert plan(store).refusal == "The environment already has requests 2.32.3 or newer."


@pytest.mark.parametrize("key", ["requirements/requests|~/Real/script|requirements.txt", "requirements/requests@2.32.3|x",
                                 "requirements/req uests@2.32.3|~/Real/script|requirements.txt",
                                 "requirements/requests@2.32.3|~/Real/script|../requirements.txt",
                                 "requirements/requests@2.32.3|~/Real/script|requirements-dev.txt",
                                 "requirements/requests@2.32.3|~/Real/script|/etc/requirements.txt",
                                 "requirements/-r@2.32.3|~/Real/script|requirements.txt"])
def test_bad_keys_are_refused(tmp_path, store, key):
    make_project(tmp_path)
    assert plan(store, key=key).refusal == "Watchtower cannot read this update request."


def test_a_project_outside_the_project_folders_is_refused(tmp_path, store):
    make_project(tmp_path, where="Elsewhere")
    key = ru.make_key("requests", "2.32.3", "~/Elsewhere/script")
    assert plan(store, key=key).refusal == "Watchtower cannot find this requirements.txt in the project folders."


def test_a_file_that_is_a_symlink_out_of_the_project_is_refused(tmp_path, store):
    root = make_project(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("requests==2.31.0\n")
    (root / "requirements.txt").unlink()
    (root / "requirements.txt").symlink_to(outside)
    assert plan(store).refusal.startswith("Watchtower cannot find this requirements.txt")


@pytest.mark.parametrize("dry", [FakeDry(code=1), FakeDry("not json"), FakeDry("{}"),
                                 FakeDry(report_for("idna", "3.20"))])
def test_a_failed_or_odd_dry_run_is_refused(tmp_path, store, dry):
    make_project(tmp_path)
    assert plan(store, dry).refusal == "Watchtower cannot read the requirements plan."


@pytest.mark.parametrize("pypi", [FakePyPI(status=500), FakePyPI(error=OSError("down")), FakePyPI({"urls": "x"})])
def test_unknown_build_need_is_refused(tmp_path, store, pypi):
    make_project(tmp_path)
    assert plan(store, pypi=pypi).refusal == "Watchtower cannot check whether requests 2.32.3 needs a source build."


def test_pypi_with_no_files_is_refused(tmp_path, store):
    make_project(tmp_path)
    assert plan(store, pypi=FakePyPI({"urls": []})).refusal == "PyPI has no files for requests 2.32.3."


# Run and verify


def test_a_pin_update_is_verified_after_the_environment_and_the_file_show_the_target(tmp_path, store):
    root = make_project(tmp_path)
    p = plan(store)
    runner = FakePip(root)
    attempt, checked = run(store, runner, p.id)
    assert attempt.status == "verified" and attempt.error is None
    assert (attempt.before_version, attempt.target_version, attempt.after_version) == ("2.31.0", "2.32.3", "2.32.3")
    assert attempt.command == p.command == runner.calls[0][0] and attempt.exit_code == 0
    assert attempt.result_rows == [{"label": "requirements.txt", "value": "requests==2.32.3", "ok": True},
                                   {"label": "Installed (.venv)", "value": "requests 2.32.3", "ok": True}]
    assert (root / "requirements.txt").read_text() == SIMPLE.replace("requests==2.31.0", "requests==2.32.3")
    assert "Edited requirements.txt: requests==2.31.0 → requests==2.32.3" in attempt.output
    assert checked["kind"] == "requirements" and runner.calls[0][1]["PIP_REQUIRE_VIRTUALENV"] == "1"
    assert [a.status for a in UpdateLog(store).attempts()] == ["verified"]


def test_the_file_is_edited_only_after_the_environment_shows_the_target(tmp_path, store):
    root = make_project(tmp_path)
    attempt, _ = run(store, FakePip(root, "nothing"), plan(store).id)
    assert attempt.status == "not_verified" and attempt.error == "Not verified: the environment still has 2.31.0."
    assert (root / "requirements.txt").read_text() == SIMPLE  # Not edited: the environment did not change.
    assert attempt.result_rows[1] == {"label": "Installed (.venv)", "value": "requests 2.31.0", "ok": False}


def test_a_failed_command_leaves_the_file_and_is_failed(tmp_path, store):
    root = make_project(tmp_path)
    attempt, _ = run(store, FakePip(root, "nothing", code=1), plan(store).id)
    assert attempt.status == "failed" and attempt.error == "The update failed (exit code 1)."
    assert (root / "requirements.txt").read_text() == SIMPLE and "ERROR: Could not install" in attempt.output


def test_a_range_update_verifies_with_the_file_unchanged(tmp_path, store):
    root = make_project(tmp_path)
    key = ru.make_key("click", "8.2.1", "~/Real/script")
    p = plan(store, FakeDry(report_for("click", "8.2.1")), FakePyPI(wheel_page("click", "8.2.1")), key)
    attempt, _ = run(store, FakePip(root, name="click", target="8.2.1"), p.id, key,
                     FakeDry(report_for("click", "8.2.1")), FakePyPI(wheel_page("click", "8.2.1")))
    assert attempt.status == "verified" and (root / "requirements.txt").read_text() == SIMPLE
    assert attempt.result_rows[0] == {"label": "requirements.txt", "value": "click>=8.0,<9", "ok": True}


def test_an_edit_that_fails_after_the_install_is_not_verified(tmp_path, store):
    root = make_project(tmp_path)
    attempt, _ = run(store, FakePip(root, "edit_blocked"), plan(store).id)
    assert attempt.status == "not_verified"
    assert attempt.error == "pip installed requests 2.32.3, but Watchtower could not edit requirements.txt."


def test_files_that_pip_changed_beside_requirements_are_not_verified(tmp_path, store):
    root = make_project(tmp_path)
    attempt, _ = run(store, FakePip(root, "stray"), plan(store).id)
    assert attempt.status == "not_verified" and attempt.error == "pip changed files that Watchtower did not plan: README.md."


def test_a_replaced_environment_is_not_verified(tmp_path, store):
    root = make_project(tmp_path)
    attempt, _ = run(store, FakePip(root, "env_replaced"), plan(store).id)
    assert attempt.status == "not_verified" and attempt.error == "pip replaced the environment. Watchtower did not plan that."


def test_the_file_is_backed_up_privately_before_the_run(tmp_path, store):
    root = make_project(tmp_path)
    old = os.umask(0o022)
    try:
        attempt, _ = run(store, FakePip(root), plan(store).id)
    finally:
        os.umask(old)
    folder = store.data_dir / "update-backups" / f"attempt-{attempt.id}"
    assert (folder / "requirements.txt").read_text() == SIMPLE  # The file before the run.
    assert stat.S_IMODE(os.stat(folder).st_mode) == 0o700
    assert {stat.S_IMODE(os.stat(f).st_mode) for f in folder.iterdir()} == {0o600}
    assert f"Backup of requirements.txt: {folder}" in attempt.output


def test_a_changed_file_or_environment_invalidates_the_plan(tmp_path, store):
    root = make_project(tmp_path)
    p = plan(store)
    (root / "requirements.txt").write_text(SIMPLE + "# edited by the owner\n")
    runner = FakePip(root)
    attempt, _ = run(store, runner, p.id)
    assert (attempt.status, attempt.error) == ("plan_changed", "The plan changed. Review the new plan.")
    assert runner.calls == []
    p2 = plan(store)
    put_dist(root, "urllib3", "1.26.19")  # The environment moved.
    assert run(store, runner, p2.id)[0].status == "plan_changed"


def test_a_major_change_needs_its_own_confirmation(tmp_path, store):
    root = make_project(tmp_path, text="requests==2.31.0\n")
    key = ru.make_key("requests", "3.0.0", "~/Real/script")
    dry, pypi = FakeDry(report_for("requests", "3.0.0")), FakePyPI(wheel_page("requests", "3.0.0"))
    p = plan(store, dry, pypi, key)
    runner = FakePip(root, target="3.0.0")
    attempt, _ = run(store, runner, p.id, key, dry, pypi)
    assert attempt.status == "refused" and attempt.error == "A new major version needs its own confirmation."
    assert runner.calls == []
    attempt, _ = run(store, runner, p.id, key, dry, pypi, confirm_major=True)
    assert attempt.status == "verified" and (root / "requirements.txt").read_text() == "requests==3.0.0\n"


def test_a_source_build_runs_only_after_the_scripts_confirmation(tmp_path, store):
    root = make_project(tmp_path, text="pycrypto==2.6.0\n", installed={"pycrypto": "2.6.0"})
    key = ru.make_key("pycrypto", "2.6.1", "~/Real/script")
    pypi = FakePyPI(PYPI_PYCRYPTO)
    p = plan(store, pypi=pypi, key=key)
    runner = FakePip(root, name="pycrypto", target="2.6.1")
    attempt, _ = run(store, runner, p.id, key, pypi=pypi)
    assert attempt.status == "refused" and attempt.error == "This update needs install scripts. Confirm them first."
    assert runner.calls == []
    attempt, _ = run(store, runner, p.id, key, pypi=pypi, confirm_scripts=True)
    assert attempt.status == "verified" and runner.calls[0][0] == p.scripts_command
    assert "--no-binary=pycrypto" in runner.calls[0][0]


def test_the_first_run_always_has_no_build(tmp_path, store):
    root = make_project(tmp_path)
    runner = FakePip(root)
    run(store, runner, plan(store).id)
    assert "--only-binary=:all:" in runner.calls[0][0] and not any(a.startswith("--no-binary") for a in runner.calls[0][0])
    assert not any(a in runner.calls[0][0] for a in ("-r", "--upgrade", "-U", "uninstall", "--user"))


def test_an_interrupted_run_is_logged(tmp_path, store):
    root = make_project(tmp_path)

    def interrupted(args, env, on_line):
        raise Interrupted()

    with pytest.raises(Interrupted):
        run(store, interrupted, plan(store).id)
    assert [a.status for a in UpdateLog(store).attempts()] == ["interrupted"]
    assert (root / "requirements.txt").read_text() == SIMPLE


def test_a_crashing_runner_is_a_failed_attempt(tmp_path, store):
    make_project(tmp_path)

    def crash(args, env, on_line):
        raise OSError("no such file")

    attempt, _ = run(store, crash, plan(store).id)
    assert attempt.status == "failed" and "no such file" in attempt.output


# A .venv with no pip: uv (#96)

UV_DRY = (FIX / "uv-dry-run-requests-2.32.3.txt").read_text()
UV_DRY_LITELLM = (FIX / "uv-dry-run-litellm-1.84.0.txt").read_text()


def fake_uv(tmp_path):
    """A path that stands in for the uv binary. Nothing starts it: the runs are fakes."""
    path = tmp_path / "bin" / "uv"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 99\n")
    path.chmod(0o755)
    return str(path)


class FakeUvDry:
    """Answers `uv pip install --dry-run`. uv writes the plan to stderr. Never starts a process."""

    def __init__(self, uv, err=UV_DRY, code=0):
        self.uv, self.err, self.code, self.calls = uv, err, code, []

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), kwargs))
        assert args[:3] == [self.uv, "pip", "install"] and "--dry-run" in args
        assert "--only-binary=:all:" in args and not any(a.startswith("--no-binary") for a in args)
        assert kwargs["env"]["UV_PYTHON_DOWNLOADS"] == "never"
        assert not {k for k in kwargs["env"] if k.startswith("UV_")} - {"UV_PYTHON_DOWNLOADS", "UV_NO_PROGRESS"}
        return subprocess.CompletedProcess(args, self.code, "", "error: boom" if self.code else self.err)


def test_a_venv_with_no_pip_plans_with_uv_into_that_venv(tmp_path, store):
    root = make_project(tmp_path, pip=False)
    uv = fake_uv(tmp_path)
    dry = FakeUvDry(uv)
    p = plan(store, dry, uv=uv)
    python = str(root / ".venv" / "bin" / "python")
    assert p.refusal is None and p.installed_version == "2.31.0" and p.target_version == "2.32.3"
    assert p.command == [uv, "pip", "install", "--python", python, "--only-binary=:all:", "requests==2.32.3"]
    assert dry.calls[0][0] == [uv, "pip", "install", "--dry-run", "--python", python, "--only-binary=:all:",
                               "requests==2.32.3"]
    assert rows(p)["Other packages"]["value"] == "No other packages change."
    assert rows(p)["Build"]["value"] == "Disabled (wheels only)"
    assert not (root / ".venv" / "lib" / "python3.12" / "site-packages" / "pip").exists()  # uv installs no pip.
    assert (root / "requirements.txt").read_text() == SIMPLE


def test_the_uv_dry_run_lists_the_other_packages_that_change(tmp_path, store):
    root = make_project(tmp_path, text="litellm==1.52.2\n", installed={"litellm": "1.52.2", "zipp": "3.20.0"}, pip=False)
    uv = fake_uv(tmp_path)
    key = ru.make_key("litellm", "1.84.0", "~/Real/script")
    err = UV_DRY_LITELLM.replace(" + fastuuid", " - litellm==1.52.2\n - zipp==3.20.0\n + fastuuid")
    p = plan(store, FakeUvDry(uv, err), FakePyPI(wheel_page("litellm", "1.84.0")), key, uv=uv)
    assert p.refusal is None and p.installed_version == "1.52.2" and p.major_change is False
    assert rows(p)["Other packages"]["value"] == "6 packages change"
    assert rows(p)["Other packages"]["items"] == ["fastuuid 0.14.0 (new)", "importlib-metadata 8.9.0 (new)",
                                                  "jiter 0.18.0 (new)", "openai 2.54.0 (new)", "tiktoken 0.14.0 (new)",
                                                  "zipp 3.20.0 → 4.1.2"]


@pytest.mark.parametrize("err,code", [("", 0), ("Would make no changes\n", 0), (UV_DRY, 2),
                                      (UV_DRY.replace("requests==2.32.3", "requests==2.32.2"), 0)])
def test_a_failed_or_odd_uv_dry_run_is_refused(tmp_path, store, err, code):
    make_project(tmp_path, pip=False)
    uv = fake_uv(tmp_path)
    assert plan(store, FakeUvDry(uv, err, code), uv=uv).refusal == "Watchtower cannot read the requirements plan."


def test_a_venv_with_no_pip_and_no_uv_still_refuses_and_shows_the_installed_version(tmp_path, store, monkeypatch):
    monkeypatch.setattr(ru, "find_uv", lambda: None, raising=False)
    make_project(tmp_path, pip=False)
    dry = FakeDry()
    p = plan(store, dry)
    assert p.refusal == "The environment has no pip. Watchtower does not install tools into it."
    assert p.installed_version == "2.31.0"  # The dialog shows `2.31.0 → 2.32.3`, not `? → 2.32.3`.
    assert dry.calls == []


def test_a_refused_plan_still_shows_the_installed_version(tmp_path, store):
    make_project(tmp_path, text="--index-url https://example.invalid/simple\n" + SIMPLE)
    p = plan(store)
    assert p.refusal.startswith("requirements.txt sets a package index") and p.installed_version == "2.31.0"


def test_a_venv_with_pip_keeps_the_pip_command_when_uv_exists(tmp_path, store):
    root = make_project(tmp_path)
    p = plan(store, uv=fake_uv(tmp_path))
    assert p.command[:4] == [str(root / ".venv" / "bin" / "python"), "-m", "pip", "install"]


def test_a_source_build_with_uv_is_refused(tmp_path, store):
    make_project(tmp_path, text="pycrypto==2.6.0\n", installed={"pycrypto": "2.6.0"}, pip=False)
    uv = fake_uv(tmp_path)
    dry = FakeUvDry(uv)
    key = ru.make_key("pycrypto", "2.6.1", "~/Real/script")
    p = plan(store, dry, FakePyPI(PYPI_PYCRYPTO), key, uv=uv)
    assert p.refusal == "pycrypto needs a source build. Watchtower builds from source with pip only."
    assert dry.calls == [] and p.scripts_command is None


def test_a_uv_update_is_verified_from_the_venv_and_runs_with_the_uv_environment(tmp_path, store):
    root = make_project(tmp_path, pip=False)
    uv = fake_uv(tmp_path)
    p = plan(store, FakeUvDry(uv), uv=uv)
    runner = FakePip(root)
    attempt, _ = run_update(store, KEY, p.id, run=FakeUvDry(uv), fetch=FakePyPI(), runner=runner,
                            uv_options={**MAC, "uv": uv})
    assert attempt.status == "verified" and attempt.after_version == "2.32.3"
    assert runner.calls[0][0] == p.command and runner.calls[0][0][:3] == [uv, "pip", "install"]
    env = runner.calls[0][1]
    assert env["UV_PYTHON_DOWNLOADS"] == "never" and not any(k.startswith("PIP_") for k in env)
    assert (root / "requirements.txt").read_text() == SIMPLE.replace("requests==2.31.0", "requests==2.32.3")


def test_a_uv_run_that_leaves_the_old_version_is_not_verified(tmp_path, store):
    root = make_project(tmp_path, pip=False)
    uv = fake_uv(tmp_path)
    p = plan(store, FakeUvDry(uv), uv=uv)
    runner = FakePip(root, mode="nothing")  # Exit code 0, but .venv still has 2.31.0.
    attempt, _ = run_update(store, KEY, p.id, run=FakeUvDry(uv), fetch=FakePyPI(), runner=runner,
                            uv_options={**MAC, "uv": uv})
    assert attempt.status == "not_verified" and attempt.error == "Not verified: the environment still has 2.31.0."
    assert (root / "requirements.txt").read_text() == SIMPLE


# A pinned package that is not installed: the pin only (#96, owner decision)

PIN_ONLY_ROW = "Not installed. Watchtower changes the pin in requirements.txt only and installs nothing."


def test_a_pinned_package_that_is_not_installed_plans_a_pin_only_change(tmp_path, store, monkeypatch):
    monkeypatch.setattr(ru, "find_uv", lambda: None)  # No pip and no uv: the pin only needs neither.
    root = make_project(tmp_path, installed={"click": "8.1.7"}, pip=False)
    dry, pypi = FakeDry(), FakePyPI()
    p = plan(store, dry, pypi)
    assert p.refusal is None and p.command == [] and p.installed_version is None and p.target_version == "2.32.3"
    assert [x["label"] for x in p.rows] == ["Project", "Environment", "requirements.txt", "Evidence",
                                            "Installed (.venv)", "Lockfile"]
    r = rows(p)
    assert r["requirements.txt"]["value"] == "requests==2.31.0 → requests==2.32.3"
    assert r["Installed (.venv)"]["value"] == PIN_ONLY_ROW
    assert p.major_change is False and p.scripts == [] and p.manual_steps == []
    assert dry.calls == [] and pypi.calls == []  # No pip, no uv, no PyPI.
    assert (root / "requirements.txt").read_text() == SIMPLE


def test_a_pin_only_change_keeps_extras_markers_and_marks_a_major_pin(tmp_path, store):
    make_project(tmp_path, installed={"click": "8.1.7"})
    key = ru.make_key("Flask", "4.0.1", "~/Real/script")
    p = plan(store, key=key)
    assert p.refusal is None and p.major_change is True
    assert rows(p)["requirements.txt"]["value"] == "Flask[async]==3.0.0 → Flask[async]==4.0.1"


def test_a_pin_that_already_has_the_target_is_refused_when_not_installed(tmp_path, store):
    make_project(tmp_path, text="requests==2.32.3\n", installed={"click": "8.1.7"})
    assert plan(store).refusal == "requirements.txt already pins requests 2.32.3 or newer."


def test_a_continued_pin_line_that_is_not_installed_is_refused(tmp_path, store):
    make_project(tmp_path, text=(FIX / "continued.txt").read_text(), installed={"click": "8.1.7"})
    assert plan(store).refusal == "The line of requests continues on the next line. Watchtower cannot edit it."


def test_a_pin_only_update_edits_the_file_installs_nothing_and_is_pin_updated(tmp_path, store):
    root = make_project(tmp_path, installed={"click": "8.1.7"}, pip=False)
    p = plan(store)
    runner = FakePip(root)
    attempt, checked = run(store, runner, p.id)
    assert runner.calls == []  # Nothing ran: no pip, no uv.
    assert attempt.status == "pin_updated" and attempt.error is None
    assert (attempt.before_version, attempt.after_version, attempt.exit_code) == (None, None, None)
    assert attempt.command == []
    assert (root / "requirements.txt").read_text() == SIMPLE.replace("requests==2.31.0", "requests==2.32.3")
    assert attempt.result_rows == [{"label": "requirements.txt", "value": "requests==2.32.3", "ok": True},
                                   {"label": "Installed (.venv)", "value": "requests not installed"}]
    assert "Edited requirements.txt: requests==2.31.0 → requests==2.32.3" in attempt.output
    assert "No command runs." in attempt.output
    assert not (root / ".venv" / "lib" / "python3.12" / "site-packages" / "requests-2.32.3.dist-info").exists()
    assert list((tmp_path / "data" / "update-backups").glob("attempt-*/requirements.txt"))


def test_a_pin_only_update_whose_edit_fails_is_not_verified(tmp_path, store, monkeypatch):
    root = make_project(tmp_path, installed={"click": "8.1.7"})
    p = plan(store)
    monkeypatch.setattr(ru, "apply_edit", lambda path, name, target: False)
    attempt, _ = run(store, FakePip(root), p.id)
    assert attempt.status == "not_verified" and attempt.error == "Not verified: requirements.txt still says requests==2.31.0."
    assert (root / "requirements.txt").read_text() == SIMPLE


def test_a_package_installed_after_the_plan_changes_the_plan(tmp_path, store):
    root = make_project(tmp_path, installed={"click": "8.1.7"})
    p = plan(store)
    put_dist(root, "requests", "2.31.0")
    attempt, _ = run(store, FakePip(root), p.id)
    assert attempt.status == "plan_changed"


# Findings


def test_block_reason_is_none_for_a_ready_project_and_other_files(tmp_path):
    root = make_project(tmp_path)
    assert ru.block_reason("~/Real/script", "requirements.txt") is None
    assert ru.block_reason("~/Real/script", "uv.lock") is None
    assert ru.block_reason("~/Real/missing", "requirements.txt") is None


def test_block_reason_names_includes_and_a_missing_environment(tmp_path):
    root = make_project(tmp_path, text=(FIX / "with-hashes.txt").read_text())
    assert ru.block_reason("~/Real/script", "requirements.txt") == "requirements.txt with -r includes or hashes is not supported."
    (root / "requirements.txt").write_text("requests==2.31.0\n")
    (root / ".venv" / "pyvenv.cfg").unlink()
    assert ru.block_reason("~/Real/script", "requirements.txt") == "No environment found. Watchtower does not create environments."
