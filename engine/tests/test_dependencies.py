"""The Projects `Dependencies` table (#81): the engine side. Real registry answers (fixtures/registries), real
requirements.txt and Cargo shapes (fixtures/requirements, fixtures/cargo). No network, no process."""
import gzip
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from watchtower_engine import cli
from watchtower_engine.dependencies import project_dependencies
from watchtower_engine.discovery import Project
from watchtower_engine.feeds import registries
from watchtower_engine.feeds.homebrew import Response
from watchtower_engine.updates import requirements as req_updates
from watchtower_engine.scope import list_projects

from test_requirements_update import FIX as REQ_FIX
from test_requirements_update import INSTALLED, SIMPLE, make_project, put_dist

REG = Path(__file__).parent / "fixtures" / "registries"
CARGO = Path(__file__).parent / "fixtures" / "cargo"
T1, T2, T3 = "2026-10-30T08:00:00Z", "2026-10-30T20:00:00Z", "2026-11-01T08:00:00Z"


class FakeRegistry:
    """Answers from the real fixtures. A name without a fixture fails like a registry that does not answer."""

    def __init__(self, fail=()):
        self.calls, self.fail = [], set(fail)
        self.gzip = False  # True: answer in gzip, like the real PyPI.

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        if url.startswith("https://pypi.org/simple/"):
            name = url.split("/")[4]
            path = REG / f"pypi-simple-{name.lower()}.json"
        elif url.startswith("https://index.crates.io/"):
            name = url.rsplit("/", 1)[1]
            path = REG / f"crates-{name}.ndjson"
        else:
            raise AssertionError(url)
        if name in self.fail or (not path.exists() and not name.startswith("pkg")):
            raise OSError("down")
        body = path.read_bytes() if path.exists() else b'{"versions": ["1.0.0", "1.1.0"], "files": []}'  # `pkgN`: a made-up project.
        if self.gzip:
            return Response(200, {"content-encoding": "gzip"}, gzip.compress(body))
        return Response(200, {}, body)

    def names(self):
        return [u.rsplit("/", 2)[-2] if "pypi.org" in u else u.rsplit("/", 1)[1] for u, _ in self.calls]


def cargo_project(tmp_path, name="tool", source="tool", where="Projects"):
    root = tmp_path / "home" / where / name
    shutil.copytree(CARGO / source, root)
    (root / "src").mkdir(exist_ok=True)
    return root


def find(tmp_path, name):
    return next(p for p in list_projects(tmp_path / "data").projects if p.name == name)


def deps(tmp_path, name, fetch=None, findings=(), now=T1):
    return project_dependencies(find(tmp_path, name), findings, tmp_path / "data", fetch or FakeRegistry(), lambda: now)


def section(result, manifest):
    return next(s for s in result["sections"] if s["manifest"] == manifest)


def rows(sec):
    return {r["package"]: r for r in sec["rows"]}


# requirements.txt


def test_a_requirements_project_lists_every_direct_dependency_with_installed_and_latest(tmp_path):
    make_project(tmp_path)
    result = deps(tmp_path, "script")
    assert result["supported"] is True and result["project"] == "~/Real/script"
    sec = section(result, "requirements.txt")
    assert sec["kind"] == "requirements" and sec["refusal"] is None
    r = rows(sec)
    assert set(r) == {"requests", "urllib3", "click", "rich", "PyYAML", "Flask", "pytest"}  # -e and URL lines are not rows.
    assert (r["requests"]["declared"], r["requests"]["evidence"]) == ("==2.31.0", "exact_pin")
    assert (r["click"]["declared"], r["click"]["evidence"]) == (">=8.0,<9", "range")
    assert (r["PyYAML"]["declared"], r["PyYAML"]["evidence"]) == ("", "unpinned")
    assert r["requests"]["installed"] == "2.31.0" and r["requests"]["installed_label"] == ".venv"
    assert (r["requests"]["latest"], r["urllib3"]["latest"], r["click"]["latest"], r["rich"]["latest"]) == (
        "2.34.2", "2.8.0", "8.5.0", "15.0.0")
    assert sec["latest_source"] == {"registry": "PyPI", "retrieved_at": T1, "error": "PyPI did not respond."}


def test_the_status_and_the_update_of_each_requirements_row(tmp_path):
    make_project(tmp_path)
    r = rows(section(deps(tmp_path, "script"), "requirements.txt"))
    assert r["requests"]["status"] == "update_available"
    assert r["requests"]["update_key"] == "requirements/requests@2.34.2|~/Real/script|requirements.txt"
    assert r["requests"]["update_refusal"] is None
    assert r["PyYAML"]["update_key"] == "requirements/PyYAML@6.0.3|~/Real/script|requirements.txt"  # Unpinned.
    assert r["pytest"]["update_key"] == "requirements/pytest@9.2.0|~/Real/script|requirements.txt"  # `>=7.4` allows it.
    assert r["click"]["update_key"] == "requirements/click@8.5.0|~/Real/script|requirements.txt"  # `>=8.0,<9` allows 8.5.0.
    # A range that does not allow the latest version: no key, the plan's own text.
    assert r["rich"]["update_key"] is None
    assert r["rich"]["update_refusal"] == 'requirements.txt requires "rich~=13.7". That does not allow 15.0.0. Change it there first.'
    # Not installed: nothing to compare, the registry did not answer for Flask either.
    assert (r["Flask"]["installed"], r["Flask"]["latest"], r["Flask"]["status"]) == (None, None, "unknown")
    assert r["Flask"]["latest_error"] == "PyPI did not respond." and r["Flask"]["update_key"] is None


def test_an_up_to_date_row_has_no_update(tmp_path):
    make_project(tmp_path, installed={**INSTALLED, "requests": "2.34.2"})
    row = rows(section(deps(tmp_path, "script"), "requirements.txt"))["requests"]
    assert (row["status"], row["update_key"], row["update_refusal"]) == ("up_to_date", None, None)


def test_rows_sort_vulnerable_then_update_available_then_name(tmp_path):
    make_project(tmp_path)
    finding = SimpleNamespace(status="open", ecosystem="PyPI", package="Click", paths=[SimpleNamespace(project_path="~/Real/script", lockfile="requirements.txt")],
                              id="SEC-0007", severity="high")
    sec = section(deps(tmp_path, "script", findings=[finding]), "requirements.txt")
    order = [r["package"] for r in sec["rows"]]
    assert order[0] == "click" and rows(sec)["click"]["status"] == "vulnerable"
    assert (rows(sec)["click"]["finding_id"], rows(sec)["click"]["severity"]) == ("SEC-0007", "high")
    updates = [r["package"] for r in sec["rows"] if r["status"] == "update_available"]
    assert order[1:1 + len(updates)] == sorted(updates, key=str.lower)
    assert order[-1] == "Flask"  # Unknown rows come last.


def test_a_finding_of_another_project_or_a_resolved_one_does_not_mark_a_row(tmp_path):
    make_project(tmp_path)
    other = SimpleNamespace(status="open", ecosystem="PyPI", package="requests", paths=[SimpleNamespace(project_path="~/Real/else", lockfile="requirements.txt")],
                            id="SEC-0001", severity="high")
    resolved = SimpleNamespace(status="resolved", ecosystem="PyPI", package="requests",
                               paths=[SimpleNamespace(project_path="~/Real/script", lockfile="requirements.txt")], id="SEC-0002", severity="high")
    npm = SimpleNamespace(status="open", ecosystem="npm", package="requests", paths=[SimpleNamespace(project_path="~/Real/script", lockfile="requirements.txt")],
                          id="SEC-0003", severity="high")
    row = rows(section(deps(tmp_path, "script", findings=[other, resolved, npm]), "requirements.txt"))["requests"]
    assert row["status"] == "update_available" and row["finding_id"] is None


@pytest.mark.parametrize("fixture,refusal", [
    ("with-include.txt", "requirements.txt with -r includes or hashes is not supported."),
    ("with-hashes.txt", "requirements.txt with -r includes or hashes is not supported."),
    ("with-index.txt", "requirements.txt sets a package index. Watchtower cannot update it.")])
def test_an_unsupported_file_lists_its_rows_without_update_and_names_the_reason(tmp_path, fixture, refusal):
    make_project(tmp_path, text=(REQ_FIX / fixture).read_text())
    sec = section(deps(tmp_path, "script"), "requirements.txt")
    assert sec["refusal"] == refusal and "requests" in rows(sec)
    assert all(r["update_key"] is None for r in sec["rows"])
    assert rows(sec)["requests"]["update_refusal"] == refusal  # A newer version exists, the plan would refuse it.


def test_no_environment_and_no_pip_are_named_and_installed_is_not_known(tmp_path, monkeypatch):
    monkeypatch.setattr(req_updates, "find_uv", lambda: None, raising=False)  # No uv on this Mac.
    make_project(tmp_path, env=False)
    sec = section(deps(tmp_path, "script"), "requirements.txt")
    assert sec["refusal"] == "No environment found. Watchtower does not create environments."
    assert all(r["installed"] is None and r["update_key"] is None for r in sec["rows"])
    shutil.rmtree(tmp_path / "home")
    make_project(tmp_path, pip=False)
    assert section(deps(tmp_path, "script"), "requirements.txt")["refusal"].startswith("The environment has no pip.")


def test_a_venv_with_no_pip_is_updatable_when_uv_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(req_updates, "find_uv", lambda: "/opt/homebrew/bin/uv", raising=False)
    make_project(tmp_path, pip=False)
    sec = section(deps(tmp_path, "script", FakeRegistry()), "requirements.txt")
    assert sec["refusal"] is None
    assert rows(sec)["requests"]["installed"] == "2.31.0" and rows(sec)["requests"]["update_key"] is not None


def test_a_name_that_appears_twice_is_not_updatable(tmp_path):
    make_project(tmp_path, text=(REQ_FIX / "duplicate.txt").read_text(), installed={"numpy": "1.26.4"})
    sec = section(deps(tmp_path, "script", FakeRegistry()), "requirements.txt")
    assert [r["update_key"] for r in sec["rows"]] == [None, None]


# Cargo.toml


def test_a_cargo_project_lists_declared_locked_and_latest(tmp_path):
    cargo_project(tmp_path)
    result = deps(tmp_path, "tool")
    sec = section(result, "Cargo.toml")
    assert sec["kind"] == "cargo" and sec["refusal"] is None
    r = rows(sec)
    assert set(r) == {"serde", "itoa", "smallvec", "memchr"}
    assert (r["serde"]["declared"], r["serde"]["evidence"], r["serde"]["installed"], r["serde"]["installed_label"]) == (
        "1.0.190", "range", "1.0.190", "locked")
    assert (r["itoa"]["declared"], r["itoa"]["evidence"]) == ("=1.0.9", "exact_pin")
    assert r["memchr"]["table"] == "dev-dependencies"
    assert (r["serde"]["latest"], r["itoa"]["latest"], r["memchr"]["latest"]) == ("1.0.229", "1.0.18", "2.8.3")
    assert sec["latest_source"]["registry"] == "crates.io"


def test_a_pre_release_is_never_the_latest_version(tmp_path):
    cargo_project(tmp_path)
    assert rows(section(deps(tmp_path, "tool"), "Cargo.toml"))["smallvec"]["latest"] == "1.16.4"  # The index also lists 2.0.0-beta.x.


def test_the_cargo_update_keys_and_refusals_use_the_adapters_texts(tmp_path):
    cargo_project(tmp_path)
    r = rows(section(deps(tmp_path, "tool"), "Cargo.toml"))
    assert r["serde"]["update_key"] == "cargo/serde@1.0.229|~/Projects/tool|Cargo.lock" and r["serde"]["status"] == "update_available"
    assert r["smallvec"]["update_key"] == "cargo/smallvec@1.16.4|~/Projects/tool|Cargo.lock"
    # The exact pin `=1.0.9` does not allow the latest version. The plan refuses it with this text.
    assert r["itoa"]["update_key"] is None
    assert r["itoa"]["update_refusal"] == 'Cargo.toml requires itoa "=1.0.9". That does not allow 1.0.18. Change it there first.'
    assert (r["memchr"]["status"], r["memchr"]["update_key"], r["memchr"]["update_refusal"]) == ("up_to_date", None, None)


def test_a_workspace_is_named_and_has_no_rows(tmp_path):
    cargo_project(tmp_path, name="ws", source="workspace")
    sec = section(deps(tmp_path, "ws"), "Cargo.toml")
    assert sec["refusal"] == "Cargo workspaces are not supported yet." and sec["rows"] == []


def test_a_cargo_lock_that_does_not_match_turns_update_off_but_keeps_the_rows(tmp_path):
    root = cargo_project(tmp_path)
    (root / "Cargo.lock").unlink()
    sec = section(deps(tmp_path, "tool"), "Cargo.toml")
    assert sec["refusal"] == "Cargo.lock is missing or out of date. Run cargo yourself first."
    assert sec["rows"] and all(r["update_key"] is None for r in sec["rows"])


def test_git_and_path_dependencies_are_listed_without_a_lookup_or_update(tmp_path):
    root = cargo_project(tmp_path)
    (root / "Cargo.toml").write_text((root / "Cargo.toml").read_text() +
                                     'local = { path = "../local" }\ngitdep = { git = "https://example.com/x.git" }\n')
    registry = FakeRegistry()
    sec = section(deps(tmp_path, "tool", registry), "Cargo.toml")
    r = rows(sec)
    assert (r["local"]["evidence"], r["gitdep"]["evidence"]) == ("path", "git")
    assert "local" not in registry.names() and "gitdep" not in registry.names()


# Manifests keyed by their relative path (#85)


def test_a_manifest_below_the_project_folder_is_its_own_section(tmp_path):
    root = cargo_project(tmp_path, name="mono")
    (root / "capture").mkdir()
    shutil.copy(CARGO / "tool" / "Cargo.toml", root / "capture" / "Cargo.toml")
    shutil.copy(CARGO / "tool" / "Cargo.lock", root / "capture" / "Cargo.lock")
    (root / "scripts" / "x").mkdir(parents=True)
    (root / "scripts" / "x" / "requirements.txt").write_text("requests==2.31.0\n")
    project = Project("mono", str(root), "~/Projects", ["Cargo.toml", "capture/Cargo.toml", "scripts/x/requirements.txt",
                                                        "package-lock.json"], "active", real_path=str(root))
    result = project_dependencies(project, [], tmp_path / "data", FakeRegistry(), lambda: T1)
    assert [s["manifest"] for s in result["sections"]] == ["Cargo.toml", "capture/Cargo.toml", "scripts/x/requirements.txt"]
    nested = rows(section(result, "capture/Cargo.toml"))["serde"]
    assert nested["update_key"] == "cargo/serde@1.0.229|~/Projects/mono|capture/Cargo.lock"
    assert section(result, "scripts/x/requirements.txt")["refusal"].startswith("No environment found")


def test_a_project_with_no_supported_manifest_says_so(tmp_path):
    root = tmp_path / "home" / "Projects" / "web"
    root.mkdir(parents=True)
    (root / "package.json").write_text("{}")
    result = deps(tmp_path, "web")
    assert result["supported"] is False and result["sections"] == []


def test_an_empty_requirements_file_has_no_rows(tmp_path):
    make_project(tmp_path, text="# nothing here\n")
    assert section(deps(tmp_path, "script"), "requirements.txt")["rows"] == []


# Registries


def test_the_request_holds_the_package_name_and_nothing_else(tmp_path):
    make_project(tmp_path, text="requests==2.31.0\n")
    registry = FakeRegistry()
    deps(tmp_path, "script", registry)
    assert registry.calls[0][0] == "https://pypi.org/simple/requests/"
    assert set(registry.calls[0][1]) == {"User-Agent", "Accept", "Accept-Encoding"} and "2.31" not in registry.calls[0][0]


def test_an_answer_under_a_day_old_is_reused_and_an_older_one_is_asked_again(tmp_path):
    make_project(tmp_path, text="requests==2.31.0\n")
    deps(tmp_path, "script", FakeRegistry(), now=T1)
    again = FakeRegistry()
    sec = section(deps(tmp_path, "script", again, now=T2), "requirements.txt")
    assert again.calls == [] and sec["latest_source"]["retrieved_at"] == T1  # The retrieval time of the answer.
    old = FakeRegistry()
    sec = section(deps(tmp_path, "script", old, now=T3), "requirements.txt")
    assert len(old.calls) == 1 and sec["latest_source"]["retrieved_at"] == T3


def test_a_failed_request_keeps_the_earlier_answer_and_says_so(tmp_path):
    make_project(tmp_path, text="requests==2.31.0\n")
    deps(tmp_path, "script", FakeRegistry(), now=T1)
    sec = section(deps(tmp_path, "script", FakeRegistry(fail={"requests"}), now=T3), "requirements.txt")
    row = rows(sec)["requests"]
    assert (row["latest"], row["latest_error"]) == ("2.34.2", "PyPI did not respond.")
    assert sec["latest_source"] == {"registry": "PyPI", "retrieved_at": T1, "error": "PyPI did not respond."}


def test_the_registry_cache_is_private(tmp_path):
    make_project(tmp_path, text="requests==2.31.0\n")
    deps(tmp_path, "script")
    folder = tmp_path / "data" / "cache" / "registries"
    assert stat.S_IMODE(os.stat(folder).st_mode) == 0o700
    assert {stat.S_IMODE(os.stat(f).st_mode) for f in folder.iterdir()} == {0o600}


def test_a_package_name_that_does_not_look_like_a_name_is_never_requested(tmp_path):
    registry = FakeRegistry()
    out = registries.lookup(registries.PYPI, ["requests", "../etc/passwd", "a b", "x" * 200], tmp_path / "data", registry,
                            lambda: T1)
    assert [u for u, _ in registry.calls] == ["https://pypi.org/simple/requests/"]
    assert out["../etc/passwd"].version is None and out["../etc/passwd"].error == "The name is not a package name."
    assert not out["../etc/passwd"].pending


def test_the_crate_index_path_follows_the_registry_rules():
    assert [registries.crate_path(n) for n in ("a", "ab", "abc", "serde", "Serde")] == [
        "1/a", "2/ab", "3/a/abc", "se/rd/serde", "se/rd/serde"]


@pytest.mark.parametrize("body", [b"not json", b'{"versions": 5}', b'{"versions": ["<script>"]}', b'{"versions": ["1.0"], "files": 3}',
                                  b"[]", b""])
def test_a_bad_pypi_answer_is_no_version_or_an_error(body):
    try:
        assert registries.parse_pypi(body) is None
    except ValueError:
        pass


def test_yanked_and_pre_release_crate_versions_are_skipped():
    body = "\n".join(json.dumps(x) for x in (
        {"vers": "1.0.0", "yanked": False}, {"vers": "1.1.0", "yanked": True}, {"vers": "2.0.0-rc.1", "yanked": False},
        {"vers": "1.0.5+meta", "yanked": False})).encode() + b"\nnot json\n"
    assert registries.parse_crate(body) == "1.0.0"


# One finding, two requirements files (QA of #81)


def two_files(tmp_path):
    """The owner's biggest project shape: two requirements files with the same packages, one folder each."""
    root = tmp_path / "home" / "Real" / "twin"
    for sub, spec, version in (("a", "requests==2.19.0", "2.19.0"), ("b", "requests>=2.32", "2.32.3")):
        (root / sub / ".venv" / "bin").mkdir(parents=True)
        (root / sub / "requirements.txt").write_text(spec + "\n")
        python = root / sub / ".venv" / "bin" / "python"
        python.write_text("#!/bin/sh\n")
        python.chmod(0o755)
        (root / sub / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\nversion_info = 3.12.4\n")
        (root / sub / ".venv" / "lib" / "python3.12" / "site-packages" / "pip").mkdir(parents=True)
        put_dist(root / sub, "requests", version)
    return root


def finding_in(lockfile, **extra):
    return SimpleNamespace(status="open", ecosystem="PyPI", package="requests", id="SEC-0001", severity="high",
                           paths=[SimpleNamespace(project_path="~/Real/twin", lockfile=lockfile)], **extra)


def test_a_finding_of_one_requirements_file_does_not_mark_the_same_package_in_another(tmp_path):
    two_files(tmp_path)
    result = deps(tmp_path, "twin", findings=[finding_in("a/requirements.txt")])
    a = rows(section(result, "a/requirements.txt"))["requests"]
    b = rows(section(result, "b/requirements.txt"))["requests"]
    assert (a["status"], a["finding_id"], a["severity"]) == ("vulnerable", "SEC-0001", "high")
    assert (b["status"], b["finding_id"], b["severity"]) == ("update_available", None, None)


def test_a_finding_marks_the_file_that_the_path_names(tmp_path):
    two_files(tmp_path)
    result = deps(tmp_path, "twin", findings=[finding_in("b/requirements.txt")])
    assert rows(section(result, "a/requirements.txt"))["requests"]["finding_id"] is None
    assert rows(section(result, "b/requirements.txt"))["requests"]["finding_id"] == "SEC-0001"


def test_a_finding_of_a_lockfile_does_not_mark_a_requirements_row(tmp_path):
    make_project(tmp_path)
    for lockfile in ("uv.lock", "package-lock.json", "other/requirements.txt"):
        row = rows(section(deps(tmp_path, "script", findings=[
            SimpleNamespace(status="open", ecosystem="PyPI", package="requests", id="SEC-0001", severity="high",
                            paths=[SimpleNamespace(project_path="~/Real/script", lockfile=lockfile)])]), "requirements.txt"))["requests"]
        assert row["finding_id"] is None, lockfile


def test_a_cargo_lock_finding_marks_the_cargo_toml_of_its_own_folder(tmp_path):
    root = cargo_project(tmp_path, name="mono")
    (root / "capture").mkdir()
    shutil.copy(CARGO / "tool" / "Cargo.toml", root / "capture" / "Cargo.toml")
    shutil.copy(CARGO / "tool" / "Cargo.lock", root / "capture" / "Cargo.lock")
    finding = SimpleNamespace(status="open", ecosystem="crates.io", package="serde", id="SEC-0009", severity="medium",
                              paths=[SimpleNamespace(project_path="~/Projects/mono", lockfile="capture/Cargo.lock")])
    project = Project("mono", str(root), "~/Projects", ["Cargo.toml", "capture/Cargo.toml"], "active", real_path=str(root))
    result = project_dependencies(project, [finding], tmp_path / "data", FakeRegistry(), lambda: T1)
    assert rows(section(result, "capture/Cargo.toml"))["serde"]["finding_id"] == "SEC-0009"
    assert rows(section(result, "Cargo.toml"))["serde"]["finding_id"] is None


# Lookups: a lighter answer, a cap, a true text for a row not asked yet (QA of #81)


def many_packages(tmp_path, count):
    make_project(tmp_path, text="".join(f"pkg{n}==1.0.0\n" for n in range(count)))


def test_the_pypi_request_asks_for_the_small_simple_index_in_gzip(tmp_path):
    make_project(tmp_path, text="requests==2.31.0\n")
    registry = FakeRegistry()
    deps(tmp_path, "script", registry)
    headers = registry.calls[0][1]
    assert headers["Accept"] == "application/vnd.pypi.simple.v1+json" and headers["Accept-Encoding"] == "gzip"


def test_a_gzip_answer_is_read_and_a_bomb_is_refused(tmp_path):
    make_project(tmp_path, text="requests==2.31.0\n")
    registry = FakeRegistry()
    registry.gzip = True
    assert rows(section(deps(tmp_path, "script", registry), "requirements.txt"))["requests"]["latest"] == "2.34.2"
    bomb = lambda url, headers: Response(200, {"content-encoding": "gzip"}, gzip.compress(b"0" * (registries.MAX_BYTES + 1)))
    out = registries.lookup(registries.PYPI, ["requests"], tmp_path / "data2", bomb, lambda: T1)
    assert out["requests"].version is None and out["requests"].error == "PyPI did not respond."


def test_the_real_answer_is_far_smaller_than_the_project_json():
    # The real requests answer: the whole versions list. The full project JSON of the same day was 193 KB, 43 KB in gzip.
    body = (REG / "pypi-simple-requests.json").read_bytes()
    assert len(json.loads(body)["versions"]) >= 160 and len(body) < 60_000 and len(gzip.compress(body)) < 15_000


def test_one_call_asks_for_at_most_the_cap_and_the_rest_are_pending_with_a_true_text(tmp_path):
    many_packages(tmp_path, 30)
    registry = FakeRegistry()
    result = deps(tmp_path, "script", registry)
    sec = section(result, "requirements.txt")
    assert len(registry.calls) == registries.MAX_LOOKUPS == 25
    waiting = [r for r in sec["rows"] if r["latest_pending"]]
    assert len(waiting) == 5 and sec["pending"] == 5 and result["pending"] == 5
    assert all(r["latest"] is None and r["latest_error"] is None for r in waiting)  # Nothing failed: it was not asked yet.
    assert sec["latest_source"]["error"] is None  # "PyPI did not respond." would be false.


def test_the_next_call_asks_only_the_rest_and_the_table_completes(tmp_path):
    many_packages(tmp_path, 30)
    first, second = FakeRegistry(), FakeRegistry()
    deps(tmp_path, "script", first)
    result = deps(tmp_path, "script", second)
    assert len(second.calls) == 5 and not set(first.names()) & set(second.names())
    assert result["pending"] == 0 and not any(r["latest_pending"] for r in section(result, "requirements.txt")["rows"])
    third = FakeRegistry()
    deps(tmp_path, "script", third)
    assert third.calls == []  # Everything is cached for a day.


def test_a_failed_request_is_an_error_and_not_pending(tmp_path):
    make_project(tmp_path, text="requests==2.31.0\n")
    result = deps(tmp_path, "script", FakeRegistry(fail={"requests"}))
    row = rows(section(result, "requirements.txt"))["requests"]
    assert (row["latest_pending"], row["latest_error"], result["pending"]) == (False, "PyPI did not respond.", 0)


def test_the_cap_can_be_set_for_one_call(tmp_path):
    many_packages(tmp_path, 12)
    registry = FakeRegistry()
    result = project_dependencies(find(tmp_path, "script"), [], tmp_path / "data", registry, lambda: T1, max_lookups=4)
    assert len(registry.calls) == 4 and result["pending"] == 8


def test_the_command_sets_the_cap_and_prints_the_pending_count(tmp_path, capsys):
    make_project(tmp_path, text="".join(f"pkg{n}==1.0.0\n" for n in range(6)))  # The network is off: asked rows fail.
    folder = str(tmp_path / "home" / "Real" / "script")
    assert cli.main(["--data-dir", str(tmp_path / "data"), "dependencies", "--max-lookups", "2", folder]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["pending"] == 4 and out["sections"][0]["pending"] == 4
    assert sum(1 for r in out["sections"][0]["rows"] if r["latest_error"]) == 2


# A pre-release is never the latest version (QA of #81)


def test_a_package_with_only_pre_releases_has_no_latest_and_says_so(tmp_path):
    make_project(tmp_path, text="betaonly==1.0.0rc1\n", installed={"betaonly": "1.0.0rc1"})
    sec = section(deps(tmp_path, "script"), "requirements.txt")
    row = rows(sec)["betaonly"]
    assert (row["latest"], row["latest_error"], row["latest_pending"], row["status"]) == (None, None, False, "unknown")
    assert row["latest_note"] == "No stable release." and row["update_key"] is None


def test_the_latest_of_pypi_is_the_highest_stable_release(tmp_path):
    body = lambda name: (REG / f"pypi-simple-{name}.json").read_bytes()
    assert registries.parse_pypi(body("stableandbeta")) == "1.5.0"  # 2.0.0a1, 2.0.0rc2 and 2.0.0.dev3 are skipped.
    assert registries.parse_pypi(body("yankedtop")) == "1.1.0"  # 2.0.0 and 2.0.1.post1 have only yanked files.
    assert registries.parse_pypi(body("betaonly")) is None
    assert registries.parse_pypi(body("pyyaml")) == "6.0.3"  # The real list also holds 6.0.2rc1.


@pytest.mark.parametrize("version,stable", [
    ("1.0", True), ("2.34.2", True), ("1.0.post1", True), ("1!2.0", True), ("1.0a1", False), ("1.0b2", False),
    ("1.0rc1", False), ("1.0.dev3", False), ("1.0.post1.dev2", False), ("2.0.0a1.post3", False)])
def test_stable_and_pre_release_pypi_versions(version, stable):
    assert registries.is_stable(version) is stable


def test_a_pre_release_pin_still_shows_the_stable_latest(tmp_path):
    make_project(tmp_path, text="requests==2.31.0rc1\n", installed={"requests": "2.31.0rc1"})
    row = rows(section(deps(tmp_path, "script"), "requirements.txt"))["requests"]
    assert row["latest"] == "2.34.2"


# Reading only


def test_listing_starts_no_program(tmp_path, monkeypatch):
    make_project(tmp_path)
    cargo_project(tmp_path)

    def no_process(*args, **kwargs):
        raise AssertionError("a program started")

    monkeypatch.setattr(subprocess, "Popen", no_process)
    monkeypatch.setattr(subprocess, "run", no_process)
    monkeypatch.setattr(os, "system", no_process)
    assert deps(tmp_path, "script")["supported"] and deps(tmp_path, "tool")["supported"]


# The JSON contract with the app

SWIFT_FIXTURES = Path(__file__).parents[2] / "Tests" / "WatchtowerCoreTests" / "Fixtures"


@pytest.mark.parametrize("kind,setup", [("requirements", lambda t: make_project(t)), ("cargo", lambda t: cargo_project(t, name="crabby"))])
def test_the_keys_match_the_json_that_the_app_decodes(tmp_path, kind, setup):
    setup(tmp_path)
    result = deps(tmp_path, "script" if kind == "requirements" else "crabby")
    app = json.loads((SWIFT_FIXTURES / f"dependencies-{kind}.json").read_text())
    assert set(result) == set(app)
    assert set(result["sections"][0]) == set(app["sections"][0])
    assert set(result["sections"][0]["rows"][0]) == set(app["sections"][0]["rows"][0])
    assert set(result["sections"][0]["latest_source"]) == set(app["sections"][0]["latest_source"])


# The CLI


def test_the_dependencies_command_prints_the_sections_as_json(tmp_path, capsys):
    make_project(tmp_path)
    folder = str(tmp_path / "home" / "Real" / "script")
    assert cli.main(["--data-dir", str(tmp_path / "data"), "dependencies", folder]) == 0  # The network is off: no latest.
    out = json.loads(capsys.readouterr().out)
    sec = out["sections"][0]
    assert out["project"] == "~/Real/script" and sec["manifest"] == "requirements.txt"
    assert all(r["latest"] is None and r["latest_error"] == "PyPI did not respond." for r in sec["rows"])
    assert sec["latest_source"]["error"] == "PyPI did not respond."


def test_the_dependencies_command_refuses_a_folder_that_is_not_a_project(tmp_path, capsys):
    folder = tmp_path / "home" / "Real" / "nothing-here"
    folder.mkdir(parents=True)
    assert cli.main(["--data-dir", str(tmp_path / "data"), "dependencies", str(tmp_path / "elsewhere")]) == 1
    assert json.loads(capsys.readouterr().err)["error"] == "That folder is not a project in the project roots."
