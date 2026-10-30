"""Running version and container metadata (#17). Fixtures only: no process list of this Mac, no network."""
import ast
import json
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

from watchtower_engine import cli, discovery, refresh, settings
from watchtower_engine.inventory import containers, running
from watchtower_engine.inventory.homebrew import SourceResult
from watchtower_engine.models import CoverageRecord, ItemRecord
from watchtower_engine.store import Store

FIX = Path(__file__).parent / "fixtures" / "running"
NOW = "2026-10-30T09:12:00Z"


def fake_run(ps=None, ls=None, ps_code=0, ls_code=0, calls=None):
    def run(args, **kwargs):
        if calls is not None:
            calls.append(list(args))
        if args[0].endswith("ps"):
            if ps_code == -1:
                raise PermissionError("operation not permitted")
            return SimpleNamespace(returncode=ps_code, stdout=ps if ps is not None else (FIX / "ps.txt").read_text())
        return SimpleNamespace(returncode=ls_code, stdout=ls if ls is not None else (FIX / "lsappinfo.txt").read_text())
    return run


def app(name, path, version, build):
    return ItemRecord(id=f"app:{name}", source="apps", name=name, state="manual", kind="app", installed_version=version,
                      attributes={"path": path, "build": build})


def formula(name, version):
    return ItemRecord(id=f"formula:{name}", source="homebrew", name=name, state="up_to_date", kind="formula",
                      installed_version=version)


def runtime(version, path):
    return ItemRecord(id=f"runtime:{path}", source="runtimes", name="Node.js", state="manual", kind="runtime",
                      installed_version=version, attributes={"path": path, "product": "nodejs"})


def attrs(item):
    return {k: v for k, v in (item.attributes or {}).items() if k in running.ATTRIBUTE_KEYS}


# Parse


def test_ps_and_lsappinfo_fixtures_parse():
    paths = running.parse_ps((FIX / "ps.txt").read_text())
    assert "/Applications/Cloudflare WARP.app/Contents/MacOS/Cloudflare WARP" in paths and len(paths) == 8
    builds = running.parse_lsappinfo((FIX / "lsappinfo.txt").read_text())
    assert builds == {"/System/Library/CoreServices/loginwindow.app": "3037.6.3.100",
                      "/Applications/Cloudflare WARP.app": "20269008.2115", "/Applications/Caffeine.app": "30"}


# The running version is separate from the installed version


def test_an_app_that_runs_an_older_build_keeps_both_versions_apart():
    item = app("Caffeine", "/Applications/Caffeine.app", "1.2.0", "31")
    coverage = running.check([item], True, fake_run(), lambda: NOW)
    assert item.installed_version == "1.2.0"
    assert attrs(item) == {"runningState": "known", "runningVersion": "30", "runningKind": "build", "runningChecked": NOW}
    assert coverage.state == "complete" and coverage.note is None


def test_an_app_with_the_same_build_runs_the_installed_version():
    item = app("Caffeine", "/Applications/Caffeine.app", "1.2.0", "30")
    running.check([item], True, fake_run(), lambda: NOW)
    assert attrs(item)["runningVersion"] == "1.2.0" and attrs(item)["runningKind"] == "version"


def test_an_app_without_a_build_attribute_has_the_version_as_its_build():
    same = app("Caffeine", "/Applications/Caffeine.app", "30", "30")
    del same.attributes["build"]  # The inventory leaves `build` out if it equals the version.
    older = app("Caffeine", "/Applications/Caffeine.app", "31", "31")
    del older.attributes["build"]
    running.check([same, older], True, fake_run(), lambda: NOW)
    assert (attrs(same)["runningVersion"], attrs(same)["runningKind"]) == ("30", "version")
    assert (attrs(older)["runningVersion"], attrs(older)["runningKind"]) == ("30", "build")


def test_an_app_without_a_launchservices_record_runs_an_unknown_version():
    item = app("Caffeine", "/Applications/Caffeine.app", "1.2.0", "30")
    running.check([item], True, fake_run(ls_code=1), lambda: NOW)
    assert attrs(item) == {"runningState": "unknown_version", "runningChecked": NOW}


def test_a_formula_reads_the_version_from_the_cellar_path_and_takes_the_oldest_process():
    node, redis, wget = formula("node", "22.9.0"), formula("redis", "7.4.1"), formula("wget", "1.25.0")
    running.check([node, redis, wget], True, fake_run(), lambda: NOW)
    assert attrs(node)["runningVersion"] == "22.8.0" and attrs(node)["runningKind"] == "version"
    assert attrs(redis) == {"runningState": "unknown_version", "runningChecked": NOW}  # Started through the `opt` link.
    assert attrs(wget) == {"runningState": "none", "runningChecked": NOW}


def test_a_runtime_install_runs_when_a_process_starts_inside_its_folder():
    on = runtime("20.11.0", "/Users/me/.nvm/versions/node/v20.11.0")
    off = runtime("18.0.0", "/Users/me/.nvm/versions/node/v18.0.0")
    running.check([on, off], True, fake_run(), lambda: NOW)
    assert attrs(on)["runningVersion"] == "20.11.0" and attrs(off)["runningState"] == "none"


def test_a_folder_name_that_starts_the_same_does_not_match():
    item = app("Caffeine", "/Applications/Caff", "1", "30")  # `/Applications/Caffeine.app/...` is a different folder.
    running.check([item], True, fake_run(), lambda: NOW)
    assert attrs(item)["runningState"] == "none"


# Unknown stays unknown


def test_a_denied_process_list_never_becomes_no_process_found():
    items = [app("Caffeine", "/Applications/Caffeine.app", "1.2.0", "30"), formula("node", "22.9.0")]
    for kwargs in ({"ps_code": 1}, {"ps_code": -1}, {"ps": ""}):
        coverage = running.check(items, True, fake_run(**kwargs), lambda: NOW)
        assert [attrs(i)["runningState"] for i in items] == ["denied", "denied"]
        assert "runningVersion" not in attrs(items[0])
        assert coverage.state == "complete" and coverage.note == running.NOTE_DENIED  # The refresh is not partial.


def test_a_skipped_probe_marks_every_item_not_checked_and_starts_no_program():
    calls = []
    items = [app("Caffeine", "/Applications/Caffeine.app", "1.2.0", "30"), formula("node", "22.9.0"),
             runtime("20.11.0", "/Users/me/.nvm/versions/node/v20.11.0"),
             ItemRecord(id="macos", source="macos", name="macOS", state="manual")]
    coverage = running.check(items, False, fake_run(calls=calls), lambda: NOW)
    assert calls == [] and coverage.state == "not_run"
    assert [attrs(i) for i in items[:3]] == [{"runningState": "not_checked"}] * 3
    assert items[3].attributes is None  # macOS has no probe: no Running row.


def test_old_running_attributes_are_replaced_not_kept():
    item = app("Caffeine", "/Applications/Caffeine.app", "1.2.0", "31")
    item.attributes.update(runningState="known", runningVersion="9", runningKind="version", runningChecked="2020-01-01T00:00:00Z")
    running.check([item], False)
    assert attrs(item) == {"runningState": "not_checked"} and item.attributes["path"]


# No credential or browser path; only two read-only tools


def test_the_probe_runs_only_ps_and_lsappinfo_and_reads_no_arguments():
    calls = []
    running.check([formula("node", "1")], True, fake_run(calls=calls), lambda: NOW)
    assert calls == [running.PS, running.LSAPPINFO]
    assert running.PS[-1] == "pid=,comm="  # `comm` is the executable path. `command` would add the arguments.
    strings = []
    for module in (running, containers):
        tree = ast.parse(Path(module.__file__).read_text())
        docs = {id(n.body[0].value) for n in ast.walk(tree)
                if isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef)) and n.body
                and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
        strings += [n.value for n in ast.walk(tree)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs]
    text = " ".join(strings).lower()
    for forbidden in ("cookies", "keychain", "history.db", "login data", "~/.docker", "/.docker/", "/security", "mail", "token"):
        assert forbidden not in text


# Settings


def test_the_setting_is_on_by_default_and_the_file_is_private(tmp_path):
    assert settings.check_running_versions(tmp_path) is True
    (tmp_path / "settings.json").write_text("not json")
    assert settings.check_running_versions(tmp_path) is True
    settings.save({"check_running_versions": False}, tmp_path / "data")
    assert settings.check_running_versions(tmp_path / "data") is False
    mode = stat.S_IMODE(os.stat(tmp_path / "data" / "settings.json").st_mode)
    assert mode == 0o600 and stat.S_IMODE(os.stat(tmp_path / "data").st_mode) == 0o700


def test_cli_settings_round_trip(tmp_path, capsys):
    assert cli.main(["--data-dir", str(tmp_path), "settings"]) == 0
    assert json.loads(capsys.readouterr().out)["settings"] == {"check_running_versions": True}
    assert cli.main(["--data-dir", str(tmp_path), "setting-set", "check-running-versions", "off"]) == 0
    assert json.loads(capsys.readouterr().out)["settings"] == {"check_running_versions": False}


# Refresh


def test_refresh_runs_the_running_source_and_the_toggle_decides(tmp_path):
    item = app("Caffeine", "/Applications/Caffeine.app", "1.2.0", "31")
    sources = [refresh.Source("apps", "Applications", lambda: SourceResult(CoverageRecord("apps", "Applications", "complete"), [item]))]
    sources.append(refresh.Source(running.SOURCE, running.LABEL,
                                  lambda: running.collect([item], settings.check_running_versions(tmp_path), fake_run())))
    with Store(tmp_path) as store:
        state = refresh.run_refresh(store, sources)
    saved = next(i for i in state["items"] if i["id"] == item.id)
    assert saved["attributes"]["runningVersion"] == "30" and saved["installed_version"] == "1.2.0"
    assert next(c for c in state["coverage"] if c["source"] == "running")["state"] == "complete"
    settings.save({"check_running_versions": False}, tmp_path)
    with Store(tmp_path) as store:
        state = refresh.run_refresh(store, sources)
    saved = next(i for i in state["items"] if i["id"] == item.id)
    assert saved["attributes"]["runningState"] == "not_checked" and "runningVersion" not in saved["attributes"]


def test_default_sources_list_the_running_source_after_the_inventory(tmp_path):
    names = [s.source for s in refresh.default_sources(tmp_path)]
    assert names.index("running") > names.index("runtimes") and names.index("running") > names.index("homebrew")


# Container metadata


def test_dockerfile_images_skip_stages_scratch_and_variables():
    text = """# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 node:20.11 AS build
RUN npm ci
FROM build AS test
FROM scratch
FROM ${BASE}
FROM gcr.io/distroless/nodejs20-debian12@sha256:%s
""" % ("a" * 64)
    assert containers.dockerfile_images(text) == ["node:20.11", "gcr.io/distroless/nodejs20-debian12@sha256:" + "a" * 64]


def test_compose_images_are_read_without_secrets_or_variables():
    text = """services:
  db:
    image: "postgres:16.2"   # the database
  cache:
    image: redis:7
  app:
    image: ${REGISTRY}/app:latest
    environment:
      - TOKEN=abc
"""
    assert containers.compose_images(text) == ["postgres:16.2", "redis:7"]


def test_project_images_read_regular_files_only_and_start_nothing(tmp_path):
    project = tmp_path / "web"
    project.mkdir()
    (project / "Dockerfile").write_text("FROM node:20.11\n")
    (project / "compose.yaml").write_text("services:\n  db:\n    image: postgres:16\n")
    (tmp_path / "outside.yml").write_text("services:\n  x:\n    image: evil:1\n")
    os.symlink(tmp_path / "outside.yml", project / "docker-compose.yml")
    (project / "Dockerfile.big").write_text("FROM big:1\n" + "#" * containers.MAX_BYTES)
    assert containers.project_images(str(project)) == ["node:20.11", "postgres:16"]
    assert containers.project_images(str(tmp_path / "missing")) == []


def test_discovery_adds_the_images_to_an_active_project_only(tmp_path):
    root = tmp_path / "Projects"
    for name in ("web", "old"):
        (root / name).mkdir(parents=True)
        (root / name / "package.json").write_text("{}")
        (root / name / "Dockerfile").write_text("FROM node:20.11\n")
    found = discovery.discover((str(root),), inactive=frozenset({str((root / "old").resolve())}))
    by_name = {p.name: p.to_dict() for p in found.projects}
    assert by_name["web"]["container_images"] == ["node:20.11"]
    assert "container_images" not in by_name["old"]  # Not read: unknown, not "none".
    (root / "web" / "Dockerfile").unlink()
    again = discovery.discover((str(root),), inactive=frozenset())
    assert next(p for p in again.projects if p.name == "web").to_dict()["container_images"] == []  # Read: none.
