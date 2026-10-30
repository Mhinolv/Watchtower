"""#80: exact pins of requirements.txt in the offline OSV scan, and findings that open the #30 plan.

The scanner output is real OSV-Scanner 2.7.0 output (fixtures/requirements/README.md). No network.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from watchtower_engine.discovery import discover
from watchtower_engine.scanners import osv, requirements_pins
from watchtower_engine.scanners import release_pin as pin
from watchtower_engine.scanners.release_pin import Asset
from watchtower_engine.scope import list_projects
from watchtower_engine.store import Store
from watchtower_engine.updater import plan_update
from watchtower_engine.updates import requirements as ru

from contract import Clock
from test_osv import NOW, FakeDownload, both_dbs, calls, install
from test_requirements_update import FakeDry, FakePyPI, MAC, make_project, report_for

FIX = Path(__file__).parent / "fixtures" / "requirements"
MIXED = (FIX / "requirements-pins-and-ranges.txt").read_text()
SCAN_OUTPUT = (FIX / "osv-scan-output.json").read_text()


def fake_scanner(tmp_path):
    """A stand-in OSV-Scanner. It logs its arguments and the text of each input file, then prints the real
    output for each requirements.txt input. It refuses to run without --offline."""
    log = tmp_path / "scanner-calls.jsonl"
    script = f"""#!{sys.executable} -I
import json, os, sys
args = sys.argv[1:]
locks = [args[i + 1] for i, a in enumerate(args) if a == "--lockfile"]
with open({str(log)!r}, "a") as f:
    f.write(json.dumps({{"args": args, "inputs": {{l: open(l).read() for l in locks}}}}) + "\\n")
if "--offline" not in args or not os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"):
    sys.exit(3)
template = {SCAN_OUTPUT!r}
results = []
for l in locks:
    if l.endswith("requirements.txt"):
        results += json.loads(template.replace("__REQUIREMENTS__", l))["results"]
sys.stdout.write(json.dumps({{"results": results}}))
sys.exit(1 if results else 0)
""".encode()
    return Asset("osv-scanner_test", hashlib.sha256(script).hexdigest()), script, log


def project(home, name, files, where="Real"):
    root = home / where / name
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    return root


def scan(tmp_path, roots):
    data = tmp_path / "data"
    asset, script, log = fake_scanner(tmp_path)
    install(data, asset, script)
    found = discover(tuple(str(r) for r in roots)).projects
    return osv.collect(data, found, asset=asset, download=FakeDownload(both_dbs()), now=lambda: NOW), log


def rows(result):
    return {(s.name, lf.path): lf for s in result.projects for lf in s.lockfiles}


@pytest.fixture
def home(tmp_path):
    return tmp_path / "home"


# What goes to the scanner


def test_only_exact_pins_go_to_the_scanner_and_ranges_never_do(tmp_path, home):
    project(home, "script", {"requirements.txt": MIXED})
    result, log = scan(tmp_path, [home / "Real"])
    (call,) = calls(log)
    (path, text), = call["inputs"].items()
    assert text == "requests==2.31.0\nurllib3==1.26.18\nJinja2==3.1.2\n"  # No range, marker, extra or comment.
    assert path.startswith(str(tmp_path / "data" / "osv" / "requirements-pins"))
    assert str(home) not in " ".join(call["args"])  # The project file itself is not given to the scanner.
    assert not (tmp_path / "data" / "osv" / "requirements-pins").exists()  # The pins file is gone after the scan.
    lf = rows(result)[("script", "requirements.txt")]
    assert (lf.status, lf.ecosystem, len(lf.pins), lf.other_lines) == ("scanned", "PyPI", 3, 3)
    assert lf.to_dict() == {"path": "requirements.txt", "ecosystem": "PyPI", "status": "scanned", "note": None,
                            "pins": 3, "other_lines": 3}
    assert result.coverage.state == "complete" and result.coverage.error is None


def test_a_vulnerable_pin_without_a_lockfile_makes_matches_for_the_file(tmp_path, home):
    project(home, "script", {"requirements.txt": MIXED})
    result, _ = scan(tmp_path, [home / "Real"])
    by_name = {m.name: m for m in result.matches}
    assert set(by_name) == {"requests", "urllib3", "jinja2"}
    m = by_name["requests"]
    assert (m.project_path, m.lockfile, m.version, m.ecosystem) == ("~/Real/script", "requirements.txt", "2.31.0", "PyPI")
    assert any("GHSA-9wx4-h78v-vm56" in a["ids"] for a in m.advisories)
    assert "flask" not in by_name and "click" not in by_name  # Range lines make no finding.


def test_a_file_with_only_ranges_runs_no_scan_for_it(tmp_path, home):
    project(home, "script", {"requirements.txt": "flask>=2.0,<3\nclick~=8.1\nidna\n"})
    result, log = scan(tmp_path, [home / "Real"])
    assert calls(log) == []
    lf = rows(result)[("script", "requirements.txt")]
    assert (lf.status, len(lf.pins), lf.other_lines) == ("scanned", 0, 3)
    assert result.matches == []


def test_a_folder_with_a_lockfile_is_not_a_requirements_only_project(tmp_path, home):
    project(home, "api", {"requirements.txt": MIXED, "uv.lock": "version = 1\n", "pyproject.toml": ""})
    scans = osv.plan(discover((str(home / "Real"),)).projects)
    assert [lf.path for s in scans for lf in s.lockfiles] == ["uv.lock"]


def test_a_nested_requirements_only_folder_is_scanned(tmp_path, home):
    project(home, "mono", {"web/package.json": "{}", "tools/requirements.txt": MIXED})
    scans = osv.plan(discover((str(home / "Real"),)).projects)
    assert [(lf.path, lf.ecosystem) for s in scans for lf in s.lockfiles] == [("tools/requirements.txt", "PyPI")]


# Skipped files


@pytest.mark.parametrize("fixture", ["with-include.txt", "with-hashes.txt", "with-constraint.txt"])
def test_includes_and_hashes_are_skipped_with_a_note_and_partial_coverage(tmp_path, home, fixture):
    project(home, "script", {"requirements.txt": (FIX / fixture).read_text()})
    project(home, "web", {"requirements.txt": MIXED})
    result, log = scan(tmp_path, [home / "Real"])
    lf = rows(result)[("script", "requirements.txt")]
    assert (lf.status, lf.ecosystem, lf.note) == ("skipped", None, "-r includes or hashes are not supported")
    assert result.coverage.state == "partial"
    assert result.coverage.error == "1 requirements project skipped."
    assert len(calls(log)[0]["inputs"]) == 1  # Only the other project's pins.


def test_two_skipped_files_and_nothing_else_still_make_partial_coverage(tmp_path, home):
    project(home, "a", {"requirements.txt": (FIX / "with-include.txt").read_text()})
    project(home, "b", {"requirements.txt": (FIX / "with-hashes.txt").read_text()})
    result, log = scan(tmp_path, [home / "Real"])
    assert (result.coverage.state, result.coverage.error) == ("partial", "2 requirements projects skipped.")
    assert calls(log) == []


def test_no_requirements_and_no_lockfile_has_the_new_note(tmp_path, home):
    project(home, "notes", {"README.md": "", "package.json": "{}"})
    (scan_row,) = osv.plan(discover((str(home / "Real"),)).projects)
    assert scan_row.note == "No lockfile. Watchtower scans lockfiles and requirements.txt only."


# Findings and the #30 plan


def finish(store, result):
    r = store.begin_refresh()
    store.finish_refresh(r.id, "complete", coverage=[result.coverage], scan=result)
    return store.state()


def test_a_finding_from_a_pin_carries_evidence_and_opens_the_requirements_plan(tmp_path, home):
    root = make_project(tmp_path, text=MIXED)
    result, _ = scan(tmp_path, [home / "Real"])
    with Store(tmp_path / "data", clock=Clock(*[f"2026-10-29T10:{m:02d}:00Z" for m in range(60)])) as store:
        state = finish(store, result)
        finding = next(f for f in state["findings"] if f["package"] == "requests")
        (path,) = finding["paths"]
        assert (path["lockfile"], path["version"], path["dependency_path"], path["update_block"]) == (
            "requirements.txt", "2.31.0", None, None)
        assert path["evidence"] == {"declared": "requests==2.31.0", "evidence": "Exact pin", "installed": "2.31.0"}
        # The Swift key rule (RequirementsUpdate.key): requirements/<package>@<fixed>|<project>|<file>.
        key = ru.make_key(finding["package"], finding["fixed_in"], path["project_path"], path["lockfile"])
        report = report_for("requests", finding["fixed_in"])
        page = {"urls": [{"filename": f"requests-{finding['fixed_in']}-py3-none-any.whl", "packagetype": "bdist_wheel"}]}
        plan = plan_update(store, key, run=FakeDry(report), fetch=FakePyPI(page), uv_options=MAC)
        assert plan.kind == "requirements" and plan.refusal is None
        assert plan.target_version == finding["fixed_in"]
        assert {r["label"]: r["value"] for r in plan.rows}["requirements.txt"] == \
            f"requests==2.31.0 → requests=={finding['fixed_in']}"
    assert root.is_dir()


def test_a_refused_project_shows_the_30_reason_on_the_path(tmp_path, home):
    make_project(tmp_path, text=MIXED, env=False)
    result, _ = scan(tmp_path, [home / "Real"])
    with Store(tmp_path / "data", clock=Clock(*[f"2026-10-29T10:{m:02d}:00Z" for m in range(60)])) as store:
        state = finish(store, result)
    path = next(f for f in state["findings"] if f["package"] == "urllib3")["paths"][0]
    assert path["update_block"] == "No environment found. Watchtower does not create environments."
    assert path["evidence"] == {"declared": "urllib3==1.26.18", "evidence": "Exact pin", "installed": None}


def test_other_finding_paths_have_no_evidence_field(tmp_path):
    assert ru.path_evidence("~/Real/script", "uv.lock", "httpx") is None


# Projects list


def test_the_project_list_has_the_requirements_summary(tmp_path, home):
    project(home, "script", {"requirements.txt": MIXED})
    project(home, "legacy", {"requirements.txt": (FIX / "with-include.txt").read_text()})
    project(home, "api", {"requirements.txt": MIXED, "uv.lock": "version = 1\n"})
    found = {p.name: p.to_dict() for p in list_projects(tmp_path / "data", roots=(str(home / "Real"),)).projects}
    assert found["script"]["requirements"] == [{"file": "requirements.txt", "pins": 3, "other_lines": 3, "skipped": None}]
    assert found["legacy"]["requirements"] == [{"file": "requirements.txt", "pins": 0, "other_lines": 0,
                                                "skipped": "-r includes or hashes are not supported"}]
    assert "requirements" not in found["api"]


def test_the_pins_file_is_private(tmp_path):
    path = requirements_pins.write_pins([("requests", "2.31.0")], tmp_path / "data", 0)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert oct(path.parent.stat().st_mode & 0o777) == "0o700"
    assert path.read_text() == "requests==2.31.0\n"


# Nested folders (#85 discovery walks 8 levels and gives paths relative to the project)


def test_a_deeply_nested_requirements_file_makes_a_finding_with_its_relative_path(tmp_path, home):
    project(home, "mono", {"web/package.json": "{}", "web/package-lock.json": "{}",
                           "services/api/scripts/requirements.txt": MIXED})
    found = discover((str(home / "Real"),)).projects
    assert "services/api/scripts/requirements.txt" in found[0].manifests
    result, log = scan(tmp_path, [home / "Real"])
    lf = rows(result)[("mono", "services/api/scripts/requirements.txt")]
    assert (lf.status, lf.ecosystem, len(lf.pins)) == ("scanned", "PyPI", 3)
    assert any(text == "requests==2.31.0\nurllib3==1.26.18\nJinja2==3.1.2\n"
               for c in calls(log) for text in c["inputs"].values())
    with Store(tmp_path / "data", clock=Clock(*[f"2026-10-29T10:{m:02d}:00Z" for m in range(60)])) as store:
        state = finish(store, result)
    path = next(f for f in state["findings"] if f["package"] == "requests")["paths"][0]
    assert (path["project_path"], path["lockfile"]) == ("~/Real/mono", "services/api/scripts/requirements.txt")
    assert path["evidence"] == {"declared": "requests==2.31.0", "evidence": "Exact pin", "installed": None}
    assert path["update_block"] == "No environment found. Watchtower does not create environments."
    key = ru.make_key("requests", "2.32.4", path["project_path"], path["lockfile"])
    assert ru.parse_key(key).file == "services/api/scripts/requirements.txt"
    summary = {p.name: p.to_dict() for p in list_projects(tmp_path / "data", roots=(str(home / "Real"),)).projects}
    assert summary["mono"]["requirements"] == [{"file": "services/api/scripts/requirements.txt", "pins": 3,
                                                "other_lines": 3, "skipped": None}]
