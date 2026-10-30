"""#88: a project cut at the folder limit is a coverage gap, never complete coverage."""
import pytest

from watchtower_engine import discovery, refresh
from watchtower_engine.discovery import discover
from watchtower_engine.models import CoverageRecord
from watchtower_engine.refresh import run_refresh
from watchtower_engine.scanners import osv
from watchtower_engine.scanners.osv import OsvResult
from watchtower_engine.store import Store


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home"
    (h / "Projects").mkdir(parents=True)
    (h / "Real").mkdir()
    return h


def project(root, name, *files):
    folder = root / name
    folder.mkdir(parents=True, exist_ok=True)
    for f in files:
        (folder / f).parent.mkdir(parents=True, exist_ok=True)
        (folder / f).write_text("")
    return folder


BIG = ["top/Cargo.lock"] + [f"many/n{i:02d}/package-lock.json" for i in range(20)]


def refresh_with_osv_only(tmp_path, monkeypatch):
    """Run the real OSV source of the refresh with a stub scan, so only discovery is real."""
    seen = []

    def collect(data_dir, projects, **kw):
        seen.append(projects)
        return OsvResult(CoverageRecord(osv.SOURCE, osv.LABEL, "complete"), [], [], [])

    monkeypatch.setattr(osv, "collect", collect)
    sources = [s for s in refresh.default_sources(tmp_path / "data") if s.source == osv.SOURCE]
    with Store(tmp_path / "data") as store:
        state = run_refresh(store, sources)
    return {c["source"]: c for c in state["coverage"]}, state, seen


# Regression test (#88): the cut was silent and the coverage stayed complete.


def test_a_cut_project_makes_the_projects_coverage_partial_and_names_it(tmp_path, home, monkeypatch):
    monkeypatch.setattr(discovery, "MAX_DIRS", 5)
    project(home / "Projects", "big", *BIG)
    project(home / "Projects", "small", "package-lock.json")
    coverage, state, _ = refresh_with_osv_only(tmp_path, monkeypatch)
    projects = coverage["projects"]
    assert projects["state"] == "partial"
    assert projects["label"] == "Projects"
    assert projects["error"] == "Discovery stopped early in big. Deeper manifests are not listed."
    assert projects["detail"] == "~/Projects/big: stopped after 5 folders"
    assert state["refresh"]["status"] == "partial"


def test_no_cut_means_complete_projects_coverage(tmp_path, home, monkeypatch):
    project(home / "Projects", "small", "package-lock.json", "app/uv.lock")
    coverage, state, _ = refresh_with_osv_only(tmp_path, monkeypatch)
    assert (coverage["projects"]["state"], coverage["projects"]["error"]) == ("complete", None)
    assert state["refresh"]["status"] == "complete"


# Discovery itself


def test_the_walk_stops_at_the_limit_and_says_so(home):
    project(home / "Projects", "big", *BIG)
    project(home / "Projects", "small", "package-lock.json")
    found = {p.name: p for p in discover(max_dirs=5).projects}
    assert found["big"].cut and not found["small"].cut
    manifests = found["big"].manifests
    assert "top/Cargo.lock" in manifests  # Found before the cut: still listed.
    assert len(manifests) < len(BIG)  # Only reachable after the cut: not listed.
    assert all(m in BIG for m in manifests)  # Nothing is invented.
    assert found["big"].to_dict()["discovery_note"] == \
        "Watchtower stopped after 5 folders. Deeper manifests are not listed."
    assert "discovery_note" not in found["small"].to_dict()


def test_a_project_exactly_at_the_limit_is_not_cut(home):
    project(home / "Projects", "fits", "a/package-lock.json", "b/uv.lock")  # 3 folders: fits, a, b.
    (p,) = discover(max_dirs=3).projects
    assert not p.cut and p.manifests == ["a/package-lock.json", "b/uv.lock"]


def test_the_default_limit_is_unchanged(home):
    assert discovery.MAX_DIRS == 5000
    project(home / "Projects", "p", *BIG)
    (p,) = discover().projects
    assert not p.cut and len(p.manifests) == len(BIG)


def test_an_inactive_cut_project_is_not_a_gap(tmp_path, home, monkeypatch):
    import os

    monkeypatch.setattr(discovery, "MAX_DIRS", 5)
    folder = project(home / "Projects", "big", *BIG)
    from watchtower_engine.scope import Scope
    Scope(tmp_path / "data").set_active(os.path.realpath(folder), False)
    coverage, _, _ = refresh_with_osv_only(tmp_path, monkeypatch)
    assert coverage["projects"]["state"] == "complete"


def test_the_osv_scan_gets_the_same_projects(tmp_path, home, monkeypatch):
    monkeypatch.setattr(discovery, "MAX_DIRS", 5)
    project(home / "Projects", "big", *BIG)
    _, _, seen = refresh_with_osv_only(tmp_path, monkeypatch)
    (projects,) = seen
    assert [p.name for p in projects] == ["big"] and projects[0].cut
