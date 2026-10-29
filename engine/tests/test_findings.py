import json
import sqlite3

import pytest

from watchtower_engine import cli, findings
from watchtower_engine.findings import FindingError
from watchtower_engine.models import CoverageRecord as C
from watchtower_engine.scanners import osv
from watchtower_engine.scanners.osv import Lockfile, Match, OsvResult, ProjectScan, advisory_groups, severity_label
from watchtower_engine.store import Store

from contract import Clock

T = [f"2026-10-{d:02d}T10:00:00Z" for d in range(20, 32)] + [f"2026-11-{d:02d}T10:00:00Z" for d in range(1, 10)]
DB_AT = "2026-10-29T06:00:00Z"


def adv(ids, title="Bad thing", severity="high", fixed=()):
    return {"ids": sorted(ids), "title": title, "severity": severity, "fixed_in": list(fixed)}


def match(project="web", lockfile="package-lock.json", name="lodash", version="4.17.20",
          groups=(), eco="npm", dep=None):
    ids = sorted({i for g in groups for i in g["ids"]})
    return Match(project, f"~/Projects/{project}", lockfile, name, eco, version, dep, ids, [], list(groups))


def scan(matches=(), state="complete", error=None, scanned=(("web", "package-lock.json"),)):
    projects = {}
    for project, lockfile in scanned:
        projects.setdefault(project, []).append(Lockfile(lockfile, "npm", "scanned"))
    plans = [ProjectScan(p, f"~/Projects/{p}", lfs) for p, lfs in projects.items()]
    return OsvResult(C("osv", "OSV", state, error=error, source_at=DB_AT), plans, list(matches), [])


LODASH = adv(["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"], "Command Injection in lodash", "high", ["4.17.21"])


def refresh(store, result, status="complete"):
    r = store.begin_refresh()
    store.finish_refresh(r.id, status, coverage=[result.coverage], scan=result)
    # A fixed early time: reading does not use the test clock, and no deferral has ended.
    return {f.id: f for f in findings.list_findings(store.db, "2026-10-01T00:00:00Z")}


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "data", clock=Clock(*T * 2)) as s:
        yield s


def clock_store(tmp_path, *times):
    return Store(tmp_path / "data", clock=Clock(*times))


# Stable ids and merging


def test_first_scan_creates_findings_with_stable_ids(tmp_path):
    other = adv(["CVE-2020-28500", "GHSA-29mw-wpgm-hmr9"], "ReDoS", "medium")
    with Store(tmp_path, clock=Clock(*T * 2)) as s:
        first = refresh(s, scan([match(groups=[LODASH, other])]))
        assert sorted(first) == ["SEC-0001", "SEC-0002"]
        again = refresh(s, scan([match(groups=[other, LODASH])]))
    assert {i: (f.package, f.advisory_ids) for i, f in again.items()} == {
        i: (f.package, f.advisory_ids) for i, f in first.items()}


def test_repeat_scan_keeps_ids_and_first_seen_and_moves_last_seen(store):
    refresh(store, scan([match(groups=[LODASH])]))
    [f] = refresh(store, scan([match(groups=[LODASH])])).values()
    assert f.id == "SEC-0001"
    assert (f.first_seen, f.last_seen) == (T[1], T[3])  # begin/finish take 2 clock ticks each
    assert (f.source, f.source_at) == ("OSV", DB_AT)


def test_ids_are_never_reused_after_a_new_finding(store):
    refresh(store, scan([match(groups=[LODASH])]))
    other = adv(["GHSA-new"], "New")
    result = refresh(store, scan([match(groups=[LODASH]), match(name="minimist", version="1.2.5", groups=[other])]))
    assert result["SEC-0001"].package == "lodash" and result["SEC-0002"].package == "minimist"


def test_aliases_merge_across_projects_and_keep_every_path(store):
    ghsa = adv(["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"])
    osv_only = adv(["CVE-2021-23337", "OSV-2021-1"])
    result = refresh(store, scan(
        [match("web", groups=[ghsa]), match("api", name="lodash", groups=[osv_only], version="4.17.19")],
        scanned=(("web", "package-lock.json"), ("api", "package-lock.json"))))
    [f] = result.values()
    assert f.advisory_ids == ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm", "OSV-2021-1"]
    assert [(p.project, p.version) for p in f.paths] == [("api", "4.17.19"), ("web", "4.17.20")]


def test_one_package_in_two_lockfiles_of_a_project_gives_two_paths(store):
    result = refresh(store, scan(
        [match(lockfile="package-lock.json", groups=[LODASH]), match(lockfile="app/package-lock.json", groups=[LODASH])],
        scanned=(("web", "package-lock.json"), ("web", "app/package-lock.json"))))
    [f] = result.values()
    assert [p.lockfile for p in f.paths] == ["app/package-lock.json", "package-lock.json"]


def test_a_later_scan_that_bridges_two_findings_merges_them_into_the_older_id(store):
    a = adv(["GHSA-a"], "A")
    b = adv(["GHSA-b"], "B")
    refresh(store, scan([match(groups=[a]), match(lockfile="x/package-lock.json", groups=[b])],
                        scanned=(("web", "package-lock.json"), ("web", "x/package-lock.json"))))
    bridge = adv(["GHSA-a", "GHSA-b"], "A and B")
    result = refresh(store, scan([match(groups=[bridge])],
                                 scanned=(("web", "package-lock.json"), ("web", "x/package-lock.json"))))
    assert list(result) == ["SEC-0001"]
    assert result["SEC-0001"].advisory_ids == ["GHSA-a", "GHSA-b"]
    new = refresh(store, scan([match(groups=[bridge]), match(name="other", groups=[adv(["GHSA-z"])])]))
    assert sorted(new) == ["SEC-0001", "SEC-0003"]


def test_same_advisory_for_two_packages_is_two_findings(store):
    shared = adv(["GHSA-shared"])
    result = refresh(store, scan([match(name="a", groups=[shared]), match(name="b", groups=[shared])]))
    assert sorted(f.package for f in result.values()) == ["a", "b"]


def test_match_without_groups_still_makes_a_finding(store):
    m = Match("web", "~/Projects/web", "package-lock.json", "lodash", "npm", "4.17.20", None,
              ["GHSA-1"], ["CVE-1"])
    [f] = refresh(store, scan([m])).values()
    assert f.advisory_ids == ["CVE-1", "GHSA-1"] and f.severity == "unknown"
    assert f.title == "Known vulnerability in lodash"


# Severity, fixed version, next steps


def test_severity_labels():
    assert [severity_label(x) for x in ("9.8", 7.2, "5.3", "0.5", "0", "HIGH", "MODERATE", "Critical", "x", None, True)] == [
        "critical", "high", "medium", "low", "unknown", "high", "medium", "critical", "unknown", "unknown", "unknown"]


def test_fixed_in_is_the_lowest_fix_above_every_affected_version(store):
    g = adv(["GHSA-1"], fixed=["3.0.1", "4.17.21", "4.17.5"])
    [f] = refresh(store, scan([match(version="4.17.20", groups=[g])])).values()
    assert f.fixed_in == "4.17.21"
    assert f.next_steps == ["Update lodash to 4.17.21 or later in the lockfile.", "Restart the dev server after the update."]


def test_no_fixed_version(store):
    [f] = refresh(store, scan([match(groups=[adv(["GHSA-1"])])])).values()
    assert f.fixed_in is None
    assert f.next_steps == ["Check the advisory for a workaround. No fixed version is known."]


def test_worse_severity_wins_when_findings_merge(store):
    refresh(store, scan([match(groups=[adv(["GHSA-1", "CVE-1"], severity="low")])]))
    [f] = refresh(store, scan([match(groups=[adv(["CVE-1"], severity="critical")])])).values()
    assert f.severity == "critical"


def test_advisory_groups_read_scanner_output():
    entry = {
        "vulnerabilities": [
            {"id": "GHSA-1", "aliases": ["CVE-1"], "summary": "  First  ",
             "database_specific": {"severity": "MODERATE"},
             "affected": [{"package": {"name": "Left_Pad", "ecosystem": "PyPI"},
                           "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0"}]}]},
                          {"package": {"name": "other"}, "ranges": [{"events": [{"fixed": "9"}]}]},
                          "junk", {"package": 5}]},
            {"id": "PYSEC-1", "aliases": ["CVE-1"], "summary": 7},
            {"id": "GHSA-2", "aliases": []},
        ],
        "groups": [{"ids": ["GHSA-1", "PYSEC-1"], "aliases": ["CVE-1"], "max_severity": "9.1"},
                   {"ids": ["GHSA-2"], "aliases": []}],
    }
    first, second = advisory_groups(entry, "left-pad")
    assert first == {"ids": ["CVE-1", "GHSA-1", "PYSEC-1"], "title": "First", "severity": "critical",
                     "fixed_in": ["2.0"]}
    assert second == {"ids": ["GHSA-2"], "title": None, "severity": "unknown", "fixed_in": []}
    without_groups = {"vulnerabilities": [{"id": "A", "aliases": ["B"]}]}
    assert advisory_groups(without_groups, "x")[0]["ids"] == ["A", "B"]


# Resolution needs complete evidence


def test_complete_scan_without_the_package_resolves_the_finding(store):
    refresh(store, scan([match(groups=[LODASH])]))
    [f] = refresh(store, scan([])).values()
    assert f.status == "resolved"
    assert f.resolved_scan_at == f.resolved_at == T[3]
    assert f.paths == [] and f.next_steps == []


def test_fixing_one_of_two_paths_keeps_the_finding_open_with_the_other(store):
    both = scan([match("web", groups=[LODASH]), match("api", groups=[LODASH])],
                scanned=(("web", "package-lock.json"), ("api", "package-lock.json")))
    refresh(store, both)
    [f] = refresh(store, scan([match("web", groups=[LODASH])],
                              scanned=(("web", "package-lock.json"), ("api", "package-lock.json")))).values()
    assert f.status == "open" and [p.project for p in f.paths] == ["web"]


def test_upgraded_version_replaces_the_old_path(store):
    refresh(store, scan([match(version="4.17.20", groups=[LODASH])]))
    [f] = refresh(store, scan([match(version="4.17.19", groups=[LODASH])])).values()
    assert [p.version for p in f.paths] == ["4.17.19"] and f.status == "open"


@pytest.mark.parametrize("state,error", [
    ("partial", "OSV database is not downloaded. Projects were not scanned."),
    ("stale", "OSV database is 9 days old. Results can miss new advisories."),
    ("failed", "OSV-Scanner stopped with an error."),
    ("not_run", None),
    ("complete", "OSV database did not update. Results use the last copy."),
])
def test_incomplete_scan_never_resolves_or_removes_a_path(store, state, error):
    refresh(store, scan([match(groups=[LODASH])]))
    [f] = refresh(store, scan([], state=state, error=error), status="partial").values()
    assert f.status == "open" and len(f.paths) == 1
    assert f.last_seen == T[1]


def test_partial_scan_still_records_new_findings(store):
    [f] = refresh(store, scan([match(groups=[LODASH])], state="partial", error="Some lockfiles were not scanned.")).values()
    assert f.status == "open"


def test_lockfile_that_was_not_scanned_is_no_evidence(store):
    refresh(store, scan([match(groups=[LODASH])]))
    # The next complete scan does not list the lockfile as scanned (inactive project, lockfile gone).
    [f] = refresh(store, scan([], scanned=())).values()
    assert f.status == "open" and len(f.paths) == 1
    other = scan([], scanned=(("web", "other-lock.json"),))
    [f] = refresh(store, other).values()
    assert f.status == "open"


def test_resolved_finding_that_returns_is_open_with_the_same_id(store):
    refresh(store, scan([match(groups=[LODASH])]))
    refresh(store, scan([]))
    [f] = refresh(store, scan([match(groups=[LODASH])])).values()
    assert (f.id, f.status, f.resolved_at, f.resolved_scan_at) == ("SEC-0001", "open", None, None)
    assert f.first_seen == T[1]


def test_failed_save_keeps_the_previous_findings(tmp_path, monkeypatch):
    with Store(tmp_path, clock=Clock(*T * 2)) as s:
        refresh(s, scan([match(groups=[LODASH])]))
        r = s.begin_refresh()
        monkeypatch.setattr(findings, "apply_scan", lambda *a: (_ for _ in ()).throw(RuntimeError("disk")))
        with pytest.raises(RuntimeError):
            s.finish_refresh(r.id, "complete", coverage=[C("osv", "OSV", "complete")], scan=scan([]))
        monkeypatch.undo()
        [f] = s.findings()
        assert f.status == "open" and len(f.paths) == 1


# Defer and backlog


def test_defer_sets_a_date_and_the_finding_reopens_after_it(tmp_path):
    times = [f"2026-10-29T10:{m:02d}:00Z" for m in range(10)]
    with Store(tmp_path, clock=Clock(*times)) as s:
        refresh(s, scan([match(groups=[LODASH])]))
        f = s.defer_finding("SEC-0001", 7)
        assert (f.status, f.deferred_until) == ("deferred", "2026-11-05T10:02:00Z")
        [again] = s.findings()  # The clock reads 2026-10-29T10:04, before the end of the deferral.
        assert again.status == "deferred"


def test_deferral_that_ended_counts_as_open(tmp_path):
    with Store(tmp_path, clock=Clock(*[f"2026-10-29T10:0{m}:00Z" for m in range(4)], "2026-11-30T00:00:00Z")) as s:
        refresh(s, scan([match(groups=[LODASH])]))
        s.defer_finding("SEC-0001", 30)
        [f] = s.findings()
    assert f.status == "open" and f.deferred_until is None


def test_a_scan_does_not_change_a_deferred_or_backlog_finding(store):
    refresh(store, scan([match(groups=[LODASH])]))
    store.defer_finding("SEC-0001", 30)
    [f] = refresh(store, scan([match(groups=[LODASH])])).values()
    assert f.status == "deferred"
    store.backlog_finding("SEC-0001")
    [f] = refresh(store, scan([match(groups=[LODASH])])).values()
    assert (f.status, f.deferred_until) == ("backlog", None)
    assert store.reopen_finding("SEC-0001").status == "open"


def test_defer_days_and_unknown_ids_are_refused(store):
    refresh(store, scan([match(groups=[LODASH])]))
    with pytest.raises(FindingError, match="7 or 30"):
        store.defer_finding("SEC-0001", 5)
    for bad in ("SEC-0099", "nope", "SEC-", ""):
        with pytest.raises(FindingError):
            store.backlog_finding(bad)
    assert store.findings()[0].status == "open"


def test_a_resolved_finding_cannot_be_deferred_or_moved(store):
    refresh(store, scan([match(groups=[LODASH])]))
    refresh(store, scan([]))
    for act in (lambda: store.defer_finding("SEC-0001", 7), lambda: store.backlog_finding("sec-0001"),
                lambda: store.reopen_finding("SEC-0001")):
        with pytest.raises(FindingError, match="resolved"):
            act()


def test_resolution_clears_a_deferral(store):
    refresh(store, scan([match(groups=[LODASH])]))
    store.defer_finding("SEC-0001", 7)
    [f] = refresh(store, scan([])).values()
    assert (f.status, f.deferred_until) == ("resolved", None)


# Order and state output


def test_findings_sort_by_severity_then_newest_last_seen(store):
    old = adv(["GHSA-old"], severity="high")
    refresh(store, scan([match(name="old", groups=[old])]))
    new_high = adv(["GHSA-new"], severity="high")
    crit = adv(["GHSA-crit"], severity="critical")
    low = adv(["GHSA-low"], severity="low")
    # A partial scan adds findings and leaves `old` with its older last_seen.
    refresh(store, scan([match(name="newer", groups=[new_high]), match(name="crit", groups=[crit]),
                         match(name="low", groups=[low])], state="partial", error="Some lockfiles were not scanned."),
            status="partial")
    assert [f.package for f in store.findings()] == ["crit", "newer", "old", "low"]


def test_state_output_has_findings_and_survives_a_new_store_object(tmp_path):
    with Store(tmp_path, clock=Clock(*T * 2)) as s:
        refresh(s, scan([match(groups=[LODASH], dep=["app", "lodash"])]))
    with Store(tmp_path) as s:
        [f] = s.state()["findings"]
    assert f["id"] == "SEC-0001"
    assert f["paths"] == [{"project": "web", "project_path": "~/Projects/web", "lockfile": "package-lock.json",
                           "version": "4.17.20", "dependency_path": ["app", "lodash"]}]
    assert set(f) == {"id", "ecosystem", "package", "title", "severity", "advisory_ids", "fixed_in", "status",
                      "deferred_until", "first_seen", "last_seen", "resolved_at", "resolved_scan_at", "source",
                      "source_at", "paths", "next_steps", "kev", "malware", "withdrawn_at"}


def test_old_store_without_findings_tables_opens(tmp_path):
    data = tmp_path / "data"
    Store(data).close()
    db = sqlite3.connect(data / "watchtower.sqlite3")
    db.executescript("DROP TABLE finding_paths; DROP TABLE findings;")
    db.commit()
    db.close()
    with Store(data) as s:
        assert s.state()["findings"] == []


# CLI


def test_cli_finding_commands(tmp_path, capsys):
    data = tmp_path / "data"
    with Store(data) as s:
        refresh(s, scan([match(groups=[LODASH])]))
    assert cli.main(["--data-dir", str(data), "finding-defer", "sec-0001", "7"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["finding"]["status"] == "deferred" and out["finding"]["deferred_until"]
    assert cli.main(["--data-dir", str(data), "finding-backlog", "SEC-0001"]) == 0
    assert json.loads(capsys.readouterr().out)["finding"]["status"] == "backlog"
    assert cli.main(["--data-dir", str(data), "finding-reopen", "SEC-0001"]) == 0
    assert json.loads(capsys.readouterr().out)["finding"]["status"] == "open"
    assert cli.main(["--data-dir", str(data), "finding-backlog", "SEC-0042"]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and json.loads(captured.err)["error"] == "There is no finding SEC-0042."


def test_osv_collect_gives_findings_from_real_scanner_shaped_output(tmp_path):
    text = (osv.__file__ and open(__import__("pathlib").Path(__file__).parent / "fixtures" / "osv" / "scan-output.json").read())
    text = text.replace("__NPM_LOCK__", "/p/web/package-lock.json").replace("__UV_LOCK__", "/p/api/uv.lock")
    rows = osv.parse_output(text)
    lodash = next(r for r in rows["/p/web/package-lock.json"] if r["name"] == "lodash")
    assert [g["ids"] for g in lodash["advisories"]] == [
        ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"], ["CVE-2020-28500", "GHSA-29mw-wpgm-hmr9"]]
