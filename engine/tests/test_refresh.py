import json
import os
import signal

import pytest

from watchtower_engine import cli, refresh
from watchtower_engine.inventory.homebrew import SourceResult
from watchtower_engine.models import CoverageRecord as C
from watchtower_engine.models import ItemRecord as I
from watchtower_engine.refresh import Cancelled, ScanSourceResult, Source, StopOnSigterm, run_refresh
from watchtower_engine.scanners.osv import Match, OsvResult
from watchtower_engine.store import Store

from contract import Clock


def clock():
    return Clock(*[f"2026-10-29T10:{m:02d}:00Z" for m in range(30)])


def ok(source, label, *items):
    return Source(source, label, lambda: SourceResult(C(source, label, "complete"), list(items)))


def boom(source, label, exc=RuntimeError("broken")):
    def collect():
        raise exc
    return Source(source, label, collect)


BREW = ok("homebrew", "Homebrew", I("formula:git", "homebrew", "git", "update_available"))
APPS = ok("apps", "Applications", I("app:a", "apps", "A", "up_to_date"))


def test_complete_refresh_saves_every_source_and_reports_progress(tmp_path):
    seen = []
    with Store(tmp_path, clock=clock()) as s:
        state = run_refresh(s, [BREW, APPS], lambda d, t, l: seen.append((d, t, l)))
    assert seen == [(0, 2, "Homebrew"), (1, 2, "Applications"), (2, 2, "")]
    assert state["refresh"]["status"] == "complete"
    assert state["refresh"]["last_complete_at"] == state["refresh"]["finished_at"]
    assert [i["id"] for i in state["items"]] == ["app:a", "formula:git"]


def test_a_failing_source_makes_a_partial_refresh(tmp_path):
    with Store(tmp_path, clock=clock()) as s:
        run_refresh(s, [BREW, APPS])
        state = run_refresh(s, [BREW, boom("apps", "Applications")])
    r = state["refresh"]
    assert r["status"] == "partial"
    assert r["error"] == "Some sources did not finish."
    assert r["last_complete_at"] == "2026-10-29T10:01:00Z"
    cov = {c["source"]: c for c in state["coverage"]}
    assert cov["apps"]["state"] == "failed"
    assert cov["apps"]["error"] == "Applications check did not finish."
    assert "broken" in cov["apps"]["detail"]
    assert {i["id"] for i in state["items"]} == {"app:a", "formula:git"}  # old apps rows stay


def test_all_sources_failing_is_a_failed_refresh(tmp_path):
    with Store(tmp_path, clock=clock()) as s:
        run_refresh(s, [BREW])
        state = run_refresh(s, [boom("homebrew", "Homebrew")])
    assert state["refresh"]["status"] == "failed"
    assert state["refresh"]["last_complete_at"] == "2026-10-29T10:01:00Z"


def test_cancel_keeps_previous_results(tmp_path):
    with Store(tmp_path, clock=clock()) as s:
        run_refresh(s, [BREW, APPS])
        before_cov, before_items = s.coverage(), s.items()
        newer = ok("homebrew", "Homebrew", I("formula:new", "homebrew", "new", "vulnerable"))
        with pytest.raises(Cancelled):
            run_refresh(s, [newer, boom("apps", "Applications", Cancelled())])
        latest = s.latest_refresh()
        assert latest.status == "cancelled"
        assert latest.last_complete_at == "2026-10-29T10:01:00Z"
        assert s.coverage() == before_cov  # not marked stale
        assert s.items() == before_items


def test_sigterm_during_a_source_cancels(tmp_path):
    def kill_me():
        os.kill(os.getpid(), signal.SIGTERM)
        raise AssertionError("SIGTERM did not stop the source")

    with Store(tmp_path, clock=clock()) as s, StopOnSigterm() as guard:
        with pytest.raises(Cancelled):
            run_refresh(s, [BREW, Source("apps", "Applications", kill_me)], guard=guard)
        assert s.latest_refresh().status == "cancelled"


def test_sigterm_after_the_sources_does_not_cut_the_save(tmp_path):
    with Store(tmp_path, clock=clock()) as s, StopOnSigterm() as guard:
        def progress(done, total, label):
            if done == total:
                os.kill(os.getpid(), signal.SIGTERM)  # arrives during the save step

        state = run_refresh(s, [BREW], progress, guard)
    assert state["refresh"]["status"] == "complete"


def test_osv_scan_becomes_findings_in_the_same_save(tmp_path):
    adv = {"ids": ["CVE-1", "GHSA-1"], "title": "Bad", "severity": "high", "fixed_in": ["4.17.21"]}
    m = Match("web", "~/Projects/web", "package-lock.json", "lodash", "npm", "4.17.20", None,
              ["GHSA-1"], ["CVE-1"], [adv])
    scan = OsvResult(C("osv", "OSV", "complete"), [], [m], [])
    osv_source = Source("osv", "OSV", lambda: ScanSourceResult(scan.coverage, [], scan))
    with Store(tmp_path, clock=clock()) as s:
        state = run_refresh(s, [BREW, osv_source])
    assert state["items"] == [i for i in state["items"] if i["source"] != "osv"]
    [finding] = state["findings"]
    assert (finding["id"], finding["package"], finding["status"]) == ("SEC-0001", "lodash", "open")


def test_cli_refresh_prints_state_and_progress(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(refresh, "default_sources", lambda data_dir: [BREW, APPS])
    assert cli.main(["--data-dir", str(tmp_path), "refresh"]) == 0
    captured = capsys.readouterr()
    state = json.loads(captured.out)
    assert state["schema_version"] == 1 and state["refresh"]["status"] == "complete"
    lines = [json.loads(line) for line in captured.err.splitlines()]
    assert [l["progress"]["done"] for l in lines] == [0, 1, 2]
    assert all(l["progress"]["total"] == 2 for l in lines)


def test_cli_refresh_stop_exits_130_with_empty_stdout(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(refresh, "default_sources",
                        lambda data_dir: [boom("homebrew", "Homebrew", Cancelled())])
    assert cli.main(["--data-dir", str(tmp_path), "refresh"]) == 130
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err.splitlines()[-1])["error"] == "Refresh stopped."
