import json
import sqlite3

import pytest

from watchtower_engine import cli, findings, refresh
from watchtower_engine.feeds.github import GithubData, Lookup, key
from watchtower_engine.feeds.kev import KevData
from watchtower_engine.inventory.homebrew import SourceResult
from watchtower_engine.models import CoverageRecord as C
from watchtower_engine.refresh import ScanSourceResult, Source, run_refresh
from watchtower_engine.store import Store

from contract import Clock
from test_findings import LODASH, T, adv, match, scan

MAL = adv(["GHSA-mal1-ware-0001"], "Malware in minimist-fx", "critical")
KEV_ENTRY = {"cve": "CVE-2021-23337", "date_added": "2026-10-22", "due_date": "2026-11-12", "ransomware": False}
LATER = "2999-01-01T00:00:00Z"


def kev_data(entries=None, loaded=True):
    return KevData(entries if entries is not None else {"CVE-2021-23337": KEV_ENTRY},
                   "2026-10-29T08:00:00Z" if loaded else None, fresh=loaded)


def github_data(ids_malware=(), withdrawn=None, known=True):
    """Answers for the lodash ids and the malware id. `known=False`: no answer was retrieved."""
    data = GithubData()
    for kind, param, value in (("reviewed", "ghsa_id", "GHSA-35jh-r3h4-6jhm"), ("malware", "ghsa_id", "GHSA-35jh-r3h4-6jhm"),
                               ("reviewed", "ghsa_id", "GHSA-mal1-ware-0001"), ("malware", "ghsa_id", "GHSA-mal1-ware-0001")):
        lookup = Lookup(kind, param, value)
        if known:
            rows = []
            if kind == "malware" and value in ids_malware:
                rows = [{"ghsa_id": value, "type": "malware", "withdrawn_at": None}]
            if kind == "reviewed" and withdrawn and value == "GHSA-35jh-r3h4-6jhm":
                rows = [{"ghsa_id": value, "type": "reviewed", "withdrawn_at": withdrawn}]
            lookup.advisories, lookup.fetched_at = rows, "2026-10-29T08:00:00Z"
        data.lookups[key(kind, param, value)] = lookup
    return data


def enrich(store, result, kev=None, github=None):
    r = store.begin_refresh()
    store.finish_refresh(r.id, "complete", coverage=[result.coverage], scan=result, kev=kev, github=github)
    return {f.package: f for f in findings.list_findings(store.db, "2026-10-01T00:00:00Z")}


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "data", clock=Clock(*T * 2)) as s:
        yield s


def test_kev_marks_the_finding_by_any_cve_alias(store):
    [f] = enrich(store, scan([match(groups=[LODASH])]), kev=kev_data()).values()
    assert f.kev == KEV_ENTRY and f.malware is None and f.withdrawn_at is None
    assert f.to_dict()["kev"] == KEV_ENTRY


def test_a_finding_is_not_marked_without_a_cve_in_the_catalog(store):
    [f] = enrich(store, scan([match(groups=[adv(["GHSA-x"])])]), kev=kev_data()).values()
    assert f.kev is None


def test_kev_matches_by_the_advisory_id_not_by_the_product_name(store):
    # The catalog lists a Lodash product, but this finding has another CVE. No mark.
    entries = {"CVE-2021-23337": KEV_ENTRY}
    [f] = enrich(store, scan([match(name="lodash", groups=[adv(["CVE-2099-1", "GHSA-other"])])]),
                 kev=kev_data(entries)).values()
    assert f.kev is None


def test_a_kev_mark_is_removed_when_the_catalog_no_longer_lists_it(store):
    enrich(store, scan([match(groups=[LODASH])]), kev=kev_data())
    [f] = enrich(store, scan([match(groups=[LODASH])]), kev=kev_data({"CVE-1-1": KEV_ENTRY})).values()
    assert f.kev is None


def test_missing_kev_data_keeps_the_old_mark(store):
    enrich(store, scan([match(groups=[LODASH])]), kev=kev_data())
    [f] = enrich(store, scan([match(groups=[LODASH])]), kev=kev_data({}, loaded=False)).values()
    assert f.kev == KEV_ENTRY
    [f] = enrich(store, scan([match(groups=[LODASH])]), kev=None).values()
    assert f.kev == KEV_ENTRY


def test_cached_kev_data_still_marks(store):
    cached = KevData({"CVE-2021-23337": KEV_ENTRY}, "2026-10-28T08:00:00Z", fresh=False, error="CISA KEV did not load.")
    [f] = enrich(store, scan([match(groups=[LODASH])]), kev=cached).values()
    assert f.kev == KEV_ENTRY


def test_malware_and_withdrawn_marks(store):
    result = scan([match(groups=[LODASH]), match(name="minimist-fx", groups=[MAL])])
    out = enrich(store, result, github=github_data(ids_malware={"GHSA-mal1-ware-0001"},
                                                   withdrawn="2026-10-28T08:00:00Z"))
    assert out["minimist-fx"].malware == {"advisory_id": "GHSA-mal1-ware-0001"}
    assert out["lodash"].malware is None and out["lodash"].withdrawn_at == "2026-10-28T08:00:00Z"
    assert out["minimist-fx"].withdrawn_at is None


def test_marks_are_cleared_only_when_every_answer_is_known(store):
    result = scan([match(name="minimist-fx", groups=[MAL])])
    enrich(store, result, github=github_data(ids_malware={"GHSA-mal1-ware-0001"}))
    [f] = enrich(store, result, github=github_data(known=False)).values()
    assert f.malware is not None  # No answer: the mark stays.
    [f] = enrich(store, result, github=github_data(ids_malware=())).values()
    assert f.malware is None  # Answered: it is not malware any more.


def test_a_finding_with_only_unasked_ids_is_never_cleared(store):
    other = adv(["PYSEC-2020-1"], "x")
    result = scan([match(name="py", groups=[other])])
    enrich(store, result, kev=kev_data(), github=github_data())
    store.db.execute("UPDATE findings SET malware = '{\"advisory_id\": \"x\"}'")
    [f] = enrich(store, result, kev=kev_data(), github=github_data()).values()
    assert f.malware == {"advisory_id": "x"}


def test_marks_survive_a_scan_without_feed_data_and_a_new_store_object(tmp_path):
    with Store(tmp_path, clock=Clock(*T * 2)) as s:
        enrich(s, scan([match(groups=[LODASH])]), kev=kev_data(), github=github_data(withdrawn="2026-10-28T08:00:00Z"))
        enrich(s, scan([match(groups=[LODASH])]))
    with Store(tmp_path) as s:
        [f] = s.state()["findings"]
    assert f["kev"] == KEV_ENTRY and f["withdrawn_at"] == "2026-10-28T08:00:00Z" and f["malware"] is None


def test_order_is_malware_then_known_exploited_then_severity_then_newest(store):
    high = adv(["GHSA-high"], severity="high")
    crit = adv(["GHSA-crit"], severity="critical")
    low = adv(["GHSA-low"], severity="low")
    low_kev = adv(["CVE-2021-23337"], severity="low")
    result = scan([match(name="high", groups=[high]), match(name="crit", groups=[crit]),
                   match(name="lowkev", groups=[low_kev]), match(name="low", groups=[low]),
                   match(name="mal", groups=[adv(["GHSA-mal1-ware-0001"], severity="medium")])])
    out = enrich(store, result, kev=kev_data(), github=github_data(ids_malware={"GHSA-mal1-ware-0001"}))
    ordered = [f.package for f in findings.list_findings(store.db, "2026-10-01T00:00:00Z")]
    assert ordered == ["mal", "lowkev", "crit", "high", "low"]
    assert out["lowkev"].kev and out["mal"].malware


def test_old_store_gets_the_new_columns(tmp_path):
    data = tmp_path / "data"
    Store(data).close()
    db = sqlite3.connect(data / "watchtower.sqlite3")
    db.executescript("DROP TABLE finding_paths; DROP TABLE findings; "
                     "CREATE TABLE findings (seq INTEGER PRIMARY KEY, ecosystem TEXT NOT NULL, package TEXT NOT NULL, "
                     "title TEXT, severity TEXT NOT NULL, advisory_ids TEXT NOT NULL, fixed_versions TEXT NOT NULL, "
                     "status TEXT NOT NULL, deferred_until TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, "
                     "resolved_at TEXT, resolved_scan_at TEXT, source_at TEXT);"
                     "INSERT INTO findings VALUES (1, 'npm', 'old', 't', 'high', '[\"GHSA-x\"]', '[]', 'open', NULL, "
                     "'2026-10-20T00:00:00Z', '2026-10-20T00:00:00Z', NULL, NULL, NULL);")
    db.commit()
    db.close()
    with Store(data) as s:
        [f] = s.findings()
    assert (f.package, f.kev, f.malware, f.withdrawn_at) == ("old", None, None, None)


# Refresh wiring


def test_refresh_gives_feed_data_to_the_store_and_saves_coverage_with_notes(tmp_path):
    result = scan([match(groups=[LODASH])])
    osv_source = Source("osv", "OSV", lambda: ScanSourceResult(result.coverage, [], result))
    kev_source = Source("kev", "CISA KEV", lambda: ScanSourceResult(
        C("kev", "CISA KEV", "complete", source_at="2026-10-29T08:00:00Z", note="official mirror"), [],
        kev=kev_data()))
    gh = github_data(withdrawn="2026-10-28T08:00:00Z")
    gh_source = Source("github", "GitHub Advisories", lambda: ScanSourceResult(
        C("github", "GitHub Advisories", "failed", error="GitHub Advisories did not load.",
          source_at="2026-10-28T08:00:00Z", note="rate limit"), [], github=gh))
    with Store(tmp_path, clock=Clock(*T * 2)) as s:
        state = run_refresh(s, [osv_source, kev_source, gh_source])
    [f] = state["findings"]
    assert f["kev"] == KEV_ENTRY and f["withdrawn_at"] == "2026-10-28T08:00:00Z"
    cov = {c["source"]: c for c in state["coverage"]}
    assert (cov["kev"]["state"], cov["kev"]["note"]) == ("complete", "official mirror")
    assert (cov["github"]["state"], cov["github"]["note"], cov["github"]["source_at"]) == (
        "failed", "rate limit", "2026-10-28T08:00:00Z")
    assert state["refresh"]["status"] == "partial"  # A failed feed is visible in the refresh.


def test_the_default_sources_run_kev_github_and_epss_after_osv(tmp_path):
    names = [s.source for s in refresh.default_sources(tmp_path)]
    assert names == ["homebrew", "apps", "macos", "osv", "kev", "github", "epss"]


def test_only_advisory_ids_are_collected_for_github(tmp_path):
    result = scan([match(project="secret-project", groups=[LODASH], version="9.9.9")])
    with Store(tmp_path, clock=Clock(*T * 2)) as s:
        r = s.begin_refresh()
        s.finish_refresh(r.id, "complete", coverage=[result.coverage], scan=result)
    groups = refresh.advisory_id_groups(tmp_path, [result])
    assert all(isinstance(i, str) for g in groups for i in g)
    flat = {i for g in groups for i in g}
    assert flat == {"CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"}
    assert not any("secret" in i or "9.9.9" in i or "lodash" in i for i in flat)


def test_resolved_findings_are_not_sent_to_github(tmp_path):
    with Store(tmp_path, clock=Clock(*T * 2)) as s:
        for result in (scan([match(groups=[LODASH])]), scan([])):
            r = s.begin_refresh()
            s.finish_refresh(r.id, "complete", coverage=[result.coverage], scan=result)
    assert refresh.advisory_id_groups(tmp_path, []) == []


# Withdrawn only if every id is withdrawn (#65). Real nltk ids: a live advisory and a withdrawn duplicate.


def test_a_wrong_withdrawn_mark_is_cleared_and_the_other_marks_stay(store, tmp_path):
    from test_github import NLTK, nltk_fetch, rate_limited
    from watchtower_engine.feeds.github import load
    result = scan([match(name="nltk", groups=[adv(NLTK, severity="medium")])])
    kev = kev_data({"CVE-2026-12259": {**KEV_ENTRY, "cve": "CVE-2026-12259"}})
    # The reviewed answers arrive. The malware answers hit the rate limit, so the malware mark is unknown.
    fetch = nltk_fetch({("malware", "GHSA-5wp5-5229-5g6q"): rate_limited()})
    data = load(tmp_path / "gh", [NLTK], fetch, lambda: "2026-10-30T08:00:00Z")
    assert data.assess(NLTK).withdrawn_known and not data.assess(NLTK).malware_known
    enrich(store, result, kev=kev)  # KEV mark first, no GitHub data yet.
    store.db.execute("UPDATE findings SET withdrawn_at = ?, malware = ?",
                     ("2026-09-09T16:33:54Z", json.dumps({"advisory_id": "GHSA-prior-mark-0001"})))
    [f] = enrich(store, result, kev=kev, github=data).values()
    assert f.withdrawn_at is None  # The old bug set it from the duplicate.
    assert f.kev["cve"] == "CVE-2026-12259"
    assert f.malware == {"advisory_id": "GHSA-prior-mark-0001"}  # No malware answer: the prior mark stays.


def test_a_finding_with_every_id_withdrawn_shows_the_mark_and_the_date(store, tmp_path):
    from test_github import nltk_fetch
    from watchtower_engine.feeds.github import load
    ids = ["GHSA-gf32-cmjh-8m9v"]
    result = scan([match(name="dup", groups=[adv(ids, severity="critical")])])
    data = load(tmp_path / "gh", [ids], nltk_fetch(), lambda: "2026-10-30T08:00:00Z")
    [f] = enrich(store, result, github=data).values()
    assert f.withdrawn_at == "2026-09-09T16:33:54Z"
