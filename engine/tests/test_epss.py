"""EPSS scores (#57). Fixtures only: no network. The fixture holds real rows of the public EPSS file."""
import gzip
import os
import stat
from pathlib import Path

import pytest

from watchtower_engine import cli, findings, refresh
from watchtower_engine.feeds import epss
from watchtower_engine.feeds.homebrew import Response
from watchtower_engine.refresh import ScanSourceResult, Source, run_refresh
from watchtower_engine.inventory.homebrew import SourceResult
from watchtower_engine.models import CoverageRecord as C
from watchtower_engine.store import Store

from contract import Clock
from test_findings import T, adv, match, scan

CSV = (Path(__file__).parent / "fixtures" / "epss" / "epss_scores-excerpt.csv").read_bytes()
GZ = gzip.compress(CSV)  # The real file is gzip with no content-encoding header.
D1, D2, D3, D6 = ("2026-10-29T08:00:00Z", "2026-10-29T20:00:00Z", "2026-10-30T09:00:00Z", "2026-11-01T09:00:00Z")
LOG4J, NODE, MISSING = "CVE-2021-44228", "CVE-2020-8203", "CVE-2099-0001"


class FakeFetch:
    def __init__(self, answer=None):
        self.answer, self.calls = Response(200, {"content-type": "binary/octet-stream"}, GZ) if answer is None else answer, []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


# The file


def test_the_real_rows_are_read_with_score_percentile_and_date():
    scores, score_date = epss.parse(GZ, [LOG4J, "cve-2016-10394", MISSING])
    assert scores == {LOG4J: (0.99999, 1.0), "CVE-2016-10394": (0.00098, 0.00745)}
    assert score_date == "2026-10-29"


def test_a_plain_csv_and_a_gzip_file_read_the_same():
    assert epss.parse(CSV, [LOG4J]) == epss.parse(GZ, [LOG4J])
    assert len(epss.parse(CSV)[0]) == 10  # No filter keeps every row.


@pytest.mark.parametrize("body", [b"", b"not csv", b"cve,epss,percentile\n", b"#c\ncve,epss,percentile\nCVE-2021-1,2,0.5\n",
                                  b"cve,score\nCVE-2021-44228,0.5\n", b"\x1f\x8bbroken"])
def test_a_file_that_is_not_epss_data_is_refused(body):
    with pytest.raises(ValueError):
        epss.parse(body)


def test_bad_rows_are_skipped_and_good_rows_stay():
    body = b"cve,epss,percentile\nnot-a-cve,0.1,0.1\nCVE-2021-44228,abc,0.1\nCVE-2021-44228,0.5,0.6\nCVE-2020-8203,0.1\n"
    assert epss.parse(body)[0] == {"CVE-2021-44228": (0.5, 0.6)}


# Download and cache


def test_the_request_is_one_get_of_the_bulk_file_with_no_finding_data(tmp_path):
    fetch = FakeFetch()
    data = epss.load(tmp_path, [LOG4J, NODE], fetch, lambda: D1)
    assert [u for u, _ in fetch.calls] == ["https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"]
    assert set(fetch.calls[0][1]) == {"User-Agent", "Accept-Encoding"}
    assert LOG4J not in str(fetch.calls) and NODE not in str(fetch.calls)
    assert (data.fresh, data.fetched_at, data.score_date, data.error) == (True, D1, "2026-10-29", None)
    assert data.scores == {LOG4J: (0.99999, 1.0), NODE: (0.05213, 0.92481)}
    cov = data.coverage()
    assert (cov.source, cov.label, cov.state, cov.source_at) == ("epss", "EPSS", "complete", D1)


def test_a_cache_hit_within_a_day_uses_no_network_and_keeps_the_retrieval_time(tmp_path):
    epss.load(tmp_path, [LOG4J], FakeFetch(), lambda: D1)
    fetch = FakeFetch(OSError("must not be called"))
    data = epss.load(tmp_path, [LOG4J, "CVE-2024-3094"], fetch, lambda: D2)  # A new CVE is found in the cached file.
    assert fetch.calls == []
    assert (data.fresh, data.fetched_at) == (True, D1)
    assert data.scores["CVE-2024-3094"] == (0.909, 0.99806)
    assert data.coverage().state == "complete" and data.coverage().source_at == D1


def test_a_stale_cache_downloads_again_once_it_is_a_day_old(tmp_path):
    epss.load(tmp_path, [LOG4J], FakeFetch(), lambda: D1)
    fetch = FakeFetch()
    data = epss.load(tmp_path, [LOG4J], fetch, lambda: D3)
    assert len(fetch.calls) == 1 and data.fetched_at == D3 and data.fresh


@pytest.mark.parametrize("failure", [OSError("down"), Response(503, {}, b""), Response(200, {}, b"not epss"),
                                     Response(200, {}, b"")])
def test_a_failed_download_keeps_the_earlier_scores_and_is_partial(tmp_path, failure):
    epss.load(tmp_path, [LOG4J], FakeFetch(), lambda: D1)
    data = epss.load(tmp_path, [LOG4J], FakeFetch(failure), lambda: D6)
    assert data.scores == {LOG4J: (0.99999, 1.0)}
    assert (data.fresh, data.fetched_at, data.error) == (False, D1, "EPSS download failed.")
    cov = data.coverage()
    assert (cov.state, cov.source_at, cov.error) == ("partial", D1, "EPSS download failed.")
    assert "epss_scores-current.csv.gz" in cov.detail


def test_a_failed_download_with_no_cache_is_failed_and_has_no_scores(tmp_path):
    data = epss.load(tmp_path, [LOG4J], FakeFetch(OSError("down")), lambda: D1)
    assert not data.loaded and data.scores == {}
    assert data.coverage().state == "failed" and data.coverage().source_at is None


def test_a_damaged_cache_is_downloaded_again(tmp_path):
    epss.load(tmp_path, [LOG4J], FakeFetch(), lambda: D1)
    (tmp_path / "cache" / "epss" / "epss.csv.gz").write_bytes(b"damaged")
    fetch = FakeFetch()
    data = epss.load(tmp_path, [LOG4J], fetch, lambda: D2)
    assert len(fetch.calls) == 1 and data.fetched_at == D2


def test_the_cache_is_private_and_holds_the_gzip_file(tmp_path):
    epss.load(tmp_path, [LOG4J], FakeFetch(Response(200, {}, CSV)), lambda: D1)  # A plain CSV is stored as gzip.
    folder = tmp_path / "cache" / "epss"
    assert stat.S_IMODE(os.stat(folder).st_mode) == 0o700
    assert all(stat.S_IMODE(os.stat(p).st_mode) == 0o600 for p in folder.iterdir())
    assert (folder / "epss.csv.gz").read_bytes()[:2] == b"\x1f\x8b"


# Findings


def enrich(store, result, data):
    r = store.begin_refresh()
    store.finish_refresh(r.id, "complete", coverage=[result.coverage], scan=result, epss=data)
    return {f.package: f for f in findings.list_findings(store.db, "2026-10-30T00:00:00Z")}


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "data", clock=Clock(*T * 3)) as s:
        yield s


def data_for(tmp_path, cves, now=D1, answer=None):
    return epss.load(tmp_path / "epss", cves, FakeFetch(answer), lambda: now)


def test_a_finding_with_a_cve_shows_score_and_percentile(store, tmp_path):
    result = scan([match(name="log4j", groups=[adv(["GHSA-jfh8-c2jp-5v3q", LOG4J], severity="critical")])])
    [f] = enrich(store, result, data_for(tmp_path, [LOG4J])).values()
    assert f.epss == {"cve": LOG4J, "score": 0.99999, "percentile": 1.0, "score_date": "2026-10-29",
                      "fetched_at": D1}
    assert f.to_dict()["epss"]["score"] == 0.99999


def test_a_cve_that_is_not_in_the_file_is_kept_as_missing(store, tmp_path):
    [f] = enrich(store, scan([match(groups=[adv([MISSING])])]), data_for(tmp_path, [MISSING])).values()
    assert f.epss == {"cve": MISSING, "score": None, "percentile": None, "score_date": "2026-10-29",
                      "fetched_at": D1}


def test_a_finding_with_no_cve_has_no_epss_value(store, tmp_path):
    [f] = enrich(store, scan([match(groups=[adv(["GHSA-xxxx-yyyy-zzzz"])])]), data_for(tmp_path, [LOG4J])).values()
    assert f.epss is None


def test_the_cve_with_the_highest_score_is_shown(store, tmp_path):
    result = scan([match(groups=[adv([NODE, LOG4J, "GHSA-a"])])])
    [f] = enrich(store, result, data_for(tmp_path, [NODE, LOG4J])).values()
    assert f.epss["cve"] == LOG4J


def test_a_failed_download_never_clears_earlier_scores(store, tmp_path):
    result = scan([match(groups=[adv([LOG4J])])])
    enrich(store, result, data_for(tmp_path, [LOG4J]))
    failed = data_for(tmp_path, [LOG4J], now=D6, answer=OSError("down"))
    [f] = enrich(store, result, failed).values()
    assert f.epss["score"] == 0.99999 and f.epss["fetched_at"] == D1  # The old time shows the age.


def test_no_data_at_all_leaves_the_old_value(store, tmp_path):
    result = scan([match(groups=[adv([LOG4J])])])
    enrich(store, result, data_for(tmp_path, [LOG4J]))
    nothing = epss.load(tmp_path / "none", [LOG4J], FakeFetch(OSError("down")), lambda: D6)
    [f] = enrich(store, result, nothing).values()
    assert f.epss["score"] == 0.99999
    [g] = enrich(store, result, None).values()
    assert g.epss["score"] == 0.99999


def test_order_is_malware_kev_epss_then_severity(store, tmp_path):
    rows = [("low-hot", "CVE-2022-22965", "low"),       # EPSS 99.6%
            ("crit-cold", "CVE-2016-10394", "critical"),  # EPSS 0.098%
            ("high-mid", "CVE-2021-23337", "high"),      # EPSS 21%
            ("crit-none", "GHSA-none", "critical"),
            ("med-none", "GHSA-none2", "medium"),
            ("kev-low", "CVE-2024-3094", "low")]          # EPSS 91%, but known exploited
    result = scan([match(name=n, groups=[adv([i], severity=s)]) for n, i, s in rows])
    from watchtower_engine.feeds.kev import KevData
    kev = KevData({"CVE-2024-3094": {"cve": "CVE-2024-3094", "date_added": "2026-10-22", "due_date": "2026-11-12",
                                     "ransomware": False}}, D1, fresh=True)
    r = store.begin_refresh()
    store.finish_refresh(r.id, "complete", coverage=[result.coverage], scan=result, kev=kev,
                         epss=data_for(tmp_path, [i for _, i, _ in rows]))
    ordered = [f.package for f in findings.list_findings(store.db, "2026-10-30T00:00:00Z")]
    assert ordered == ["kev-low", "low-hot", "high-mid", "crit-cold", "crit-none", "med-none"]


def test_an_old_store_gets_the_epss_column(tmp_path):
    import sqlite3
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript("CREATE TABLE findings (seq INTEGER PRIMARY KEY, kev TEXT, malware TEXT, withdrawn_at TEXT);")
    findings.migrate(db)
    assert "epss" in {r["name"] for r in db.execute("PRAGMA table_info(findings)")}


# Refresh


def test_the_refresh_runs_epss_and_saves_its_coverage_row(tmp_path):
    result = scan([match(groups=[adv([LOG4J])])])
    data = data_for(tmp_path, [LOG4J])
    sources = [Source("osv", "OSV", lambda: ScanSourceResult(result.coverage, [], result)),
               Source("epss", "EPSS", lambda: ScanSourceResult(data.coverage(), [], epss=data))]
    with Store(tmp_path / "data", clock=Clock(*T * 3)) as s:
        state = run_refresh(s, sources)
    cov = {c["source"]: c for c in state["coverage"]}
    assert (cov["epss"]["state"], cov["epss"]["source_at"], cov["epss"]["label"]) == ("complete", D1, "EPSS")
    assert state["findings"][0]["epss"]["score"] == 0.99999


def test_a_failed_download_makes_the_refresh_partial(tmp_path):
    data = epss.load(tmp_path / "e", [LOG4J], FakeFetch(OSError("down")), lambda: D1)
    sources = [Source("epss", "EPSS", lambda: ScanSourceResult(data.coverage(), [], epss=data))]
    with Store(tmp_path / "data", clock=Clock(*T * 3)) as s:
        state = run_refresh(s, sources)
    assert state["refresh"]["status"] in ("partial", "failed")
    assert state["coverage"][0]["source"] == "epss" and state["coverage"][0]["state"] == "failed"


def test_only_cve_ids_of_open_findings_are_passed_to_the_loader(tmp_path, monkeypatch):
    seen = {}

    def fake_load(data_dir, cves, *a, **k):
        seen["cves"] = set(cves)
        return epss.EpssData()

    with Store(tmp_path, clock=Clock(*T * 3)) as s:
        enrich(s, scan([match(name="a", groups=[adv(["GHSA-only-ghsa", LOG4J])])]), None)
    monkeypatch.setattr(epss, "load", fake_load)
    source = next(x for x in refresh.default_sources(tmp_path) if x.source == "epss")
    assert source.collect().coverage.source == "epss"
    assert seen["cves"] == {LOG4J}  # Ids that are not CVEs are not passed on. The request has none of them.
