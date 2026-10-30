"""#56: GitHub advisory answers from the local OSV database, before any API request."""
import json
import zipfile

from watchtower_engine.feeds import github
from watchtower_engine.feeds.github import load

from test_github import FakeFetch, reply

DB_AT = "2026-10-29T07:00:00Z"
T1 = "2026-10-29T08:00:00Z"


def ghsa(n: int) -> str:
    return f"GHSA-aaaa-bbbb-{n:04d}"


def write_db(data_dir, ecosystem, entries, fetched_at=DB_AT):
    """An OSV `all.zip` in the layout of OSV-Scanner v2.7.0, and its retrieval time."""
    folder = data_dir / "osv" / "osv-scalibr" / ecosystem
    folder.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(folder / "all.zip", "w") as z:
        for entry in entries:
            z.writestr(f"{entry['id']}.json", json.dumps(entry))
    meta_path = data_dir / "osv" / "databases.json"
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    meta[ecosystem] = {"fetched_at": fetched_at, "sha256": "x", "etag": None}
    meta_path.write_text(json.dumps(meta))


def reviewed(ident, aliases=(), withdrawn=None):
    return {"id": ident, "aliases": list(aliases), "withdrawn": withdrawn, "published": "2026-01-01T00:00:00Z",
            "database_specific": {"github_reviewed": True, "severity": "HIGH"}}


def malicious(ident, aliases=(), withdrawn=None):
    return {"id": ident, "aliases": list(aliases), "withdrawn": withdrawn, "published": "2026-01-01T00:00:00Z"}


# Regression test (#56): about 600 findings left GitHub Advisories `partial` with `request limit`.


def test_hundreds_of_ids_in_the_local_database_finish_in_one_refresh_without_requests(tmp_path):
    write_db(tmp_path, "npm", [reviewed(ghsa(i), [f"CVE-2026-{i:05d}"]) for i in range(300)])
    write_db(tmp_path, "PyPI", [reviewed(ghsa(i)) for i in range(300, 600)])
    groups = [[ghsa(i), f"CVE-2026-{i:05d}"] for i in range(600)]
    fetch = FakeFetch()
    data = load(tmp_path, groups, fetch, lambda: T1)
    assert (data.state, data.reason) == ("complete", None)
    assert fetch.calls == []
    assert data.coverage().error is None
    verdict = data.assess(groups[0])
    assert verdict.withdrawn_known and verdict.malware_known
    assert verdict.malware_id is None and verdict.withdrawn_at is None


# What the local database answers


def test_a_withdrawn_local_advisory_is_withdrawn(tmp_path):
    write_db(tmp_path, "npm", [reviewed(ghsa(1), withdrawn="2026-02-17T21:40:20Z")])
    data = load(tmp_path, [[ghsa(1)]], FakeFetch(), lambda: T1)
    assert data.assess([ghsa(1)]).withdrawn_at == "2026-02-17T21:40:20Z"


def test_a_malicious_package_entry_marks_its_ghsa_alias_as_malware(tmp_path):
    # OSV-Scanner reports the MAL id with its GHSA alias. The GHSA id has no file of its own.
    write_db(tmp_path, "npm", [malicious("MAL-2026-10", [ghsa(7)])])
    fetch = FakeFetch()
    data = load(tmp_path, [["MAL-2026-10", ghsa(7)]], fetch, lambda: T1)
    assert fetch.calls == []
    verdict = data.assess(["MAL-2026-10", ghsa(7)])
    assert verdict.malware_id == ghsa(7) and verdict.malware_known
    assert verdict.withdrawn_known and verdict.withdrawn_at is None


def test_a_withdrawn_malicious_package_entry_is_not_malware(tmp_path):
    write_db(tmp_path, "npm", [malicious("MAL-2026-11", [ghsa(8)], withdrawn="2026-03-01T00:00:00Z")])
    data = load(tmp_path, [["MAL-2026-11", ghsa(8)]], FakeFetch(), lambda: T1)
    verdict = data.assess(["MAL-2026-11", ghsa(8)])
    assert verdict.malware_id is None and verdict.malware_known


def test_a_cve_only_finding_uses_the_local_advisory_that_names_the_cve(tmp_path):
    write_db(tmp_path, "PyPI", [reviewed(ghsa(9), ["CVE-2026-00009", "PYSEC-2026-9"])])
    fetch = FakeFetch()
    data = load(tmp_path, [["PYSEC-2026-9", "CVE-2026-00009"]], fetch, lambda: T1)
    assert fetch.calls == []
    assert data.assess(["PYSEC-2026-9", "CVE-2026-00009"]).withdrawn_known


def test_ghsa_ids_match_without_regard_to_case(tmp_path):
    write_db(tmp_path, "npm", [reviewed("GHSA-abcd-efgh-ijkl")])
    fetch = FakeFetch()
    load(tmp_path, [["GHSA-ABCD-EFGH-IJKL"]], fetch, lambda: T1)
    assert fetch.calls == []


# The API runs only for the rest


def test_only_ids_that_the_local_database_lacks_go_to_the_api(tmp_path):
    write_db(tmp_path, "npm", [reviewed(ghsa(1))])
    fetch = FakeFetch()
    data = load(tmp_path, [[ghsa(1)], [ghsa(2)], ["CVE-2026-99999"]], fetch, lambda: T1)
    assert sorted(fetch.asked()) == sorted([("reviewed", ghsa(2)), ("malware", ghsa(2)),
                                            ("reviewed", "CVE-2026-99999"), ("malware", "CVE-2026-99999")])
    assert data.state == "complete"


def test_local_answers_do_not_use_the_request_limit(tmp_path):
    write_db(tmp_path, "npm", [reviewed(ghsa(i)) for i in range(100)])
    groups = [[ghsa(i)] for i in range(105)]
    fetch = FakeFetch()
    data = load(tmp_path, groups, fetch, lambda: T1, max_requests=10)
    assert len(fetch.calls) == 10  # The 5 missing ids need 10 requests.
    assert data.state == "complete"


def test_the_local_answer_wins_over_an_old_api_answer(tmp_path):
    load(tmp_path, [[ghsa(3)]], FakeFetch({("reviewed", ghsa(3)): reply([{"ghsa_id": ghsa(3)}])}), lambda: T1)
    write_db(tmp_path, "npm", [reviewed(ghsa(3), withdrawn="2026-10-29T06:00:00Z")])
    data = load(tmp_path, [[ghsa(3)]], FakeFetch(), lambda: T1)
    assert data.assess([ghsa(3)]).withdrawn_at == "2026-10-29T06:00:00Z"


def test_the_age_of_local_answers_is_the_age_of_the_database(tmp_path):
    write_db(tmp_path, "npm", [reviewed(ghsa(1))], fetched_at="2026-10-28T07:00:00Z")
    data = load(tmp_path, [[ghsa(1)]], FakeFetch(), lambda: T1)
    assert data.fetched_at == "2026-10-28T07:00:00Z"


def test_no_local_database_means_the_api_as_before(tmp_path):
    fetch = FakeFetch()
    load(tmp_path, [[ghsa(1)]], fetch, lambda: T1)
    assert len(fetch.calls) == 2


def test_a_broken_local_database_is_ignored(tmp_path):
    folder = tmp_path / "osv" / "osv-scalibr" / "npm"
    folder.mkdir(parents=True)
    (folder / "all.zip").write_bytes(b"not a zip")
    fetch = FakeFetch()
    assert load(tmp_path, [[ghsa(1)]], fetch, lambda: T1).state == "complete"
    assert len(fetch.calls) == 2


def test_a_bad_local_entry_is_ignored(tmp_path):
    folder = tmp_path / "osv" / "osv-scalibr" / "npm"
    folder.mkdir(parents=True)
    with zipfile.ZipFile(folder / "all.zip", "w") as z:
        z.writestr(f"{ghsa(1)}.json", "{broken")
        z.writestr(f"{ghsa(2)}.json", json.dumps([1, 2]))
    fetch = FakeFetch()
    load(tmp_path, [[ghsa(1)], [ghsa(2)]], fetch, lambda: T1)
    assert len(fetch.calls) == 4


# Cache lifetime


def test_cached_api_answers_live_seven_days(tmp_path):
    assert github.TTL_HOURS >= 7 * 24
    load(tmp_path, [[ghsa(1)]], FakeFetch(), lambda: T1)
    fetch = FakeFetch()
    data = load(tmp_path, [[ghsa(1)]], fetch, lambda: "2026-11-05T07:59:00Z")  # 6 days 23 h later.
    assert fetch.calls == [] and data.state == "complete"
    later = FakeFetch()
    load(tmp_path, [[ghsa(1)]], later, lambda: "2026-11-05T08:00:00Z")  # 7 days later.
    assert len(later.calls) == 2


def test_a_later_refresh_finishes_the_ids_that_the_limit_left(tmp_path):
    groups = [[ghsa(i)] for i in range(30)]
    first = load(tmp_path, groups, FakeFetch(), lambda: T1)
    assert (first.state, first.reason) == ("partial", "request limit")
    second_fetch = FakeFetch()
    second = load(tmp_path, groups, second_fetch, lambda: "2026-10-30T08:00:00Z")
    assert len(second_fetch.calls) == 20  # Only the ids that the first refresh left.
    assert second.state == "complete"


# #66: a GHSA record with a MAL- alias can be malware on GitHub. Only the API answers for it.

MALWARE_GHSA = "GHSA-cxm3-wv7p-598c"  # A real case: reviewed in OSV, malware on GitHub.


def mal_aliased(ident, cve=None):
    aliases = ([cve] if cve else []) + ["MAL-2025-41436", "MAL-2025-41437"]
    return {**reviewed(ident, aliases, withdrawn="2026-07-28T12:42:28Z"),
            "database_specific": {"github_reviewed": True, "severity": "CRITICAL", "cwe_ids": ["CWE-506"]}}


def test_a_ghsa_record_with_a_mal_alias_goes_to_the_api_and_is_malware(tmp_path):
    write_db(tmp_path, "npm", [mal_aliased(MALWARE_GHSA, "CVE-2025-10894"), reviewed(ghsa(1))])
    fetch = FakeFetch({("malware", MALWARE_GHSA): reply([{"ghsa_id": MALWARE_GHSA, "type": "malware"}])})
    data = load(tmp_path, [[MALWARE_GHSA, "CVE-2025-10894"], [ghsa(1)]], fetch, lambda: T1)
    assert sorted(fetch.asked()) == [("malware", MALWARE_GHSA), ("reviewed", MALWARE_GHSA)]
    verdict = data.assess([MALWARE_GHSA, "CVE-2025-10894"])
    assert verdict.malware_id == MALWARE_GHSA and verdict.malware_known
    assert data.state == "complete"


def test_a_cve_whose_local_advisory_has_a_mal_alias_goes_to_the_api(tmp_path):
    write_db(tmp_path, "npm", [mal_aliased(ghsa(2), "CVE-2025-10894")])
    fetch = FakeFetch()
    load(tmp_path, [["PYSEC-2025-1", "CVE-2025-10894"]], fetch, lambda: T1)
    assert sorted(fetch.asked()) == [("malware", "CVE-2025-10894"), ("reviewed", "CVE-2025-10894")]


def test_the_cve_index_keeps_only_summary_fields(tmp_path):
    entry = reviewed(ghsa(3), ["CVE-2026-00003"])
    entry.update({"details": "x" * 5000, "affected": [{"package": {"name": "p"}, "ranges": []}],
                  "references": [{"url": "https://example.com"}] * 20})
    write_db(tmp_path, "npm", [entry])
    local = github.LocalAdvisories.open(tmp_path)
    try:
        (summary,) = local.by_cve()["CVE-2026-00003"]
    finally:
        local.close()
    assert set(summary) <= {"ghsa_id", "cve_id", "severity", "withdrawn_at", "published_at", "reviewed",
                            "malware_alias"}
    assert "details" not in summary and "affected" not in summary


def test_the_cve_index_memory_stays_small_for_large_records(tmp_path):
    import tracemalloc
    entries = [{**reviewed(ghsa(i), [f"CVE-2026-{i:05d}"]), "details": "d" * 8000,
                "affected": [{"package": {"name": f"p{i}"}, "versions": [f"1.{v}" for v in range(200)]}]}
               for i in range(600)]
    write_db(tmp_path, "npm", entries)
    local = github.LocalAdvisories.open(tmp_path)
    try:
        tracemalloc.start()
        before = tracemalloc.get_traced_memory()[0]
        index = local.by_cve()
        kept = tracemalloc.get_traced_memory()[0] - before
        tracemalloc.stop()
    finally:
        local.close()
    assert len(index) == 600
    assert kept < 2 * 1024 * 1024  # Full records would keep about 7 MB here.
