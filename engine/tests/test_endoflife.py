"""Vendor support status from endoflife.date (#59). Real API answers (fixtures/endoflife), no network.
The tests set the clock: the states do not depend on the day that they run."""
import json
import os
import stat
import urllib.error
from datetime import date
from pathlib import Path

import pytest

from watchtower_engine import refresh
from watchtower_engine.feeds import endoflife
from watchtower_engine.feeds.endoflife import Cycle
from watchtower_engine.feeds.homebrew import Response
from watchtower_engine.inventory import macos, runtimes
from watchtower_engine.inventory.homebrew import SourceResult
from watchtower_engine.models import CoverageRecord, ItemRecord
from watchtower_engine.refresh import run_refresh
from watchtower_engine.store import Store

FIX = Path(__file__).parent / "fixtures" / "endoflife"
T1, T2, T3 = "2026-10-30T08:00:00Z", "2026-10-31T09:00:00Z", "2027-02-15T08:00:00Z"


class FakeFetch:
    """Answers with the real fixtures. A product without a file is a 404, like the site."""

    def __init__(self, fail=()):
        self.calls, self.fail = [], set(fail)

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        slug = url.rsplit("/", 2)[-2]
        if slug in self.fail:
            raise OSError("down")
        path = FIX / f"{slug}.json"
        if not path.exists():
            return Response(404, {}, b"<html>Page not Found</html>")
        return Response(200, {}, path.read_bytes())

    def products(self):
        return [u.rsplit("/", 2)[-2] for u, _ in self.calls]


def runtime(name, version, product, path="/Users/me/.nvm/versions/node/v22", kind="runtime"):
    attributes = {"product": product, "path": path, "family": product}
    if product != "java":
        attributes["eolProduct"] = product
    return ItemRecord(id=f"{kind}:test:{name}{version}", source="runtimes", name=name, state="manual", kind=kind,
                      installed_version=version, origin="nvm", note="Watchtower does not check updates for this install yet.",
                      attributes=attributes)


def mac(version="15.7.9"):
    return ItemRecord(id="macos", source="macos", name="macOS", state="manual", kind="os", installed_version=version,
                      note="Update macOS in System Settings.", attributes={"build": "24G830"})


def run(items, tmp_path, fetch=None, now=T1):
    fetch = fetch or FakeFetch()
    return endoflife.check(items, tmp_path / "data", fetch, lambda: now), fetch


def attrs(item):
    return {k: v for k, v in item.attributes.items() if k in endoflife.ATTRIBUTE_KEYS}  # `eolProduct` is the input.


# States, from the real answers


def test_supported_security_only_and_end_of_life_of_real_node_and_python_lines(tmp_path):
    items = [runtime("Node.js", "26.1.0", "nodejs"), runtime("Node.js", "24.9.0", "nodejs"), runtime("Node.js", "25.2.0", "nodejs"),
             runtime("Python", "3.14.0", "python"), runtime("Python", "3.13.7", "python"), runtime("Python", "3.10.14", "python")]
    coverage, _ = run(items, tmp_path)
    assert coverage.state == "complete" and coverage.source_at == T1
    got = {(i.name, i.installed_version): attrs(i) for i in items}
    assert got[("Node.js", "26.1.0")] == {"eolState": "supported", "eolCycle": "26", "eolEnd": "2029-04-30", "eolChecked": T1}
    assert got[("Node.js", "24.9.0")]["eolState"] == "security_only" and got[("Node.js", "24.9.0")]["eolEnd"] == "2028-04-30"
    assert got[("Node.js", "25.2.0")]["eolState"] == "end_of_life" and got[("Node.js", "25.2.0")]["eolEnd"] == "2026-06-01"
    assert got[("Python", "3.14.0")]["eolState"] == "supported" and got[("Python", "3.14.0")]["eolCycle"] == "3.14"
    assert got[("Python", "3.13.7")]["eolState"] == "security_only" and got[("Python", "3.13.7")]["eolCycle"] == "3.13"
    assert got[("Python", "3.10.14")]["eolState"] == "end_of_life" and got[("Python", "3.10.14")]["eolEnd"] == "2026-10-01"


def test_macos_has_a_release_line_and_no_end_date_when_the_site_has_none(tmp_path):
    current, old = mac("15.7.9"), mac("14.8.1")
    run([current], tmp_path)
    assert attrs(current) == {"eolState": "supported", "eolCycle": "15", "eolChecked": T1}  # No `eolEnd`: not announced.
    run([old], tmp_path / "other")
    assert attrs(old)["eolState"] == "end_of_life" and attrs(old)["eolEnd"] == "2026-09-14"


def test_a_rapid_security_response_suffix_does_not_change_the_line(tmp_path):
    item = mac("15.1 (a)")
    run([item], tmp_path)
    assert attrs(item)["eolCycle"] == "15"


def test_the_ends_soon_window_is_90_days(tmp_path):
    items = [runtime("Ruby", "3.3.6", "ruby")]
    run(items, tmp_path, now=T3)  # 2027-02-15: Ruby 3.3 ends on 2027-03-31, 44 days later.
    assert attrs(items[0])["eolState"] == "ends_soon" and attrs(items[0])["eolEnd"] == "2027-03-31"
    today = date(2027, 1, 1)
    edge = lambda days: endoflife.status(Cycle("1", eol_from=date.fromordinal(today.toordinal() + days).isoformat()), today).state
    assert (edge(89), edge(90), edge(91)) == ("ends_soon", "ends_soon", "supported")
    assert (edge(1), edge(0), edge(-1)) == ("ends_soon", "end_of_life", "end_of_life")  # The end date itself is over.


def test_a_line_in_the_security_phase_shows_security_only_before_ends_soon(tmp_path):
    item = runtime("Node.js", "22.9.0", "nodejs")  # Active support of Node 22 ended on 2025-10-21.
    run([item], tmp_path, now=T3)
    assert attrs(item)["eolState"] == "security_only" and attrs(item)["eolEnd"] == "2027-04-30"


def test_a_security_only_line_stays_security_only_when_it_ends_soon():
    cycle = Cycle("8", eol_from="2027-01-20", eoas_from="2026-01-01")
    assert endoflife.status(cycle, date(2027, 1, 1)).state == "security_only"


def test_a_date_decides_and_the_flag_decides_only_without_a_date():
    old_data = Cycle("5", eol_from="2026-01-01", is_eol=False)  # Cached data ages: the flag was false when it was read.
    assert endoflife.status(old_data, date(2026, 6, 1)).state == "end_of_life"
    assert endoflife.status(Cycle("5", is_eol=True), date(2026, 6, 1)) == endoflife.Status("end_of_life", None, "5")
    assert endoflife.status(Cycle("5", is_eoas=True), date(2026, 6, 1)).state == "security_only"
    assert endoflife.status(Cycle("5"), date(2026, 6, 1)) == endoflife.Status("supported", None, "5")


@pytest.mark.parametrize("version,line", [("3.12.11", "3.12"), ("3.12", "3.12"), ("v22.9.0", "22"), ("3.13.0rc1", "3.13"),
                                          ("22.9.0-nightly", "22")])
def test_the_installed_version_picks_the_longest_line_that_starts_it(version, line):
    cycles = [Cycle("3.1"), Cycle("3.12"), Cycle("3.13"), Cycle("3"), Cycle("22"), Cycle("2")]
    assert endoflife.find_cycle(cycles, version).name == line


@pytest.mark.parametrize("version", ["3.1.5x", "latest", "system", "", "31.0.0", "4"])
def test_a_version_without_a_line_has_none(version):
    assert endoflife.find_cycle([Cycle("3.12"), Cycle("3.13"), Cycle("22")], version) is None


def test_a_line_that_the_site_does_not_list_is_not_known(tmp_path):
    item = runtime("Node.js", "31.0.0", "nodejs")
    coverage, _ = run([item], tmp_path)
    assert attrs(item) == {"eolState": "unknown", "eolChecked": T1} and coverage.state == "complete"


# Only the product name leaves this Mac


def test_the_request_holds_the_product_name_and_nothing_else(tmp_path):
    items = [runtime("Node.js", "22.9.0", "nodejs", path="/Users/me/Real/secret-client/.nvm/v22"),
             runtime("Python", "3.12.11", "python"), runtime("Python", "3.11.13", "python"), mac()]
    items[0].project = "secret-client"
    _, fetch = run(items, tmp_path)
    assert sorted(fetch.products()) == ["macos", "nodejs", "python"]  # One request for each product, not for each install.
    for url, headers in fetch.calls:
        assert url == f"https://endoflife.date/api/v1/products/{url.rsplit('/', 2)[-2]}/"
        assert set(headers) == {"User-Agent", "Accept"}
        text = url + json.dumps(headers)
        assert not any(bit in text for bit in ("secret", "/Users", "22.9", "3.12", "15.7", "24G830"))


def test_a_product_name_that_is_not_a_name_is_never_requested(tmp_path):
    bad = runtime("Evil", "1.0.0", "x")
    bad.attributes["eolProduct"] = "../../etc/passwd?x=1"
    _, fetch = run([bad], tmp_path)
    assert fetch.calls == [] and attrs(bad)["eolState"] == "unknown"


def test_a_runtime_with_no_product_is_unknown_and_makes_no_request(tmp_path):
    java = runtime("Java", "21.0.4", "java")
    coverage, fetch = run([java], tmp_path)
    assert fetch.calls == [] and attrs(java) == {"eolState": "unknown"} and coverage.state == "complete"


def test_sdks_extensions_and_other_items_get_no_support_attribute(tmp_path):
    sdk = runtime("macOS SDK", "15.2", "sdk", kind="sdk")
    sdk.attributes["eolProduct"] = "macos"
    ext = runtime("ms-python.python", "2024.20.0", "ext", kind="extension")
    app = ItemRecord(id="com.x", source="apps", name="X", state="up_to_date", installed_version="1.0")
    _, fetch = run([sdk, ext, app, mac()], tmp_path)
    assert fetch.products() == ["macos"]
    assert not any(k in endoflife.ATTRIBUTE_KEYS for i in (sdk, ext, app) for k in (i.attributes or {}))


def test_the_update_state_and_the_note_are_not_changed(tmp_path):
    item = runtime("Node.js", "25.2.0", "nodejs")
    before = (item.state, item.note, item.error, item.latest_version)
    run([item], tmp_path)
    assert (item.state, item.note, item.error, item.latest_version) == before  # An EOL runtime is not `Update available`.


def test_old_eol_keys_are_replaced_not_kept(tmp_path):
    item = runtime("Node.js", "26.1.0", "nodejs")
    item.attributes.update({"eolState": "end_of_life", "eolEnd": "1999-01-01", "eolError": "old"})
    run([item], tmp_path)
    assert attrs(item) == {"eolState": "supported", "eolCycle": "26", "eolEnd": "2029-04-30", "eolChecked": T1}


# Errors and unknown products


def test_a_failed_request_keeps_the_earlier_answer_and_says_so(tmp_path):
    run([runtime("Node.js", "24.9.0", "nodejs"), mac()], tmp_path, now=T1)
    item, laptop = runtime("Node.js", "24.9.0", "nodejs"), mac()
    coverage, _ = run([item, laptop], tmp_path, FakeFetch(fail={"nodejs"}), now=T2)
    assert attrs(item) == {"eolState": "security_only", "eolCycle": "24", "eolEnd": "2028-04-30", "eolChecked": T1,
                           "eolError": "endoflife.date did not respond."}  # The earlier label and the age of the data.
    assert attrs(laptop)["eolChecked"] == T2 and "eolError" not in attrs(laptop)  # Another product is not affected.
    assert (coverage.state, coverage.error, coverage.source_at) == (
        "partial", "endoflife.date did not respond. Watchtower used the last copy.", T1)
    assert "GET https://endoflife.date/api/v1/products/nodejs/" in coverage.detail


def test_a_failure_with_no_copy_does_not_claim_that_a_copy_was_used(tmp_path):
    coverage, _ = run([runtime("Node.js", "26.1.0", "nodejs"), mac()], tmp_path, FakeFetch(fail={"nodejs"}))
    assert (coverage.state, coverage.error) == ("partial", "endoflife.date did not respond.")  # macOS answered.
    assert coverage.source_at == T1


def test_the_earlier_data_ages_with_the_calendar(tmp_path):
    first = runtime("Ruby", "3.3.6", "ruby")
    run([first], tmp_path, now=T1)
    assert attrs(first)["eolState"] == "supported"  # Read on 2026-10-30.
    item = runtime("Ruby", "3.3.6", "ruby")
    run([item], tmp_path, FakeFetch(fail={"ruby"}), now=T3)  # 2027-02-15, API down: the date decides.
    assert attrs(item)["eolState"] == "ends_soon" and attrs(item)["eolChecked"] == T1


def test_a_failed_request_with_no_earlier_answer_is_unknown_with_the_error(tmp_path):
    item = runtime("Node.js", "22.9.0", "nodejs")
    coverage, _ = run([item], tmp_path, FakeFetch(fail={"nodejs"}))
    assert attrs(item) == {"eolState": "unknown", "eolError": "endoflife.date did not respond."}
    assert (coverage.state, coverage.error) == ("failed", "endoflife.date did not respond.")


@pytest.mark.parametrize("body", [b"not json", b"[]", b'{"result": []}', b'{"result": {"releases": []}}',
                                  b'{"result": {"releases": [1, "x", {"name": "<b>"}]}}', b"x" * (endoflife.MAX_BYTES + 1)])
def test_a_bad_answer_is_a_failure_and_keeps_the_earlier_data(tmp_path, body):
    run([runtime("Node.js", "26.1.0", "nodejs")], tmp_path, now=T1)
    item = runtime("Node.js", "26.1.0", "nodejs")
    bad = lambda url, headers: Response(200, {}, body)
    coverage, _ = run([item], tmp_path, bad, now=T2)
    assert attrs(item)["eolState"] == "supported" and attrs(item)["eolChecked"] == T1 and "eolError" in attrs(item)
    assert coverage.state == "partial"


def test_an_http_error_status_is_a_failure(tmp_path):
    item = runtime("Node.js", "26.1.0", "nodejs")
    coverage, _ = run([item], tmp_path, lambda u, h: Response(503, {}, b""))
    assert coverage.state == "failed" and attrs(item)["eolError"] == endoflife.ERROR_FAILED


def test_a_product_with_no_entry_is_unknown_and_the_coverage_says_which(tmp_path):
    item = runtime("Zed", "1.2.3", "zed")
    coverage, fetch = run([item, mac()], tmp_path)
    assert attrs(item) == {"eolState": "unknown"}  # No error: the site answered.
    assert coverage.state == "complete" and coverage.detail == "No entry at endoflife.date for: zed."
    assert fetch.products() == ["macos", "zed"]


def test_a_404_that_the_http_client_raises_is_no_entry_too(tmp_path):
    def gone(url, headers):
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
    item = runtime("Zed", "1.2.3", "zed")
    coverage, _ = run([item], tmp_path, gone)
    assert attrs(item) == {"eolState": "unknown"} and coverage.state == "complete"


def test_a_product_that_the_site_dropped_does_not_keep_an_old_copy(tmp_path):
    run([runtime("Node.js", "26.1.0", "nodejs")], tmp_path, now=T1)
    gone = lambda url, headers: Response(404, {}, b"")
    item = runtime("Node.js", "26.1.0", "nodejs")
    run([item], tmp_path, gone, now=T2)
    assert attrs(item) == {"eolState": "unknown"}


def test_a_hostile_answer_is_read_for_known_fields_only():
    body = json.dumps({"result": {"releases": [
        {"name": "9", "eolFrom": "not a date", "isEol": "yes", "isEoas": 1, "eoasFrom": "2026-13-45", "x": "<script>"},
        {"name": "../8", "eolFrom": "2026-01-01"}, {"name": "7", "eolFrom": "2026-01-01", "isEol": True}]}}).encode()
    nine, seven = endoflife.parse(body)
    assert (nine.eol_from, nine.is_eol, nine.is_eoas, nine.eoas_from) == (None, False, False, None)  # Only `true` counts.
    assert (seven.name, seven.eol_from, seven.is_eol) == ("7", "2026-01-01", True)


# The cache


def test_the_cache_is_private_and_holds_dates_only(tmp_path):
    run([runtime("Node.js", "26.1.0", "nodejs")], tmp_path)
    folder = tmp_path / "data" / "cache" / "endoflife"
    assert stat.S_IMODE(os.stat(folder).st_mode) == 0o700
    assert {stat.S_IMODE(os.stat(f).st_mode) for f in folder.iterdir()} == {0o600}
    saved = json.loads((folder / "products.json").read_text())
    assert set(saved["products"]) == {"nodejs"} and "/Users" not in json.dumps(saved)


def test_a_cache_of_another_format_is_ignored(tmp_path):
    folder = tmp_path / "data" / "cache" / "endoflife"
    folder.mkdir(parents=True)
    (folder / "products.json").write_text(json.dumps({"format": 99, "products": {"nodejs": {"fetched_at": T1, "cycles": []}}}))
    item = runtime("Node.js", "26.1.0", "nodejs")
    coverage, _ = run([item], tmp_path, FakeFetch(fail={"nodejs"}))
    assert attrs(item) == {"eolState": "unknown", "eolError": endoflife.ERROR_FAILED} and coverage.state == "failed"


# Refresh


def test_refresh_runs_endoflife_after_sofa_and_the_support_shows_in_the_saved_state(tmp_path, monkeypatch):
    monkeypatch.setattr(macos, "collect", lambda: SourceResult(CoverageRecord("macos", "macOS", "complete"), [mac()]))
    monkeypatch.setattr(runtimes, "collect", lambda: SourceResult(CoverageRecord("runtimes", "Runtimes", "complete"),
                                                                  [runtime("Node.js", "25.2.0", "nodejs")]))
    real = endoflife.check
    monkeypatch.setattr(endoflife, "check", lambda items, data_dir: real(items, data_dir, FakeFetch(), lambda: T1))
    sources = [s for s in refresh.default_sources(tmp_path) if s.source in ("macos", "runtimes", "endoflife")]
    assert [s.source for s in sources] == ["macos", "runtimes", "endoflife"]
    with Store(tmp_path) as store:
        state = run_refresh(store, sources)
    assert {c["source"]: (c["state"], c["label"]) for c in state["coverage"]}["endoflife"] == ("complete", "endoflife.date")
    items = {i["id"]: i for i in state["items"]}
    assert items["macos"]["attributes"]["eolState"] == "supported"
    node = next(i for i in state["items"] if i["source"] == "runtimes")
    assert node["attributes"]["eolState"] == "end_of_life" and node["state"] == "manual"


def test_a_failed_endoflife_source_does_not_stop_the_refresh(tmp_path, monkeypatch):
    monkeypatch.setattr(macos, "collect", lambda: SourceResult(CoverageRecord("macos", "macOS", "complete"), [mac()]))
    monkeypatch.setattr(runtimes, "collect", lambda: SourceResult(CoverageRecord("runtimes", "Runtimes", "complete"), []))
    real = endoflife.check
    monkeypatch.setattr(endoflife, "check", lambda items, data_dir: real(items, data_dir, FakeFetch(fail={"macos"}), lambda: T1))
    sources = [s for s in refresh.default_sources(tmp_path) if s.source in ("macos", "runtimes", "endoflife")]
    with Store(tmp_path) as store:
        state = run_refresh(store, sources)
    assert {c["source"]: c["state"] for c in state["coverage"]} == {"macos": "complete", "runtimes": "complete", "endoflife": "failed"}
    assert state["refresh"]["status"] == "partial"
