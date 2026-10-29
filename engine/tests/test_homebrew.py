import gzip
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from watchtower_engine import cli
from watchtower_engine.feeds import homebrew as feed
from watchtower_engine.feeds.homebrew import URLS, Response, load_catalog
from watchtower_engine.inventory import homebrew as hb
from watchtower_engine.inventory.homebrew import collect, version_key
from watchtower_engine.store import Store

from contract import Clock

FIX = Path(__file__).parent / "fixtures" / "homebrew"
BREW_INFO = (FIX / "brew-info.json").read_text()
CATALOG = {"formula": (FIX / "formula.json").read_bytes(), "cask": (FIX / "cask.json").read_bytes()}
T1, T2, T3 = "2026-10-29T08:00:00Z", "2026-10-29T11:00:00Z", "2026-10-29T12:00:00Z"


class FakeRun:
    """Stands in for subprocess.run. Never starts a process."""

    def __init__(self, stdout=BREW_INFO, returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, self.returncode, self.stdout, self.stderr)


class FakeFetch:
    """Answers by URL. A value can be a Response or an exception to raise."""

    def __init__(self, **by_kind):
        self.by_url = {URLS[k]: v for k, v in by_kind.items()}
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        answer = self.by_url[url]
        if isinstance(answer, BaseException):
            raise answer
        return answer


def ok(kind, etag=None):
    return Response(200, {"etag": etag} if etag else {}, CATALOG[kind])


def both_ok(**kw):
    return FakeFetch(formula=ok("formula", **kw), cask=ok("cask", **kw))


def run_collect(data_dir, fetch, now=T1, run=None):
    return collect(data_dir, brew="/fake/brew", run=run or FakeRun(), fetch=fetch, now=lambda: now)


def by_name(result):
    return {i.name: i for i in result.items}


# Complete refresh


def test_items_show_current_candidate_identity_and_source_age(tmp_path):
    result = run_collect(tmp_path, both_ok())
    assert result.coverage.state == "complete"
    assert result.coverage.error is None
    items = by_name(result)
    git = items["git"]
    assert (git.id, git.kind, git.state) == ("formula:git", "formula", "update_available")
    assert (git.installed_version, git.latest_version) == ("2.46.0", "2.47.1")
    assert git.source_at == T1
    assert git.origin is None and git.error is None and git.note is None
    for item in result.items:
        assert item.source == "homebrew"
        if item.state != "manual":
            assert item.source_at == T1, item.name


def test_states_for_every_formula_and_cask_case(tmp_path):
    items = by_name(run_collect(tmp_path, both_ok()))
    got = {name: (i.state, i.installed_version, i.latest_version) for name, i in items.items()}
    assert got == {
        "git": ("update_available", "2.46.0", "2.47.1"),  # linked keg, not the retained 2.45.0
        "openssl@3": ("up_to_date", "3.4.0_1", "3.4.0_1"),  # revision counts
        "node": ("pinned", "22.9.0", "23.1.0"),
        "widget": ("manual", "1.0", None),
        "oldtool": ("update_available", "1.0", "1.1"),  # found by its old name
        "neovim": ("unknown", "HEAD-1a2b3c4", "0.10.2"),
        "gone": ("unknown", "0.1", None),
        "local": ("manual", "2.0", None),
        "zed": ("unknown", "0.158.2", "0.159.0"),
        "fluff": ("update_available", "1.2,100", "1.3,200"),
        "steady": ("up_to_date", "5.0", "5.0"),
        "nightly": ("unknown", "latest", "latest"),
        "gizmo": ("manual", "3.0", None),
    }
    assert "removed" not in items  # a cask with no installed version


def test_notes_and_identity_match_design_text(tmp_path):
    items = by_name(run_collect(tmp_path, both_ok()))
    assert items["node"].note == "Pinned with brew pin. Watchtower does not update pinned items."
    assert items["zed"].note == "This app updates itself. The Homebrew version can be behind the app."
    assert items["widget"].note == "Watchtower cannot check tap acme/tools."
    assert (items["widget"].id, items["widget"].origin) == ("formula:acme/tools/widget", "acme/tools")
    assert (items["gizmo"].id, items["gizmo"].origin) == ("cask:acme/casks/gizmo", "acme/casks")
    assert items["gizmo"].note == "Watchtower cannot check tap acme/casks."
    assert items["local"].note == "Watchtower cannot check a package that has no tap."
    assert items["gone"].note == "The Homebrew catalog has no entry for gone."
    assert items["neovim"].note == "Watchtower cannot compare this version."
    assert items["steady"].note is None
    assert items["zed"].id == "cask:zed" and items["zed"].kind == "cask"


def test_sort_puts_update_available_first_then_name(tmp_path):
    names = [i.name for i in run_collect(tmp_path, both_ok()).items]
    assert names == [
        "fluff", "git", "oldtool",
        "gizmo", "gone", "local", "neovim", "nightly", "node", "openssl@3", "steady", "widget", "zed",
    ]


# Homebrew command


def test_brew_command_is_read_only_and_does_not_auto_update(tmp_path):
    run = FakeRun()
    run_collect(tmp_path, both_ok(), run=run)
    assert len(run.calls) == 1
    args, kwargs = run.calls[0]
    assert args == ["/fake/brew", "info", "--json=v2", "--installed"]
    assert kwargs["env"]["HOMEBREW_NO_AUTO_UPDATE"] == "1"
    assert kwargs["env"]["HOMEBREW_NO_ANALYTICS"] == "1"
    assert kwargs["timeout"] == hb.BREW_TIMEOUT_SECONDS
    assert kwargs["stdin"] == subprocess.DEVNULL


def test_brew_not_installed_is_not_run(tmp_path, monkeypatch):
    monkeypatch.setattr(hb, "find_brew", lambda: None)
    result = collect(tmp_path, run=FakeRun(), fetch=both_ok())
    assert (result.coverage.state, result.coverage.error) == ("not_run", "Homebrew is not installed.")
    assert result.items == []


@pytest.mark.parametrize("run", [
    FakeRun(returncode=1, stderr="Error: something broke"),
    FakeRun(stdout="not json"),
    FakeRun(stdout="[]"),
])
def test_brew_failure_is_failed_coverage(tmp_path, run):
    fetch = both_ok()
    result = run_collect(tmp_path, fetch, run=run)
    assert result.coverage.state == "failed"
    assert result.coverage.error == "Homebrew did not list the installed packages."
    assert result.coverage.detail
    assert result.items == []
    assert fetch.calls == []


def test_only_needed_catalogs_are_fetched(tmp_path):
    info = json.loads(BREW_INFO)
    info["casks"] = []
    fetch = both_ok()
    result = run_collect(tmp_path, fetch, run=FakeRun(stdout=json.dumps(info)))
    assert [url for url, _ in fetch.calls] == [URLS["formula"]]
    assert result.coverage.state == "complete"


# Catalog failures


def test_partial_catalog_failure_without_cache_marks_error(tmp_path):
    fetch = FakeFetch(formula=ok("formula"), cask=OSError("timed out"))
    result = run_collect(tmp_path, fetch)
    assert result.coverage.state == "partial"
    assert result.coverage.error == "Homebrew catalog did not load."
    assert "cask.json" in result.coverage.detail
    items = by_name(result)
    for name in ("zed", "fluff", "steady", "nightly"):
        assert items[name].state == "error", name
        assert items[name].error == "Homebrew catalog did not load."
        assert items[name].latest_version is None and items[name].source_at is None
    assert items["gizmo"].state == "manual"  # a tap item never needs the catalog
    assert items["git"].state == "update_available" and items["git"].error is None


def test_failed_catalog_uses_cache_and_keeps_old_badge_and_age(tmp_path):
    first = by_name(run_collect(tmp_path, both_ok(), now=T1))
    fetch = FakeFetch(formula=OSError("down"), cask=ok("cask"))
    result = run_collect(tmp_path, fetch, now=T2)
    assert result.coverage.state == "partial"
    items = by_name(result)
    for name in ("git", "node", "oldtool", "openssl@3"):
        assert items[name].state == first[name].state, name
        assert items[name].latest_version == first[name].latest_version
        assert items[name].source_at == T1
        assert items[name].error == "Homebrew catalog did not load."
    assert items["fluff"].source_at == T2 and items["fluff"].error is None


def test_all_catalogs_fail_without_cache_is_failed(tmp_path):
    result = run_collect(tmp_path, FakeFetch(formula=OSError("x"), cask=OSError("y")))
    assert result.coverage.state == "failed"
    assert result.coverage.error == "Homebrew catalog did not load."
    states = {i.state for i in result.items}
    assert states == {"error", "manual"}


@pytest.mark.parametrize("bad", [
    Response(500, {}, b"oops"),
    Response(200, {}, b"{not json"),
    Response(200, {}, b'{"a": 1}'),
])
def test_bad_catalog_response_is_a_failure(tmp_path, bad):
    catalog = load_catalog("cask", tmp_path, FakeFetch(cask=bad), now=lambda: T1)
    assert not catalog.loaded and catalog.error == "Homebrew catalog did not load."


def test_oversize_catalog_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(feed, "MAX_BYTES", 100)
    big = gzip.compress(b"[" + b"1," * 500 + b"1]")
    catalog = load_catalog("cask", tmp_path, FakeFetch(cask=Response(200, {"content-encoding": "gzip"}, big)))
    assert not catalog.loaded


def test_gzip_catalog_is_read(tmp_path):
    body = gzip.compress(CATALOG["cask"])
    fetch = FakeFetch(cask=Response(200, {"content-encoding": "gzip"}, body))
    catalog = load_catalog("cask", tmp_path, fetch, now=lambda: T1)
    assert catalog.fresh and catalog.lookup("zed")["version"] == "0.159.0"
    assert fetch.calls[0][1]["Accept-Encoding"] == "gzip"


def test_unchanged_catalog_uses_etag_and_counts_as_fresh(tmp_path):
    run_collect(tmp_path, both_ok(etag='"v1"'), now=T1)
    not_modified = Response(304, {"etag": '"v1"'}, b"")
    fetch = FakeFetch(formula=not_modified, cask=not_modified)
    result = run_collect(tmp_path, fetch, now=T3)
    assert all(h["If-None-Match"] == '"v1"' for _, h in fetch.calls)
    assert result.coverage.state == "complete"
    assert by_name(result)["git"].latest_version == "2.47.1"
    assert by_name(result)["git"].source_at == T3


def test_requests_send_no_inventory(tmp_path):
    fetch = both_ok()
    run_collect(tmp_path, fetch)
    for url, headers in fetch.calls:
        assert url in URLS.values() and "?" not in url
        assert set(headers) <= {"User-Agent", "Accept-Encoding", "If-None-Match"}


def test_cache_is_private(tmp_path):
    data = tmp_path / "data"
    run_collect(data, both_ok())
    for path in (data, data / "cache", data / "cache" / "homebrew"):
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o700, path
    files = list((data / "cache" / "homebrew").iterdir())
    assert sorted(f.name for f in files) == ["cask.json", "formula.json"]
    for f in files:
        assert stat.S_IMODE(os.stat(f).st_mode) == 0o600, f


def test_corrupt_cache_is_ignored(tmp_path):
    run_collect(tmp_path, both_ok())
    (tmp_path / "cache" / "homebrew" / "cask.json").write_text("{broken")
    catalog = load_catalog("cask", tmp_path, FakeFetch(cask=OSError("down")))
    assert not catalog.loaded


# Versions


@pytest.mark.parametrize("older,newer", [
    ("2.46.0", "2.47.1"),
    ("2.9", "2.10"),
    ("3.4.0", "3.4.0_1"),
    ("1.2,100", "1.3,200"),
    ("1.0", "1.0.1"),
])
def test_version_order(older, newer):
    assert version_key(older) < version_key(newer)


def test_installed_newer_than_catalog_is_up_to_date(tmp_path):
    info = json.loads(BREW_INFO)
    info["formulae"][0]["installed"] = [{"version": "2.48.0"}]
    info["formulae"][0]["linked_keg"] = "2.48.0"
    items = by_name(run_collect(tmp_path, both_ok(), run=FakeRun(stdout=json.dumps(info))))
    assert items["git"].state == "up_to_date"


# Store and CLI


def test_result_round_trips_through_store(tmp_path):
    result = run_collect(tmp_path / "cache-home", both_ok())
    with Store(tmp_path / "data", clock=Clock(T1, T2)) as s:
        r = s.begin_refresh()
        s.finish_refresh(r.id, "complete", coverage=[result.coverage], items=result.items)
        saved = {i.id: i for i in s.items()}
    for item in result.items:
        stored = saved[item.id]
        item.seen_at = T2
        assert stored == item


def test_cli_homebrew_prints_coverage_and_items(tmp_path, monkeypatch, capsys):
    real = hb.collect
    monkeypatch.setattr(
        hb, "collect",
        lambda data_dir: real(data_dir, brew="/fake/brew", run=FakeRun(), fetch=both_ok(), now=lambda: T1),
    )
    assert cli.main(["--data-dir", str(tmp_path), "homebrew"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    out = json.loads(captured.out)
    assert set(out) == {"schema_version", "coverage", "items"}
    assert out["coverage"]["source"] == "homebrew" and out["coverage"]["state"] == "complete"
    assert out["items"][0]["state"] == "update_available"
    assert {"origin", "source_at", "note"} <= set(out["items"][0])
