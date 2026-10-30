import base64
import hashlib
import io
import json
import os
import stat
import sys
import zipfile
from pathlib import Path

import pytest

from watchtower_engine import cli
from watchtower_engine.discovery import discover
from watchtower_engine.feeds import osv_database as osvdb
from watchtower_engine.net import Downloaded
from watchtower_engine.scanners import osv
from watchtower_engine.scanners import release_pin as pin
from watchtower_engine.scanners.release_pin import Asset

FIX = Path(__file__).parent / "fixtures" / "osv"
NOW = "2026-10-29T12:00:00Z"
DAY_AGO = "2026-10-28T22:10:00Z"
NINE_DAYS_AGO = "2026-10-20T10:00:00Z"
NPM_URL = osvdb.URL.format(ecosystem="npm")
PYPI_URL = osvdb.URL.format(ecosystem="PyPI")


def zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("GHSA-0000-0000-0000.json", "{}")
    return buf.getvalue()


ZIP = zip_bytes()


class FakeDownload:
    """Answers by URL with (status, headers, body) or raises. Never uses the network."""

    def __init__(self, answers=None):
        self.answers = answers or {}
        self.calls = []

    def __call__(self, url, dest, headers):
        self.calls.append((url, dict(headers)))
        answer = self.answers.get(url, OSError("network is disabled in tests"))
        if isinstance(answer, BaseException):
            raise answer
        status, resp_headers, body = answer
        Path(dest).write_bytes(body)
        return Downloaded(status, resp_headers)


def fake_scanner(tmp_path, code=0, stdout=None):
    """A stand-in OSV-Scanner. It logs its call, refuses to run without --offline, prints the fixture."""
    log = tmp_path / "scanner-calls.jsonl"
    # The fixture has one npm result and one uv result. Copy each one for every matching lockfile.
    output = f"text = {stdout!r}" if stdout is not None else f"""fixture = json.load(open({str(FIX / 'scan-output.json')!r}))
npm_result, uv_result = fixture["results"]
results = [dict(npm_result, source={{"path": l, "type": "lockfile"}}) for l in locks if l.endswith("package-lock.json")]
results += [dict(uv_result, source={{"path": l, "type": "lockfile"}}) for l in locks if l.endswith("uv.lock")]
results.append(dict(uv_result, source={{"path": "/not/scanned/uv.lock", "type": "lockfile"}}))
text = json.dumps({{"results": results}})"""
    script = f"""#!{sys.executable} -I
import json, os, sys
args = sys.argv[1:]
with open({str(log)!r}, "a") as f:
    f.write(json.dumps({{"args": args, "env": dict(os.environ)}}) + "\\n")
if "--offline" not in args or not os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"):
    sys.exit(3)
locks = [args[i + 1] for i, a in enumerate(args) if a == "--lockfile"]
{output}
sys.stdout.write(text)
sys.exit({code})
""".encode()
    asset = Asset("osv-scanner_test", hashlib.sha256(script).hexdigest())
    return asset, script, log


def install(data, asset, script):
    path = pin.scanner_path(data, asset)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(script)
    return path


def calls(log):
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


@pytest.fixture
def home(tmp_path):
    return tmp_path / "home"


@pytest.fixture
def projects(home):
    root = home / "Projects"
    files = {
        "web": {"package.json": "{}", "package-lock.json": (FIX / "package-lock.json").read_text()},
        "api": {"pyproject.toml": "", "uv.lock": (FIX / "uv.lock").read_text()},
        "mono": {"app/package-lock.json": (FIX / "package-lock.json").read_text(), "Cargo.lock": ""},
        "notes": {"README.md": ""},
        "old": {"package-lock.json": "{}"},
    }
    for name, content in files.items():
        for rel, text in content.items():
            path = root / name / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
    return discover((str(root),), inactive={os.path.realpath(root / "old")}).projects


def seed_db(data, ecosystem, at):
    url = osvdb.URL.format(ecosystem=ecosystem)
    db = osvdb.update_database(ecosystem, data, FakeDownload({url: (200, {"etag": '"e1"'}, ZIP)}), lambda: at)
    assert db.fresh


def both_dbs(status=200):
    return {NPM_URL: (status, {"etag": '"e2"'}, ZIP), PYPI_URL: (status, {"etag": '"e2"'}, ZIP)}


def scan(data, projects, asset, download=None, now=NOW):
    return osv.collect(data, projects, asset=asset, download=download or FakeDownload(both_dbs()),
                       now=lambda: now)


def lockfile_rows(result):
    return {(p.name, lf.path): (lf.status, lf.note) for p in result.projects for lf in p.lockfiles}


# Network-disabled scan


def test_network_disabled_scan_completes(tmp_path, projects):
    data = tmp_path / "data"
    asset, script, log = fake_scanner(tmp_path, code=1)
    install(data, asset, script)
    seed_db(data, "npm", DAY_AGO)
    seed_db(data, "PyPI", DAY_AGO)
    result = scan(data, projects, asset, download=FakeDownload())  # every request fails
    assert result.coverage.state == "complete"
    assert result.coverage.error == "OSV database did not update. Results use the last copy."
    assert result.coverage.source_at == DAY_AGO
    assert len(result.matches) == 5
    assert len(calls(log)) == 1


def test_scanner_runs_offline_with_private_database_folder(tmp_path, projects):
    data = tmp_path / "data"
    asset, script, log = fake_scanner(tmp_path, code=1)
    install(data, asset, script)
    scan(data, projects, asset)
    (call,) = calls(log)
    args = call["args"]
    assert args[:5] == ["scan", "source", "--offline", "--format", "json"]
    locks = [args[i + 1] for i, a in enumerate(args) if a == "--lockfile"]
    assert sorted(os.path.relpath(l, tmp_path / "home" / "Projects") for l in locks) == [
        "api/uv.lock", "mono/app/package-lock.json", "web/package-lock.json",
    ]
    for flag in ("--download-offline-databases", "fix", "--call-analysis", "--experimental-call-analysis"):
        assert flag not in args
    assert call["env"]["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] == str(data / "osv")
    assert (data / "osv" / "osv-scalibr" / "npm" / "all.zip").is_file()
    assert (data / "osv" / "osv-scalibr" / "PyPI" / "all.zip").is_file()


# npm and uv advisories


def test_npm_and_uv_advisories_parse(tmp_path, projects):
    data = tmp_path / "data"
    asset, script, _ = fake_scanner(tmp_path, code=1)
    install(data, asset, script)
    result = scan(data, projects, asset)
    assert result.coverage.state == "complete" and result.coverage.error is None
    assert result.coverage.source_at == NOW
    got = sorted((m.project, m.lockfile, m.name, m.ecosystem, m.version) for m in result.matches)
    assert got == [
        ("api", "uv.lock", "jinja2", "PyPI", "3.1.2"),
        ("mono", "app/package-lock.json", "lodash", "npm", "4.17.20"),
        ("mono", "app/package-lock.json", "minimist", "npm", "1.2.5"),
        ("web", "package-lock.json", "lodash", "npm", "4.17.20"),
        ("web", "package-lock.json", "minimist", "npm", "1.2.5"),
    ]
    by_key = {(m.project, m.name): m for m in result.matches}
    lodash = by_key[("web", "lodash")]
    assert lodash.advisory_ids == ["GHSA-29mw-wpgm-hmr9", "GHSA-35jh-r3h4-6jhm"]
    assert lodash.aliases == ["CVE-2020-28500", "CVE-2021-23337"]
    assert lodash.dependency_path is None
    assert lodash.project_path == "~/Projects/web"
    jinja = by_key[("api", "jinja2")]
    assert jinja.advisory_ids == ["GHSA-h5c8-rqwp-cp95", "PYSEC-2024-1"]
    assert jinja.aliases == ["CVE-2024-22195"]
    assert set(lodash.to_dict()) == {
        "project", "project_path", "lockfile", "name", "ecosystem", "version",
        "dependency_path", "advisory_ids", "aliases", "advisories",
    }
    # Two advisory groups for lodash. PYSEC and GHSA are one group for jinja2.
    assert [g["ids"] for g in lodash.advisories] == [
        ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"], ["CVE-2020-28500", "GHSA-29mw-wpgm-hmr9"],
    ]
    assert [g["severity"] for g in lodash.advisories] == ["high", "medium"]
    assert [g["ids"] for g in jinja.advisories] == [["CVE-2024-22195", "GHSA-h5c8-rqwp-cp95", "PYSEC-2024-1"]]


def test_parse_output_reads_fixture_paths_exactly():
    text = (FIX / "scan-output.json").read_text().replace("__NPM_LOCK__", "/p/web/package-lock.json")
    text = text.replace("__UV_LOCK__", "/p/api/uv.lock")
    found = osv.parse_output(text)
    assert [r["name"] for r in found[os.path.realpath("/p/web/package-lock.json")]] == ["lodash", "minimist"]
    assert [r["name"] for r in found[os.path.realpath("/p/api/uv.lock")]] == ["jinja2"]


def test_lockfile_rows_and_project_notes(tmp_path, projects):
    data = tmp_path / "data"
    asset, script, _ = fake_scanner(tmp_path)
    install(data, asset, script)
    result = scan(data, projects, asset)
    assert lockfile_rows(result) == {
        ("api", "uv.lock"): ("scanned", None),
        ("mono", "Cargo.lock"): ("not_supported", "not supported yet"),
        ("mono", "app/package-lock.json"): ("scanned", None),
        ("web", "package-lock.json"): ("scanned", None),
    }
    notes = {p.name: p.note for p in result.projects}
    assert notes == {"api": None, "mono": None, "notes": "No lockfile. Watchtower scans lockfiles only.",
                     "web": None}
    assert "old" not in notes  # inactive projects are not scanned


def test_no_supported_lockfile_needs_no_scanner_or_download(tmp_path, home):
    root = home / "Projects"
    (root / "rusty").mkdir(parents=True)
    (root / "rusty" / "Cargo.lock").write_text("")
    download = FakeDownload()
    result = osv.collect(tmp_path / "data", discover((str(root),)).projects, asset=Asset("x", "0" * 64),
                         download=download, now=lambda: NOW)
    assert result.coverage.state == "complete"
    assert download.calls == []


# Checksum


def test_hash_mismatch_rejects_installed_scanner(tmp_path, projects):
    data = tmp_path / "data"
    asset, script, log = fake_scanner(tmp_path)
    path = install(data, asset, script + b"# tampered\n")
    download = FakeDownload(both_dbs())
    result = scan(data, projects, asset, download=download)
    assert result.coverage.state == "failed"
    assert result.coverage.error == "OSV-Scanner failed its checksum. Watchtower did not run it."
    assert calls(log) == []
    assert not path.exists()
    assert download.calls == []  # no database download for a scanner that cannot run
    assert {s for s, _ in lockfile_rows(result).values()} == {"not_scanned", "not_supported"}


def test_hash_mismatch_rejects_downloaded_scanner(tmp_path, projects):
    data = tmp_path / "data"
    asset, script, log = fake_scanner(tmp_path)
    download = FakeDownload({asset.url: (200, {}, script + b"# changed in transit\n")})
    result = scan(data, projects, asset, download=download)
    assert result.coverage.error == "OSV-Scanner failed its checksum. Watchtower did not run it."
    assert calls(log) == []
    assert list((data / "tools").iterdir()) == []


def test_scanner_changed_after_install_is_not_run(tmp_path, projects, monkeypatch):
    data = tmp_path / "data"
    asset, script, log = fake_scanner(tmp_path)
    path = install(data, asset, script)
    real_update = osvdb.update_database

    def update_then_tamper(*args, **kwargs):
        path.write_bytes(script + b"# swapped\n")
        return real_update(*args, **kwargs)

    monkeypatch.setattr(osv, "update_database", update_then_tamper)
    result = scan(data, projects, asset)
    assert result.coverage.error == "OSV-Scanner failed its checksum. Watchtower did not run it."
    assert calls(log) == []


def test_verified_download_is_installed_private_and_runs(tmp_path, projects):
    data = tmp_path / "data"
    asset, script, log = fake_scanner(tmp_path)
    download = FakeDownload({asset.url: (200, {}, script), **both_dbs()})
    result = scan(data, projects, asset, download=download)
    assert result.coverage.state == "complete"
    path = pin.scanner_path(data, asset)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(data / "tools").st_mode) == 0o700
    assert len(calls(log)) == 1


def test_scanner_download_failure_is_reported(tmp_path, projects):
    asset, _, log = fake_scanner(tmp_path)
    result = scan(tmp_path / "data", projects, asset, download=FakeDownload())
    assert (result.coverage.state, result.coverage.error) == (
        "failed", "OSV-Scanner is not downloaded. Projects were not scanned.")
    assert calls(log) == []


def test_pins_are_the_official_v2_7_0_digests():
    assert pin.OSV_SCANNER_VERSION == "2.7.0"
    assert pin.ASSETS["arm64"] == Asset(
        "osv-scanner_darwin_arm64", "d4926ef8da134332543be276dff157e4c170f99ad91fc48e89448a8816bdf70b")
    assert pin.ASSETS["x86_64"] == Asset(
        "osv-scanner_darwin_amd64", "e82c5df7ab0a42dff29a1cd0660711447b56b4c0483ff66ad8634df10fd81a45")
    assert pin.ASSETS["arm64"].url == (
        "https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_darwin_arm64")
    with pytest.raises(pin.ScannerUnavailable):
        pin.asset_for("ppc")


# Database states


def test_stale_database_shows_explicit_state(tmp_path, projects):
    data = tmp_path / "data"
    asset, script, log = fake_scanner(tmp_path, code=1)
    install(data, asset, script)
    seed_db(data, "npm", NINE_DAYS_AGO)
    seed_db(data, "PyPI", DAY_AGO)
    result = scan(data, projects, asset, download=FakeDownload())
    assert result.coverage.state == "stale"
    assert result.coverage.error == "OSV database is 9 days old. Results can miss new advisories."
    assert result.coverage.source_at == NINE_DAYS_AGO
    assert result.matches  # a stale database still scans
    assert len(calls(log)) == 1


def test_seven_days_is_not_stale_yet(tmp_path, projects):
    data = tmp_path / "data"
    asset, script, _ = fake_scanner(tmp_path)
    install(data, asset, script)
    seed_db(data, "npm", "2026-10-22T12:00:00Z")
    seed_db(data, "PyPI", "2026-10-22T12:00:00Z")
    result = scan(data, projects, asset, download=FakeDownload())
    assert result.coverage.state == "complete"


def test_new_download_clears_stale_state(tmp_path, projects):
    data = tmp_path / "data"
    asset, script, _ = fake_scanner(tmp_path)
    install(data, asset, script)
    seed_db(data, "npm", NINE_DAYS_AGO)
    seed_db(data, "PyPI", NINE_DAYS_AGO)
    result = scan(data, projects, asset)
    assert (result.coverage.state, result.coverage.error, result.coverage.source_at) == ("complete", None, NOW)


def test_missing_database_does_not_scan(tmp_path, projects):
    data = tmp_path / "data"
    asset, script, log = fake_scanner(tmp_path)
    install(data, asset, script)
    result = scan(data, projects, asset, download=FakeDownload())
    assert result.coverage.state == "failed"
    assert result.coverage.error == "OSV database is not downloaded. Projects were not scanned."
    assert calls(log) == []
    assert lockfile_rows(result)[("web", "package-lock.json")] == (
        "not_scanned", "OSV database is not downloaded")


def test_one_missing_database_is_partial(tmp_path, projects):
    data = tmp_path / "data"
    asset, script, log = fake_scanner(tmp_path, code=1)
    install(data, asset, script)
    result = scan(data, projects, asset, download=FakeDownload({NPM_URL: (200, {}, ZIP)}))
    assert result.coverage.state == "partial"
    assert result.coverage.error == "OSV database is not downloaded. Projects were not scanned."
    rows = lockfile_rows(result)
    assert rows[("web", "package-lock.json")] == ("scanned", None)
    assert rows[("api", "uv.lock")] == ("not_scanned", "OSV database is not downloaded")
    assert {m.ecosystem for m in result.matches} == {"npm"}
    (call,) = calls(log)
    assert not any(a.endswith("uv.lock") for a in call["args"])


def test_database_download_checks(tmp_path):
    good_md5 = base64.b64encode(hashlib.md5(ZIP).digest()).decode()
    db = osvdb.update_database("npm", tmp_path, FakeDownload(
        {NPM_URL: (200, {"x-goog-hash": f"crc32c=AAAA, md5={good_md5}", "etag": '"e1"'}, ZIP)}), lambda: NOW)
    assert db.fresh and db.sha256 == hashlib.sha256(ZIP).hexdigest()
    bad = osvdb.update_database("npm", tmp_path, FakeDownload(
        {NPM_URL: (200, {"x-goog-hash": "md5=" + base64.b64encode(b"x" * 16).decode()}, ZIP)}), lambda: NOW)
    assert not bad.fresh and bad.loaded and bad.fetched_at == NOW and bad.error == "OSV database did not update."
    notzip = osvdb.update_database("npm", tmp_path, FakeDownload({NPM_URL: (200, {}, b"<html>")}), lambda: NOW)
    assert not notzip.fresh
    assert (tmp_path / "osv" / "osv-scalibr" / "npm" / "all.zip").read_bytes() == ZIP  # old copy kept


def test_database_uses_etag_and_304(tmp_path):
    osvdb.update_database("PyPI", tmp_path, FakeDownload({PYPI_URL: (200, {"etag": '"v1"'}, ZIP)}), lambda: DAY_AGO)
    download = FakeDownload({PYPI_URL: (304, {"etag": '"v1"'}, b"")})
    db = osvdb.update_database("PyPI", tmp_path, download, lambda: NOW)
    assert download.calls == [(PYPI_URL, {"If-None-Match": '"v1"'})]
    assert db.fresh and db.fetched_at == NOW
    assert (tmp_path / "osv" / "osv-scalibr" / "PyPI" / "all.zip").read_bytes() == ZIP


def test_database_files_are_private(tmp_path):
    seed_db(tmp_path / "data", "npm", NOW)
    osv_root = tmp_path / "data" / "osv"
    for d in (tmp_path / "data", osv_root, osv_root / "osv-scalibr", osv_root / "osv-scalibr" / "npm"):
        assert stat.S_IMODE(os.stat(d).st_mode) == 0o700, d
    for f in (osv_root / "databases.json", osv_root / "osv-scalibr" / "npm" / "all.zip"):
        assert stat.S_IMODE(os.stat(f).st_mode) == 0o600, f
    assert sorted(p.name for p in (osv_root / "osv-scalibr" / "npm").iterdir()) == ["all.zip"]


def test_requests_name_only_the_ecosystem_or_release_asset(tmp_path, projects):
    asset, script, _ = fake_scanner(tmp_path)
    asset = Asset(asset.name, asset.sha256)
    download = FakeDownload({asset.url: (200, {}, script), **both_dbs()})
    scan(tmp_path / "data", projects, asset, download=download)
    urls = [url for url, _ in download.calls]
    assert urls == [asset.url, PYPI_URL, NPM_URL]
    for _, headers in download.calls:
        assert set(headers) <= {"If-None-Match"}


# Scanner output


@pytest.mark.parametrize("stdout", [
    "not json",
    "[]",
    '{"results": {}}',
    '{"results": [{"packages": []}]}',
    '{"results": [{"source": {"path": "/x"}, "packages": [{"package": {"name": "a"}}]}]}',
    '{"results": [{"source": {"path": "/x"}, "packages": [{"package": {"name": "a", "version": "1", '
    '"ecosystem": "npm"}, "vulnerabilities": [{"aliases": ["CVE-1"]}]}]}]}',
])
def test_unreadable_output_is_reported(tmp_path, projects, stdout):
    data = tmp_path / "data"
    asset, script, _ = fake_scanner(tmp_path, code=1, stdout=stdout)
    install(data, asset, script)
    result = scan(data, projects, asset)
    assert (result.coverage.state, result.coverage.error) == ("failed", "OSV-Scanner output was not readable.")
    assert result.matches == []


def test_no_packages_exit_128_is_complete(tmp_path, projects):
    data = tmp_path / "data"
    asset, script, _ = fake_scanner(tmp_path, code=128, stdout="")
    install(data, asset, script)
    result = scan(data, projects, asset)
    assert result.coverage.state == "complete" and result.matches == []


def test_scanner_error_exit_is_reported(tmp_path, projects):
    data = tmp_path / "data"
    asset, script, _ = fake_scanner(tmp_path, code=127, stdout="")
    install(data, asset, script)
    result = scan(data, projects, asset)
    assert (result.coverage.state, result.coverage.error) == ("failed", "OSV-Scanner stopped with an error.")


def test_output_for_unknown_paths_is_ignored(tmp_path, home):
    root = home / "Projects"
    (root / "api").mkdir(parents=True)
    (root / "api" / "uv.lock").write_text((FIX / "uv.lock").read_text())
    data = tmp_path / "data"
    asset, script, _ = fake_scanner(tmp_path, code=1)
    install(data, asset, script)
    result = scan(data, discover((str(root),)).projects, asset)
    assert [m.name for m in result.matches] == ["jinja2"]  # the fake also reports /not/scanned/uv.lock


# CLI


def test_cli_osv_prints_json(tmp_path, projects, monkeypatch, capsys):
    data = tmp_path / "data"
    asset, script, _ = fake_scanner(tmp_path, code=1)
    install(data, asset, script)
    real = osv.collect
    root = str(tmp_path / "home" / "Projects")
    monkeypatch.setattr(cli, "list_projects", lambda data_dir: discover((root,)))
    monkeypatch.setattr(osv, "collect", lambda data_dir, projects: real(
        data_dir, projects, asset=asset, download=FakeDownload(both_dbs()), now=lambda: NOW))
    assert cli.main(["--data-dir", str(data), "osv"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    out = json.loads(captured.out)
    assert set(out) == {"schema_version", "coverage", "databases", "projects", "matches"}
    assert out["coverage"]["source"] == "osv" and out["coverage"]["source_at"] == NOW
    assert [d["ecosystem"] for d in out["databases"]] == ["PyPI", "npm"]


# Bug #49: OSV-Scanner v2.7.0 reads <cache>/osv-scalibr/<ECOSYSTEM>/all.zip.

import pwd
import shutil

SCALIBR = Path("osv") / "osv-scalibr"
OLD = Path("osv") / "osv-scanner"


def test_new_database_is_saved_where_the_scanner_reads_it(tmp_path):
    data = tmp_path / "data"
    seed_db(data, "npm", NOW)
    assert (data / SCALIBR / "npm" / "all.zip").read_bytes() == ZIP
    assert not (data / OLD).exists()


def test_old_layout_moves_without_a_new_download(tmp_path):
    data = tmp_path / "data"
    old = data / OLD / "npm"
    old.mkdir(parents=True)
    (old / "all.zip").write_bytes(ZIP)
    (data / "osv" / "databases.json").write_text(json.dumps(
        {"npm": {"fetched_at": DAY_AGO, "sha256": hashlib.sha256(ZIP).hexdigest(), "etag": '"e1"'}}))
    download = FakeDownload()  # every request fails: the network is off
    db = osvdb.update_database("npm", data, download, lambda: NOW)
    assert db.loaded and db.fetched_at == DAY_AGO
    assert db.path == data / SCALIBR / "npm" / "all.zip"
    assert db.path.read_bytes() == ZIP
    assert not (data / OLD).exists()
    assert download.calls == [(NPM_URL, {"If-None-Match": '"e1"'})]  # the same conditional request as before


def test_old_copy_is_dropped_when_the_new_layout_already_has_one(tmp_path):
    data = tmp_path / "data"
    seed_db(data, "npm", DAY_AGO)
    stale = data / OLD / "npm"
    stale.mkdir(parents=True)
    (stale / "all.zip").write_bytes(b"old")
    db = osvdb.update_database("npm", data, FakeDownload(), lambda: NOW)
    assert db.loaded and db.path.read_bytes() == ZIP
    assert not (data / OLD).exists()


def test_scan_with_an_old_layout_database_finds_the_advisories(tmp_path, projects):
    data = tmp_path / "data"
    asset, script, log = fake_scanner(tmp_path, code=1)
    install(data, asset, script)
    for eco in ("npm", "PyPI"):
        seed_db(data, eco, DAY_AGO)
        (data / OLD / eco).mkdir(parents=True)
        os.replace(data / SCALIBR / eco / "all.zip", data / OLD / eco / "all.zip")  # as an older engine left it
    result = scan(data, projects, asset, download=FakeDownload())
    assert result.coverage.state == "complete" and result.matches
    assert (data / SCALIBR / "npm" / "all.zip").is_file()


def test_scanner_error_keeps_its_message_in_detail(tmp_path, projects):
    data = tmp_path / "data"
    msg = "could not load db for npm ecosystem: unable to fetch OSV database"
    asset, script, _ = fake_scanner(tmp_path, code=127, stdout="")
    script = script.replace(b"sys.stdout.write(text)", f"sys.stderr.write({msg!r})".encode())
    asset = Asset(asset.name, hashlib.sha256(script).hexdigest())
    install(data, asset, script)
    result = scan(data, projects, asset)
    assert (result.coverage.state, result.coverage.error) == ("failed", "OSV-Scanner stopped with an error.")
    assert msg in result.coverage.detail and "127" in result.coverage.detail


# The real pinned scanner, offline, on a one-advisory database. Skipped where the binary is absent (CI).

REAL_HOME = pwd.getpwuid(os.getuid()).pw_dir  # conftest points HOME at a temp folder
REAL_SCANNER = Path(REAL_HOME) / "Library/Application Support/Watchtower/tools" / (
    f"{pin.ASSETS['arm64'].name}-{pin.OSV_SCANNER_VERSION}")


def advisory_zip() -> bytes:
    advisory = {
        "schema_version": "1.6.0", "id": "GHSA-test-0049-wtwr", "modified": "2026-10-01T00:00:00Z",
        "published": "2026-10-01T00:00:00Z", "aliases": ["CVE-2099-0049"], "summary": "Test advisory for #49",
        "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("GHSA-test-0049-wtwr.json", json.dumps(advisory))
    return buf.getvalue()


@pytest.mark.skipif(not REAL_SCANNER.is_file() or os.uname().machine != "arm64",
                    reason="the pinned OSV-Scanner binary is not on this Mac")
def test_real_pinned_scanner_reads_the_saved_database_offline(tmp_path, home):
    asset = pin.ASSETS["arm64"]
    pin.verify(REAL_SCANNER, asset)  # run only the pinned, checksum-verified binary
    data = tmp_path / "data"
    tools = data / "tools"
    tools.mkdir(parents=True)
    shutil.copy2(REAL_SCANNER, pin.scanner_path(data, asset))
    root = home / "Projects"
    project = root / "web"
    project.mkdir(parents=True)
    (project / "package.json").write_text('{"name": "web", "dependencies": {"lodash": "4.17.20"}}')
    (project / "package-lock.json").write_text(json.dumps({
        "name": "web", "lockfileVersion": 3, "requires": True,
        "packages": {"": {"name": "web", "dependencies": {"lodash": "4.17.20"}},
                     # A real lockfile has `resolved`. Without it, the scanner does not match the package.
                     "node_modules/lodash": {
                         "version": "4.17.20",
                         "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                         "integrity": "sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA=="}}}))
    zipped = advisory_zip()
    download = FakeDownload({NPM_URL: (200, {"etag": '"t"'}, zipped)})
    result = osv.collect(data, discover((str(root),)).projects, asset=asset, download=download, now=lambda: NOW)
    assert result.coverage.state == "complete", result.coverage.detail
    assert [(m.name, m.version) for m in result.matches] == [("lodash", "4.17.20")]
    assert result.matches[0].advisory_ids == ["GHSA-test-0049-wtwr"]
