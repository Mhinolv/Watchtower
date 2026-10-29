import os
import stat

import pytest

from watchtower_engine.models import (
    CoverageRecord as C,
    ItemRecord as I,
    RefreshRecord,
    owner_error,
)
from watchtower_engine.store import Store, StoreError, default_data_dir

from contract import Clock, build_partial_state


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def clock(n=20):
    return Clock(*[f"2026-10-29T10:{m:02d}:00Z" for m in range(n)])


# Data folder and file modes


def test_data_dir_is_0700_and_every_file_is_0600(tmp_path):
    old = os.umask(0o022)
    try:
        data = tmp_path / "data"
        build_partial_state(data).close()
    finally:
        os.umask(old)
    assert mode(data) == 0o700
    files = list(data.iterdir())
    assert files
    for f in files:
        assert mode(f) == 0o600, f.name


def test_existing_loose_modes_are_tightened(tmp_path):
    data = tmp_path / "data"
    data.mkdir(mode=0o755)
    os.chmod(data, 0o755)
    db = data / "watchtower.sqlite3"
    db.touch()
    os.chmod(db, 0o644)
    Store(data).close()
    assert mode(data) == 0o700
    assert mode(db) == 0o600


def test_default_data_dir_is_application_support(tmp_path):
    assert default_data_dir() == tmp_path / "home" / "Library" / "Application Support" / "Watchtower"


def test_env_overrides_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("WATCHTOWER_DATA_DIR", str(tmp_path / "x"))
    assert default_data_dir() == tmp_path / "x"


# Round trip


def test_records_round_trip_through_sqlite(tmp_path):
    data = tmp_path / "data"
    with Store(data, clock=clock()) as s:
        r = s.begin_refresh()
        assert r == RefreshRecord(id=r.id, status="running", started_at="2026-10-29T10:00:00Z")
        s.finish_refresh(
            r.id,
            "complete",
            coverage=[C("homebrew", "Homebrew", "complete")],
            items=[I("formula:git", "homebrew", "git", "update_available", kind="formula",
                     installed_version="2.46.0", latest_version="2.47.1", project=None,
                     detail="d")],
        )
    with Store(data) as s:
        assert s.latest_refresh() == RefreshRecord(
            id=r.id,
            status="complete",
            started_at="2026-10-29T10:00:00Z",
            finished_at="2026-10-29T10:01:00Z",
            last_complete_at="2026-10-29T10:01:00Z",
        )
        assert s.coverage() == [
            C("homebrew", "Homebrew", "complete", last_success_at="2026-10-29T10:01:00Z")
        ]
        assert s.items() == [
            I("formula:git", "homebrew", "git", "update_available", kind="formula",
              installed_version="2.46.0", latest_version="2.47.1",
              seen_at="2026-10-29T10:01:00Z", detail="d")
        ]


def test_partial_refresh_round_trips_and_keeps_last_complete_at(tmp_path):
    data = tmp_path / "data"
    build_partial_state(data).close()
    with Store(data) as s:
        r = s.latest_refresh()
        assert r.status == "partial"
        assert r.finished_at == "2026-10-29T08:31:45Z"
        assert r.last_complete_at == "2026-10-28T09:02:10Z"
        cov = {c.source: c for c in s.coverage()}
        assert cov["homebrew"].state == "complete"
        assert cov["homebrew"].last_success_at == "2026-10-29T08:31:45Z"
        assert cov["apps"].state == "failed"
        assert cov["apps"].last_success_at == "2026-10-28T09:02:10Z"
        assert cov["projects"].state == "partial"
        assert cov["projects"].last_success_at is None
        assert cov["osv"].state == "not_run"
        assert cov["macos"].state == "stale"
        assert cov["macos"].last_success_at == "2026-10-28T09:02:10Z"


# Failure keeps the previous successful completion time


def _complete_then(s, status, **kw):
    r1 = s.begin_refresh()
    s.finish_refresh(r1.id, "complete", coverage=[C("homebrew", "Homebrew", "complete")],
                     items=[I("formula:git", "homebrew", "git", "up_to_date")])
    r2 = s.begin_refresh()
    return r1, s.finish_refresh(r2.id, status, **kw)


@pytest.mark.parametrize("status", ["failed", "partial", "cancelled"])
def test_only_complete_refresh_moves_last_complete_at(tmp_path, status):
    with Store(tmp_path, clock=clock()) as s:
        _, r2 = _complete_then(s, status, error="Homebrew API did not respond.")
        assert r2.status == status
        assert r2.last_complete_at == "2026-10-29T10:01:00Z"
        assert r2.finished_at == "2026-10-29T10:03:00Z"
        assert r2.error == "Homebrew API did not respond."


def test_second_complete_refresh_moves_last_complete_at(tmp_path):
    with Store(tmp_path, clock=clock()) as s:
        _, r2 = _complete_then(s, "complete")
        assert r2.last_complete_at == "2026-10-29T10:03:00Z"


def test_failed_save_rolls_back_and_keeps_previous_state(tmp_path, monkeypatch):
    with Store(tmp_path, clock=clock()) as s:
        r1 = s.begin_refresh()
        s.finish_refresh(r1.id, "complete", coverage=[C("homebrew", "Homebrew", "complete")],
                         items=[I("formula:git", "homebrew", "git", "up_to_date")])
        before_cov, before_items = s.coverage(), s.items()

        def broken(*args):
            raise RuntimeError("disk full")

        monkeypatch.setattr(s, "_write_items", broken)
        r2 = s.begin_refresh()
        with pytest.raises(RuntimeError):
            s.finish_refresh(r2.id, "complete",
                             coverage=[C("homebrew", "Homebrew", "failed", error="x")],
                             items=[I("formula:git", "homebrew", "git", "vulnerable")])
        after = s.latest_refresh()
        assert after.status == "failed"
        assert after.error == "Watchtower could not save the refresh results."
        assert after.detail == "RuntimeError('disk full')"
        assert after.last_complete_at == "2026-10-29T10:01:00Z"
        assert s.coverage() == before_cov
        assert s.items() == before_items


def test_unfinished_refresh_is_marked_failed_by_next_begin(tmp_path):
    with Store(tmp_path, clock=clock()) as s:
        r1 = s.begin_refresh()
        r2 = s.begin_refresh()
        old = s.refresh(r1.id)
        assert old.status == "failed"
        assert old.error == "Refresh did not finish."
        assert old.last_complete_at is None
        assert r2.status == "running"


# Items and coverage


def test_complete_source_replaces_items_other_sources_keep_them(tmp_path):
    with Store(tmp_path, clock=clock()) as s:
        r1 = s.begin_refresh()
        s.finish_refresh(r1.id, "complete",
                         coverage=[C("homebrew", "Homebrew", "complete"), C("apps", "Apps", "complete")],
                         items=[I("formula:old", "homebrew", "old", "up_to_date"),
                                I("app:a", "apps", "A", "up_to_date")])
        r2 = s.begin_refresh()
        s.finish_refresh(r2.id, "partial",
                         coverage=[C("homebrew", "Homebrew", "complete"), C("apps", "Apps", "failed")],
                         items=[I("formula:new", "homebrew", "new", "update_available")])
        ids = [(i.source, i.id) for i in s.items()]
        assert ids == [("apps", "app:a"), ("homebrew", "formula:new")]


def test_partial_source_updates_reported_items(tmp_path):
    with Store(tmp_path, clock=clock()) as s:
        r1 = s.begin_refresh()
        s.finish_refresh(r1.id, "complete", coverage=[C("apps", "Apps", "complete")],
                         items=[I("app:a", "apps", "A", "up_to_date"), I("app:b", "apps", "B", "up_to_date")])
        r2 = s.begin_refresh()
        s.finish_refresh(r2.id, "partial", coverage=[C("apps", "Apps", "partial")],
                         items=[I("app:a", "apps", "A", "vulnerable")])
        items = {i.id: i for i in s.items()}
        assert items["app:a"].state == "vulnerable"
        assert items["app:a"].seen_at == "2026-10-29T10:03:00Z"
        assert items["app:b"].state == "up_to_date"
        assert items["app:b"].seen_at == "2026-10-29T10:01:00Z"


def test_errors_are_cleaned_and_detail_is_kept(tmp_path):
    long = "Could not read /private/etc/secret.conf because\nthe file\tis locked " + "x" * 80
    with Store(tmp_path, clock=clock()) as s:
        r = s.begin_refresh()
        s.finish_refresh(r.id, "failed", error=long, detail=long,
                         coverage=[C("apps", "Apps", "failed", error=long, detail=long)],
                         items=[I("app:a", "apps", "A", "error", error=long, detail=long)])
        for rec in (s.latest_refresh(), s.coverage()[0], s.items()[0]):
            assert "\n" not in rec.error and "/private" not in rec.error
            assert len(rec.error) <= 80
            assert rec.detail == long


# Validation


def test_invalid_values_are_rejected(tmp_path):
    with pytest.raises(ValueError):
        C("x", "X", "fresh")
    with pytest.raises(ValueError):
        I("a", "x", "A", "outdated")
    with Store(tmp_path, clock=clock()) as s:
        r = s.begin_refresh()
        with pytest.raises(ValueError):
            s.finish_refresh(r.id, "running")
        with pytest.raises(ValueError):
            s.finish_refresh(r.id, "done")
        s.finish_refresh(r.id, "complete")
        with pytest.raises(ValueError):
            s.finish_refresh(r.id, "complete")
        with pytest.raises(ValueError):
            s.finish_refresh(999, "complete")


def test_newer_store_schema_is_refused(tmp_path):
    Store(tmp_path).close()
    import sqlite3

    db = sqlite3.connect(tmp_path / "watchtower.sqlite3")
    db.execute("UPDATE meta SET value = '2' WHERE key = 'schema_version'")
    db.commit()
    db.close()
    with pytest.raises(StoreError) as exc:
        Store(tmp_path)
    assert str(exc.value) == "A newer Watchtower wrote this data."


# owner_error


def test_owner_error_is_one_short_line():
    assert owner_error(None) is None
    assert owner_error("  \n ") is None
    assert owner_error("Homebrew API\n did  not respond.") == "Homebrew API did not respond."
    out = owner_error("word " * 40)
    assert len(out) == 80 and out.endswith("...")


def test_owner_error_redacts_paths_outside_scan_roots():
    roots = ("~/Projects", "/Applications")
    assert owner_error("Cannot open /etc/hosts now.", roots) == "Cannot open <path> now."
    assert owner_error("Cannot open ~/.ssh/config.", roots) == "Cannot open <path>."
    assert owner_error("Bad /Applications/Zed.app bundle.", roots) == "Bad /Applications/Zed.app bundle."
    assert owner_error("Bad ~/Projects/web/package.json file.", roots) == "Bad ~/Projects/web/package.json file."
    assert owner_error("Sneaky /Applications/../etc/passwd x", roots) == "Sneaky <path> x"
    assert owner_error("See https://api.github.com/x and/or retry.", roots) == (
        "See https://api.github.com/x and/or retry."
    )


def test_owner_error_redacts_file_urls():
    roots = ("~/Projects", "/Applications")
    assert owner_error("Cannot open file:///etc/passwd", roots) == "Cannot open <path>"
    assert owner_error("Cannot open file:///etc/passwd.", roots) == "Cannot open <path>."
    assert owner_error("Bad (file://localhost/etc/hosts) x", roots) == "Bad (<path>) x"
    assert owner_error("Bad FILE:///etc/hosts x", roots) == "Bad <path> x"
    assert owner_error("Read file:///Users/me/Library/Application%20Support/Foo failed", roots) == (
        "Read <path> failed"
    )
    assert owner_error("Read file:///Users/me/Library/Application Support/Foo", roots) == "Read <path>"
    assert owner_error("Sneaky file:///Applications/../etc/passwd x", roots) == "Sneaky <path> x"
    assert "/etc" not in owner_error("a file:///etc/passwd b file:///etc/hosts", roots)


def test_owner_error_redacts_whole_paths_that_contain_spaces():
    roots = ("~/Projects", "/Applications")
    assert owner_error("Read failed: /Users/me/Library/Application Support/Foo", roots) == (
        "Read failed: <path>"
    )
    assert owner_error("Read /Users/me/My Documents/Old Stuff/a.txt failed", roots) == (
        "Read <path> failed"
    )
    assert owner_error('Read "/Users/me/Application Support/Foo" failed', roots) == 'Read "<path>" failed'
    assert owner_error("Read ~/Library/Application Support/Foo.", roots) == "Read <path>."
    # The end is not clear, so redact the next capitalized words too.
    assert owner_error("Cannot create /Library/Application Support: no access", roots) == (
        "Cannot create <path>: no access"
    )
    assert owner_error("Cannot create /Library/Application Support", roots) == "Cannot create <path>"
    assert "Support" not in owner_error("Cannot read /Users/me/Library/Application Support/Foo", roots)


def test_owner_error_keeps_text_that_is_not_a_path():
    roots = ("~/Projects", "/Applications")
    assert owner_error("Read ~/Projects/my app/package.json failed", roots) == (
        "Read ~/Projects/my app/package.json failed"
    )
    assert owner_error("Bad /Applications/Zed Preview.app/Contents now", roots) == (
        "Bad /Applications/Zed Preview.app/Contents now"
    )
    assert owner_error("Cannot open /etc/hosts now.", roots) == "Cannot open <path> now."
    assert owner_error("Cannot open /etc/hosts. Try again", roots) == "Cannot open <path>. Try again"
    assert owner_error("Read /etc/hosts and/or retry", roots) == "Read <path> and/or retry"
    assert owner_error("Read /etc/hosts via https://api.github.com/x ok", roots) == (
        "Read <path> via https://api.github.com/x ok"
    )


def test_owner_error_still_applies_the_80_character_limit_after_redaction():
    out = owner_error("Cannot open file:///etc/passwd " + "word " * 40)
    assert out.startswith("Cannot open <path> word")
    assert len(out) == 80 and out.endswith("...")


def test_store_from_schema_1_gets_new_item_columns(tmp_path):
    import sqlite3

    db = sqlite3.connect(tmp_path / "watchtower.sqlite3")
    db.executescript("""
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO meta VALUES ('schema_version', '1');
        CREATE TABLE items (source TEXT NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL,
            state TEXT NOT NULL, kind TEXT, installed_version TEXT, latest_version TEXT,
            project TEXT, seen_at TEXT, error TEXT, detail TEXT, PRIMARY KEY (source, id));
        INSERT INTO items (source, id, name, state) VALUES ('apps', 'app:a', 'A', 'up_to_date');
    """)
    db.close()
    with Store(tmp_path, clock=clock()) as s:
        assert s.items() == [I("app:a", "apps", "A", "up_to_date")]
        r = s.begin_refresh()
        s.finish_refresh(r.id, "complete", coverage=[C("homebrew", "Homebrew", "complete")],
                         items=[I("formula:w", "homebrew", "w", "manual", origin="acme/tools",
                                  source_at="2026-10-29T09:00:00Z", note="Watchtower cannot check tap acme/tools.")])
    with Store(tmp_path) as s:
        w = {i.id: i for i in s.items()}["formula:w"]
        assert (w.origin, w.source_at, w.note) == (
            "acme/tools", "2026-10-29T09:00:00Z", "Watchtower cannot check tap acme/tools."
        )


def test_owner_error_redacts_a_second_path_after_a_path_inside_the_roots():
    roots = ("~/Projects", "/Applications")
    assert owner_error("Cannot copy ~/Projects/app to /etc/shadow", roots) == (
        "Cannot copy ~/Projects/app to <path>"
    )
    assert owner_error("Cannot copy ~/Projects/app to /Users/me/.ssh/id_rsa", roots) == (
        "Cannot copy ~/Projects/app to <path>"
    )
    assert owner_error("Copy /Applications/Zed.app /var/log/system.log failed", roots) == (
        "Copy /Applications/Zed.app <path> failed"
    )
    assert owner_error("Copy ~/Projects/my app/x to /etc/shadow", roots) == (
        "Copy ~/Projects/my app/x to <path>"
    )
    assert owner_error("Copy ~/Projects/app To /etc/shadow", roots) == "Copy ~/Projects/app To <path>"
    assert owner_error("Copy ~/Projects/a b/c /etc/shadow", roots) == "Copy ~/Projects/a b/c <path>"
    assert owner_error("Copy ~/Projects/a ~/.ssh/id_rsa", roots) == "Copy ~/Projects/a <path>"
    assert owner_error("Copy ~/Projects/a file:///etc/shadow", roots) == "Copy ~/Projects/a <path>"
    assert owner_error("Copy /etc/hosts to /etc/shadow", roots) == "Copy <path> to <path>"
