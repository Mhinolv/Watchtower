import json
import os
import stat

import pytest

from watchtower_engine.discovery import discover
from watchtower_engine.scope import FILE_NAME, Scope, ScopeError, list_projects, set_project_active


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home"
    (h / "Projects").mkdir()
    (h / "Real").mkdir()
    return h


@pytest.fixture
def data(tmp_path):
    return tmp_path / "data"


def make(home, root, name, *files):
    folder = home / root / name
    folder.mkdir(parents=True, exist_ok=True)
    for f in files:
        (folder / f).write_text("")
    return folder


def states(result):
    return {p.name: p.state for p in result.projects}


def test_every_project_starts_active(home, data):
    make(home, "Projects", "web")
    make(home, "Real", "api")
    assert states(list_projects(data)) == {"web": "active", "api": "active"}


def test_reading_choices_creates_nothing(home, data):
    make(home, "Projects", "web")
    list_projects(data)
    assert not data.exists()


def test_inactive_choice_survives_rediscovery_and_a_new_scope_object(home, data):
    web = make(home, "Projects", "web", "package.json")
    make(home, "Projects", "api")
    changed = set_project_active(str(web), False, data)
    assert (changed.name, changed.state) == ("web", "inactive")
    for _ in range(2):
        assert states(list_projects(data)) == {"api": "active", "web": "inactive"}
    set_project_active(str(web), True, data)
    assert states(list_projects(data)) == {"api": "active", "web": "active"}


def test_choice_survives_when_the_folder_goes_away_and_comes_back(home, data):
    web = make(home, "Projects", "web")
    set_project_active(str(web), False, data)
    web.rmdir()
    assert list_projects(data).projects == []
    web.mkdir()
    assert states(list_projects(data)) == {"web": "inactive"}


def test_choice_made_through_a_symlink_applies_to_the_one_row(home, data):
    web = make(home, "Projects", "web")
    alias = home / "Real" / "web"
    os.symlink(web, alias)
    set_project_active(str(alias), False, data)
    result = list_projects(data)
    assert [(p.name, p.state) for p in result.projects] == [("web", "inactive")]


def test_inactive_wins_over_inaccessible(home, data):
    web = make(home, "Projects", "web")
    set_project_active(str(web), False, data)
    os.chmod(web, 0)
    try:
        if os.access(web, os.R_OK):
            pytest.skip("running as a user that ignores folder modes")
        assert states(list_projects(data)) == {"web": "inactive"}
    finally:
        os.chmod(web, 0o700)


def test_unknown_folder_is_refused_and_nothing_is_saved(home, data, tmp_path):
    make(home, "Projects", "web")
    with pytest.raises(ScopeError):
        set_project_active(str(tmp_path / "elsewhere"), False, data)
    assert not (data / FILE_NAME).exists()


def test_data_dir_and_file_are_private(home, data):
    web = make(home, "Projects", "web")
    old = os.umask(0o022)
    try:
        set_project_active(str(web), False, data)
    finally:
        os.umask(old)
    assert mode(data) == 0o700
    assert mode(data / FILE_NAME) == 0o600
    assert [f.name for f in data.iterdir()] == [FILE_NAME]


def test_file_format_is_versioned_and_sorted(home, data):
    for name in ("b", "a"):
        set_project_active(str(make(home, "Projects", name)), False, data)
    saved = json.loads((data / FILE_NAME).read_text())
    assert saved == {
        "version": 1,
        "inactive": sorted(os.path.realpath(home / "Projects" / n) for n in ("a", "b")),
    }


def test_unknown_keys_in_the_file_are_ignored(home, data):
    web = make(home, "Projects", "web")
    data.mkdir()
    (data / FILE_NAME).write_text(
        json.dumps({"version": 1, "inactive": [os.path.realpath(web)], "future": {"x": 1}})
    )
    assert states(list_projects(data)) == {"web": "inactive"}


@pytest.mark.parametrize("text", ["{not json", "[]", '{"inactive": "web"}', '{"version": "1"}'])
def test_bad_file_raises_and_is_never_overwritten(home, data, text):
    web = make(home, "Projects", "web")
    data.mkdir()
    (data / FILE_NAME).write_text(text)
    with pytest.raises(ScopeError):
        list_projects(data)
    with pytest.raises(ScopeError):
        set_project_active(str(web), False, data)
    assert (data / FILE_NAME).read_text() == text


def test_newer_file_version_is_refused(home, data):
    data.mkdir()
    (data / FILE_NAME).write_text(json.dumps({"version": 2, "inactive": []}))
    with pytest.raises(ScopeError) as exc:
        Scope(data).inactive()
    assert str(exc.value) == "A newer Watchtower wrote this data."


def test_failed_write_keeps_the_old_choices(home, data, monkeypatch):
    web = make(home, "Projects", "web")
    api = make(home, "Projects", "api")
    set_project_active(str(web), False, data)

    def boom(*a, **kw):
        raise OSError("disk full")

    with monkeypatch.context() as m:
        m.setattr(os, "replace", boom)
        with pytest.raises(OSError):
            set_project_active(str(api), False, data)
    assert states(list_projects(data)) == {"web": "inactive", "api": "active"}
    assert [f.name for f in data.iterdir()] == [FILE_NAME]
