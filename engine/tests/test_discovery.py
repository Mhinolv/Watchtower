import os
import subprocess

import pytest

from watchtower_engine.discovery import MANIFEST_NAMES, discover, display_path


@pytest.fixture
def home(tmp_path):
    """The temp home from conftest, with both project roots."""
    h = tmp_path / "home"
    (h / "Projects").mkdir()
    (h / "Real").mkdir()
    return h


def project(root, name, *files):
    folder = root / name
    folder.mkdir(parents=True, exist_ok=True)
    for f in files:
        (folder / f).parent.mkdir(parents=True, exist_ok=True)
        (folder / f).write_text("")
    return folder


def rows(result):
    return [(p.root, p.name, p.state, p.manifests) for p in result.projects]


def test_lists_projects_in_both_roots_with_fields(home):
    project(home / "Projects", "web", "package.json", "package-lock.json", "README.md")
    project(home / "Real", "api", "uv.lock", "pyproject.toml")
    result = discover()
    assert result.root_errors == []
    assert rows(result) == [
        ("~/Projects", "web", "active", ["package-lock.json", "package.json"]),
        ("~/Real", "api", "active", ["pyproject.toml", "uv.lock"]),
    ]
    web = result.projects[0].to_dict()
    assert web == {
        "name": "web",
        "path": str(home / "Projects" / "web"),
        "root": "~/Projects",
        "manifests": ["package-lock.json", "package.json"],
        "state": "active",
    }


def test_project_without_manifest_is_listed(home):
    project(home / "Projects", "notes", "README.md")
    assert rows(discover()) == [("~/Projects", "notes", "active", [])]


def test_sorts_by_root_then_case_insensitive_name(home):
    for name in ("beta", "Alpha", "alpine", "Zed"):
        project(home / "Projects", name)
    project(home / "Real", "aaa")
    assert [(p.root, p.name) for p in discover().projects] == [
        ("~/Projects", "Alpha"),
        ("~/Projects", "alpine"),
        ("~/Projects", "beta"),
        ("~/Projects", "Zed"),
        ("~/Real", "aaa"),
    ]


def test_hidden_folders_and_plain_files_are_not_projects(home):
    project(home / "Projects", ".cache", "package.json")
    (home / "Projects" / "notes.txt").write_text("x")
    project(home / "Projects", "real-one")
    assert [p.name for p in discover().projects] == ["real-one"]


def test_manifests_one_level_down_and_skip_dependency_folders(home):
    project(home / "Projects", "mono", "Package.swift", "engine/pyproject.toml",
            "node_modules/dep/package.json", "node_modules/package.json", ".git/go.mod",
            "a/b/Cargo.toml")
    assert discover().projects[0].manifests == ["Package.swift", "engine/pyproject.toml"]


def test_only_known_manifest_names_match(home):
    project(home / "Projects", "p", "package.json.bak", "Package.json", "go.mod")
    assert discover().projects[0].manifests == ["go.mod"]
    assert "package.json" in MANIFEST_NAMES


def test_manifest_contents_are_never_read(home, monkeypatch):
    folder = project(home / "Projects", "p", "package.json", "Cargo.toml")
    (folder / "package.json").write_text("{ this is not json")
    opened = []
    real_open = open

    def spy(file, *a, **kw):
        opened.append(str(file))
        return real_open(file, *a, **kw)

    monkeypatch.setattr("builtins.open", spy)
    result = discover()
    assert result.projects[0].manifests == ["Cargo.toml", "package.json"]
    assert not [f for f in opened if f.endswith(("package.json", "Cargo.toml"))]


# Root errors


def test_missing_root_is_reported_and_other_root_still_runs(home):
    (home / "Real").rmdir()
    project(home / "Projects", "web")
    result = discover()
    assert [p.name for p in result.projects] == ["web"]
    assert [e.to_dict() for e in result.root_errors] == [
        {"root": "~/Real", "kind": "missing", "message": "~/Real does not exist."}
    ]


def test_unreadable_root_is_reported(home):
    project(home / "Real", "api", "uv.lock")
    os.chmod(home / "Real", 0)
    try:
        if os.access(home / "Real", os.R_OK):
            pytest.skip("running as a user that ignores folder modes")
        result = discover()
    finally:
        os.chmod(home / "Real", 0o700)
    assert result.projects == []
    assert [e.to_dict() for e in result.root_errors] == [
        {"root": "~/Real", "kind": "permission_denied",
         "message": "Cannot read ~/Real: permission denied."}
    ]


def test_root_that_is_a_file_is_reported(home):
    (home / "Real").rmdir()
    (home / "Real").write_text("x")
    [error] = discover().root_errors
    assert (error.kind, error.message) == ("not_a_directory", "~/Real is not a folder.")


def test_unreadable_project_is_inaccessible_not_dropped(home):
    project(home / "Projects", "locked", "package.json")
    project(home / "Projects", "open", "go.mod")
    os.chmod(home / "Projects" / "locked", 0)
    try:
        if os.access(home / "Projects" / "locked", os.R_OK):
            pytest.skip("running as a user that ignores folder modes")
        result = discover()
    finally:
        os.chmod(home / "Projects" / "locked", 0o700)
    assert rows(result) == [
        ("~/Projects", "locked", "inaccessible", []),
        ("~/Projects", "open", "active", ["go.mod"]),
    ]


# Symlinks and worktrees


def test_symlink_to_a_listed_project_adds_no_row(home):
    project(home / "Projects", "web", "package.json")
    os.symlink(home / "Projects" / "web", home / "Projects" / "web-alias")
    os.symlink(home / "Projects" / "web", home / "Real" / "web")
    result = discover()
    assert rows(result) == [("~/Projects", "web", "active", ["package.json"])]
    assert result.projects[0].path == str(home / "Projects" / "web")
    assert result.skipped == []


def test_symlink_listed_before_its_target_still_gives_one_row(home):
    # "Real" sorts after "Projects", and "aaa" sorts before "web".
    project(home / "Projects", "web", "package.json")
    os.symlink(home / "Projects" / "web", home / "Projects" / "aaa")
    assert [(p.root, p.name) for p in discover().projects] == [("~/Projects", "web")]


def test_symlink_out_of_the_roots_is_skipped_and_never_read(home, tmp_path):
    outside = project(tmp_path / "elsewhere", "secret", "package.json")
    os.symlink(outside, home / "Projects" / "escape")
    result = discover()
    assert result.projects == []
    assert [s.to_dict() for s in result.skipped] == [
        {"path": display_path(home / "Projects" / "escape"),
         "reason": "Symlink leads outside the project roots."}
    ]


def test_symlink_to_a_folder_inside_a_project_is_skipped(home):
    project(home / "Projects", "web", "sub/package.json")
    os.symlink(home / "Projects" / "web" / "sub", home / "Real" / "sub-link")
    result = discover()
    assert [p.name for p in result.projects] == ["web"]
    assert len(result.skipped) == 1


def test_broken_symlink_is_ignored(home):
    os.symlink(home / "gone", home / "Projects" / "dead")
    result = discover()
    assert result.projects == [] and result.skipped == []


def test_root_that_is_a_symlink_keeps_the_owner_path(home, tmp_path):
    (home / "Real").rmdir()
    disk = tmp_path / "disk" / "Real"
    project(disk, "api", "uv.lock")
    os.symlink(disk, home / "Real")
    [p] = discover().projects
    assert (p.root, p.name, p.path) == ("~/Real", "api", str(home / "Real" / "api"))


def git(cwd, *args):
    subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=cwd, check=True, capture_output=True,
    )


def test_worktree_of_a_listed_project_adds_no_row(home):
    main = project(home / "Projects", "app", "package.json")
    git(main, "init", "-q")
    git(main, "add", ".")
    git(main, "commit", "-q", "-m", "x")
    git(main, "worktree", "add", "-q", str(home / "Real" / "app-feature"))
    assert (home / "Real" / "app-feature" / ".git").is_file()
    assert rows(discover()) == [("~/Projects", "app", "active", ["package.json"])]


def test_worktree_whose_main_repo_is_outside_the_roots_is_kept(home, tmp_path):
    main = project(tmp_path / "elsewhere", "app", "package.json")
    git(main, "init", "-q")
    git(main, "add", ".")
    git(main, "commit", "-q", "-m", "x")
    git(main, "worktree", "add", "-q", str(home / "Projects" / "app-feature"))
    assert [p.name for p in discover().projects] == ["app-feature"]


def test_submodule_style_git_file_is_not_a_worktree(home):
    folder = project(home / "Projects", "sub")
    (folder / ".git").write_text("gitdir: ../.git/modules/sub\n")
    project(home / "Projects", "outer")
    assert [p.name for p in discover().projects] == ["outer", "sub"]


# Inactive choice


def test_inactive_state_applies_by_resolved_path(home):
    web = project(home / "Projects", "web")
    project(home / "Projects", "api")
    result = discover(inactive={os.path.realpath(web)})
    assert [(p.name, p.state) for p in result.projects] == [("api", "active"), ("web", "inactive")]
