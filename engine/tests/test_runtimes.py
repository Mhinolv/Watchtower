"""Runtime, SDK and editor-extension inventory (#16). Fixtures only: real files of the build Mac, cut down,
and temp folders. The engine never runs a program here, and these tests check that nothing does."""
import json
import os
import plistlib
import shutil
import subprocess
from pathlib import Path

import pytest

from watchtower_engine import cli, refresh
from watchtower_engine.inventory import runtimes
from watchtower_engine.models import CoverageRecord
from watchtower_engine.refresh import Source, run_refresh
from watchtower_engine.store import Store

from contract import Clock

FIX = Path(__file__).parent / "fixtures" / "runtimes"
FOLDERS = json.loads((FIX / "extension-folders.json").read_text())


@pytest.fixture
def machine(tmp_path, monkeypatch):
    """A fake home and a fake system root. Any attempt to start a program fails the test."""
    def no_process(*args, **kwargs):
        raise AssertionError(f"the inventory started a program: {args}")
    monkeypatch.setattr(subprocess, "Popen", no_process)
    monkeypatch.setattr(subprocess, "run", no_process)
    monkeypatch.setattr(os, "system", no_process)
    home, system = tmp_path / "mac-home", tmp_path / "mac-system"
    home.mkdir()
    system.mkdir()
    return home, system


def mkdir(*parts):
    path = Path(*parts)
    path.mkdir(parents=True, exist_ok=True)
    return path


def put(path: Path, source: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIX / source, path)


def collect(machine):
    home, system = machine
    return runtimes.collect(home, system)


def by(result, **match):
    return [i for i in result.items if all(getattr(i, k, None) == v or (i.attributes or {}).get(k) == v for k, v in match.items())]


# Runtimes


def test_three_node_versions_are_three_rows_and_only_the_newest_is_current(machine):
    home, _ = machine
    for v in ("v18.20.4", "v22.9.0", "v20.17.0"):
        mkdir(home, ".nvm/versions/node", v)
    mkdir(home, ".nvm/versions/node/latest-alias-not-a-version")
    (home / ".nvm/alias").mkdir()
    result = collect(machine)
    nodes = by(result, product="nodejs")
    assert [(i.installed_version, i.state, i.note) for i in nodes] == [
        ("22.9.0", "manual", runtimes.NOTE_NEWEST), ("20.17.0", "unknown", "Old copy"), ("18.20.4", "unknown", "Old copy")]
    new = nodes[0]
    assert (new.name, new.kind, new.origin, new.source) == ("Node.js", "runtime", "nvm", "runtimes")
    assert new.attributes["path"] == str(home / ".nvm/versions/node/v22.9.0")
    assert (new.attributes["product"], new.attributes["eolProduct"], new.attributes["copies"]) == ("nodejs", "nodejs", "3")
    assert new.attributes["group"] == "Runtimes" and new.attributes["family"] == "nodejs"
    assert nodes[1].attributes["oldCopy"] == "true" and "oldCopy" not in new.attributes
    assert result.coverage.state == "complete"


def test_each_runtime_gets_a_stable_product_name_and_the_plain_version_for_59(machine):
    home, system = machine
    mkdir(home, ".nvm/versions/node/v22.9.0")
    mkdir(home, ".volta/tools/image/node/20.11.1")
    mkdir(home, ".local/share/fnm/node-versions/v21.7.3/installation")
    mkdir(home, ".pyenv/versions/3.12.4")
    mkdir(home, ".pyenv/versions/3.13.0rc1")
    mkdir(home, ".pyenv/versions/miniconda3-latest")
    mkdir(home, ".rbenv/versions/3.3.1")
    mkdir(home, ".asdf/installs/golang/1.22.3")
    mkdir(home, ".asdf/installs/elixir/1.16.0")
    mkdir(home, ".local/share/mise/installs/node/22.4.0")
    mkdir(home, ".sdkman/candidates/java/21.0.2-tem")
    mkdir(home, ".sdkman/candidates/gradle/8.7")
    result = collect(machine)
    got = sorted((i.attributes["product"], i.installed_version, i.origin) for i in by(result, kind="runtime"))
    assert got == [("go", "1.22.3", "asdf"), ("gradle", "8.7", "SDKMAN!"), ("java", "21.0.2", "SDKMAN!"),
                   ("nodejs", "20.11.1", "Volta"), ("nodejs", "21.7.3", "fnm"), ("nodejs", "22.4.0", "mise"),
                   ("nodejs", "22.9.0", "nvm"), ("python", "3.12.4", "pyenv"), ("python", "3.13.0rc1", "pyenv"),
                   ("ruby", "3.3.1", "rbenv")]
    assert all(i.installed_version and not i.installed_version.startswith("v") for i in by(result, kind="runtime"))
    eol = {i.attributes["product"]: i.attributes.get("eolProduct") for i in by(result, kind="runtime")}
    assert eol == {"go": "go", "gradle": "gradle", "java": None, "nodejs": "nodejs", "python": "python", "ruby": "ruby"}


def test_symlinks_and_current_are_aliases_and_not_copies(machine):
    home, _ = machine
    mkdir(home, ".sdkman/candidates/java/21.0.2-tem")
    (home / ".sdkman/candidates/java/current").symlink_to(home / ".sdkman/candidates/java/21.0.2-tem")
    mkdir(home, ".pyenv/versions/3.12.4")
    (home / ".pyenv/versions/3.12").symlink_to(home / ".pyenv/versions/3.12.4")
    result = collect(machine)
    assert len(by(result, kind="runtime")) == 2


def test_rustup_reads_the_version_from_the_channel_manifest_as_text(machine):
    home, _ = machine
    manifest = ('date = "2024-05-02"\n[pkg.cargo]\nversion = "0.79.0 (f06ad46b3 2024-04-08)"\n'
                '[pkg.rust]\nversion = "1.78.0 (9b00956e5 2024-04-29)"\n')
    tc = mkdir(home, ".rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib")
    (tc / "multirust-channel-manifest.toml").write_text(manifest)
    mkdir(home, ".rustup/toolchains/1.70.0-aarch64-apple-darwin")  # A pinned name, no manifest.
    result = collect(machine)
    rust = {i.attributes["toolchain"]: i for i in by(result, product="rust")}
    assert rust["stable-aarch64-apple-darwin"].installed_version == "1.78.0"
    assert (rust["1.70.0-aarch64-apple-darwin"].installed_version, rust["1.70.0-aarch64-apple-darwin"].note) == (
        "1.70.0", "Old copy")


def test_a_version_that_cannot_be_read_is_unknown_with_the_file_named(machine):
    home, _ = machine
    mkdir(home, ".rustup/toolchains/nightly-aarch64-apple-darwin")
    result = collect(machine)
    [rust] = by(result, product="rust")
    assert (rust.installed_version, rust.state, rust.note) == (None, "unknown",
                                                              "Version not found in multirust-channel-manifest.toml.")
    assert result.coverage.state == "partial" and result.coverage.error == "1 versions could not be read."
    assert "Runtimes: Rust" in result.coverage.detail and "Version not found in multirust" in result.coverage.detail


def test_java_and_go_installs_are_read_from_their_version_files(machine):
    home, system = machine
    jdk = mkdir(system, "Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents")
    (jdk / "Info.plist").write_bytes(plistlib.dumps({"CFBundleName": "OpenJDK 21.0.2", "JavaVM": {"JVMVersion": "21.0.2"}}))
    old = mkdir(system, "Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents")
    (old / "Info.plist").write_bytes(plistlib.dumps({"CFBundleName": "OpenJDK 17.0.9", "JavaVM": {"JVMVersion": "17.0.9"}}))
    mkdir(system, "Library/Java/JavaVirtualMachines/broken.jdk/Contents")
    mkdir(system, "usr/local/go")
    (system / "usr/local/go/VERSION").write_text("go1.22.3\ntime 2024-05-01T00:00:00Z\n")
    mkdir(home, "sdk/go1.21.0")
    (home / "sdk/go1.21.0/VERSION").write_text("go1.21.0")
    result = collect(machine)
    java = {i.installed_version: i for i in by(result, product="java")}
    assert set(java) == {"21.0.2", "17.0.9", None}
    assert java["17.0.9"].note == "Old copy" and java["21.0.2"].attributes["vendor"] == "OpenJDK 21.0.2"
    assert java[None].note == "Version not found in Info.plist."
    go = {i.installed_version: i for i in by(result, product="go")}
    assert set(go) == {"1.22.3", "1.21.0"} and go["1.21.0"].note == "Old copy"


# SDKs (real files of the build Mac)


def xcode_machine(machine):
    home, system = machine
    app = system / "Applications/Xcode.app/Contents"
    put(app / "version.plist", "xcode-version.plist")
    sdks = app / "Developer/Platforms/MacOSX.platform/Developer/SDKs"
    put(sdks / "MacOSX26.2.sdk/SDKSettings.plist", "sdksettings-macosx26.2.plist")
    (sdks / "MacOSX.sdk").symlink_to("MacOSX26.2.sdk")
    ios = app / "Developer/Platforms/iPhoneOS.platform/Developer/SDKs"
    put(ios / "iPhoneOS26.2.sdk/SDKSettings.plist", "sdksettings-iphoneos26.2.plist")
    clt = system / "Library/Developer/CommandLineTools/SDKs"
    put(clt / "MacOSX15.5.sdk/SDKSettings.plist", "sdksettings-macosx15.5.plist")
    put(clt / "MacOSX15.2.sdk/SDKSettings.plist", "sdksettings-macosx15.2.plist")
    (clt / "MacOSX.sdk").symlink_to("MacOSX15.5.sdk")
    (clt / "MacOSX15.sdk").symlink_to("MacOSX15.5.sdk")
    return collect(machine)


def test_sdks_of_xcode_and_the_command_line_tools_are_listed_without_their_aliases(machine):
    result = xcode_machine(machine)
    got = sorted((i.name, i.installed_version, i.origin, i.state, i.note) for i in by(result, kind="sdk"))
    assert got == [
        ("iOS SDK", "26.2", "Xcode", "manual", runtimes.NOTE_NEWEST),
        ("macOS SDK", "15.2", "Command Line Tools", "unknown", "Old copy"),
        ("macOS SDK", "15.5", "Command Line Tools", "manual", runtimes.NOTE_NEWEST),
        ("macOS SDK", "26.2", "Xcode", "manual", runtimes.NOTE_NEWEST)]
    xcode = by(result, name="macOS SDK", origin="Xcode")[0]
    assert xcode.attributes["toolchain"] == "Xcode 26.2" and xcode.attributes["canonicalName"] == "macosx26.2"
    assert xcode.attributes["group"] == "SDKs" and xcode.attributes["product"] == "macosx-sdk"


def test_an_sdk_without_settings_is_unknown(machine):
    _, system = machine
    mkdir(system, "Library/Developer/CommandLineTools/SDKs/MacOSX13.sdk")
    [sdk] = by(collect(machine), kind="sdk")
    assert (sdk.installed_version, sdk.state, sdk.note) == (None, "unknown", "Version not found in SDKSettings.plist.")


# Editor extensions (real folder names and manifests)


def test_the_real_extension_folder_names_parse_to_an_id_and_a_version():
    parsed = {name: runtimes.parse_extension_folder(name) for ed in FOLDERS.values() for name in ed}
    assert parsed["ms-python.python-2026.8.0-darwin-arm64"] == ("ms-python.python", "2026.8.0")
    assert parsed["bierner.markdown-mermaid-1.32.1-universal"] == ("bierner.markdown-mermaid", "1.32.1")
    assert parsed["ms-vscode-remote.remote-ssh-edit-0.87.0"] == ("ms-vscode-remote.remote-ssh-edit", "0.87.0")
    assert parsed["anysphere.cursorpyright-1.0.12"] == ("anysphere.cursorpyright", "1.0.12")
    assert parsed["extensions.json"] is None
    assert all(v is not None for k, v in parsed.items() if k != "extensions.json")


def real_extensions(machine):
    home, _ = machine
    for editor, rel in (("VS Code", ".vscode"), ("Cursor", ".cursor")):
        for name in FOLDERS[rel]:
            if name == "extensions.json":
                (home / rel / "extensions").mkdir(parents=True, exist_ok=True)
                (home / rel / "extensions" / name).write_text("[]")
            else:
                mkdir(home, rel, "extensions", name)
    put(home / ".vscode/extensions/ms-azuretools.vscode-docker-2.0.0/package.json",
        "package-ms-azuretools.vscode-docker-2.0.0.json")
    put(home / ".cursor/extensions/anthropic.claude-code-2.1.15-darwin-arm64/package.json",
        "package-anthropic.claude-code-2.1.15-darwin-arm64.json")
    return collect(machine)


def test_extensions_show_the_id_the_editor_and_the_version(machine):
    result = real_extensions(machine)
    docker = by(result, kind="extension", name="ms-azuretools.vscode-docker")
    assert sorted((i.origin, i.installed_version) for i in docker) == [("Cursor", "2.0.0"), ("VS Code", "2.0.0")]
    vs = next(i for i in docker if i.origin == "VS Code")
    assert vs.attributes["editor"] == "VS Code" and vs.attributes["displayName"] == "Docker"
    claude = by(result, name="anthropic.claude-code")[0]
    assert (claude.installed_version, claude.attributes["displayName"]) == ("2.1.15", "Claude Code for VS Code")
    assert len(by(result, kind="extension")) == len(FOLDERS[".vscode"]) + len(FOLDERS[".cursor"]) - 2  # No extensions.json.


def test_the_same_extension_in_two_editors_is_not_an_old_copy(machine):
    result = real_extensions(machine)
    py = {i.origin: i for i in by(result, name="ms-python.python")}
    assert py["VS Code"].installed_version == "2026.8.0" and py["Cursor"].installed_version == "2025.6.1"
    assert py["VS Code"].state == py["Cursor"].state == "manual"  # Each editor has one copy.
    containers = {i.origin: i for i in by(result, name="ms-azuretools.vscode-containers")}
    assert containers["Cursor"].installed_version == "2.4.5" and containers["Cursor"].note == runtimes.NOTE_NEWEST


def test_an_old_version_in_the_same_editor_is_an_old_copy_and_obsolete_is_noted(machine):
    home, _ = machine
    ext = home / ".vscode/extensions"
    mkdir(ext, "ms-python.python-2026.8.0-darwin-arm64")
    mkdir(ext, "ms-python.python-2025.1.0-darwin-arm64")
    (ext / ".obsolete").write_text(json.dumps({"ms-python.python-2025.1.0-darwin-arm64": True}))
    result = collect(machine)
    new, old = by(result, name="ms-python.python")
    assert (new.installed_version, new.state) == ("2026.8.0", "manual")
    assert (old.installed_version, old.state, old.note) == ("2025.1.0", "unknown", "Old copy")
    assert old.attributes["obsolete"] == "true" and "obsolete" not in new.attributes
    assert old.attributes["copies"] == "2"


def test_a_manifest_that_is_not_json_does_not_stop_the_list(machine):
    home, _ = machine
    ext = mkdir(home, ".vscode/extensions/acme.tool-1.2.3")
    (ext / "package.json").write_text("{not json")
    deep = mkdir(home, ".vscode/extensions/acme.deep-4.5.6")
    (deep / "package.json").write_text("[" * 100_000 + "]" * 100_000)
    result = collect(machine)
    assert sorted((i.name, i.installed_version) for i in by(result, kind="extension")) == [
        ("acme.deep", "4.5.6"), ("acme.tool", "1.2.3")]  # The folder name has the version.


def test_an_extension_manifest_is_read_as_text_and_its_code_never_runs(machine):
    home, _ = machine
    ext = mkdir(home, ".vscode/extensions/acme.tool-1.2.3")
    (ext / "package.json").write_text(json.dumps({"name": "tool", "publisher": "acme", "version": "1.2.3",
                                                  "main": "./evil.js", "scripts": {"postinstall": "touch pwned"}}))
    (ext / "evil.js").write_text("require('fs').writeFileSync('/tmp/pwned', '1')")
    collect(machine)
    assert not (ext / "pwned").exists() and not Path("/tmp/pwned").exists()


# Roots, coverage and the refresh


def test_an_unreadable_root_is_reported_and_the_other_roots_still_show(machine):
    home, _ = machine
    mkdir(home, ".pyenv/versions/3.12.4")
    locked = mkdir(home, ".nvm/versions/node")
    mkdir(locked, "v22.9.0")
    os.chmod(locked, 0)
    try:
        result = collect(machine)
    finally:
        os.chmod(locked, 0o755)
    assert [i.attributes["product"] for i in result.items] == ["python"]
    assert result.coverage.state == "partial" and result.coverage.error == "1 install folders could not be read."
    assert result.coverage.detail == "Runtimes: Cannot read ~/.nvm: permission denied."


def test_a_missing_root_is_normal(machine):
    result = collect(machine)
    assert result.items == [] and result.coverage.state == "complete" and result.coverage.error is None


def test_every_root_failing_is_failed_and_does_not_raise(machine):
    home, _ = machine
    locked = mkdir(home, ".pyenv/versions")
    os.chmod(locked, 0)
    try:
        result = collect(machine)
    finally:
        os.chmod(locked, 0o755)
    assert result.coverage.state == "failed" and result.items == []


def test_a_layout_that_raises_stops_only_itself(machine, monkeypatch):
    home, _ = machine
    mkdir(home, ".pyenv/versions/3.12.4")
    monkeypatch.setattr(runtimes, "scan_rustup", lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
    result = collect(machine)
    assert [i.attributes["product"] for i in result.items] == ["python"]
    assert result.coverage.state == "partial" and "RuntimeError" in result.coverage.detail


def test_the_items_are_ordered_by_group_name_and_newest_version(machine):
    home, system = machine
    for v in ("3.11.9", "3.12.4"):
        mkdir(home, ".pyenv/versions", v)
    mkdir(home, ".nvm/versions/node/v22.9.0")
    mkdir(home, ".vscode/extensions/acme.tool-1.2.3")
    result = xcode_machine(machine)
    order = [(i.kind, i.name, i.installed_version) for i in result.items]
    assert order[:3] == [("runtime", "Node.js", "22.9.0"), ("runtime", "Python", "3.12.4"), ("runtime", "Python", "3.11.9")]
    assert [o[0] for o in order] == sorted([o[0] for o in order], key=["runtime", "sdk", "extension"].index)


def test_the_item_ids_are_stable_and_unique_for_each_install(machine):
    home, _ = machine
    mkdir(home, ".nvm/versions/node/v22.9.0")
    mkdir(home, ".volta/tools/image/node/22.9.0")
    first = [i.id for i in collect(machine).items]
    again = [i.id for i in collect(machine).items]
    assert first == again and len(set(first)) == 2
    assert all(i.startswith("runtime:") for i in first)


def test_runtimes_are_not_project_manifests(machine, tmp_path):
    from watchtower_engine.discovery import discover
    home, _ = machine
    mkdir(home, ".nvm/versions/node/v22.9.0")
    mkdir(home, "Projects/web")
    (home / "Projects/web/package.json").write_text("{}")
    assert [p.name for p in discover((str(home / "Projects"),)).projects] == ["web"]
    assert all(i.project is None for i in collect(machine).items)


def test_the_refresh_saves_the_runtimes_source_and_a_failed_one_does_not_stop_it(machine, tmp_path):
    home, system = machine
    mkdir(home, ".pyenv/versions/3.12.4")

    def boom():
        raise OSError("disk")

    sources = [Source("runtimes", "Runtimes", lambda: runtimes.collect(home, system)),
               Source("macos", "macOS", boom)]
    with Store(tmp_path / "data", clock=Clock(*[f"2026-10-29T10:{m:02d}:00Z" for m in range(10)])) as store:
        state = run_refresh(store, sources)
    cov = {c["source"]: c for c in state["coverage"]}
    assert cov["runtimes"]["state"] == "complete" and cov["macos"]["state"] == "failed"
    assert [i["name"] for i in state["items"] if i["source"] == "runtimes"] == ["Python"]
    item = next(i for i in state["items"] if i["source"] == "runtimes")
    assert item["attributes"]["product"] == "python" and item["installed_version"] == "3.12.4"


def test_the_default_sources_include_runtimes(tmp_path):
    assert "runtimes" in [s.source for s in refresh.default_sources(tmp_path)]


# Round 2 (#16 QA): special files are never read, and uv Pythons and the python.org framework are listed

import signal
import stat as stat_module


class Hang(BaseException):  # Not an Exception: the inventory catches those.
    pass


@pytest.fixture
def guard():
    """Fail a test that blocks, instead of hanging the suite. A FIFO that is opened for reading blocks forever."""
    def handler(signum, frame):
        raise Hang("the inventory blocked on a special file")
    previous = signal.signal(signal.SIGALRM, handler)
    signal.alarm(8)
    yield
    signal.alarm(0)
    signal.signal(signal.SIGALRM, previous)


def fifo(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(path)


def test_a_fifo_as_a_manifest_is_never_opened_and_the_version_comes_from_the_folder(machine, guard):
    home, _ = machine
    ext = mkdir(home, ".vscode/extensions/evil.ext-1.0.0")
    fifo(ext / "package.json")
    fifo(home / ".vscode/extensions/.obsolete")
    result = collect(machine)
    assert [(i.name, i.installed_version) for i in by(result, kind="extension")] == [("evil.ext", "1.0.0")]


def test_a_fifo_is_not_read_in_any_other_layout(machine, guard):
    home, system = machine
    tc = mkdir(home, ".rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib")
    fifo(tc / "multirust-channel-manifest.toml")
    mkdir(system, "usr/local/go")
    fifo(system / "usr/local/go/VERSION")
    sdk = mkdir(system, "Library/Developer/CommandLineTools/SDKs/MacOSX15.5.sdk")
    fifo(sdk / "SDKSettings.plist")
    jdk = mkdir(system, "Library/Java/JavaVirtualMachines/x.jdk/Contents")
    fifo(jdk / "Info.plist")
    app = mkdir(system, "Applications/Xcode.app/Contents")
    fifo(app / "version.plist")
    fw = mkdir(system, "Library/Frameworks/Python.framework/Versions/3.13/Resources")
    fifo(fw / "Info.plist")
    result = collect(machine)
    assert result.coverage.state == "partial"
    unread = sorted((i.name, i.note) for i in result.items if i.installed_version is None)
    assert unread == [("Java", "Version not found in Info.plist."), ("Python", "Version not found in Info.plist."),
                      ("Rust", "Version not found in multirust-channel-manifest.toml."),
                      ("macosx SDK", "Version not found in SDKSettings.plist.")]  # The name comes from the folder.
    assert by(result, product="go") == []  # A FIFO is no VERSION file: this is not a Go install.


def test_a_symlink_to_dev_zero_is_not_followed_and_does_not_fill_the_memory(machine, guard):
    home, _ = machine
    ext = mkdir(home, ".vscode/extensions/evil.ext-1.0.0")
    (ext / "package.json").symlink_to("/dev/zero")
    result = collect(machine)
    assert [(i.name, i.installed_version) for i in by(result, kind="extension")] == [("evil.ext", "1.0.0")]


def test_a_symlinked_manifest_is_not_followed_even_to_a_real_file(machine, tmp_path):
    home, _ = machine
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"name": "x", "publisher": "evil", "version": "9.9.9", "displayName": "Outside"}))
    ext = mkdir(home, ".vscode/extensions/acme.tool-1.2.3")
    (ext / "package.json").symlink_to(outside)
    [item] = by(collect(machine), kind="extension")
    assert item.installed_version == "1.2.3" and "displayName" not in item.attributes


def test_a_file_over_the_cap_is_not_read(machine):
    home, _ = machine
    ext = mkdir(home, ".vscode/extensions/acme.tool-1.2.3")
    (ext / "package.json").write_text(json.dumps({"version": "9.9.9", "displayName": "x" * (runtimes.MAX_FILE_BYTES + 10)}))
    [item] = by(collect(machine), kind="extension")
    assert item.installed_version == "1.2.3"


def test_the_reader_takes_regular_files_only_and_caps_every_read(tmp_path, guard):
    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"hello")
    assert runtimes._read_regular(plain) == b"hello"
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * (runtimes.MAX_FILE_BYTES + 1))
    assert runtimes._read_regular(big) is None
    assert runtimes._read_regular(tmp_path) is None  # A folder.
    assert runtimes._read_regular(tmp_path / "missing") is None
    (tmp_path / "link").symlink_to(plain)
    assert runtimes._read_regular(tmp_path / "link") is None
    fifo(tmp_path / "pipe")
    assert runtimes._read_regular(tmp_path / "pipe") is None
    (tmp_path / "zero").symlink_to("/dev/zero")
    assert runtimes._read_regular(tmp_path / "zero") is None
    assert runtimes._read_regular(Path("/dev/null")) is None  # A character device.
    assert runtimes._read_regular(tmp_path / "plain.txt", limit=3) is None


def test_uv_pythons_are_listed_with_the_version_from_the_folder_name(machine):
    home, _ = machine
    uv = home / ".local/share/uv/python"
    for name in ("cpython-3.11.13-macos-aarch64-none", "cpython-3.12.11-macos-aarch64-none",
                 "cpython-3.13.0rc2-macos-aarch64-none", "cpython-3.13.1+freethreaded-macos-aarch64-none",
                 "pypy-3.10.14-macos-aarch64-none", ".temp", "readme-folder"):
        mkdir(uv, name)
    (uv / ".lock").write_text("")
    (uv / "cpython-3.12-macos-aarch64-none").symlink_to("cpython-3.12.11-macos-aarch64-none")  # An alias.
    result = collect(machine)
    pythons = {i.installed_version: i for i in by(result, product="python")}
    assert sorted(pythons) == ["3.11.13", "3.12.11", "3.13.0rc2", "3.13.1"]
    new = pythons["3.13.1"]
    assert (new.name, new.origin, new.kind, new.state) == ("Python", "uv", "runtime", "manual")
    assert new.attributes["eolProduct"] == "python" and new.attributes["path"].endswith("cpython-3.13.1+freethreaded-macos-aarch64-none")
    assert pythons["3.11.13"].note == "Old copy" and pythons["3.12.11"].note == "Old copy"
    assert result.coverage.state == "complete"


def test_the_python_org_framework_is_listed_by_its_info_plist_and_current_is_skipped(machine):
    _, system = machine
    versions = system / "Library/Frameworks/Python.framework/Versions"
    put(versions / "3.13/Resources/Info.plist", "python-framework-info.plist")
    (versions / "Current").symlink_to("3.13")
    mkdir(versions, "3.12/Resources")
    (versions / "3.12/Resources/Info.plist").write_bytes(plistlib.dumps({"CFBundleVersion": "3.12.9"}))
    mkdir(versions, "2.7")  # No Info.plist: the folder name is not a full version.
    result = collect(machine)
    framework = {i.installed_version: i for i in by(result, origin="python.org")}
    assert set(framework) == {"3.13.5", "3.12.9", None}
    assert framework["3.13.5"].attributes["product"] == "python" and framework["3.13.5"].state == "manual"
    assert framework["3.12.9"].note == "Old copy"
    assert framework[None].note == "Version not found in Info.plist." and result.coverage.state == "partial"


def test_python_copies_of_different_managers_are_one_family(machine):
    home, system = machine
    mkdir(home, ".pyenv/versions/3.12.4")
    mkdir(home, ".local/share/uv/python/cpython-3.12.11-macos-aarch64-none")
    put(system / "Library/Frameworks/Python.framework/Versions/3.13/Resources/Info.plist", "python-framework-info.plist")
    result = collect(machine)
    order = [(i.installed_version, i.origin, i.note) for i in by(result, product="python")]
    assert order == [("3.13.5", "python.org", runtimes.NOTE_NEWEST), ("3.12.11", "uv", "Old copy"), ("3.12.4", "pyenv", "Old copy")]
    assert {i.attributes["copies"] for i in by(result, product="python")} == {"3"}
