"""Shared engine-to-app contract fixtures.

The Swift tests decode the files in Tests/WatchtowerCoreTests/Fixtures. The engine
tests check that the engine still prints exactly that JSON. To rewrite the files
after a deliberate contract change, run: WATCHTOWER_UPDATE_FIXTURES=1 pytest
"""
import json
import os
from pathlib import Path

from watchtower_engine.models import CoverageRecord as C
from watchtower_engine.models import ItemRecord as I
from watchtower_engine.store import Store

FIXTURES = Path(__file__).resolve().parents[2] / "Tests" / "WatchtowerCoreTests" / "Fixtures"


class Clock:
    """Fixed timestamps, one per call."""

    def __init__(self, *times):
        self.times = list(times)

    def __call__(self):
        return self.times.pop(0)


def build_partial_state(data_dir) -> Store:
    """A complete refresh, then a partial one. Uses every coverage state and item state."""
    store = Store(
        data_dir,
        clock=Clock(
            "2026-10-28T09:00:00Z", "2026-10-28T09:02:10Z",
            "2026-10-29T08:30:00Z", "2026-10-29T08:31:45Z",
        ),
    )
    r1 = store.begin_refresh()
    store.finish_refresh(
        r1.id,
        "complete",
        coverage=[
            C("homebrew", "Homebrew", "complete"),
            C("apps", "Applications", "complete"),
            C("macos", "macOS", "complete"),
        ],
        items=[
            I("formula:git", "homebrew", "git", "up_to_date", kind="formula",
              installed_version="2.46.0", latest_version="2.46.0"),
            I("com.tinyspeck.slackmacgap", "apps", "Slack", "up_to_date", kind="app",
              installed_version="4.41.97", latest_version="4.41.97",
              attributes={"path": "/Applications/Slack.app", "bundleId": "com.tinyspeck.slackmacgap",
                          "build": "441097", "architecture": "arm64", "electron": "30.1.2",
                          "chromium": "124", "node": "20"}),
            I("com.example.legacy", "apps", "Legacy Tool", "manual", kind="app",
              installed_version="1.2", origin="Manual", note="Update this app from its vendor.",
              attributes={"path": "/Applications/Legacy Tool.app", "bundleId": "com.example.legacy"}),
        ],
    )
    r2 = store.begin_refresh()
    store.finish_refresh(
        r2.id,
        "partial",
        error="Some sources did not finish.",
        detail="apps: scan stopped early",
        coverage=[
            C("homebrew", "Homebrew", "complete", source_at="2026-10-29T08:30:40Z"),
            C("apps", "Applications", "failed", error="App folder scan stopped early.",
              detail="PermissionError: [Errno 1] Operation not permitted: '/Library/Secret/App.app'"),
            C("projects", "Projects", "partial", error="2 projects could not be read."),
            C("osv", "OSV", "not_run"),
        ],
        items=[
            I("formula:git", "homebrew", "git", "update_available", kind="formula",
              installed_version="2.46.0", latest_version="2.47.1", source_at="2026-10-29T08:30:40Z"),
            I("formula:openssl@3", "homebrew", "openssl@3", "vulnerable", kind="formula",
              installed_version="3.3.1", latest_version="3.4.0", source_at="2026-10-29T08:30:40Z"),
            I("formula:node", "homebrew", "node", "pinned", kind="formula",
              installed_version="22.9.0", latest_version="23.1.0", source_at="2026-10-29T08:30:40Z",
              note="Pinned with brew pin. Watchtower does not update pinned items."),
            I("formula:acme/tools/widget", "homebrew", "widget", "manual", kind="formula",
              installed_version="1.0", origin="acme/tools",
              note="Watchtower cannot check tap acme/tools."),
            I("cask:zed", "homebrew", "Zed", "error", kind="cask", installed_version="0.158.2",
              error="Homebrew API did not respond.", detail="urlopen error timed out"),
            I("npm:left-pad", "projects", "left-pad", "unknown", kind="npm",
              installed_version="1.3.0", project="watchtower"),
        ],
    )
    return store


def check_fixture(name: str, text: str) -> None:
    """Assert that `text` is the JSON in fixture `name`, or rewrite the fixture on request."""
    path = FIXTURES / name
    if os.environ.get("WATCHTOWER_UPDATE_FIXTURES") == "1":
        path.write_text(json.dumps(json.loads(text), indent=2) + "\n")
    assert json.loads(text) == json.loads(path.read_text()), f"engine output differs from {path}"
