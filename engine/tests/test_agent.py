"""Agent mode of the CLI (#111): envelope, findings filters and relevance, actor marks, refusals, lock."""
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from watchtower_engine import agent, refresh, updater
from watchtower_engine.cli import main
from watchtower_engine.inventory.homebrew import SourceResult
from watchtower_engine.lock import MESSAGE_AGENT, MESSAGE_APP, Locked, engine_lock
from watchtower_engine.models import SCHEMA_VERSION
from watchtower_engine.models import CoverageRecord as C
from watchtower_engine.store import Store
from watchtower_engine.update_log import UpdateLog

from contract import build_partial_state
from test_update import BREW, MAC, FakeBrew, FakeRunner, formula, seeded

REPO = Path(__file__).resolve().parents[2]
CLOSED = [
    ["research-run"], ["incidents-check"], ["finding-defer", "SEC-0001", "7"], ["finding-backlog", "SEC-0001"],
    ["finding-reopen", "SEC-0001"], ["vendor-note-withdraw", "VN-0001"], ["project-state", "/tmp/x", "inactive"],
    ["setting-set", "check-running-versions", "off"], ["homebrew"], ["apps"], ["osv"],
    ["vendor-note-add", "SEC-0001", "--vendor", "V", "--verdict", "fixed", "--statement", "S",
     "--confidence", "high", "--url", "https://example.com"],
]


def ok(capsys, argv, agent_name="codex"):
    """Run one agent command that must succeed. Returns `data`."""
    code = main(["--agent", agent_name, *argv])
    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert captured.err == ""
    lines = captured.out.splitlines()
    assert len(lines) == 1
    out = json.loads(lines[0])
    assert out.keys() == {"schema_version", "ok", "command", "data"}
    assert out["schema_version"] == SCHEMA_VERSION and out["ok"] is True and out["command"] in argv
    return out["data"]


def fails(capsys, argv, exit_code, code, agent_name="codex"):
    """Run one agent command that must fail. Returns the `error` object."""
    assert main(["--agent", agent_name, *argv]) == exit_code
    captured = capsys.readouterr()
    assert captured.out == ""
    lines = captured.err.splitlines()
    assert len(lines) == 1
    err = json.loads(lines[0])
    assert err.keys() == {"schema_version", "ok", "error"}
    assert err["ok"] is False and err["error"].keys() == {"code", "message", "detail"}
    assert err["error"]["code"] == code
    return err["error"]


@pytest.fixture
def partial(tmp_path):
    data = tmp_path / "data"
    build_partial_state(data).close()
    return str(data)


# Envelope and usage


def test_version_envelope(capsys):
    out_code = main(["--agent", "claude-code", "version"])
    out = json.loads(capsys.readouterr().out)
    assert out_code == 0
    assert out == {"schema_version": SCHEMA_VERSION, "ok": True, "command": "version", "data": out["data"]}
    assert out["data"]["engine"]


@pytest.mark.parametrize("argv", [["--agent", "robot", "version"], ["--agent", "codex", "findings", "--bogus"],
                                  ["--agent", "codex"], ["--agent", "codex", "nope"]])
def test_usage_errors_are_json(argv, capsys):
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    err = json.loads(captured.err)
    assert err["ok"] is False and err["error"]["code"] == "usage" and err["error"]["message"]


@pytest.mark.parametrize("argv", CLOSED)
def test_closed_commands_are_not_allowed(argv, tmp_path, capsys):
    err = fails(capsys, ["--data-dir", str(tmp_path / "data"), *argv], 3, "not_allowed")
    assert err["message"] == f"Agents cannot run `{argv[0]}`. The owner does this in the app."


@pytest.mark.parametrize("flag", ["--confirm-major", "--confirm-scripts"])
def test_confirm_flags_are_not_allowed(flag, tmp_path, capsys):
    err = fails(capsys, ["--data-dir", str(tmp_path), "update-run", "homebrew/formula:git", "--plan-id", "x", flag],
                3, "not_allowed")
    assert flag in err["message"]
    assert UpdateLog(Store(tmp_path)).attempts() == []


# State and findings


def test_state_marks_refresh_actor(partial, capsys):
    data = ok(capsys, ["--data-dir", partial, "state"])
    assert data["refresh"]["actor"] == "app" and data["refresh"]["status"] == "partial"


def test_findings_default_to_open(partial, capsys):
    data = ok(capsys, ["--data-dir", partial, "findings"])
    assert [f["id"] for f in data["findings"]] == ["SEC-0001"]
    assert data["last_refresh_at"] == "2026-10-29T08:31:45Z"


@pytest.mark.parametrize("flags,ids", [
    (["--status", "all"], ["SEC-0003", "SEC-0001", "SEC-0002"]),
    (["--status", "open,deferred"], ["SEC-0001", "SEC-0002"]),
    (["--status", "deferred"], ["SEC-0002"]),
    (["--status", "all", "--severity", "critical"], ["SEC-0003"]),
    (["--status", "all", "--severity", "HIGH,medium"], ["SEC-0001", "SEC-0002"]),
    (["--status", "all", "--ecosystem", "NPM"], ["SEC-0003", "SEC-0001", "SEC-0002"]),
    (["--status", "all", "--ecosystem", "PyPI,crates.io"], []),
    (["--status", "all", "--project", "admin"], ["SEC-0001"]),
    (["--status", "all", "--project", "web,api"], ["SEC-0001", "SEC-0002"]),
    (["--status", "all", "--project", "~/Projects/web"], ["SEC-0001", "SEC-0002"]),
    (["--status", "all", "--project", "nothing"], []),
])
def test_findings_filters(flags, ids, partial, capsys):
    data = ok(capsys, ["--data-dir", partial, "findings", *flags])
    assert [f["id"] for f in data["findings"]] == ids


def test_findings_filter_by_real_folder(partial, capsys):
    web = Path(os.environ["HOME"]) / "Projects" / "web"
    web.mkdir(parents=True)
    data = ok(capsys, ["--data-dir", partial, "findings", "--status", "all", "--project", str(web)])
    assert [f["id"] for f in data["findings"]] == ["SEC-0001", "SEC-0002"]


@pytest.mark.parametrize("flags", [["--severity", "urgent"], ["--status", "closed"], ["--status", ","]])
def test_bad_filter_values_are_usage_errors(flags, partial, capsys):
    fails(capsys, ["--data-dir", partial, "findings", *flags], 2, "usage")


def test_finding_relevance(partial, capsys):
    finding = ok(capsys, ["--data-dir", partial, "findings"])["findings"][0]
    assert finding["id"] == "SEC-0001" and finding["paths"]  # The app fields stay.
    assert finding["relevance"] == {
        "summary": "High: Command Injection in lodash in lodash 4.17.19, 4.17.20 (admin, web). Fixed in 4.17.21.",
        "signals": {"severity": "high", "kev": True, "kev_due": "2026-11-12", "epss_percentile": None,
                    "malware": False},
        "active_projects": ["admin", "web"],
        "next_steps": ["Update lodash to 4.17.21 or later in the lockfile.",
                       "Restart the dev server after the update.",
                       "Run `update-plan npm|~/Projects/admin|lodash|4.17.21`, then "
                       "`update-run npm|~/Projects/admin|lodash|4.17.21 --plan-id <id>`."],
        "blockers": [],
        "update_item": "npm|~/Projects/admin|lodash|4.17.21",
    }


def test_relevance_for_blocked_findings(partial, capsys):
    rows = {f["id"]: f["relevance"] for f in ok(capsys, ["--data-dir", partial, "findings", "--status", "all"])["findings"]}
    assert rows["SEC-0002"]["blockers"] == ["The finding is deferred.", "The source withdrew the advisory.",
                                            "No fixed version is known."]
    assert rows["SEC-0002"]["update_item"] == "npm|~/Projects/web|lodash|-"  # npm plans without a fix too.
    assert rows["SEC-0003"]["signals"]["malware"] is True
    assert rows["SEC-0003"]["blockers"] == ["The finding is resolved."]
    assert rows["SEC-0003"]["update_item"] is None and rows["SEC-0003"]["active_projects"] == []


def test_relevance_skips_inactive_projects(partial, capsys):
    admin = os.path.realpath(os.path.expanduser("~/Projects/admin"))
    (Path(partial) / "projects.json").write_text(json.dumps({"version": 1, "inactive": [admin]}))
    rel = ok(capsys, ["--data-dir", partial, "findings"])["findings"][0]["relevance"]
    assert rel["active_projects"] == ["web"] and rel["update_item"] == "npm|~/Projects/web|lodash|4.17.21"
    (Path(partial) / "projects.json").write_text(json.dumps(
        {"version": 1, "inactive": [admin, os.path.realpath(os.path.expanduser("~/Projects/web"))]}))
    rel = ok(capsys, ["--data-dir", partial, "findings"])["findings"][0]["relevance"]
    assert rel["active_projects"] == [] and rel["update_item"] is None
    assert "Every project with this finding is inactive." in rel["blockers"]


def test_relevance_flags_major_fix_and_unsupported_lockfile():
    from watchtower_engine.findings import Finding, FindingPath

    finding = Finding("SEC-0009", "npm", "left", "T", "low", ["X"], "2.0.0", "open", None, "t", "t", None, None,
                      "OSV", None, [FindingPath("app", "~/Projects/app", "yarn.lock", "1.4.0", None)], [])
    rel = agent.relevance(finding, frozenset())
    assert rel["blockers"] == [
        "The fix 2.0.0 is a new major version. The owner runs it in the app.",
        "app (yarn.lock): Watchtower updates projects with package-lock.json, uv.lock, Cargo.lock or "
        "requirements.txt only."]
    assert rel["update_item"] is None
    zero = Finding("SEC-0010", "crates.io", "z", "T", "low", ["X"], "0.3.0", "open", None, "t", "t", None, None,
                   "OSV", None, [FindingPath("t", "~/Projects/t", "Cargo.lock", "0.2.9", None)], [])
    rel = agent.relevance(zero, frozenset())
    assert rel["blockers"] == [] and rel["update_item"] == "cargo/z@0.3.0|~/Projects/t|Cargo.lock"


@pytest.mark.parametrize("now,stale", [("2026-10-30T08:31:45Z", False), ("2026-10-30T08:31:46Z", True)])
def test_stale_after_24_hours(now, stale, partial, monkeypatch, capsys):
    monkeypatch.setattr(agent, "utc_now", lambda: now)
    assert ok(capsys, ["--data-dir", partial, "findings"])["stale"] is stale


def test_findings_on_empty_store_are_stale(tmp_path, capsys):
    assert ok(capsys, ["--data-dir", str(tmp_path / "d"), "findings"]) == {
        "findings": [], "last_refresh_at": None, "stale": True}


def test_app_findings_command_has_no_envelope(partial, capsys):
    assert main(["--data-dir", partial, "findings", "--severity", "high"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out.keys() == {"schema_version", "findings"}
    assert [f["id"] for f in out["findings"]] == ["SEC-0001"] and "relevance" not in out["findings"][0]


# Refresh


@pytest.fixture
def fake_sources(monkeypatch):
    calls = []

    def sources(data_dir):
        def collect():
            calls.append(data_dir)
            return SourceResult(C("homebrew", "Homebrew", "complete"), [])
        return [refresh.Source("homebrew", "Homebrew", collect)]

    monkeypatch.setattr(refresh, "default_sources", sources)
    return calls


def test_agent_refresh_marks_the_record(fake_sources, tmp_path, capsys):
    data = ok(capsys, ["--data-dir", str(tmp_path), "refresh"], "claude-code")
    assert fake_sources and data["refresh"]["actor"] == "claude-code" and data["refresh"]["status"] == "complete"
    with Store(tmp_path) as store:
        assert store.latest_refresh().actor == "claude-code"
        assert UpdateLog(store).attempts() == []  # A refresh is not an update.


def test_app_refresh_output_has_no_actor(fake_sources, tmp_path, capsys):
    assert main(["--data-dir", str(tmp_path), "refresh"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert "actor" not in out["refresh"]
    with Store(tmp_path) as store:
        assert store.latest_refresh().actor == "app"


def test_agent_refresh_stopped_by_sigterm(monkeypatch, tmp_path, capsys):
    def sources(data_dir):
        def collect():
            raise refresh.Cancelled()
        return [refresh.Source("homebrew", "Homebrew", collect)]

    monkeypatch.setattr(refresh, "default_sources", sources)
    fails(capsys, ["--data-dir", str(tmp_path), "refresh"], 130, "interrupted")
    with Store(tmp_path) as store:
        assert store.latest_refresh().status == "cancelled"


# Updates


@pytest.fixture
def brew_cli(tmp_path, monkeypatch):
    """A Homebrew item and a fake brew. `brew_cli.make(stable)` sets the version on offer."""

    class Env:
        def make(self, stable="2.47.1", **extra):
            seeded(tmp_path, latest=stable).close()
            self.brew = FakeBrew(formula(stable=stable, **extra))
            self.runner = FakeRunner(self.brew, new_version=stable)
            return str(tmp_path)

    env = Env()
    real_plan, real_run = updater.plan_update, updater.run_update
    monkeypatch.setattr(updater, "plan_update",
                        lambda store, item, *a, **k: real_plan(store, item, brew=BREW, run=env.brew, **MAC))
    monkeypatch.setattr(updater, "run_update", lambda store, item, plan_id, cm, cs, out=lambda line: None, **kw:
                        real_run(store, item, plan_id, cm, cs, out, brew=BREW, run=env.brew, runner=env.runner,
                                 **MAC, **kw))
    return env


def test_agent_update_plan_and_run_log_the_actor(brew_cli, capsys):
    data = brew_cli.make()
    planned = ok(capsys, ["--data-dir", data, "update-plan", "homebrew/formula:git"])
    assert planned["agent_refusal"] is None
    with Store(data) as store:
        assert UpdateLog(store).attempts() == []  # A plan writes no row.
    result = ok(capsys, ["--data-dir", data, "update-run", "homebrew/formula:git", "--plan-id", planned["plan"]["id"]],
                "claude-code")
    assert result["attempt"]["status"] == "verified" and result["attempt"]["actor"] == "claude-code"
    log = ok(capsys, ["--data-dir", data, "update-log"])["attempts"]
    assert [(a["status"], a["actor"]) for a in log] == [("verified", "claude-code")]
    # The app reads the same log without the new field.
    assert main(["--data-dir", data, "update-log"]) == 0
    assert "actor" not in json.loads(capsys.readouterr().out)["attempts"][0]


def test_agent_major_update_is_refused_and_runs_nothing(brew_cli, capsys):
    data = brew_cli.make(stable="3.0.0")
    planned = ok(capsys, ["--data-dir", data, "update-plan", "homebrew/formula:git"])
    assert planned["plan"]["major_change"] and planned["agent_refusal"] == "major_refused"
    err = fails(capsys, ["--data-dir", data, "update-run", "homebrew/formula:git", "--plan-id", planned["plan"]["id"]],
                3, "major_refused")
    assert err["message"] == "Major updates need the owner in the app."
    assert err["detail"]["attempt"]["status"] == "refused"
    assert brew_cli.runner.calls == []
    with Store(data) as store:
        assert [(a.status, a.actor) for a in UpdateLog(store).attempts()] == [("refused", "codex")]


def test_agent_scripts_update_is_refused(brew_cli, capsys):
    data = brew_cli.make(post_install_defined=True)
    planned = ok(capsys, ["--data-dir", data, "update-plan", "homebrew/formula:git"])
    assert planned["agent_refusal"] == "scripts_refused"
    fails(capsys, ["--data-dir", data, "update-run", "homebrew/formula:git", "--plan-id", planned["plan"]["id"]],
          3, "scripts_refused")
    assert brew_cli.runner.calls == []


def test_agent_old_plan_id_is_plan_changed(brew_cli, capsys):
    data = brew_cli.make()
    err = fails(capsys, ["--data-dir", data, "update-run", "homebrew/formula:git", "--plan-id", "old"], 1,
                "plan_changed")
    assert err["detail"]["plan"]["id"] != "old" and brew_cli.runner.calls == []


def test_agent_failed_verification_is_update_failed(brew_cli, capsys):
    data = brew_cli.make()
    brew_cli.runner.new_version = None  # The command ends with 0 but nothing changed.
    plan_id = ok(capsys, ["--data-dir", data, "update-plan", "homebrew/formula:git"])["plan"]["id"]
    err = fails(capsys, ["--data-dir", data, "update-run", "homebrew/formula:git", "--plan-id", plan_id], 1,
                "update_failed")
    assert err["detail"]["attempt"]["status"] == "not_verified"


def test_agent_interrupted_update(brew_cli, capsys):
    data = brew_cli.make()
    brew_cli.runner.raise_exc = updater.Interrupted()
    plan_id = ok(capsys, ["--data-dir", data, "update-plan", "homebrew/formula:git"])["plan"]["id"]
    fails(capsys, ["--data-dir", data, "update-run", "homebrew/formula:git", "--plan-id", plan_id], 130,
          "interrupted")


@pytest.mark.parametrize("cmd", [["update-plan", "homebrew/formula:nothing"],
                                 ["update-run", "apps/com.example.none", "--plan-id", "x"]])
def test_unknown_item_is_not_found(cmd, brew_cli, capsys):
    data = brew_cli.make()
    fails(capsys, ["--data-dir", data, *cmd], 1, "not_found")


# Lock


def test_lock_blocks_agent_and_app(brew_cli, fake_sources, capsys):
    data = brew_cli.make()
    plan_id = ok(capsys, ["--data-dir", data, "update-plan", "homebrew/formula:git"])["plan"]["id"]
    with engine_lock(data, "codex", "refresh", clock=lambda: "2026-10-30T10:00:00Z"):
        err = fails(capsys, ["--data-dir", data, "update-run", "homebrew/formula:git", "--plan-id", plan_id], 4,
                    "locked", "claude-code")
        assert err["detail"] == {"held_by": "codex", "command": "refresh", "since": "2026-10-30T10:00:00Z"}
        assert err["message"] == MESSAGE_AGENT
        fails(capsys, ["--data-dir", data, "refresh"], 4, "locked")
        # The app gets the lock string from the engine and shows it.
        assert main(["--data-dir", data, "refresh"]) == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert json.loads(captured.err) == {"schema_version": SCHEMA_VERSION, "error": MESSAGE_AGENT,
                                            "detail": "refresh by codex since 2026-10-30T10:00:00Z"}
        assert main(["--data-dir", data, "update-run", "homebrew/formula:git", "--plan-id", plan_id]) == 1
        assert json.loads(capsys.readouterr().err)["error"] == MESSAGE_AGENT
        # Reads do not need the lock.
        ok(capsys, ["--data-dir", data, "findings"])
        ok(capsys, ["--data-dir", data, "update-plan", "homebrew/formula:git"])
    assert brew_cli.runner.calls == [] and fake_sources == []
    with Store(data) as store:
        assert UpdateLog(store).attempts() == []
    ok(capsys, ["--data-dir", data, "refresh"])  # Free again.


def test_app_holder_gets_app_message(tmp_path, capsys):
    with engine_lock(tmp_path, "app", "update-run"):
        err = fails(capsys, ["--data-dir", str(tmp_path), "refresh"], 4, "locked")
    assert err["message"] == MESSAGE_APP and err["detail"]["held_by"] == "app"


def test_lock_file_is_private_and_cleared(tmp_path):
    with engine_lock(tmp_path, "other", "refresh"):
        path = tmp_path / "engine.lock"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert json.loads(path.read_text())["held_by"] == "other"
        with pytest.raises(Locked):
            with engine_lock(tmp_path, "app", "refresh"):
                pass
    assert path.read_text() == ""
    with engine_lock(tmp_path, "app", "refresh"):
        pass


def test_lock_with_empty_holder_file(tmp_path):
    with engine_lock(tmp_path, "codex", "refresh"):
        (tmp_path / "engine.lock").write_text("")
        with pytest.raises(Locked) as caught:
            with engine_lock(tmp_path, "app", "refresh"):
                pass
    assert caught.value.holder == {"held_by": None, "command": None, "since": None}
    assert caught.value.message == MESSAGE_APP


def test_lock_is_released_after_an_error(tmp_path):
    with pytest.raises(RuntimeError):
        with engine_lock(tmp_path, "codex", "refresh"):
            raise RuntimeError("boom")
    with engine_lock(tmp_path, "app", "refresh"):
        pass


# Entry point


def test_shim_runs_agent_mode(tmp_path):
    env = {"HOME": str(tmp_path), "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    link = tmp_path / "watchtower-agent"
    link.symlink_to(REPO / "scripts" / "watchtower-agent")
    done = subprocess.run([str(link), "codex", "--data-dir", str(tmp_path / "d"), "version"],
                          capture_output=True, text=True, env=env, timeout=60)
    assert done.returncode == 0 and done.stderr == ""
    out = json.loads(done.stdout)
    assert out["ok"] is True and out["command"] == "version"
    done = subprocess.run([str(link), "codex", "--data-dir", str(tmp_path / "d"), "finding-backlog", "SEC-0001"],
                          capture_output=True, text=True, env=env, timeout=60)
    assert done.returncode == 3 and done.stdout == ""
    assert json.loads(done.stderr)["error"]["code"] == "not_allowed"


def test_rows_from_before_111_read_as_app(partial, capsys):
    import sqlite3

    db = sqlite3.connect(Path(partial) / "watchtower.sqlite3")
    db.execute("UPDATE refreshes SET actor = NULL")
    db.execute("CREATE TABLE update_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, item_key TEXT NOT NULL, "
               "name TEXT NOT NULL, kind TEXT, command TEXT NOT NULL, before_version TEXT, target_version TEXT, "
               "after_version TEXT, status TEXT NOT NULL, exit_code INTEGER, output TEXT NOT NULL DEFAULT '', "
               "error TEXT, manual_steps TEXT NOT NULL DEFAULT '[]', confirmed_major INTEGER NOT NULL DEFAULT 0, "
               "confirmed_scripts INTEGER NOT NULL DEFAULT 0, plan_id TEXT, pid INTEGER, started_at TEXT NOT NULL, "
               "finished_at TEXT, result_rows TEXT NOT NULL DEFAULT '[]')")
    db.execute("INSERT INTO update_attempts (item_key, name, command, status, started_at) "
               "VALUES ('homebrew/formula:git', 'git', '[]', 'verified', '2026-10-29T10:00:00Z')")
    db.commit()
    db.close()
    assert ok(capsys, ["--data-dir", partial, "state"])["refresh"]["actor"] == "app"
    assert [a["actor"] for a in ok(capsys, ["--data-dir", partial, "update-log"])["attempts"]] == ["app"]
