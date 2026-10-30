"""Agent mode of the CLI (#111): `watchtower --agent NAME <command>`. `scripts/watchtower-agent` starts it.

Owner decisions (2026-10-30): agents may read findings and metadata, refresh, and plan updates.
Agents may run non-major updates only. Major updates stay with the owner in the app.
Every agent refresh and update is marked with the agent name (`actor`).

NAME is `claude-code`, `codex` or `other`. Without `--agent`, the app output does not change.

Commands
- `version`, `state`, `update-log`: read only.
- `findings [--severity S] [--ecosystem E] [--project NAME_OR_PATH] [--status S]`: comma lists.
  The default status is `open`. `--status all` gives every status.
- `refresh`: runs every source. The refresh record gets `actor`. No progress lines.
- `update-plan ITEM`: the plan. It writes no update-log row.
- `update-run ITEM --plan-id ID`: non-major plans with no install scripts only. The log row gets `actor`.
- Every other command, `--confirm-major` and `--confirm-scripts`: `not_allowed`.

Output
- Success: stdout has one line `{"schema_version", "ok": true, "command", "data"}`. Exit 0.
- Error: stdout stays empty. stderr has one line
  `{"schema_version", "ok": false, "error": {"code", "message", "detail"}}`.
  `detail` is null, a string or an object. No progress lines and no prose.

`data` for each command
- `version`: `{"engine"}`.
- `state`: `{"refresh", "coverage", "items", "findings"}`. `refresh` has `actor`.
- `update-log`: `{"attempts"}`, newest first. Each attempt has `actor`.
- `findings`: `{"findings", "last_refresh_at", "stale"}`. `stale` is true if no refresh finished in the
  last 24 hours. Each finding has the app fields and `relevance`:
  `summary` (one sentence), `signals` (`severity`, `kev`, `kev_due`, `epss_percentile`, `malware`),
  `active_projects`, `next_steps`, `blockers` (why an agent cannot fix it now) and `update_item`
  (the key for `update-plan`, or null).
- `refresh`: the same object as `state`.
- `update-plan`: `{"plan", "agent_refusal"}`. `agent_refusal` is null if an agent may run the plan,
  else the error code that `update-run` gives.
- `update-run`: `{"attempt", "plan"}`. `attempt.status` is `verified`, `lockfile_updated` or `pin_updated`.

Error codes
| code | exit | when |
|---|---|---|
| `usage` | 2 | bad flag or value |
| `not_found` | 1 | unknown item |
| `not_allowed` | 3 | closed to agents |
| `major_refused` | 3 | major plan. The log has a `refused` row |
| `scripts_refused` | 3 | the plan runs install scripts. The log has a `refused` row |
| `plan_changed` | 1 | old plan id. The log has a `plan_changed` row. `detail.plan` is the new plan |
| `locked` | 4 | another refresh or update runs. `detail`: `held_by`, `command`, `since` |
| `update_failed` | 1 | the update failed, did not verify, or the plan refuses it. `detail.attempt` |
| `interrupted` | 130 | SIGTERM |
| `engine_failed` | 1 | any other error |
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone

from . import __version__
from .findings import SEVERITIES, STATUSES, Finding
from .models import SCHEMA_VERSION, utc_now
from .store import Store, StoreError, default_data_dir

AGENTS = ("claude-code", "codex", "other")
ALLOWED = ("version", "state", "update-log", "findings", "refresh", "update-plan", "update-run")
STALE_AFTER = timedelta(hours=24)

EXIT_CODES = {"usage": 2, "not_found": 1, "not_allowed": 3, "major_refused": 3, "scripts_refused": 3,
              "plan_changed": 1, "locked": 4, "update_failed": 1, "interrupted": 130, "engine_failed": 1}

MESSAGE_NOT_ALLOWED = "Agents cannot run `{command}`. The owner does this in the app."
MESSAGE_CONFIRM = "Agents cannot use `{flag}`. The owner confirms this in the app."
MESSAGE_MAJOR = "Major updates need the owner in the app."
MESSAGE_SCRIPTS = "This update runs install scripts. The owner confirms them in the app."
MESSAGE_PLAN_CHANGED = "The plan changed. Read the new plan and use its id."
MESSAGE_NOT_FOUND = "There is no item {item}."
MESSAGE_INTERRUPTED = "The {command} was interrupted."
MESSAGE_FAILED = "The Watchtower engine failed."
MESSAGE_NO_COMMAND = "Give a command: " + ", ".join(ALLOWED) + "."

# Relevance texts.
BLOCK_STATUS = "The finding is {status}."
BLOCK_WITHDRAWN = "The source withdrew the advisory."
BLOCK_NO_FIX = "No fixed version is known."
BLOCK_INACTIVE = "Every project with this finding is inactive."
BLOCK_MAJOR = "The fix {fixed} is a new major version. The owner runs it in the app."
BLOCK_NO_ADAPTER = "Watchtower updates projects with package-lock.json, uv.lock, Cargo.lock or requirements.txt only."
FIX_ONLY_LOCKFILES = ("uv.lock", "Cargo.lock", "requirements.txt")
STEP_PLAN = "Run `update-plan {key}`, then `update-run {key} --plan-id <id>`."
OK_STATUSES = ("verified", "lockfile_updated", "pin_updated")


class UsageError(Exception):
    """A bad flag or value. In agent mode the parser raises it instead of printing help."""


class AgentError(Exception):
    def __init__(self, code: str, message: str, detail=None):
        super().__init__(message)
        self.code, self.message, self.detail = code, message, detail


def wants_agent(argv: list[str]) -> bool:
    return any(a == "--agent" or a.startswith("--agent=") for a in argv)


def _emit(stream, payload: dict) -> None:
    json.dump({"schema_version": SCHEMA_VERSION, **payload}, stream)
    stream.write("\n")
    stream.flush()


def run(parser, argv: list[str]) -> int:
    """Parse `argv` with the CLI parser and run one agent command. Returns the exit code."""
    command = None
    try:
        try:
            args = parser.parse_args(argv)
        except UsageError as exc:
            raise AgentError("usage", str(exc)) from None
        command = args.cmd
        if command is None:
            raise AgentError("usage", MESSAGE_NO_COMMAND)
        data = _dispatch(args)
    except AgentError as exc:
        _emit(sys.stderr, {"ok": False, "error": {"code": exc.code, "message": exc.message, "detail": exc.detail}})
        return EXIT_CODES[exc.code]
    except StoreError as exc:
        _emit(sys.stderr, {"ok": False, "error": {"code": "engine_failed", "message": str(exc),
                                                  "detail": exc.detail}})
        return 1
    except Exception as exc:  # Never let a traceback reach stdout.
        _emit(sys.stderr, {"ok": False, "error": {"code": "engine_failed", "message": MESSAGE_FAILED,
                                                  "detail": repr(exc)}})
        return 1
    _emit(sys.stdout, {"ok": True, "command": command, "data": data})
    return 0


def _dispatch(args) -> dict:
    if args.cmd not in ALLOWED:
        raise AgentError("not_allowed", MESSAGE_NOT_ALLOWED.format(command=args.cmd))
    if args.cmd == "version":
        return {"engine": __version__}
    if args.cmd == "state":
        with Store(args.data_dir) as store:
            return _state(store)
    if args.cmd == "update-log":
        from .update_log import UpdateLog

        with Store(args.data_dir) as store:
            return {"attempts": [a.to_agent_dict() for a in UpdateLog(store).attempts()]}
    if args.cmd == "findings":
        filters = parse_filters(args)
        with Store(args.data_dir) as store:
            return findings_data(store, filters, args.data_dir)
    if args.cmd == "refresh":
        return _refresh(args)
    if args.cmd == "update-plan":
        return _update_plan(args)
    return _update_run(args)


def _state(store: Store) -> dict:
    state = store.state()
    latest = store.latest_refresh()
    if latest is not None:
        state["refresh"]["actor"] = latest.actor
    return state


# Findings


def _comma_list(value: str | None, allowed: tuple[str, ...] | None, flag: str) -> list[str] | None:
    if value is None:
        return None
    values = [v.strip() for v in value.split(",") if v.strip()]
    if not values:
        raise UsageError(f"{flag} needs a value.")
    if allowed is not None:
        values = [v.lower() for v in values]
        bad = [v for v in values if v not in allowed]
        if bad:
            raise UsageError(f"{flag} must be one of {', '.join(allowed)}, not {bad[0]!r}.")
    return values


def parse_filters(args) -> dict:
    """The `findings` filters. Raises AgentError `usage` for an unknown severity or status."""
    try:
        status = _comma_list(args.status, STATUSES + ("all",), "--status") or ["open"]
        return {
            "severity": _comma_list(args.severity, SEVERITIES, "--severity"),
            "ecosystem": _comma_list(args.ecosystem, None, "--ecosystem"),
            "project": _comma_list(args.project, None, "--project"),
            "status": None if "all" in status else status,
        }
    except UsageError as exc:
        raise AgentError("usage", str(exc)) from None


def _real(path: str) -> str:
    return os.path.realpath(os.path.expanduser(path))


def matches(finding: Finding, filters: dict) -> bool:
    if filters["status"] is not None and finding.status not in filters["status"]:
        return False
    if filters["severity"] is not None and finding.severity not in filters["severity"]:
        return False
    if filters["ecosystem"] is not None and finding.ecosystem.lower() not in {e.lower() for e in filters["ecosystem"]}:
        return False
    if filters["project"] is not None:
        names = {p.lower() for p in filters["project"]}
        paths = {_real(p) for p in filters["project"]}
        if not any(p.project.lower() in names or _real(p.project_path) in paths for p in finding.paths):
            return False
    return True


def update_key(finding: Finding, path) -> str | None:
    """The engine key that `Update…` uses for one path (same rules as `UpdateKeys` in the app)."""
    from .updates import cargo, npm, requirements, uv

    if finding.status == "resolved" or not finding.package:
        return None
    name = os.path.basename(path.lockfile)
    fixed = finding.fixed_in
    if finding.ecosystem == "PyPI" and name == "uv.lock" and fixed:
        return uv.make_key(finding.package, fixed, path.project_path, path.lockfile)
    if finding.ecosystem == "npm" and name == "package-lock.json":
        folder = os.path.dirname(path.lockfile)
        return npm.make_key(path.project_path + "/" + folder if folder else path.project_path, finding.package, fixed)
    if finding.ecosystem == "crates.io" and name == "Cargo.lock" and fixed:
        return cargo.make_key(finding.package, fixed, path.project_path, path.lockfile)
    if finding.ecosystem == "PyPI" and name == "requirements.txt" and fixed:
        return requirements.make_key(finding.package, fixed, path.project_path, path.lockfile)
    return None


def _major(version: str | None) -> int | None:
    head = (version or "").lstrip("vV").split(".", 1)[0]
    return int(head) if head.isdigit() else None


def relevance(finding: Finding, inactive: frozenset[str]) -> dict:
    """What an agent needs to rank and act on one finding."""
    active = [p for p in finding.paths if _real(p.project_path) not in inactive]
    projects = sorted({p.project for p in active})
    versions = sorted({p.version for p in finding.paths})
    blockers: list[str] = []
    if finding.status != "open":
        blockers.append(BLOCK_STATUS.format(status=finding.status))
    if finding.withdrawn_at:
        blockers.append(BLOCK_WITHDRAWN)
    if finding.fixed_in is None and finding.status != "resolved":
        blockers.append(BLOCK_NO_FIX)
    if finding.paths and not active:
        blockers.append(BLOCK_INACTIVE)
    fixed_major = _major(finding.fixed_in)
    if fixed_major is not None and any(m is not None and m < fixed_major for m in map(_major, versions)):
        blockers.append(BLOCK_MAJOR.format(fixed=finding.fixed_in))
    update_item = None
    for p in active + [p for p in finding.paths if p not in active]:
        key = update_key(finding, p)
        if p.update_block:
            blockers.append(f"{p.project} ({p.lockfile}): {p.update_block}")
        elif key is None:
            # A uv, Cargo or requirements path with no fix already has BLOCK_NO_FIX.
            if finding.status != "resolved" and os.path.basename(p.lockfile) not in FIX_ONLY_LOCKFILES:
                blockers.append(f"{p.project} ({p.lockfile}): {BLOCK_NO_ADAPTER}")
        elif update_item is None and p in active:
            update_item = key
    where = ", ".join(projects) if projects else "no active project"
    fix = f"Fixed in {finding.fixed_in}." if finding.fixed_in else "No fixed version is known."
    summary = (f"{finding.severity.capitalize()}: {finding.title} in {finding.package} "
               f"{', '.join(versions) or '(no version)'} ({where}). {fix}")
    steps = list(finding.next_steps)
    if update_item:
        steps.append(STEP_PLAN.format(key=update_item))
    return {
        "summary": summary,
        "signals": {
            "severity": finding.severity,
            "kev": finding.kev is not None,
            "kev_due": (finding.kev or {}).get("due_date"),
            "epss_percentile": (finding.epss or {}).get("percentile"),
            "malware": finding.malware is not None,
        },
        "active_projects": projects,
        "next_steps": steps,
        "blockers": blockers,
        "update_item": update_item,
    }


def _parse_time(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def findings_data(store: Store, filters: dict, data_dir=None) -> dict:
    from .scope import Scope

    inactive = Scope(data_dir or store.data_dir).inactive()
    latest = store.latest_refresh()
    last = (latest.finished_at or latest.started_at) if latest else None
    stale = last is None or _parse_time(utc_now()) - _parse_time(last) > STALE_AFTER
    rows = [f.to_dict() | {"relevance": relevance(f, inactive)} for f in store.findings() if matches(f, filters)]
    return {"findings": rows, "last_refresh_at": last, "stale": stale}


# Refresh and updates


def _locked(exc) -> AgentError:
    return AgentError("locked", exc.message, exc.holder)


def _refresh(args) -> dict:
    from .lock import Locked, engine_lock
    from .refresh import Cancelled, StopOnSigterm, default_sources, run_refresh

    data_dir = args.data_dir or default_data_dir()
    try:
        with engine_lock(data_dir, args.agent, "refresh"):
            with StopOnSigterm() as guard, Store(data_dir) as store:
                try:
                    run_refresh(store, default_sources(data_dir), guard=guard, actor=args.agent)
                except Cancelled:
                    raise AgentError("interrupted", MESSAGE_INTERRUPTED.format(command="refresh")) from None
                return _state(store)
    except Locked as exc:
        raise _locked(exc) from None


def _known_item(store: Store, item_key: str) -> bool:
    from . import updater
    from .updates import cargo, npm, requirements, uv

    if item_key.startswith((cargo.KEY_PREFIX, uv.KEY_PREFIX, requirements.KEY_PREFIX, npm.KEY_PREFIX)):
        return True
    return updater._item(store, item_key) is not None


def _plan_refusal(plan: dict) -> str | None:
    """The code that agent `update-run` gives for this plan, or None if an agent may run it."""
    if plan.get("major_change"):
        return "major_refused"
    if plan.get("scripts"):
        return "scripts_refused"
    if plan.get("refusal"):
        return "update_failed"
    return None


def _update_plan(args) -> dict:
    from . import updater

    with Store(args.data_dir) as store:
        if not _known_item(store, args.item):
            raise AgentError("not_found", MESSAGE_NOT_FOUND.format(item=args.item))
        try:
            plan = updater.plan_update(store, args.item).to_dict()
        except updater.UpdateError as exc:
            raise AgentError("engine_failed", str(exc), exc.detail) from None
    return {"plan": plan, "agent_refusal": _plan_refusal(plan)}


def _update_run(args) -> dict:
    from . import updater
    from .lock import Locked, engine_lock

    for flag, on in (("--confirm-major", args.confirm_major), ("--confirm-scripts", args.confirm_scripts)):
        if on:
            raise AgentError("not_allowed", MESSAGE_CONFIRM.format(flag=flag))
    try:
        with engine_lock(args.data_dir, args.agent, "update-run"), Store(args.data_dir) as store:
            if not _known_item(store, args.item):
                raise AgentError("not_found", MESSAGE_NOT_FOUND.format(item=args.item))
            try:
                with updater.InterruptOnSigterm():
                    attempt, plan = updater.run_update(store, args.item, args.plan_id, False, False,
                                                       actor=args.agent)
            except updater.UpdateError as exc:
                raise AgentError("engine_failed", str(exc), exc.detail) from None
            except updater.Interrupted:
                raise AgentError("interrupted", MESSAGE_INTERRUPTED.format(command="update")) from None
    except Locked as exc:
        raise _locked(exc) from None
    result = {"attempt": attempt.to_agent_dict(), "plan": plan}
    if attempt.status == "plan_changed":
        raise AgentError("plan_changed", MESSAGE_PLAN_CHANGED, result)
    if attempt.status == "refused":
        code = _plan_refusal(plan) or "update_failed"
        message = {"major_refused": MESSAGE_MAJOR, "scripts_refused": MESSAGE_SCRIPTS}.get(code, attempt.error)
        raise AgentError(code, message, result)
    if attempt.status not in OK_STATUSES:
        raise AgentError("update_failed", attempt.error or MESSAGE_FAILED, result)
    return result
