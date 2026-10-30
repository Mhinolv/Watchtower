"""Command line entry point. The Swift app calls this and reads JSON on stdout.

Every stdout object has `schema_version`. On an error, stdout stays empty: the engine
writes {"schema_version", "error", "detail"} to stderr and exits 1.

`--agent NAME` selects agent mode (#111). See `agent.py` for its commands, output and error codes.
`refresh` and `update-run` hold the engine lock (`lock.py`) in both modes.
"""
import argparse
import json
import os
import sys

from . import __version__
from . import agent
from .findings import FindingError
from .models import SCHEMA_VERSION
from .scope import list_projects, set_project_active
from .store import Store, StoreError
from .vendor_notes import VendorNoteError


def _emit(stream, payload: dict) -> None:
    json.dump({"schema_version": SCHEMA_VERSION, **payload}, stream)
    stream.write("\n")


class _Parser(argparse.ArgumentParser):
    """In agent mode a bad flag raises agent.UsageError: the agent gets JSON, not help text."""

    agent_mode = False

    def error(self, message):
        if self.agent_mode:
            raise agent.UsageError(message)
        super().error(message)


def _locked(exc) -> int:
    holder = exc.holder
    _emit(sys.stderr, {"error": exc.message,
                       "detail": f"{holder['command'] or 'a command'} by {holder['held_by'] or 'unknown'} "
                                 f"since {holder['since'] or 'unknown'}"})
    return 1


def _updates(args) -> int:
    from .lock import Locked, engine_lock

    if args.cmd == "update-run":
        try:
            with engine_lock(args.data_dir, "app", "update-run"):
                return _run_updates(args)
        except Locked as exc:
            return _locked(exc)
    return _run_updates(args)


def _run_updates(args) -> int:
    from .update_log import UpdateLog
    from .updater import InterruptOnSigterm, Interrupted, UpdateError, plan_update, run_update

    with Store(args.data_dir) as store:
        try:
            if args.cmd == "update-plan":
                _emit(sys.stdout, {"plan": plan_update(store, args.item).to_dict()})
                return 0
            if args.cmd == "update-log":
                _emit(sys.stdout, {"attempts": [a.to_dict() for a in UpdateLog(store).attempts()]})
                return 0

            def output(line):
                try:
                    _emit(sys.stderr, {"output": line})
                    sys.stderr.flush()
                except OSError:
                    pass  # The app went away. The update goes on and the log keeps the output.

            with InterruptOnSigterm():
                attempt, plan = run_update(store, args.item, args.plan_id, args.confirm_major,
                                           args.confirm_scripts, output)
            _emit(sys.stdout, {"attempt": attempt.to_dict(), "plan": plan})
            return 0
        except UpdateError as exc:
            _emit(sys.stderr, {"error": str(exc), "detail": exc.detail})
            return 1
        except Interrupted:
            _emit(sys.stderr, {"error": "The update was interrupted.", "detail": None})
            return 130


def _incidents_check(args) -> int:
    """`incidents-check`: progress lines on stderr, the incident state on stdout. SIGTERM stops it."""
    import signal

    from .research.records import Cancelled

    def progress(done, total, label):
        _emit(sys.stderr, {"progress": {"done": done, "total": total, "source": label}})
        sys.stderr.flush()

    def stop(signum, frame):
        raise Cancelled()

    previous = signal.signal(signal.SIGTERM, stop)
    try:
        with Store(args.data_dir) as store:
            try:
                state = store.check_sources(progress=progress)
            except Cancelled:
                _emit(sys.stderr, {"error": "The check was stopped.", "detail": None})
                return 130
    finally:
        signal.signal(signal.SIGTERM, previous)
    _emit(sys.stdout, state)
    return 0


def _research_run(args) -> int:
    """`research-run`: the incident state with the outcome in `research` on stdout. SIGTERM stops the run:
    the Claude process ends and nothing is saved."""
    import signal

    from .research.claude import Stopped

    def stop(signum, frame):
        raise Stopped()

    previous = signal.signal(signal.SIGTERM, stop)
    try:
        with Store(args.data_dir) as store:
            state = store.research()
    finally:
        signal.signal(signal.SIGTERM, previous)
    _emit(sys.stdout, state)
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    agent_mode = agent.wants_agent(argv)
    parser = type("Parser", (_Parser,), {"agent_mode": agent_mode})(prog="watchtower")
    parser.add_argument("--data-dir", help="data folder (default: ~/Library/Application Support/Watchtower)")
    parser.add_argument("--agent", choices=agent.AGENTS, help="agent mode for this agent (see agent.py)")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("version", help="print the engine version as JSON")
    sub.add_parser("state", help="print the last refresh, coverage and items as JSON")
    sub.add_parser("refresh", help="run every source, save the result, print the state as JSON")
    sub.add_parser("homebrew", help="check Homebrew formulae and casks, print coverage and items as JSON")
    sub.add_parser("macos", help="print the macOS version and build as JSON")
    sub.add_parser("apps", help="print installed apps and their cask links as JSON")
    sub.add_parser("settings", help="print the settings as JSON")
    sset = sub.add_parser("setting-set", help="change one setting, print the settings as JSON")
    sset.add_argument("name", choices=("check-running-versions",))
    sset.add_argument("value", choices=("on", "off"))
    sub.add_parser("projects", help="print the projects, root errors and skipped links as JSON")
    sub.add_parser("osv", help="scan the lockfiles of active projects offline with OSV-Scanner, print JSON")
    uplan = sub.add_parser("update-plan", help="plan one Homebrew update, print the plan as JSON")
    uplan.add_argument("item", help="item key, for example homebrew/formula:git")
    urun = sub.add_parser("update-run", help="run one confirmed update, print the logged attempt as JSON")
    urun.add_argument("item", help="item key, for example homebrew/formula:git")
    urun.add_argument("--plan-id", required=True, help="id of the plan that the owner confirmed")
    urun.add_argument("--confirm-major", action="store_true", help="the owner confirmed a new major version")
    urun.add_argument("--confirm-scripts", action="store_true", help="the owner confirmed install scripts")
    sub.add_parser("update-log", help="print the update log as JSON")
    fnd = sub.add_parser("findings", help="print the findings that match the filters as JSON")
    fnd.add_argument("--severity", help="comma list: critical, high, medium, low, unknown")
    fnd.add_argument("--ecosystem", help="comma list, for example npm,PyPI")
    fnd.add_argument("--project", help="comma list of project names or folders")
    fnd.add_argument("--status", help="comma list: open, deferred, backlog, resolved, all (default: open)")
    sub.add_parser("incidents", help="print the vendor incident records, sources and review as JSON")
    sub.add_parser("incidents-check", help="check the vendor sources now, save the result, print it as JSON")
    sub.add_parser("research-status", help="print whether Claude research can run, its topics and limits as JSON")
    sub.add_parser("research-run", help="run one Claude web research (5 minutes at most), print the incidents as JSON")
    for name, helptext in (("finding-defer", "defer a finding for 7 or 30 days"),
                           ("finding-backlog", "move a finding to the backlog"),
                           ("finding-reopen", "take a deferred or backlog finding back to open")):
        fp = sub.add_parser(name, help=helptext)
        fp.add_argument("id", help="finding id, for example SEC-0001")
        if name == "finding-defer":
            fp.add_argument("days", type=int, choices=(7, 30))
    vadd = sub.add_parser("vendor-note-add", help="add a vendor assessment to a finding, print the finding as JSON")
    vadd.add_argument("id", help="finding id, for example SEC-0001")
    vadd.add_argument("--vendor", required=True, help="for example Debian")
    vadd.add_argument("--verdict", required=True, choices=("fixed", "not-affected", "affected"),
                      help="what the vendor says about the installed version")
    vadd.add_argument("--statement", required=True, help="the vendor statement, for example 'Fixed by backport in 2.4.1-3.'")
    vadd.add_argument("--range", dest="affected_range", help="affected range, for example '< 2.4.1-3'")
    vadd.add_argument("--confidence", required=True, choices=("high", "medium", "low"))
    vadd.add_argument("--url", dest="source_url", required=True, help="the vendor page (http or https)")
    vadd.add_argument("--retrieved", dest="retrieved_at", help="when the page was read, 2026-10-29T09:12:00Z (default: now)")
    for name, helptext in (("vendor-note-withdraw", "mark a vendor note withdrawn; it stays in the history"),
                           ("vendor-note-check", "record that the owner checked the vendor source again")):
        vp = sub.add_parser(name, help=helptext)
        vp.add_argument("id", help="vendor note id, for example VN-0001")
    deps = sub.add_parser("dependencies", help="print the direct dependencies of one project as JSON")
    deps.add_argument("path", help="project folder")
    deps.add_argument("--max-lookups", type=int, default=None, metavar="N",
                      help="ask each registry for at most N packages (rows not asked are pending)")
    pstate = sub.add_parser("project-state", help="mark one project active or inactive")
    pstate.add_argument("path", help="project folder")
    pstate.add_argument("state", choices=("active", "inactive"))
    if agent_mode:
        return agent.run(parser, argv)
    args = parser.parse_args(argv)
    try:
        if args.cmd == "version":
            _emit(sys.stdout, {"engine": __version__})
            return 0
        if args.cmd == "state":
            with Store(args.data_dir) as store:
                state = store.state()
            _emit(sys.stdout, state)
            return 0
        if args.cmd == "refresh":
            from .refresh import Cancelled, StopOnSigterm, default_sources, run_refresh
            from .store import default_data_dir

            data_dir = args.data_dir or default_data_dir()

            from .lock import Locked, engine_lock

            def progress(done, total, label):
                _emit(sys.stderr, {"progress": {"done": done, "total": total, "source": label}})
                sys.stderr.flush()

            try:
                with engine_lock(data_dir, "app", "refresh"):
                    with StopOnSigterm() as guard, Store(data_dir) as store:
                        try:
                            state = run_refresh(store, default_sources(data_dir), progress, guard)
                        except Cancelled:
                            _emit(sys.stderr, {"error": "Refresh stopped.", "detail": None})
                            return 130
            except Locked as exc:
                return _locked(exc)
            _emit(sys.stdout, state)
            return 0
        if args.cmd in ("settings", "setting-set"):
            from . import settings

            if args.cmd == "setting-set":
                settings.save({"check_running_versions": args.value == "on"}, args.data_dir)
            _emit(sys.stdout, {"settings": settings.load(args.data_dir)})
            return 0
        if args.cmd == "incidents":
            with Store(args.data_dir) as store:
                state = store.incident_state()
            _emit(sys.stdout, state)
            return 0
        if args.cmd == "incidents-check":
            return _incidents_check(args)
        if args.cmd == "research-status":
            from .research import claude

            _emit(sys.stdout, claude.status())
            return 0
        if args.cmd == "research-run":
            return _research_run(args)
        if args.cmd in ("update-plan", "update-run", "update-log"):
            return _updates(args)
        if args.cmd == "findings":
            filters = agent.parse_filters(args)
            with Store(args.data_dir) as store:
                _emit(sys.stdout, {"findings": [f.to_dict() for f in store.findings() if agent.matches(f, filters)]})
            return 0
        if args.cmd == "homebrew":
            from .inventory import homebrew
            from .store import default_data_dir

            _emit(sys.stdout, homebrew.collect(args.data_dir or default_data_dir()).to_dict())
            return 0
        if args.cmd == "macos":
            from .inventory import macos

            _emit(sys.stdout, macos.collect().to_dict())
            return 0
        if args.cmd == "apps":
            from .inventory import apps
            from .store import default_data_dir

            from .inventory import sparkle

            data_dir = args.data_dir or default_data_dir()
            result = apps.collect_live(data_dir, sparkle_check=lambda targets: sparkle.check(targets, data_dir))
            _emit(sys.stdout, {**result.to_dict(),
                               "extra_coverage": [c.to_dict() for c in getattr(result, "extra_coverage", [])]})
            return 0
        if args.cmd == "osv":
            from .scanners import osv
            from .store import default_data_dir

            projects = list_projects(args.data_dir).projects
            _emit(sys.stdout, osv.collect(args.data_dir or default_data_dir(), projects).to_dict())
            return 0
        if args.cmd in ("finding-defer", "finding-backlog", "finding-reopen"):
            with Store(args.data_dir) as store:
                if args.cmd == "finding-defer":
                    finding = store.defer_finding(args.id, args.days)
                elif args.cmd == "finding-backlog":
                    finding = store.backlog_finding(args.id)
                else:
                    finding = store.reopen_finding(args.id)
            _emit(sys.stdout, {"finding": finding.to_dict()})
            return 0
        if args.cmd in ("vendor-note-add", "vendor-note-withdraw", "vendor-note-check"):
            with Store(args.data_dir) as store:
                if args.cmd == "vendor-note-add":
                    finding = store.add_vendor_note(
                        args.id, vendor=args.vendor, verdict=args.verdict, statement=args.statement,
                        affected_range=args.affected_range, confidence=args.confidence,
                        source_url=args.source_url, retrieved_at=args.retrieved_at)
                elif args.cmd == "vendor-note-withdraw":
                    finding = store.withdraw_vendor_note(args.id)
                else:
                    finding = store.check_vendor_note(args.id)
            _emit(sys.stdout, {"finding": finding.to_dict()})
            return 0
        if args.cmd == "projects":
            _emit(sys.stdout, list_projects(args.data_dir).to_dict())
            return 0
        if args.cmd == "dependencies":
            from .dependencies import project_dependencies
            from .store import default_data_dir

            data_dir = args.data_dir or default_data_dir()
            real = os.path.realpath(os.path.expanduser(args.path))
            project = next((p for p in list_projects(args.data_dir).projects if p.real_path == real), None)
            if project is None:
                _emit(sys.stderr, {"error": "That folder is not a project in the project roots.", "detail": None})
                return 1
            limit = {} if args.max_lookups is None else {"max_lookups": max(0, args.max_lookups)}
            with Store(data_dir) as store:
                _emit(sys.stdout, project_dependencies(project, store.findings(), data_dir, **limit))
            return 0
        if args.cmd == "project-state":
            project = set_project_active(args.path, args.state == "active", args.data_dir)
            _emit(sys.stdout, {"project": project.to_dict()})
            return 0
    except StoreError as exc:
        _emit(sys.stderr, {"error": str(exc), "detail": exc.detail})
        return 1
    except agent.AgentError as exc:  # A bad `findings` filter.
        _emit(sys.stderr, {"error": exc.message, "detail": None})
        return 2
    except (FindingError, VendorNoteError) as exc:
        _emit(sys.stderr, {"error": str(exc), "detail": None})
        return 1
    except Exception as exc:  # Never let a traceback reach stdout.
        _emit(sys.stderr, {"error": "The Watchtower engine failed.", "detail": repr(exc)})
        return 1
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
