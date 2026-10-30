"""Command line entry point. The Swift app calls this and reads JSON on stdout.

Every stdout object has `schema_version`. On an error, stdout stays empty: the engine
writes {"schema_version", "error", "detail"} to stderr and exits 1.
"""
import argparse
import json
import sys

from . import __version__
from .findings import FindingError
from .models import SCHEMA_VERSION
from .scope import list_projects, set_project_active
from .store import Store, StoreError


def _emit(stream, payload: dict) -> None:
    json.dump({"schema_version": SCHEMA_VERSION, **payload}, stream)
    stream.write("\n")


def _updates(args) -> int:
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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="watchtower")
    parser.add_argument("--data-dir", help="data folder (default: ~/Library/Application Support/Watchtower)")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("version", help="print the engine version as JSON")
    sub.add_parser("state", help="print the last refresh, coverage and items as JSON")
    sub.add_parser("refresh", help="run every source, save the result, print the state as JSON")
    sub.add_parser("homebrew", help="check Homebrew formulae and casks, print coverage and items as JSON")
    sub.add_parser("macos", help="print the macOS version and build as JSON")
    sub.add_parser("apps", help="print installed apps and their cask links as JSON")
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
    sub.add_parser("incidents", help="print the vendor incident records, sources and review as JSON")
    sub.add_parser("incidents-check", help="check the vendor sources now, save the result, print it as JSON")
    for name, helptext in (("finding-defer", "defer a finding for 7 or 30 days"),
                           ("finding-backlog", "move a finding to the backlog"),
                           ("finding-reopen", "take a deferred or backlog finding back to open")):
        fp = sub.add_parser(name, help=helptext)
        fp.add_argument("id", help="finding id, for example SEC-0001")
        if name == "finding-defer":
            fp.add_argument("days", type=int, choices=(7, 30))
    pstate = sub.add_parser("project-state", help="mark one project active or inactive")
    pstate.add_argument("path", help="project folder")
    pstate.add_argument("state", choices=("active", "inactive"))
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

            def progress(done, total, label):
                _emit(sys.stderr, {"progress": {"done": done, "total": total, "source": label}})
                sys.stderr.flush()

            with StopOnSigterm() as guard, Store(data_dir) as store:
                try:
                    state = run_refresh(store, default_sources(data_dir), progress, guard)
                except Cancelled:
                    _emit(sys.stderr, {"error": "Refresh stopped.", "detail": None})
                    return 130
            _emit(sys.stdout, state)
            return 0
        if args.cmd == "incidents":
            with Store(args.data_dir) as store:
                state = store.incident_state()
            _emit(sys.stdout, state)
            return 0
        if args.cmd == "incidents-check":
            return _incidents_check(args)
        if args.cmd in ("update-plan", "update-run", "update-log"):
            return _updates(args)
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
        if args.cmd == "projects":
            _emit(sys.stdout, list_projects(args.data_dir).to_dict())
            return 0
        if args.cmd == "project-state":
            project = set_project_active(args.path, args.state == "active", args.data_dir)
            _emit(sys.stdout, {"project": project.to_dict()})
            return 0
    except StoreError as exc:
        _emit(sys.stderr, {"error": str(exc), "detail": exc.detail})
        return 1
    except FindingError as exc:
        _emit(sys.stderr, {"error": str(exc), "detail": None})
        return 1
    except Exception as exc:  # Never let a traceback reach stdout.
        _emit(sys.stderr, {"error": "The Watchtower engine failed.", "detail": repr(exc)})
        return 1
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
