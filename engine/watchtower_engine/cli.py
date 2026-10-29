"""Command line entry point. The Swift app calls this and reads JSON on stdout.

Every stdout object has `schema_version`. On an error, stdout stays empty: the engine
writes {"schema_version", "error", "detail"} to stderr and exits 1.
"""
import argparse
import json
import sys

from . import __version__
from .models import SCHEMA_VERSION
from .store import Store, StoreError


def _emit(stream, payload: dict) -> None:
    json.dump({"schema_version": SCHEMA_VERSION, **payload}, stream)
    stream.write("\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="watchtower")
    parser.add_argument("--data-dir", help="data folder (default: ~/Library/Application Support/Watchtower)")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("version", help="print the engine version as JSON")
    sub.add_parser("state", help="print the last refresh, coverage and items as JSON")
    sub.add_parser("homebrew", help="check Homebrew formulae and casks, print coverage and items as JSON")
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
        if args.cmd == "homebrew":
            from .inventory import homebrew
            from .store import default_data_dir

            _emit(sys.stdout, homebrew.collect(args.data_dir or default_data_dir()).to_dict())
            return 0
    except StoreError as exc:
        _emit(sys.stderr, {"error": str(exc), "detail": exc.detail})
        return 1
    except Exception as exc:  # Never let a traceback reach stdout.
        _emit(sys.stderr, {"error": "The Watchtower engine failed.", "detail": repr(exc)})
        return 1
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
