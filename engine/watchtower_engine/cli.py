"""Command line entry point. The Swift app calls this and reads JSON on stdout."""
import argparse
import json
import sys

from . import __version__


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="watchtower")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("version", help="print the engine version as JSON")
    args = parser.parse_args(argv)
    if args.cmd == "version":
        json.dump({"engine": __version__}, sys.stdout)
        sys.stdout.write("\n")
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
