# Watchtower

A local-first macOS app that shows which software on this Mac is out of date or affected by a known vulnerability, and updates it with one click.

Watchtower is scheduled security research and version assessment. It is not continuous endpoint protection and not exhaustive compromise detection.

Status: in development. See `AGENTS.md`.

## Build and test

```sh
./scripts/build.sh
./scripts/test.sh
```

## Local data

The engine keeps its state in `~/Library/Application Support/Watchtower/watchtower.sqlite3`.
The folder is mode `0700` and every file in it is mode `0600`. Set `WATCHTOWER_DATA_DIR` or pass `--data-dir` to use another folder.
Scan data never goes into this repo.

## Engine CLI

The app runs the engine and reads one JSON object on stdout. Every object has `schema_version`.

| Command | Output |
|---|---|
| `watchtower version` | `{"schema_version", "engine"}` |
| `watchtower state` | `{"schema_version", "refresh", "coverage", "items"}` |

If a command fails, stdout stays empty. The engine writes `{"schema_version", "error", "detail"}` to stderr and exits 1.
The contract fixtures are in `Tests/WatchtowerCoreTests/Fixtures`. The engine tests and the Swift tests both check them.
