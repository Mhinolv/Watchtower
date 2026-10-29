# Watchtower

A local-first macOS app that shows which software on this Mac is out of date or affected by a known vulnerability, and updates it with one click.

Watchtower is scheduled security research and version assessment. It is not continuous endpoint protection and not exhaustive compromise detection.

Status: in development. See `AGENTS.md`.

## Build and test

```sh
./scripts/build.sh
./scripts/test.sh
```

## App

`swift run Watchtower` opens the dashboard and the menu bar icon. The app runs the engine in `engine/` with the first Python 3 it finds.
Set `WATCHTOWER_PYTHON` or `WATCHTOWER_ENGINE_DIR` to change that.
The app reads the stored state at launch. Only the Refresh button starts a refresh.

`scripts/snapshot.sh <out-dir>` renders the dashboard scenarios offscreen to PNG files, light and dark. It uses sample data, not the engine.

## Local data

The engine keeps its state in `~/Library/Application Support/Watchtower/watchtower.sqlite3`.
The folder is mode `0700` and every file in it is mode `0600`. Set `WATCHTOWER_DATA_DIR` or pass `--data-dir` to use another folder.
Scan data never goes into this repo.

## Engine CLI

The app runs the engine and reads one JSON object on stdout. Every object has `schema_version`.

| Command | Output |
|---|---|
| `watchtower version` | `{"schema_version", "engine"}` |
| `watchtower state` | `{"schema_version", "refresh", "coverage", "items", "findings"}` |
| `watchtower refresh` | Runs every source and saves the result. Prints the state. Progress lines go to stderr. SIGTERM saves a `cancelled` refresh and exits 130 |
| `watchtower update-plan <item>` | `{"schema_version", "plan"}`: the exact command, other packages that change, script needs, refusal |
| `watchtower update-run <item> --plan-id <id> [--confirm-major] [--confirm-scripts]` | `{"schema_version", "attempt", "plan"}`. Output lines go to stderr |
| `watchtower update-log` | `{"schema_version", "attempts"}`, newest first |
| `watchtower homebrew` | `{"schema_version", "coverage", "items"}` for Homebrew formulae and casks |
| `watchtower macos` | `{"schema_version", "coverage", "items"}` for the macOS version and build |
| `watchtower apps` | `{"schema_version", "coverage", "items"}` for apps in `/Applications` and `~/Applications` |
| `watchtower finding-defer <SEC-id> 7\|30` | `{"schema_version", "finding"}`. The finding is deferred until that many days from now |
| `watchtower finding-backlog <SEC-id>` | `{"schema_version", "finding"}`. The finding moves to the backlog |
| `watchtower finding-reopen <SEC-id>` | `{"schema_version", "finding"}`. A deferred or backlog finding is open again |
| `watchtower osv` | `{"schema_version", "coverage", "databases", "projects", "matches"}` for an offline OSV-Scanner lockfile scan |

If a command fails, stdout stays empty. The engine writes `{"schema_version", "error", "detail"}` to stderr and exits 1.
The contract fixtures are in `Tests/WatchtowerCoreTests/Fixtures`. The engine tests and the Swift tests both check them.

## External calls

| Call | Data sent | When |
|---|---|---|
| GET `https://formulae.brew.sh/api/formula.json` | None. The full public catalog. A cached `If-None-Match` ETag. | Homebrew check, if formulae are installed |
| GET `https://formulae.brew.sh/api/cask.json` | None. The full public catalog. A cached `If-None-Match` ETag. | Homebrew check, if casks are installed |
| GET `https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_darwin_<arch>` | None. The pinned release asset. | OSV scan, if the verified scanner is missing |
| GET `https://osv-vulnerabilities.storage.googleapis.com/{npm,PyPI}/all.zip` | The ecosystem name only. A cached `If-None-Match` ETag. | OSV scan, each refresh, for ecosystems with lockfiles |
| GET `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | None. A static file. | KEV check, each refresh |
| GET `https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json` | None. The official CISA mirror. | KEV check, only if the CISA file fails |
| GET `https://api.github.com/advisories?ghsa_id=<id>&type=reviewed` and `type=malware` | One advisory id (GHSA, or CVE if the finding has no GHSA id). No package, version, path or project. | GitHub check, for the unresolved findings. At most 40 requests for each refresh. Answers are reused for 6 hours |

The Homebrew check also runs one local command: `brew info --json=v2 --installed`, with `HOMEBREW_NO_AUTO_UPDATE=1`.
It never runs `brew update`, `brew upgrade` or install scripts.
The engine keeps a small catalog index in `cache/homebrew/` in the data folder. If a fetch fails, the engine uses that index and reports its original age.

The macOS and app check makes no network call. It reads `/System/Library/CoreServices/SystemVersion.plist`, each app's `Info.plist`, the Electron framework `Info.plist` and the first 4 KB of each main executable.
It never launches an app. For the cask links, `watchtower apps` also runs the `brew info` command above, once.

The OSV scan runs only OSV-Scanner v2.7.0. `engine/watchtower_engine/scanners/release_pin.py` holds the SHA-256 digests from the official release.
The engine checks the digest after the download and before each run. If the digest does not match, the scanner does not run.
The scanner runs with `--offline` against the local databases in `osv/` in the data folder, so the scan sends nothing.
It scans `package-lock.json` and `uv.lock` only. A database older than 7 days makes the OSV coverage `stale`.

## Updates

The Update button plans one Homebrew formula or cask update. Nothing runs before the owner confirms.
- The plan shows the exact command, for example `/opt/homebrew/bin/brew upgrade --formula git`, and every other package that changes.
- Planning runs `brew info --json=v2` and `brew upgrade --dry-run` for that one package, with `HOMEBREW_NO_AUTO_UPDATE=1`.
- A new major version needs a second confirmation. So does a build from source, a post-install step or a package installer.
- Before the run, the engine plans again. If the plan changed, it does not run.
- After the run, the engine reads the installed version again. Only a match with the plan counts as `Updated`.
- Every attempt goes in the update log (`update_attempts` table in the store): command, versions, output, result.
- `brew upgrade` downloads the new bottle or app from Homebrew's usual sources. Watchtower sends nothing itself.
- There is no "update all" and no `brew update`.

## Findings

Each refresh turns the OSV scan into stable findings. A finding is one advisory, with all its aliases, for one package. It has an id like `SEC-0001` that no later scan changes or reuses.
A finding lists every local lockfile that has the package. Only a complete scan resolves a finding: OSV coverage `complete` with no error, and every lockfile of the finding scanned.
A partial, stale or failed scan never removes a path or resolves a finding. The findings are saved in the same SQLite file as the rest of the state.

Two feeds add marks to the findings. CISA KEV marks `Known exploited`. GitHub marks `Malware` and `Withdrawn`.
A mark comes from the advisory ids of the finding only. The engine never infers exposure from a product name.
If a feed fails, the old marks stay and the Source section of the finding shows the failure and the age of the data. The engine keeps the last answers in `cache/kev/` and `cache/github/` in the data folder.
