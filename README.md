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

`scripts/bundle.sh [out-dir]` builds `Watchtower.app` (default `build/`). The bundle has `AppIcon.icns` from `design/logo/`, the `AccentColor` asset catalog (Watchtower Indigo) and the menu bar template icons.
The UI follows `design/system.md` and the approved mockups in `design/mockups/`.

### App versions from the cask catalog (#55)

- The Apps check matches each app to the public Homebrew cask catalog. It uses no new call: the catalog is the `cask.json` file above.
- An installed cask claims its app first. Any other app matches by bundle id (from the cask `uninstall quit` and `zap trash` entries), then by app file name.
- A cask can list the bundle id of another app. If the app file name also equals a cask's app name, only those casks stay. Casks with an `@` suffix (`slack@beta`) never count as extra matches.
- One cask gives `Latest`, the source `App · Homebrew catalog`, the `Matched by` evidence and the cask homepage. More than one cask stays `Manual update`. Watchtower does not guess.
- A newer catalog version shows `Update available`. The update stays manual: `Open Vendor Page` and `Reveal in Finder`. There is no `Update` button.
- A self-updating cask compares the app's own version, not the Homebrew receipt.

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
| `watchtower incidents` | `{"schema_version", "incidents", "sources", "review", "gaps"}`: the saved vendor incident records |
| `watchtower incidents-check` | The same, after a check of the vendor sources. Progress lines go to stderr. SIGTERM stops it and saves nothing |
| `watchtower osv` | `{"schema_version", "coverage", "databases", "projects", "matches"}` for an offline OSV-Scanner lockfile scan |

If a command fails, stdout stays empty. The engine writes `{"schema_version", "error", "detail"}` to stderr and exits 1.
The contract fixtures are in `Tests/WatchtowerCoreTests/Fixtures`. The engine tests and the Swift tests both check them.

## External calls

| Call | Data sent | When |
|---|---|---|
| GET `https://formulae.brew.sh/api/formula.json` | None. The full public catalog. A cached `If-None-Match` ETag. | Homebrew check, if formulae are installed |
| GET `https://formulae.brew.sh/api/cask.json` | None. The full public catalog. A cached `If-None-Match` ETag. | Homebrew check, if casks are installed. Apps check, if any app is found (#55) |
| GET `https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_darwin_<arch>` | None. The pinned release asset. | OSV scan, if the verified scanner is missing |
| GET `https://osv-vulnerabilities.storage.googleapis.com/{npm,PyPI}/all.zip` | The ecosystem name only. A cached `If-None-Match` ETag. | OSV scan, each refresh, for ecosystems with lockfiles |
| GET `https://registry.npmjs.org/<package>` and `/<package>/<version>` | The package name and a version only. | npm update plan, after the owner clicks `Update…` |
| `npm install --package-lock-only` in a temp copy of `package.json` and `package-lock.json` | What npm sends to its registry (package names and versions). It uses your npm config. | npm update plan |
| `mas version` and `mas list --json` | Nothing. Local calls. mas reads the Spotlight index. | Apps inventory, each refresh, only if an app has an App Store receipt |
| `mas outdated --json <id>` | The App Store ID of one app. mas asks the App Store. | App Store update plan, after the owner clicks `Check for Update…` |
| GET `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | None. A static file. | KEV check, each refresh |
| GET `https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json` | None. The official CISA mirror. | KEV check, only if the CISA file fails |
| GET `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | None. A bulk download of the whole public EPSS file (about 3 MB). No CVE list, finding id or inventory data. The URL answers 302 to the file of the day. | EPSS check, each refresh, at most once a day (the cached file is used for 24 hours) |
| GET `https://api.github.com/advisories?ghsa_id=<id>&type=reviewed` and `type=malware` | One advisory id (GHSA, or CVE if the finding has no GHSA id). No package, version, path or project. | GitHub check, only for advisory ids that the local OSV databases do not have. At most 40 requests for each refresh. Answers are reused for 7 days. No token |
| GET `https://pypi.org/pypi/<package>/<version>/json` | The package name and the target version of a uv update. | The plan of a uv update, to see if the target has a wheel for this Mac |
| GET `<SUFeedURL>`, the Sparkle appcast address in an app's `Info.plist` | None about this Mac. A `Watchtower/<version>` User-Agent. HTTPS only. | App check, each refresh, for apps that Homebrew does not cover |
| GET `https://sofafeed.macadmins.io/v2/macos_data_feed.json` and `/v2/safari_data_feed.json` | None. Two public bulk feeds (SOFA, MacAdmins). No version, path, bundle id or finding. | SOFA check, each refresh |
| GET `https://github.blog/security/feed/` | None. A static feed. | Check Sources (on demand only) |
| GET `https://www.google.com/appsstatus/dashboard/incidents.json` | None. A static feed. | Check Sources (on demand only) |
| GET `https://support.apple.com/en-us/100100` | None. A static page: the table of Apple security releases. | Check Sources (on demand only) |

The Homebrew check also runs one local command: `brew info --json=v2 --installed`, with `HOMEBREW_NO_AUTO_UPDATE=1`.
It never runs `brew update`, `brew upgrade` or install scripts.
The engine keeps a small catalog index in `cache/homebrew/` in the data folder. If a fetch fails, the engine uses that index and reports its original age.

The macOS and app check makes no network call, except the Sparkle feeds below. It reads `/System/Library/CoreServices/SystemVersion.plist`, each app's `Info.plist`, the Electron framework `Info.plist` and the first 4 KB of each main executable.
It never launches an app. For the cask links, `watchtower apps` also runs the `brew info` command above, once.

The Sparkle check reads the appcast of each app that has `SUFeedURL` and no usable Homebrew answer (#14).
It refuses an address that is not HTTPS, has a user name, password or secret query value, or points to this Mac or a local network. A redirect must pass the same rules.
The appcast is untrusted data. The engine refuses a DTD or entities, reads at most 5 MB and 500 items, and reads only the version, minimum macOS and channel fields.
It compares the newest stable release with the installed `CFBundleVersion`. It never installs: use the app's Check for Updates command.
The last good answer of each feed stays in `cache/sparkle.json` in the data folder. If a feed fails, the engine shows that answer and its date.
The SOFA check (#58) compares the installed macOS version and build and the Safari version with the SOFA feeds. The compare runs on this Mac.
The engine reads only known fields of the feeds, with format checks and limits. It shows the latest release, the CVEs that newer releases fix and the actively exploited CVEs.
The Apple security releases page (`https://support.apple.com/en-us/100100`) stays the primary source. SOFA is a summary of that page.
Safari compares within its installed major version. The engine keeps the last copy in `cache/sofa/feeds.json`. If a feed fails, it uses that copy and the coverage is `partial`.
Watchtower never installs macOS or Safari. The `Open Software Update` button opens System Settings.

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

### npm (one direct dependency in one project)
- `Update…` on an npm finding plans one package in one project with `package-lock.json` (version 2 or 3).
- The plan resolves the new lockfile in a temp copy, so the project and `node_modules` do not change before you confirm.
- The plan shows `package.json`, `package-lock.json` and every other package that changes.
- The install always runs with `--ignore-scripts`. Install scripts run with `npm rebuild <package>` only after a second confirmation that names the package and the script.
- Watchtower refuses workspaces, git, file and URL dependencies, transitive packages and complex version ranges. It never runs `npm audit fix`.
- If the project files change after the plan, the plan changes and nothing runs. If the install fails, `package.json` and `package-lock.json` go back to their state before the run.
- Verification reads the lockfile and `node_modules/<package>/package.json` separately. Only both together count as `Updated`.
- The npm and uv adapters share the plan, confirm, verify and log flow of Homebrew updates. Their plan rows and result rows come from the engine.

### uv dependency update

`Update…` in a finding or in the project detail plans the update of one direct dependency in a uv project. The item key is `uv/<package>@<fixed version>|<project path>|uv.lock`.
- The one command is `uv --project <folder> sync --upgrade-package <package>==<version> --inexact --no-build [--group <group>] [--extra <extra>]`. The groups and extras come from `pyproject.toml` and show in the plan.
- The plan reads `pyproject.toml`, `uv.lock`, the files of the existing `.venv` and one PyPI page. `uv lock --dry-run` shows the other packages that change. The engine starts no program to read the environment.
- `--no-build` keeps source builds off. If the target has no wheel for this Mac, the scripts step asks first, and only the second confirmation runs the command without `--no-build`.
- uv runs with `UV_PYTHON_DOWNLOADS=never` and without `UV_*` variables of the owner. Watchtower never creates or rebuilds an environment. It refuses a project with no `.venv`, a workspace, a git or path dependency, a package that is not a direct dependency, and a requirement in `pyproject.toml` that does not allow the target.
- Watchtower does not edit `pyproject.toml`. Before the run it copies `pyproject.toml` and `uv.lock` to `update-backups/attempt-<id>/` in the data folder.
- Success needs both: `uv.lock` and the installed package in `.venv` show the target. A new lock with the old installed version stays `Not verified`. A changed file other than `uv.lock`, or a replaced environment, is also `Not verified`.

### Mac App Store apps (mas)

- An app with an App Store receipt shows `App Store` as its source. The `Latest` column stays `—`.
- Pinned `mas`: 7.0.0 (`mas list --json` needs 7.0.0). Watchtower accepts 7.x from 7.0.0. Another version shows `mas <version> is not supported.`
- The inventory runs `mas version` and `mas list --json` only. It never runs `mas outdated`.
- `Check for Update…` runs `mas outdated --json <id>` in the plan step. If the app is current, the sheet says `<name> is up to date (<version>).`
- The one command is `mas update <id>`. App Store updates use no package scripts, so the plan says `Not used by App Store updates.`
- States from mas output: not signed in (`Sign in to the App Store, then try again.`), needs an administrator (`This update needs an administrator. Use the App Store app.`), Spotlight cannot find apps (`App Store: partial` in Coverage).
- Success needs the engine to read the installed version again from the app's `Info.plist`. Exit code 0 alone is `Not verified`.

## Findings

Each refresh turns the OSV scan into stable findings. A finding is one advisory, with all its aliases, for one package. It has an id like `SEC-0001` that no later scan changes or reuses.
A finding lists every local lockfile that has the package. Only a complete scan resolves a finding: OSV coverage `complete` with no error, and every lockfile of the finding scanned.
A partial, stale or failed scan never removes a path or resolves a finding. The findings are saved in the same SQLite file as the rest of the state.

Two feeds add marks to the findings. CISA KEV marks `Known exploited`. GitHub marks `Malware` and `Withdrawn`.
A mark comes from the advisory ids of the finding only. The engine never infers exposure from a product name.
If a feed fails, the old marks stay and the Source section of the finding shows the failure and the age of the data. The engine keeps the last answers in `cache/kev/` and `cache/github/` in the data folder.

The GitHub check reads the local OSV databases first (`osv/osv-scalibr/<ecosystem>/all.zip`, from the OSV scan). They hold the reviewed GHSA records and the malicious-package (`MAL`) records with their GHSA aliases.
If a database has the id, the engine uses that record and sends no request. The age of that answer is the age of the database.
A GHSA record that lists a `MAL-` alias can be malware on GitHub. The engine sends that id to the API (#66).
Only the other ids go to the GitHub API. The call list above does not change: no new host and no token.
If the 40-request limit leaves ids, the coverage is `partial` with `request limit`. A later refresh asks only for those ids, because answers stay valid for 7 days.

### EPSS (exploit chance)

- EPSS (FIRST) gives each CVE a score: the chance of exploit in the next 30 days. Only a bulk download is used: the whole public file, one GET, no per-finding request.
- The engine keeps the file in `cache/epss/` in the data folder and downloads it again only after one day. The Source row of a finding shows the retrieval time.
- A finding with a CVE shows the score (`94%`, `2.1%`, `<0.1%`) and the percentile. With several CVEs it shows the highest score. A finding without a CVE shows `EPSS covers CVEs only.`
- Sort order: malware, known exploited, EPSS high to low, then severity. A finding with no score sorts by severity after the others.
- Data older than 2 days shows in orange. A failed download makes the EPSS coverage `partial` and keeps the earlier scores.

## Incidents

`Check Sources` (the `Incidents` screen, ⌘6) reads three public vendor sources: the GitHub security blog, the Google Workspace status feed and the Apple security releases page. Each Apple release in the review window is a record with the status `Possible relevance`: the page lists releases, not attacks. It runs only when the owner clicks it. A refresh does not run it, and it does not start a refresh.
- Each request is one plain GET of a fixed URL. No path, project, package, account or inventory data goes out.
- Feed text is untrusted. The engine removes markup and control characters, cuts the length, keeps only https links on the host of the source, and refuses a feed with a DOCTYPE or an entity. It never follows a link or reads an instruction in the text.
- Statuses: `Confirmed` (the vendor's own incident record says so: a status page, in the voice of the vendor), `Possible relevance` (the service matches, the impact on the owner is not known), `Unconfirmed` (no primary source). A blog post or a release page is at most `Possible relevance`: advice or a notice is not a confirmation. Watchtower never says that an account is affected.
- An incident does not need a CVE. A record is never removed or resolved because a feed stopped listing it. A later check can raise its status, never lower it.
- A review window ends now and starts 48 hours before the end of the last complete review (7 days back for the first). A review is complete only if every source finished. A failed source makes it partial: its row shows the failure, the other incidents are saved, and the label keeps the end date of the last complete review. Days that no review covers show as a gap.
- A quiet feed does not prove that no breach happened. The empty result says so.
