# Watchtower v1 research

Research date: 2026-10-29. Baseline: `613799e`. Run: `research-1`.

## Executive Summary

Build the first release around one task: inspect an item, approve its update, and see verified results.
Use Homebrew for the first app and binary updates. Add npm and uv project updates through separate adapters.
Keep outdated software, confirmed advisory matches, and possible exposure as separate states.

The competitors divide into app updaters, dependency tools, and security scanners.
Watchtower can join these workflows through a native Mac window, local records, clear coverage, and one confirmed update per item.
This is a proposed advantage. The current code does not implement it.

Two current facts affect the plan:

- MacUpdater 3.5 is free but unsupported. Its publisher stopped daily maintenance and update verification. [S2]
- OSV-Scanner v2.7.0 is the latest official release. Its default network behavior exceeds Watchtower's allowed OSV payload. [S10, S11]

The plan below contains 12 focused PRs. It defines an initial v1 scope, not complete coverage of the reference spec.
The owner must approve the listed coverage limits before the team calls this scope v1.
No new account or hosted backend is required. Optional Claude research requires a separate integration decision.

## Competitors

Prices describe the reviewed tools, not the cost of packages or commercial support. Weaknesses are comparisons with Watchtower's intended scope.

| Tool | Platform and price | Target user | Useful capability | Limit relative to Watchtower's goal |
|---|---|---|---|---|
| Latest [S1] | macOS, free and open source | Personal Mac owner | Simple app update list, App Store and Sparkle support | App coverage depends on supported update channels. Project dependencies are outside its stated scope. |
| MacUpdater [S2] | macOS 13+, free, unsupported | Personal Mac owner | App version catalog, window and menu bar updates | Maintenance ended. Do not depend on its update catalog. |
| Homebrew [S3] | macOS/Linux, free and open source | Developer | Formula and cask versions, JSON output, targeted upgrades | It covers managed software. Receipts can disagree with apps that update themselves. |
| `brew cu` [S4] | macOS, free, MIT | Homebrew user | Per-cask choice and version pins | Extra tap. Its tracked version can lag an app's own updater. |
| Topgrade [S5] | macOS/Linux/Windows, free and open source | Terminal user | Many package managers through one command | Its broad update workflow conflicts with the owner's per-item approval rule. |
| `mas` [S6] | macOS, free and open source | App Store user | App discovery, outdated checks, targeted updates, JSON output | Account, privilege, Spotlight, and metadata limits need explicit states. |
| Dependabot [S7] | GitHub repositories, included for all repositories | Repository owner | Version and security PRs, ecosystem configuration | GitHub workflow. It does not represent this Mac's installed state. |
| Renovate [S8] | Repository hosts or self-hosted, open source | Developer/team | Broad manifest support, lockfile PRs, configurable update rules | Repository setup and automation exceed a personal local dashboard's needs. |
| `npm outdated` [S9] | Node-supported platforms, free | JavaScript developer | Current, wanted, and latest versions | Outdated checks alone do not assess vulnerability or update the package. |
| `pip list --outdated` [S9] | Python-supported platforms, free | Python developer | Environment-specific package versions and JSON | It describes an environment, not all project lockfiles or deployed services. |
| OSV-Scanner [S10–S12] | macOS/Linux/Windows, free and open source | Developer | Lockfile matches, package locations, aliases, offline mode | No general Mac app updater. Default scans can contact several services. |
| Grype [S13] | macOS/Linux/Windows CLI, free and open source | Container developer | Local vulnerability database, images, directories, SBOMs | No native Mac update workflow. Database age affects coverage. |
| Trivy [S14] | Local CLI/CI, including macOS, free and open source | Developer/security team | Dependencies, images, configuration, licenses, secrets | Broad scope needs restrictions. Secret scans conflict with this product's rules. |
| Socket [S15] | Hosted service, CLI and repository integrations | Developer/team | Malicious-package alerts and supply-chain risk signals | Hosted analysis and plan limits differ from the local-first requirement. |

Socket lists a free plan, Team at $25, and Business at $50 per developer seat per month under annual billing.
The listed minimums are five Team seats and twenty Business seats. These are not single-user purchase recommendations. [S15]

## Feature Matrix

`Yes` means the cited documentation describes the capability. `Limited` states its boundary.
`—` means the capability was not established in the reviewed workflow. It is not proof of product-wide absence.

| Tool | Mac apps | CLI packages | Project versions | Known advisories | Update action | Local/offline use |
|---|---|---|---|---|---|---|
| Latest | Yes | — | — | — | Supported apps | Local app, online metadata |
| MacUpdater | Yes | — | — | — | Legacy app updater | Unsupported catalog |
| Homebrew | Casks | Yes | — | Formula option¹ | Named formula/cask | Local inventory, online updates |
| `brew cu` | Casks | — | — | — | Named cask | Local CLI, online metadata |
| Topgrade | Via managers | Yes | Tool-dependent | — | Manager commands | Local CLI, online updates |
| `mas` | App Store | — | — | — | Named app | Local inventory, Apple services |
| Dependabot | — | — | Yes | Yes | Repository PR | GitHub service |
| Renovate | — | — | Yes | Configurable | Repository PR | Self-host option |
| `npm outdated` | — | Global npm | npm | — | Separate npm command | Online registry check |
| `pip list --outdated` | — | Python environment | Installed environment | — | Separate pip command | Online index check |
| OSV-Scanner | Limited components | Supported artifacts | Lockfiles | Yes | Limited npm/Maven fixes | Offline database option |
| Grype | Limited components | Supported packages | Supported artifacts | Yes | Reports fixed versions | Local database |
| Trivy | Limited components | Supported packages | Supported artifacts | Yes | Reports fixed versions | Local scan/database options |
| Socket | — | Supported dependencies | Yes | Yes, plus malware | Plan-dependent fixes | Hosted service |
| Watchtower baseline | — | — | — | — | — | Version command only |

¹ Current Homebrew documentation includes `outdated --vulnerable` for formulae. Do not assume an older installed Homebrew supports it. [S3]

## Gap Analysis

### Verified repository gaps

I read all app and engine source files and searched these terms:
`scan|inventory|refresh|update|finding|advisory|backlog|research|Settings|MenuBarExtra`.
Only comments and package descriptions matched. No release or review document exists beyond the baseline README and team inputs.

| Gap | Code evidence | Consequence | Proposed feature |
|---|---|---|---|
| No inventory or refresh command | `engine/watchtower_engine/cli.py:9` only dispatches `version` | The app cannot assess local software | 1–4, 7 |
| No engine bridge or result models | `Sources/WatchtowerCore/Version.swift:2` contains one version constant | Swift cannot display engine results | 1, 5 |
| No action list, Settings, or menu item | `Sources/WatchtowerApp/WatchtowerApp.swift:7` shows static text | The owner cannot refresh, update, or mark projects inactive | 5 |
| No update or verification code | Complete engine file list contains `cli.py` and `__init__.py` only | No safe update transaction exists | 6, 10, 11 |
| No persistent findings or feed clients | Same complete engine source inventory | No aliases, research windows, or history exist | 8, 9, 12 |

Issue check: `gh issue list -R Mhinolv/Watchtower --state open --limit 100 --json number,title,labels` returned `[]`.
The first sandbox request failed. The permitted network retry succeeded.
No open issue duplicates existed at this check. The PM must repeat the check before issue creation.

### Local research and scope

The read-only survey checked executable locations and recognized manifest filenames under the three owner-specified roots.
It did not read manifests, project source, `.env` files, credentials, browser data, or package-manager configuration.
It did not invoke discovered binaries, project scripts, builds, or services.
Generated directories, dependency trees, worktree lanes, app contents, and directory symlinks were excluded from the manifest survey.

The survey supports npm and uv as the first project adapters.
Cargo and Swift need later coverage. Requirements files need an explicit distinction between exact pins and version ranges.
Docker and Compose files establish project intent, not a deployed or active service.
The team report contains only a capability summary. No package inventory, private project path, or installed version is retained here.

### Data sources and exact access

All endpoints below are public unless stated otherwise. These are proposed app requests, not requests sent with this Mac's inventory.
Use bounded timeouts, response-size limits, cached validators, and source-specific completion timestamps.
Keep source failures visible. A cached response retains its original age.

| Source | Access | Data sent and implementation rule |
|---|---|---|
| CISA KEV [S16] | GET `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | No inventory. Parse CVE, date added, action, source notes, and ransomware status. |
| Official KEV fallback [S16] | GET `https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json` | No inventory. This official mirror worked. The CISA endpoint returned HTTP 403 during research. |
| OSV batch [S17] | POST `https://api.osv.dev/v1/querybatch`, JSON content type | Only package name, ecosystem, version. Omit paths, hashes, commits, repository names, and source. |
| OSV details [S17] | GET `https://api.osv.dev/v1/vulns/{id}` | Advisory ID only. Batch results contain IDs and modification times, not full advisory details. |
| OSV offline data [S12] | GET `https://osv-vulnerabilities.storage.googleapis.com/{ECOSYSTEM}/all.zip` | Ecosystem selection only. Use `npm` and `PyPI` initially. Store retrieval time and digest. |
| GitHub Advisories [S18] | GET `https://api.github.com/advisories` and `/advisories/{ghsa_id}` | Prefer ecosystem/date filters and local matching. Public requests need no token. |
| Homebrew [S19] | GET `https://formulae.brew.sh/api/formula.json` and `/api/cask.json` | Full catalogs disclose no package selection. Per-item alternatives are `/api/formula/{name}.json` and `/api/cask/{token}.json`. |
| Sparkle [S20] | Read bundle `SUFeedURL`, then GET its HTTPS appcast | Vendor sees an update check. Reject credential-bearing URLs and unsafe destinations. No universal appcast endpoint exists. |
| App Store [S6] | Existing `mas list --json`, `mas outdated --json`, then confirmed `mas update <id>` | Apple receives app identifiers. Probe installed command support. Older releases use `upgrade`. |
| Electron [S21] | Read framework plist, then GET `https://releases.electronjs.org/releases.json` | Download the full public mapping. No app identity must leave the Mac. |
| npm and PyPI | Public registry metadata for a selected package | Package identifier only for version checks. Never load credential files to discover private registries. |
| Vendor incidents [S22] | GET reviewed Apple, GitHub, and Google source pages or feeds | No local inventory. Status notices alone do not establish a breach. |

OSV batch results preserve request order. Each result can have a separate `next_page_token`.
Complete every page before recording success. Deduplicate requests while retaining every local package location. [S17]

For GitHub, send `Accept: application/vnd.github+json` and the documented `X-GitHub-Api-Version: 2026-03-10`.
Use `modified`, `ecosystem`, `per_page=100`, and the response's `Link` pagination.
Fetch `type=reviewed` and `type=malware` separately. The default excludes malware.
Unauthenticated REST access has a general limit of 60 requests per hour per IP. Respect rate-limit responses. [S18]

KEV membership establishes known exploitation. It does not establish a local version match.
Absence from KEV does not establish safety. Federal due dates are source facts, not automatic personal deadlines.

### Scanner pin and privacy

The official release page identifies **v2.7.0**, released **2026-10-12**, as latest. [S10]
Use a fixed tag and reviewed architecture-specific hashes. Never resolve `latest` during an app refresh.

| Asset | Published SHA-256 |
|---|---|
| `osv-scanner_darwin_arm64` | `d4926ef8da134332543be276dff157e4c170f99ad91fc48e89448a8816bdf70b` |
| `osv-scanner_darwin_amd64` | `e82c5df7ab0a42dff29a1cd0660711447b56b4c0483ff66ad8634df10fd81a45` |

The official asset page supplied these digests. I did not download or execute either binary. [S10]
The release also supplies `osv-scanner_SHA256SUMS` and `multiple.intoto.jsonl`.
The checksum text download failed through web fetch. The implementation must cross-check it before adoption.

Download from `https://github.com/google/osv-scanner/releases/download/v2.7.0/{asset}`.
Compare bytes with the reviewed SHA-256 through Python `hashlib` before execution.
Reject mismatches. Verify the scanner's reported version after the hash check.
SLSA provenance provides an additional source check. A checksum alone does not independently establish publisher identity. [S11]

Prefer `--offline`, explicit lockfile inputs, JSON output, and no transitive resolution for the initial scanner adapter.
Set `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` to the protected application data directory.
Download ecosystem databases as a separate, recorded step.
Missing or stale databases must produce an explicit coverage state.
Offline mode does not support commit-level checks. [S12]

`--offline-vulnerabilities` is weaker than `--offline`: other features can still use the network.
Default OSV-Scanner can send file hashes to OSV and use deps.dev or package registries.
Therefore, do not use a default recursive network scan for Watchtower. [S11, S12]
An optional online adapter can use the restricted OSV payload above.
Do not silently switch from offline scans to wider scanner network access.

### Version and update boundaries

- Store app path, bundle identifier, build version, display version, architecture, and observation time as separate fields.
- Record a manifest declaration, resolved lock version, installed package, and running process as different evidence types.
- Treat a missing installed environment as unknown. A lockfile does not prove installation.
- Preserve inactive projects in Backlog. Unknown deployment status stays unknown.
- Never resolve a finding because a scan failed or a source stopped mentioning it.
- Do not use one lexical or numeric comparison for every version scheme. Preserve vendor revision and branch information.

Homebrew can update dependencies or dependents during a named upgrade.
The plan must disclose this scope and prevent unexpected expansion.
Use local package receipts plus actual app bundle versions for verification. [S3, S4]

Sparkle feeds can identify releases, minimum OS versions, channels, and signed artifacts.
Reading an appcast does not grant a generic third-party updater permission to replace an app.
Use supported Homebrew or vendor routes. Otherwise show a manual update action. [S20]

Current `mas` JSON output is a stream of objects, not necessarily one JSON array.
Its accurate outdated mode initiates downloads and can show dialogs.
Do not use that mode during passive inventory. Current updates can require root privileges and an existing App Store account. [S6]

For Electron, inspect `Contents/Frameworks/Electron Framework.framework/Resources/Info.plist` without app launch.
The upstream framework has a `Version` key. Also examine available bundle-version fields as corroboration. [S21]
Match an exact Electron version to its published Node/Chromium versions.
Label those component versions as inferred from upstream metadata.
Vendor forks, removed metadata, or backports require vendor evidence. Never substitute the shell's Node version.

For npm, distinguish the version allowed by the manifest from the registry's `latest` tag.
For uv, a lock-only upgrade is not an installed update. Environment synchronization can also change other packages. [S9, S23]
Show exact commands, affected files, collateral package changes, script/build policy, and required tests before approval.
Recheck the plan before execution. A changed version or scope invalidates the approval.

## Recommended Features

This is build order and priority order within dependencies. `S` means one narrow adapter or view. `M` means one bounded workflow.
Each PR includes fixture tests and README changes for any new external call. No PR needs a new backend or account.
Proposed filenames below do not exist yet, except the baseline entry points.

### 1. Local state and engine contract — P1, M

**Problem:** No common result or durable state exists. Grype demonstrates explicit database age and failure states. [S13]

**Behavior:** Define inventory, coverage, source time, and update-attempt records. Add versioned JSON CLI responses and SQLite persistence.
Use `0700` data directories and `0600` record files. Keep errors off JSON stdout.

**Dependencies:** None.
**Files:** `engine/watchtower_engine/{models,store,cli}.py`, `Sources/WatchtowerCore/Models.swift`, corresponding tests.
**Check:** Round-trip a partial refresh and preserve the previous successful timestamp after a failed transaction.

### 2. Project scope and manifest discovery — P1, S

**Problem:** Repository tools find manifests, but Watchtower has no local project list. Renovate provides a relevant discovery model. [S8]

**Behavior:** Discover bounded project roots and recognized filenames. Default projects to active. Persist explicit exclusions and inactive state.
Do not parse dependency contents in this PR. Report inaccessible roots and unsupported formats.

**Dependencies:** 1.
**Files:** `engine/watchtower_engine/{scope,discovery}.py`, `cli.py`, engine fixtures.
**Check:** Avoid symlink escape and duplicate worktrees. Preserve a user's inactive choice after rediscovery.

### 3. Homebrew versions and update candidates — P1, M

**Problem:** The owner cannot see outdated managed binaries or apps. Homebrew and `brew cu` supply this workflow. [S3, S4]

**Behavior:** Read installed metadata and compare authoritative formula/cask metadata. Return current version, candidate, source age, and package identity.
Control Homebrew auto-update behavior. Mark unsupported taps, unknown versions, and manager errors explicitly.

**Dependencies:** 1.
**Files:** `engine/watchtower_engine/inventory/homebrew.py`, `feeds/homebrew.py`, `cli.py`, engine tests.
**Check:** Cover retained versions, pinned packages, cask self-updates, and partial catalog failures.

### 4. macOS and app bundle inventory — P1, M

**Problem:** Manager receipts omit unmanaged apps and embedded runtimes. Latest and MacUpdater emphasize app-level evidence. [S1, S2]

**Behavior:** Read OS build and app bundle metadata from approved roots. Detect Electron metadata and preserve evidence provenance.
Associate casks only through reliable identifiers. Return a manual route for unsupported apps.
Do not add universal Sparkle installation or App Store updates in this PR.

**Dependencies:** 1, 3 for cask association.
**Files:** `engine/watchtower_engine/inventory/{macos,apps}.py`, fixtures, shared models.
**Check:** Cover duplicate bundle IDs, missing versions, nested framework metadata, and ambiguous cask associations.

### 5. Refresh dashboard and project controls — P1, M

**Problem:** No useful GUI exists. Latest demonstrates a concise app list. [S1]

**Behavior:** Add Refresh, persistent last-complete time, item details, coverage states, and a menu bar entry.
Add Settings for active projects and a Backlog filter. Keep updates disabled until feature 6 supplies a valid plan.

**Dependencies:** 1–4.
**Files:** `Sources/WatchtowerCore/{EngineBridge,Models}.swift`, `Sources/WatchtowerApp/{WatchtowerApp,DashboardView,SettingsView}.swift`, Swift tests.
**Check:** Cover partial results, cancellation, missing engine, and stale data without UI-thread work.

### 6. Confirmed Homebrew update transaction — P1, M

**Problem:** A command's exit status does not prove an update. Existing manager tools provide the action, not Watchtower's required record. [S3]

**Behavior:** Plan one named formula or cask update. Show command, target, dependency scope, and major-version confirmation separately.
Record approval, before version, output, after version, verification, and remaining manual steps.
Refuse unknown collateral changes. Re-read the installed version after execution.

**Dependencies:** 1, 3–5.
**Files:** `engine/watchtower_engine/{updater,update_log}.py`, `updates/homebrew.py`, `Sources/WatchtowerApp/UpdateDialog.swift`, fixtures.
**Check:** Cover changed plans, unchanged versions after exit zero, interruption, and output redaction.

### 7. Pinned OSV lockfile scan — P1, M

**Problem:** Projects have no advisory assessment. OSV-Scanner supplies lockfile extraction and version matches. [S10–S12]

**Behavior:** Add the verified scanner wrapper and protected offline database cache. Initially enable tested npm and uv lockfile inputs only.
Preserve exact package identities, aliases, file locations, and dependency paths where available.
Report unavailable dependency paths and unsupported lockfiles explicitly. Do not run resolver, call-analysis, or fix commands.

**Dependencies:** 1, 2.
**Files:** `engine/watchtower_engine/scanners/{osv,release_pin}.py`, `feeds/osv_database.py`, engine fixtures.
**Check:** Cover checksum mismatch, missing database, positive npm/uv advisories, malformed output, and network-disabled execution.

### 8. Stable findings and evidence details — P1, M

**Problem:** Duplicate aliases and repeat scans can hide unresolved work. OSV and Grype show per-package advisory evidence. [S11, S13]

**Behavior:** Reconcile aliases into stable `SEC-` IDs while retaining all local paths.
Show relevance, fixed version when known, first/last seen, source, and restart or deployment steps.
Add Defer and Backlog states. Only complete evidence can resolve a finding.

**Dependencies:** 1, 5, 7.
**Files:** `engine/watchtower_engine/findings.py`, `store.py`, `Sources/WatchtowerApp/FindingDetailView.swift`, model tests.
**Check:** Preserve urgent unresolved items after partial scans, moved files, or source disappearance.

### 9. KEV and GitHub advisory enrichment — P1, M

**Problem:** Version matches lack exploitation and malicious-package context. Socket provides adjacent supply-chain alerts. [S15]

**Behavior:** Add public KEV and GitHub clients. Join by advisory aliases, then add exploitation evidence and malware records.
Record source retrieval time, pagination, withdrawals, rate limits, and failures. Do not infer exposure from a product name alone.

**Dependencies:** 7, 8.
**Files:** `engine/watchtower_engine/feeds/{kev,github}.py`, `findings.py`, fixture tests.
**Check:** Cover the official KEV fallback, separate malware requests, duplicate aliases, and incomplete pagination.

### 10. One npm dependency update — P1, M

**Problem:** Project findings lack an update action. npm and Dependabot demonstrate version targets and dependency changes. [S7, S9]

**Behavior:** Support one direct public npm dependency in a simple `package-lock.json` project.
Reuse feature 6's plan, confirmation, log, and verification contract. Preview manifest, lockfile, and transitive changes.
Preserve user edits and repository instructions. Refuse unsupported workspaces, git dependencies, or unknown script requirements.

**Dependencies:** 6–8.
**Files:** `engine/watchtower_engine/updates/npm.py`, npm version metadata adapter, engine fixtures.
**Check:** Verify both the lock target and installed package. Keep compatibility status separate from version verification.

### 11. One uv dependency update — P1, M

**Problem:** Python projects need a distinct update path. uv provides targeted lock upgrades and environment synchronization. [S23]

**Behavior:** Support one direct public dependency in a simple uv project with an existing environment.
Use an exact target, controlled build policy, change preview, and approved compatibility checks.
Keep extras and groups explicit. Refuse unsupported environments instead of creating or rebuilding them silently.

**Dependencies:** 6–8.
**Files:** `engine/watchtower_engine/updates/uv.py`, PyPI version metadata adapter, engine fixtures.
**Check:** A changed lockfile without the target installed version remains unverified. Protect unrelated files and packages.

### 12. On-demand vendor incident records — P2, M

**Problem:** Package databases do not cover every service incident. Socket offers adjacent incident context. [S15]

**Behavior:** Add public source checks for GitHub and Google/Gmail, plus Apple security notices.
Store incident records, reviewed sources, and review windows. Keep primary confirmation separate from possible relevance.
The first review covers seven days. Later reviews overlap the last completed review by 48 hours.
Show source failures and missed-day coverage. Do not interpret a quiet feed as proof of no breach.

**Dependencies:** 1, 8, 9.
**Files:** `engine/watchtower_engine/research/{sources,records}.py`, `Sources/WatchtowerApp/ResearchView.swift`, fixtures.
**Check:** Advance completion only after all selected checks finish. Preserve unresolved incidents without CVEs.

### Release boundary and owner decisions

**Decisions needed through main:**

1. Approve this initial scope or expand v1 beyond 12 PRs. Unmanaged apps retain manual routes until a supported adapter exists.
2. Set the project-update script/build policy. Default proposal: refuse automatic updates that require unapproved hooks or builds.
3. Set a time and cost limit for optional Claude research. Confirm that an existing permitted authentication route can support isolation.

The selected roots, active defaults, service list, manual Refresh, update logs, and separate major-version confirmation are already decided.
Do not ask the owner to decide them again.

**Reference requirements that remain after this proposed scope:**

- General Sparkle update comparison and supported vendor automation.
- App Store updates through a version-tested `mas` adapter and system-owned authentication.
- Cargo, Swift, requirements-only, and other project update adapters.
- Complete runtime/SDK and editor-extension inventories, including old retained installations.
- Running-version evidence and accessible container metadata without daemon startup or credential reads.
- Vendor-specific affected-range and backport assessment beyond package database evidence.
- Optional headless Claude web research and wider news discovery.

These are explicit gaps, not completed features. The PM should split each future adapter into its own PR.

Claude supports `-p`, JSON output, and schema-constrained results.
Current docs warn that ordinary headless runs can load hooks and MCP configuration.
Bare mode removes that discovery but does not use subscription login. [S24]
Therefore, an empty directory alone is insufficient isolation.
Do not enable Claude research until the team validates tool restrictions, existing authentication, output validation, and cost limits.
The app must send only public research topics, never source, private paths, credentials, or the full inventory.

### Validation and unverified claims

- Competitor features and access methods were checked through official pages. No product was installed or trialed.
- The scanner hashes came from official release metadata. Binary bytes and scanner behavior remain unverified locally.
- Electron mappings describe upstream builds. Vendor-specific component provenance remains unverified.
- API and CLI behavior must be tested against pinned versions. Documentation is not a successful integration test.
- The local survey establishes presence and file formats, not vulnerable packages, running processes, or deployed services.
- Builds and tests were not run because this task changes research documents only.

## Sources

All sources were accessed on 2026-10-29. Direct links below support the numbered references above.

- **S1:** [Latest](https://max.codes/latest/).
- **S2:** [MacUpdater status and features](https://www.corecode.io/macupdater/).
- **S3:** [Homebrew manual](https://docs.brew.sh/Manpage).
- **S4:** [`brew cu` documentation](https://github.com/buo/homebrew-cask-upgrade).
- **S5:** [Topgrade README](https://github.com/topgrade-rs/topgrade/blob/main/README.md).
- **S6:** [`mas` documentation](https://github.com/mas-cli/mas).
- **S7:** [Dependabot version updates](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-version-updates), [GitHub security features](https://docs.github.com/en/code-security/getting-started/github-security-features).
- **S8:** [Renovate documentation](https://docs.renovatebot.com/).
- **S9:** [`npm outdated`](https://docs.npmjs.com/cli/v12/commands/npm-outdated/), [`npm install`](https://docs.npmjs.com/cli/v12/commands/npm-install/), [`pip list`](https://pip.pypa.io/en/stable/cli/pip_list/).
- **S10:** [OSV-Scanner v2.7.0](https://github.com/google/osv-scanner/releases/tag/v2.7.0), [official asset names and digests](https://github.com/google/osv-scanner/releases/expanded_assets/v2.7.0).
- **S11:** [OSV-Scanner privacy and features](https://github.com/google/osv-scanner), [installation and provenance](https://google.github.io/osv-scanner/installation/), [CLI usage](https://google.github.io/osv-scanner/usage/), [supported artifacts](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/).
- **S12:** [OSV-Scanner offline mode](https://google.github.io/osv-scanner/usage/offline-mode/).
- **S13:** [Grype scope](https://oss.anchore.com/docs/guides/vulnerability/), [Grype database](https://oss.anchore.com/docs/guides/vulnerability/database/), [Grype local use](https://oss.anchore.com/docs/guides/vulnerability/getting-started/).
- **S14:** [Trivy repository and scope](https://github.com/aquasecurity/trivy).
- **S15:** [Socket plans and features](https://socket.dev/pricing).
- **S16:** [Official CISA mirror](https://github.com/cisagov/kev-data), [mirror JSON](https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json), [schema](https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities_schema.json).
- **S17:** [OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/), [OSV advisory details](https://google.github.io/osv.dev/get-v1-vulns/).
- **S18:** [GitHub global advisory API](https://docs.github.com/en/rest/security-advisories/global-advisories), [GitHub rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api).
- **S19:** [Homebrew JSON API](https://formulae.brew.sh/docs/api/).
- **S20:** [Sparkle feed configuration](https://sparkle-project.org/documentation/customization/), [Sparkle update format and signatures](https://sparkle-project.org/documentation/publishing/).
- **S21:** [Electron framework version metadata](https://releases.electronjs.org/release/v4.0.0), [Electron release mapping](https://releases.electronjs.org/), [mapping JSON](https://releases.electronjs.org/releases.json).
- **S22:** [Apple security releases](https://support.apple.com/en-us/100100), [GitHub security notices](https://github.blog/security/), [Google security notices](https://blog.google/security/).
- **S23:** [uv lock and environment behavior](https://docs.astral.sh/uv/concepts/projects/sync/), [uv command reference](https://docs.astral.sh/uv/reference/cli/).
- **S24:** [Claude Code headless behavior](https://code.claude.com/docs/en/headless).
