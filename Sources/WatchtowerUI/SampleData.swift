import Foundation
import SwiftUI
import WatchtowerCore

/// Fixed sample states for previews and snapshots. No engine runs.
public enum SampleData {
    /// 2026-10-29 12:00 UTC.
    public static let now = Date(timeIntervalSince1970: 1_793_275_200)

    public static func ago(_ hours: Double) -> Date { now.addingTimeInterval(-hours * 3600) }

    public static let projects: [ProjectRecord] = [
        ProjectRecord(name: "web", path: NSHomeDirectory() + "/Projects/web", root: "~/Projects",
                      manifests: ["package-lock.json", "package.json"], state: "active"),
        ProjectRecord(name: "api", path: NSHomeDirectory() + "/Projects/api", root: "~/Projects",
                      manifests: ["pyproject.toml", "uv.lock"], state: "active"),
        ProjectRecord(name: "old-site", path: NSHomeDirectory() + "/Projects/old-site", root: "~/Projects",
                      manifests: ["Cargo.lock"], state: "inactive"),
    ]

    static func item(_ id: String, _ source: String, _ name: String, _ state: ItemState, kind: String,
                     installed: String?, latest: String?, project: String? = nil, origin: String? = nil,
                     note: String? = nil, error: String? = nil, detail: String? = nil,
                     sourceAt: Date? = nil) -> ItemRecord {
        ItemRecord(id: id, source: source, name: name, state: state, kind: kind, installedVersion: installed,
                   latestVersion: latest, project: project, seenAt: sourceAt, error: error, detail: detail,
                   origin: origin, sourceAt: sourceAt, note: note, attributes: nil)
    }

    public static func items(at time: Date) -> [ItemRecord] {
        [
            item("formula:git", "homebrew", "git", .updateAvailable, kind: "formula", installed: "2.46.0",
                 latest: "2.47.1", sourceAt: time),
            item("formula:node", "homebrew", "node", .pinned, kind: "formula", installed: "22.9.0",
                 latest: "23.1.0", note: "Pinned with brew pin. Watchtower does not update pinned items.",
                 sourceAt: time),
            item("cask:zed", "homebrew", "zed", .unknown, kind: "cask", installed: "0.158.2", latest: "0.159.0",
                 note: "This app updates itself. The Homebrew version can be behind the app.", sourceAt: time),
            item("formula:acme/tools/widget", "homebrew", "widget", .manual, kind: "formula", installed: "1.0",
                 latest: nil, origin: "acme/tools", note: "Watchtower cannot check tap acme/tools."),
            item("formula:openssl@3", "homebrew", "openssl@3", .upToDate, kind: "formula", installed: "3.4.0",
                 latest: "3.4.0", sourceAt: time),
            item("com.tinyspeck.slackmacgap", "apps", "Slack", .upToDate, kind: "app", installed: "4.41.97",
                 latest: "4.41.97", sourceAt: time),
            ItemRecord(id: "com.apple.iWork.Keynote", source: "apps", name: "Keynote", state: .unknown, kind: "app",
                       installedVersion: "11.0", latestVersion: nil, origin: "App Store",
                       note: "Watchtower checks App Store versions only when you click Check for Update…",
                       attributes: ["adamId": "409183694", "path": "/Applications/Keynote.app"]),
            item("com.example.legacy", "apps", "Legacy Tool", .manual, kind: "app", installed: "1.2", latest: nil),
            item("md.obsidian", "apps", "Obsidian", .error, kind: "app", installed: "1.7.4", latest: nil,
                 error: "Version could not be read.", detail: "Info.plist has no CFBundleShortVersionString"),
            item("macos", "macos", "macOS", .manual, kind: "os", installed: "15.1", latest: nil,
                 note: "Update macOS in System Settings."),
        ]
    }

    static func days(_ day: Double) -> Date { now.addingTimeInterval(-day * 86400) }

    private static func path(_ project: String, _ lockfile: String, _ version: String,
                             via: [String]? = nil) -> FindingPath {
        FindingPath(project: project, projectPath: "~/Projects/\(project)", lockfile: lockfile, version: version,
                    dependencyPath: via)
    }

    /// Findings for the snapshots: open with 2 paths, critical, deferred and resolved.
    public static let findings: [FindingRecord] = [
        FindingRecord(id: "SEC-0001", package: "lodash", title: "Command Injection in lodash", severity: .high,
                      advisoryIds: ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"], fixedIn: "4.17.21",
                      firstSeen: days(9), lastSeen: ago(2), sourceAt: ago(6),
                      paths: [path("api", "tools/package-lock.json", "4.17.19", via: ["build-tools", "lodash"]),
                              path("web", "package-lock.json", "4.17.20")],
                      nextSteps: ["Update lodash to 4.17.21 or later in the lockfile.",
                                  "Restart the dev server after the update."],
                      kev: KevMark(cve: "CVE-2021-23337", dateAdded: "2026-10-22", dueDate: "2026-11-12")),
        FindingRecord(id: "SEC-0002", package: "minimist", title: "Prototype Pollution in minimist",
                      severity: .critical, advisoryIds: ["CVE-2021-44906", "GHSA-xvch-5gv4-984h", "OSV-2021-1"],
                      fixedIn: "1.2.6", firstSeen: days(3), lastSeen: ago(2), sourceAt: ago(6),
                      paths: [path("web", "package-lock.json", "1.2.5", via: ["mkdirp", "minimist"])],
                      nextSteps: ["Update minimist to 1.2.6 or later in the lockfile.",
                                  "Restart the dev server after the update."],
                      malware: MalwareMark(advisoryId: "GHSA-mal1-ware-0001")),
        FindingRecord(id: "SEC-0003", package: "lodash", title: "ReDoS in lodash", severity: .medium,
                      advisoryIds: ["CVE-2020-28500", "GHSA-29mw-wpgm-hmr9"], status: .deferred,
                      deferredUntil: now.addingTimeInterval(7 * 86400), firstSeen: days(9), lastSeen: ago(2),
                      sourceAt: ago(6), paths: [path("web", "package-lock.json", "4.17.20")],
                      nextSteps: ["Check the advisory for a workaround. No fixed version is known."]),
        FindingRecord(id: "SEC-0004", ecosystem: "PyPI", package: "jinja2",
                      title: "Jinja vulnerable to HTML attribute injection", severity: .high,
                      advisoryIds: ["CVE-2024-22195", "GHSA-h5c8-rqwp-cp95", "PYSEC-2024-1"], fixedIn: "3.1.3",
                      status: .resolved, firstSeen: days(12), lastSeen: days(1), resolvedAt: ago(30),
                      resolvedScanAt: ago(30), sourceAt: ago(30), paths: []),
        FindingRecord(id: "SEC-0005", package: "yaml-tools", title: "Regular expression slowdown in the parser",
                      severity: .low, advisoryIds: ["CVE-2026-20202", "GHSA-wthd-rawn-0005"], fixedIn: "2.1.1",
                      firstSeen: days(5), lastSeen: ago(2), sourceAt: ago(6),
                      paths: [path("web", "package-lock.json", "2.1.0")],
                      nextSteps: ["Update yaml-tools to 2.1.1 or later in the lockfile.",
                                  "Restart the dev server after the update."],
                      withdrawnAt: days(1)),
        FindingRecord(id: "SEC-0008", package: "yaml-tools", title: "Regular expression slowdown in the parser",
                      severity: .low, advisoryIds: ["CVE-2026-20203", "GHSA-bkgg-yaml-0008"], fixedIn: "2.1.2",
                      status: .backlog, firstSeen: days(9), lastSeen: ago(2), sourceAt: ago(6),
                      paths: [path("api", "tools/package-lock.json", "2.1.0")]),
        FindingRecord(id: "SEC-0006", ecosystem: "PyPI", package: "httpx", title: "Request smuggling in httpx",
                      severity: .high, advisoryIds: ["CVE-2026-31337", "GHSA-uvuv-httpx-0006"], fixedIn: "0.27.2",
                      firstSeen: days(2), lastSeen: ago(2), sourceAt: ago(6),
                      paths: [FindingPath(project: "tool", projectPath: "~/Real/tool", lockfile: "uv.lock",
                                          version: "0.26.0"),
                              FindingPath(project: "old-tool", projectPath: "~/Real/old-tool", lockfile: "uv.lock",
                                          version: "0.25.1",
                                          updateBlock: "No environment found. Watchtower does not create environments.")],
                      nextSteps: ["Update httpx to 0.27.2 or later in the lockfile.",
                                  "Restart the dev server after the update."]),
    ]

    public static func coverage(at time: Date, failing: Set<String> = []) -> [CoverageRecord] {
        [("homebrew", "Homebrew"), ("apps", "Applications"), ("macos", "macOS"), ("osv", "OSV"),
         ("kev", "CISA KEV"), ("github", "GitHub Advisories")].map { source, label in
            failing.contains(source)
                ? CoverageRecord(source: source, label: label, state: .failed, lastSuccessAt: ago(30),
                                 error: "\(label) check did not finish.")
                : CoverageRecord(source: source, label: label, state: .complete, lastSuccessAt: time)
        }
    }

    public static func state(status: RefreshStatus, finished: Date, lastComplete: Date?,
                             failing: Set<String> = [], findings: [FindingRecord] = SampleData.findings)
        -> EngineState {
        EngineState(schemaVersion: 1,
                    refresh: RefreshRecord(id: 7, status: status, startedAt: finished.addingTimeInterval(-90),
                                           finishedAt: finished, lastCompleteAt: lastComplete),
                    coverage: coverage(at: lastComplete ?? finished, failing: failing),
                    items: items(at: lastComplete ?? finished), findings: findings)
    }

    /// The scenarios that the snapshot script renders.
    public enum Scenario: String, CaseIterable, Sendable {
        case neverRefreshed = "never-refreshed"
        case complete
        case stale
        case partial
        case running
        case settingsInactive = "settings-inactive"
        case backlog
        case backlogEmpty = "backlog-empty"
        case findings
        case findingOpen = "finding-open"
        case findingDeferred = "finding-deferred"
        case findingResolved = "finding-resolved"
        case findingPartial = "finding-partial"
        case findingsEmpty = "findings-empty"
        case findingMalware = "finding-malware"
        case findingWithdrawn = "finding-withdrawn"
        case findingFeedFailed = "finding-feed-failed"
        case findingUv = "finding-uv"
        case failed
        case chipSelected = "chip-selected"
        case sparkleNewer = "sparkle-newer"
        case sparkleBeta = "sparkle-beta"
        case sparkleOsTooOld = "sparkle-os-too-old"
        case sparkleRejected = "sparkle-rejected"
        case sparkleFailed = "sparkle-failed"
        case menubarFindings = "menubar-findings"
        case menubarAllClear = "menubar-all-clear"
        case menubarStale = "menubar-stale"
        case menubarNever = "menubar-never"

        /// Scenarios that render the menu bar popover, not the window.
        public var isMenuBar: Bool { rawValue.hasPrefix("menubar-") }
    }

    @MainActor
    public static func model(_ scenario: Scenario) -> DashboardModel {
        let clock: @Sendable () -> Date = { now }
        let engine = PreviewEngine()
        switch scenario {
        case .neverRefreshed:
            return DashboardModel(engine: engine, projects: projects, clock: clock)
        case .complete, .settingsInactive:
            let model = DashboardModel(engine: engine, state: state(status: .complete, finished: ago(2),
                                                                    lastComplete: ago(2)),
                                       projects: projects, clock: clock)
            model.selection = .homebrew
            model.selectedItemKey = "homebrew/formula:git"
            return model
        case .stale:
            let model = DashboardModel(engine: engine, state: state(status: .complete, finished: ago(51),
                                                                    lastComplete: ago(51)),
                                       projects: projects, clock: clock)
            model.selection = .homebrew
            return model
        case .partial:
            let model = DashboardModel(engine: engine,
                                       state: state(status: .partial, finished: ago(1), lastComplete: ago(26),
                                                    failing: ["apps", "osv"]),
                                       projects: projects, clock: clock)
            model.selection = .apps
            return model
        case .running:
            let model = DashboardModel(engine: engine, state: state(status: .complete, finished: ago(3),
                                                                    lastComplete: ago(3)),
                                       projects: projects, isRefreshing: true,
                                       progress: RefreshProgress(done: 2, total: 4, source: "macOS"), clock: clock)
            model.selection = .homebrew
            return model
        case .backlog:
            let model = DashboardModel(engine: engine, state: state(status: .complete, finished: ago(2),
                                                                    lastComplete: ago(2)),
                                       projects: projects, clock: clock)
            model.selection = .backlog
            model.selectedItemKey = projects[2].path
            return model
        case .backlogEmpty:
            // Every project is active and no finding is in the backlog.
            let active = projects.map { var p = $0; p.state = "active"; return p }
            let findings = SampleData.findings.filter { $0.status != .backlog }
            let model = DashboardModel(engine: engine, state: state(status: .complete, finished: ago(2),
                                                                    lastComplete: ago(2), findings: findings),
                                       projects: active, clock: clock)
            model.selection = .backlog
            return model
        case .findings, .findingOpen, .findingDeferred, .findingResolved, .findingPartial, .findingsEmpty,
             .findingMalware, .findingWithdrawn, .findingFeedFailed, .findingUv:
            return findingsModel(scenario, engine: engine, clock: clock)
        case .failed:
            let model = DashboardModel(engine: engine, state: state(status: .failed, finished: ago(1),
                                                                    lastComplete: ago(18),
                                                                    failing: ["homebrew", "apps", "macos", "osv"]),
                                       projects: projects, clock: clock)
            model.selection = .apps
            return model
        case .chipSelected:
            let model = DashboardModel(engine: engine, state: state(status: .complete, finished: ago(2),
                                                                    lastComplete: ago(2)),
                                       projects: projects, clock: clock)
            model.selection = .apps
            model.itemFilter = .error
            return model
        case .sparkleNewer, .sparkleBeta, .sparkleOsTooOld, .sparkleRejected, .sparkleFailed:
            return sparkleModel(scenario, engine: engine, clock: clock)
        case .menubarFindings, .menubarNever:
            return model(scenario == .menubarNever ? .neverRefreshed : .complete)
        case .menubarStale:
            return model(.stale)
        case .menubarAllClear:
            var clear = state(status: .complete, finished: ago(0.2), lastComplete: ago(0.2), findings: [])
            clear.items = clear.items.filter { ![.updateAvailable, .error, .vulnerable].contains($0.state) }
            return DashboardModel(engine: engine, state: clear, projects: projects, clock: clock)
        }
    }
}

extension SampleData {
    @MainActor
    static func findingsModel(_ scenario: Scenario, engine: PreviewEngine,
                              clock: @escaping @Sendable () -> Date) -> DashboardModel {
        let partial = scenario == .findingPartial
        var sample = state(status: partial ? .partial : .complete, finished: ago(2),
                           lastComplete: partial ? ago(26) : ago(2), failing: partial ? ["osv"] : [],
                           findings: scenario == .findingsEmpty ? [] : findings)
        if scenario == .findingFeedFailed {
            // GitHub hit its rate limit. The cached answers from yesterday are still in use. KEV came
            // from the official mirror.
            sample.refresh?.status = .partial
            sample.coverage = sample.coverage.map { c in
                var c = c
                if c.source == "github" {
                    c.state = .failed
                    c.error = "GitHub Advisories did not load."
                    c.sourceAt = days(1)
                    c.note = "rate limit"
                }
                if c.source == "kev" { c.note = "official mirror" }
                return c
            }
        }
        let model = DashboardModel(engine: engine, state: sample, projects: projects, clock: clock)
        model.selection = .findings
        switch scenario {
        case .findingOpen, .findingPartial, .findingFeedFailed: model.selectedItemKey = "SEC-0001"
        case .findingMalware: model.selectedItemKey = "SEC-0002"
        case .findingWithdrawn: model.selectedItemKey = "SEC-0005"
        case .findingUv: model.selectedItemKey = "SEC-0006"
        case .findingDeferred:
            model.findingFilter = .deferred
            model.selectedItemKey = "SEC-0003"
        case .findingResolved:
            model.findingFilter = .resolved
            model.selectedItemKey = "SEC-0004"
        default: break
        }
        return model
    }
}

extension SampleData {
    /// One app with a Sparkle feed (#14), in the state of `scenario`, selected in Apps.
    static func sparkleApp(_ scenario: Scenario) -> ItemRecord {
        let feed = "https://updates.example.com/acme-notes/appcast.xml"
        var app = item("com.example.acme-notes", "apps", "Acme Notes", .updateAvailable, kind: "app",
                       installed: "3.3.0", latest: "3.4.1", origin: "Sparkle feed",
                       note: "Use the app's Check for Updates command to install it.", sourceAt: ago(3))
        var attributes = ["path": "/Applications/Acme Notes.app", "bundleId": "com.example.acme-notes",
                          "sparkleFeed": feed, "sparkleLatest": "3.4.1 (341)", "sparkleChannel": "Stable",
                          "sparkleMinimumOs": "14.0", "sparkleChecked": "2026-10-29T09:12:00Z"]
        switch scenario {
        case .sparkleBeta:
            app.state = .upToDate
            app.installedVersion = "3.4.1"
            app.note = "A beta (3.5b1) is available."
        case .sparkleOsTooOld:
            app.state = .manual
            attributes["sparkleMinimumOs"] = "15.2"
            app.note = "3.4.1 needs macOS 15.2. This Mac has 15.1."
        case .sparkleRejected:
            app.state = .unknown
            app.latestVersion = nil
            app.origin = nil
            app.sourceAt = nil
            app.note = "Watchtower reads HTTPS feeds only."
            attributes = ["path": attributes["path"]!, "bundleId": attributes["bundleId"]!,
                          "sparkleFeed": "http://updates.example.com/acme-notes/appcast.xml"]
        case .sparkleFailed:
            // The feed did not load. The evidence from the day before stays.
            app.sourceAt = days(1)
            attributes["sparkleChecked"] = "2026-10-28T09:12:00Z"
            app.error = "Feed check failed."
            app.detail = "URLError(code: -1001, \"The request timed out.\")"
        default: break
        }
        app.attributes = attributes
        return app
    }

    @MainActor
    static func sparkleModel(_ scenario: Scenario, engine: PreviewEngine,
                             clock: @escaping @Sendable () -> Date) -> DashboardModel {
        var sample = state(status: .complete, finished: ago(2), lastComplete: ago(2))
        let app = sparkleApp(scenario)
        sample.items.append(app)
        let failed = scenario == .sparkleFailed
        sample.coverage.append(CoverageRecord(source: "sparkle", label: "Sparkle feeds",
                                              state: failed ? .partial : .complete, lastSuccessAt: ago(2),
                                              error: failed ? "Some Sparkle feeds did not load." : nil,
                                              note: failed ? "5 of 6 read" : "6 of 6 read"))
        if failed { sample.refresh?.status = .partial }
        let model = DashboardModel(engine: engine, state: sample, projects: projects, clock: clock)
        model.selection = .apps
        model.selectedItemKey = app.key
        return model
    }
}

/// An engine for previews and snapshots. It answers at once and never starts a process.
public struct PreviewEngine: EngineClient {
    public init() {}

    public func state() async throws -> EngineState {
        SampleData.state(status: .complete, finished: SampleData.ago(2), lastComplete: SampleData.ago(2))
    }

    public func refresh(progress: @escaping @Sendable (RefreshProgress) -> Void) async throws -> EngineState {
        try await state()
    }

    public func projects() async throws -> ProjectList {
        ProjectList(schemaVersion: 1, projects: SampleData.projects, rootErrors: [], skipped: [])
    }

    public func setProject(path: String, active: Bool) async throws -> ProjectRecord {
        var project = SampleData.projects.first { $0.path == path }!
        project.state = active ? "active" : "inactive"
        return project
    }

    private func finding(_ id: String, _ change: (inout FindingRecord) -> Void) throws -> FindingRecord {
        guard var found = SampleData.findings.first(where: { $0.id == id }) else {
            throw EngineError.reported(message: "There is no finding \(id).", detail: nil)
        }
        change(&found)
        return found
    }

    public func deferFinding(id: String, days: Int) async throws -> FindingRecord {
        try finding(id) {
            $0.status = .deferred
            $0.deferredUntil = SampleData.now.addingTimeInterval(Double(days) * 86400)
        }
    }

    public func moveFindingToBacklog(id: String) async throws -> FindingRecord {
        try finding(id) { $0.status = .backlog }
    }

    public func reopenFinding(id: String) async throws -> FindingRecord {
        try finding(id) { $0.status = .open }
    }
}

struct DashboardView_Previews: PreviewProvider {
    static var previews: some View {
        ForEach(SampleData.Scenario.allCases, id: \.self) { scenario in
            DashboardView(model: SampleData.model(scenario))
                .frame(width: 1100, height: 640)
                .previewDisplayName(scenario.rawValue)
        }
    }
}

struct SettingsView_Previews: PreviewProvider {
    static var previews: some View {
        SettingsView(model: SampleData.model(.settingsInactive))
    }
}

// MARK: - Update samples

extension PreviewEngine: UpdateClient {
    public func updatePlan(itemKey: String) async throws -> UpdatePlan { SampleData.plan() }

    public func runUpdate(itemKey: String, planID: String, confirmMajor: Bool, confirmScripts: Bool,
                          output: @escaping @Sendable (String) -> Void) async throws -> (UpdateAttempt, UpdatePlan) {
        (SampleData.attempt(.verified), SampleData.plan())
    }

    public func updateLog() async throws -> [UpdateAttempt] { SampleData.attempts }
}

extension SampleData {
    public static func plan(major: Bool = false, scripts: [String] = []) -> UpdatePlan {
        UpdatePlan(id: "3f2a9c41d07e5b18", itemKey: "homebrew/formula:git", name: "git", kind: "formula",
                   fullName: "git", installedVersion: "2.46.0", targetVersion: major ? "3.0.0" : "2.47.1",
                   command: ["/opt/homebrew/bin/brew", "upgrade", "--formula", "git"],
                   alsoChanges: [PackageChange(name: "pcre2", before: nil, after: "10.44", change: "install"),
                                 PackageChange(name: "git-lfs", before: "3.5.1", after: "3.5.1_1", change: "upgrade")],
                   majorChange: major, scripts: scripts)
    }

    public static func attempt(_ status: UpdateStatus, id: Int = 4, name: String = "git",
                               manualSteps: [String] = []) -> UpdateAttempt {
        let after: String? = switch status {
        case .verified: "2.47.1"
        case .notVerified, .failed: "2.46.0"
        default: nil
        }
        return UpdateAttempt(id: id, itemKey: "homebrew/formula:\(name)", name: name, kind: "formula",
                             command: ["/opt/homebrew/bin/brew", "upgrade", "--formula", name],
                             beforeVersion: "2.46.0", targetVersion: "2.47.1", afterVersion: after, status: status,
                             exitCode: status == .failed ? 1 : (status == .verified || status == .notVerified ? 0 : nil),
                             output: "==> Upgrading 1 outdated package:\n\(name) 2.46.0 -> 2.47.1\n==> Pouring \(name)--2.47.1.arm64_sequoia.bottle.tar.gz",
                             error: nil, manualSteps: manualSteps, startedAt: ago(Double(5 - id)), finishedAt: ago(Double(5 - id) - 0.01))
    }

    public static let attempts: [UpdateAttempt] = [
        attempt(.verified, id: 4), attempt(.notVerified, id: 3), attempt(.failed, id: 2), attempt(.planChanged, id: 1),
    ]

    /// A uv plan with a group, three other packages and the Build row (#11).
    public static func uvPlan(build: Bool = false, refusal: String? = nil) -> UpdatePlan {
        let rows = [
            PlanRow(label: "Project", value: "~/Real/tool"),
            PlanRow(label: "Environment", value: refusal == nil ? ".venv (exists)" : ".venv (missing)"),
            PlanRow(label: "pyproject.toml", value: "No change"),
            PlanRow(label: "uv.lock", value: "httpx 0.26.0 → 0.27.2"),
            PlanRow(label: "Groups and extras", value: "Groups: dev. Extras: none."),
            PlanRow(label: "Other packages", value: "3 packages change",
                    items: ["anyio 4.2.0 → 4.3.0", "sniffio 1.3.1 (new)", "h11 0.13.0 (removed)"]),
            PlanRow(label: "Build", value: "Disabled"),
        ]
        return UpdatePlan(id: "9d4c0b7a1e2f3a55", itemKey: "uv/httpx@0.27.2|~/Real/tool|uv.lock", name: "httpx",
                          kind: "uv", fullName: "httpx", installedVersion: "0.26.0", targetVersion: "0.27.2",
                          command: ["/Users/me/.local/bin/uv", "--project", "~/Real/tool", "sync", "--upgrade-package",
                                    "httpx==0.27.2", "--inexact", "--no-build", "--group", "dev"],
                          scripts: build ? ["httpx needs a source build: no wheel for this platform."] : [],
                          refusal: refusal, rows: rows,
                          scriptsMessage: build ? "httpx needs a source build: no wheel for this platform." : nil)
    }

    public static func uvAttempt(verified: Bool) -> UpdateAttempt {
        let installed = verified ? "0.27.2" : "0.26.0"
        return UpdateAttempt(id: 6, itemKey: "uv/httpx@0.27.2|~/Real/tool|uv.lock", name: "httpx", kind: "uv",
                             command: ["/Users/me/.local/bin/uv", "--project", "~/Real/tool", "sync",
                                       "--upgrade-package", "httpx==0.27.2", "--inexact", "--no-build"],
                             beforeVersion: "0.26.0", targetVersion: "0.27.2", afterVersion: installed,
                             status: verified ? .verified : .notVerified, exitCode: 0,
                             output: "Resolved 12 packages in 1ms\nUpdated httpx v0.26.0 -> v0.27.2",
                             error: verified ? nil : "Not verified: the environment still has 0.26.0.",
                             manualSteps: verified ? ["Restart the dev server after the update."] : [],
                             startedAt: ago(0.1), finishedAt: ago(0.09),
                             resultRows: [PlanRow(label: "Lockfile", value: "httpx 0.27.2", ok: true),
                                          PlanRow(label: "Installed (.venv)", value: "httpx \(installed)",
                                                  ok: verified)])
    }

    public enum UpdateScenario: String, CaseIterable, Sendable {
        case plan = "update-plan"
        case majorAlert = "update-major-alert"
        case scripts = "update-scripts"
        case running = "update-running"
        case verified = "update-verified"
        case notVerified = "update-not-verified"
        case failed = "update-failed"
        case planChanged = "update-plan-changed"
        case manualSteps = "update-manual-steps"
        case log = "update-log"
        case uvPlan = "update-uv-plan"
        case uvBuild = "update-uv-build"
        case uvVerified = "update-uv-verified"
        case uvLockOnly = "update-uv-lock-only"
        case uvNoEnv = "update-uv-no-env"
        case npmPlan = "update-npm-plan"
        case npmScripts = "update-npm-scripts"
        case npmVerified = "update-npm-verified"
        case npmLockfileOnly = "update-npm-lockfile-only"
        case npmNotSupported = "update-npm-not-supported"
        case masChecking = "update-mas-checking"
        case masPlan = "update-mas-plan"
        case masCurrent = "update-mas-current"
        case masSignedOut = "update-mas-signed-out"
        case masAdmin = "update-mas-admin"
    }

    /// An App Store app plan (#13). `refusal` is the explicit state from the engine.
    public static func masPlan(name: String = "Keynote", installed: String? = "11.0", target: String? = "12.0",
                               refusal: String? = nil) -> UpdatePlan {
        UpdatePlan(id: "5d0c8e17a2b64f93", itemKey: "apps/com.apple.iWork.Keynote", name: name, kind: "mas",
                   fullName: "409183694", installedVersion: installed, targetVersion: target,
                   command: ["/opt/homebrew/bin/mas", "update", "409183694"], majorChange: refusal == nil,
                   refusal: refusal,
                   rows: [PlanRow(label: "Scripts", value: "Not used by App Store updates.")])
    }

    public static func npmPlan(scripts: Bool = false) -> UpdatePlan {
        let npm = "/opt/homebrew/bin/npm"
        let rows = [PlanRow(label: "Project", value: "~/Projects/storefront"),
                    PlanRow(label: "package.json", value: "\"acme-router\": \"^4.17.1\" → \"^4.19.2\""),
                    PlanRow(label: "package-lock.json", value: "acme-router 4.17.1 → 4.19.2"),
                    PlanRow(label: "Other packages", value: "3 packages change",
                            items: ["path-to-regexp 0.1.7 → 0.1.10", "cookie 0.5.0 → 0.6.0", "send 0.18.0 → 0.19.0"]),
                    PlanRow(label: "Scripts", value: "Disabled (--ignore-scripts)")]
        return UpdatePlan(
            id: "9c1e0b7a55d2f310", itemKey: "npm|~/Projects/storefront|acme-router|4.19.0", name: "acme-router",
            kind: "npm", fullName: "acme-router", installedVersion: "4.17.1", targetVersion: "4.19.2",
            command: [npm, "install", "acme-router@^4.19.2", "--save-prod", "--ignore-scripts", "--no-audit",
                      "--no-fund", "--prefix", "/Users/me/Projects/storefront"],
            scripts: scripts ? ["esbuild needs its postinstall script"] : [],
            manualSteps: ["Run the project tests: npm test", "Restart anything that runs this project."],
            rows: rows, scriptsMessage: scripts ? "esbuild needs its postinstall script." : nil,
            scriptDetails: scripts ? [ScriptDetail(package: "esbuild", version: "0.21.5", script: "postinstall")] : nil)
    }

    public static func npmAttempt(installed: String) -> UpdateAttempt {
        let ok = installed == "4.19.2"
        return UpdateAttempt(
            id: 9, itemKey: "npm|~/Projects/storefront|acme-router|4.19.0", name: "acme-router", kind: "npm",
            command: npmPlan().command, beforeVersion: "4.17.1", targetVersion: "4.19.2", afterVersion: "4.19.2",
            status: ok ? .verified : .notVerified, exitCode: 0, output: "added 1 package, changed 3 packages",
            error: ok ? nil : "Not verified: the installed package is still \(installed).",
            startedAt: ago(0.1), finishedAt: ago(0.09),
            resultRows: [PlanRow(label: "Lockfile", value: "acme-router 4.19.2", ok: true),
                         PlanRow(label: "Installed (node_modules)", value: "acme-router \(installed)", ok: ok)])
    }

    @MainActor
    public static func updateModel(_ scenario: UpdateScenario) -> UpdateModel {
        let engine = PreviewEngine()
        let step: UpdateModel.Step = switch scenario {
        case .plan, .log: .plan(plan())
        case .majorAlert: .confirmMajor(plan(major: true))
        case .scripts: .confirmScripts(plan(scripts: ["the formula runs a post-install step"]))
        case .running: .running(plan())
        case .verified: .result(attempt(.verified), plan())
        case .notVerified: .result(attempt(.notVerified), plan())
        case .failed: .result(attempt(.failed), plan())
        case .planChanged: .result(attempt(.planChanged), plan())
        case .manualSteps: .result(attempt(.verified, name: "fluff", manualSteps: ["Quit and reopen Fluff if it is open."]), plan())
        case .uvPlan: .plan(uvPlan())
        case .uvBuild: .confirmScripts(uvPlan(build: true))
        case .uvVerified: .result(uvAttempt(verified: true), uvPlan())
        case .uvLockOnly: .result(uvAttempt(verified: false), uvPlan())
        case .uvNoEnv: .plan(uvPlan(refusal: "No environment found. Watchtower does not create environments."))
        case .npmPlan: .plan(npmPlan())
        case .npmScripts: .confirmScripts(npmPlan(scripts: true))
        case .npmVerified: .result(npmAttempt(installed: "4.19.2"), npmPlan())
        case .npmLockfileOnly: .result(npmAttempt(installed: "4.17.1"), npmPlan())
        case .masChecking: .loading("Keynote")
        case .masPlan: .plan(masPlan())
        case .masCurrent: .plan(masPlan(name: "Numbers", installed: "5.2", target: nil,
                                        refusal: "Numbers is up to date (5.2)."))
        case .masSignedOut: .plan(masPlan(installed: nil, target: nil, refusal: "Sign in to the App Store, then try again."))
        case .masAdmin: .plan(masPlan(installed: nil, target: nil,
                                      refusal: "This update needs an administrator. Use the App Store app."))
        case .npmNotSupported:
            .plan(UpdatePlan(id: "0", itemKey: "npm|~/Projects/monorepo|acme-router|-", name: "acme-router",
                             kind: "npm", fullName: "acme-router", installedVersion: nil, targetVersion: nil,
                             command: ["/opt/homebrew/bin/npm", "install", "acme-router"],
                             refusal: "Watchtower cannot update workspace projects yet.",
                             rows: [PlanRow(label: "Project", value: "~/Projects/monorepo")]))
        }
        let model = UpdateModel(client: engine, step: scenario == .log ? .idle : step,
                                output: ["==> Upgrading 1 outdated package:", "git 2.46.0 -> 2.47.1",
                                         "==> Pouring git--2.47.1.arm64_sequoia.bottle.tar.gz"],
                                attempts: attempts, checkingStore: scenario == .masChecking)
        if scenario == .log { model.selectedAttemptID = 3 }
        return model
    }
}

struct UpdateDialog_Previews: PreviewProvider {
    static var previews: some View {
        ForEach(SampleData.UpdateScenario.allCases, id: \.self) { scenario in
            UpdateDialog(model: SampleData.updateModel(scenario))
                .previewDisplayName(scenario.rawValue)
        }
    }
}

// MARK: - Incident samples (#12)

extension PreviewEngine: IncidentClient {
    public func incidents() async throws -> IncidentState { SampleData.incidentState() }

    public func checkSources(progress: @escaping @Sendable (RefreshProgress) -> Void) async throws -> IncidentState {
        SampleData.incidentState()
    }
}

extension SampleData {
    private static func incident(_ n: Int, _ service: String, _ title: String, _ published: String,
                                 _ status: IncidentStatus, _ sourceName: String, source: String,
                                 cves: [String] = []) -> IncidentRecord {
        IncidentRecord(id: String(format: "INC-%04d", n), source: source, service: service, title: title,
                       summary: "A short text from the source. Watchtower shows it as plain text.",
                       published: published, status: status, sourceName: sourceName,
                       url: "https://github.blog/security/sample-\(n)", cves: cves, firstSeen: ago(4), lastSeen: ago(4))
    }

    /// Four sample incidents with the three statuses. Only a status page can be `Confirmed`: a blog post or a
    /// release page is `Possible relevance`. `Unconfirmed` needs a source that is not the vendor's own.
    public static let incidentList: [IncidentRecord] = [
        incident(1, "Google / Gmail", "Unauthorized access to a test account was found and fixed (sample)", "2026-10-27",
                 .confirmed, "Google Workspace status", source: "google"),
        incident(2, "GitHub", "Third-party app tokens reset after a security event (sample)", "2026-10-26",
                 .possible, "GitHub security blog", source: "github"),
        incident(3, "Apple", "Security release: iOS 27.2 and iPadOS 27.2 (sample)", "2026-10-24",
                 .possible, "Apple security releases", source: "apple"),
        incident(4, "GitHub", "Report of leaked access tokens on a forum (sample)", "2026-10-23",
                 .unconfirmed, "News report only", source: "github"),
    ]

    /// Two sample breach rows of Have I Been Pwned (#60). The data is made up.
    public static func hibpIncidents(new: Bool = false) -> [IncidentRecord] {
        func row(_ n: Int, _ service: String, _ title: String, _ date: String, _ added: String, _ status: IncidentStatus,
                 _ verified: Bool, _ count: Int, _ domain: String, new: Bool) -> IncidentRecord {
            IncidentRecord(id: String(format: "INC-%04d", n), source: "hibp", service: service, title: title,
                           summary: "A sample description from the breach list. Watchtower shows it as plain text.",
                           published: date, status: status, sourceName: "Have I Been Pwned",
                           url: "https://haveibeenpwned.com/PwnedWebsites#Sample\(n)", firstSeen: ago(4), lastSeen: ago(4),
                           breach: BreachDetails(breachDate: date, addedDate: added,
                                                 dataClasses: ["Email addresses", "Passwords"], pwnCount: count,
                                                 domain: domain, verified: verified), isNew: new)
        }
        return [
            row(10, "GitHub", "GitHub data breach (sample)", "2024-06-04", "2026-10-27", .possible, true, 1_200_000,
                "github.com", new: new),
            row(11, "Google / Gmail", "Google account data breach (sample)", "2026-09-18", "2026-10-25", .unconfirmed,
                false, 48_500, "accounts.google.com", new: false),
        ]
    }

    public static func incidentSources(failed: Bool = false, hibpFailed: Bool = false) -> [IncidentSource] {
        [
            IncidentSource(source: "github", label: "GitHub", state: .complete, lastSuccessAt: ago(4)),
            failed
                ? IncidentSource(source: "google", label: "Google / Gmail", state: .failed, lastSuccessAt: ago(28),
                                 error: "Google / Gmail: check failed. The review is not complete.", note: "HTTP 503")
                : IncidentSource(source: "google", label: "Google / Gmail", state: .complete, lastSuccessAt: ago(4)),
            IncidentSource(source: "apple", label: "Apple security", state: .complete, lastSuccessAt: ago(4)),
            hibpFailed
                ? IncidentSource(source: "hibp", label: "Have I Been Pwned", state: .failed, lastSuccessAt: days(2),
                                 error: "Have I Been Pwned: check failed. The review is not complete.", note: "HTTP 503")
                : IncidentSource(source: "hibp", label: "Have I Been Pwned", state: .complete, lastSuccessAt: ago(4)),
        ]
    }

    public static func incidentState(incidents: [IncidentRecord] = incidentList, failed: Bool = false,
                                     gaps: [IncidentGap] = [], hibpFailed: Bool = false) -> IncidentState {
        IncidentState(incidents: incidents, sources: incidentSources(failed: failed, hibpFailed: hibpFailed),
                      review: IncidentReview(windowStart: days(7), windowEnd: failed ? ago(28) : ago(4),
                                             lastAttemptState: failed ? "partial" : "complete", lastAttemptAt: ago(4)),
                      gaps: gaps)
    }

    public enum IncidentScenario: String, CaseIterable, Sendable {
        case incidents
        case missed = "incidents-missed"
        case failed = "incidents-failed"
        case checking = "incidents-checking"
        case empty = "incidents-empty"
        case hibp = "incidents-hibp"
        case hibpNew = "incidents-hibp-new"
        case hibpFailed = "incidents-hibp-failed"
        case hibpNone = "incidents-hibp-none"
    }

    /// The window and the incident model of one scenario. The window shows the `Incidents` section.
    @MainActor
    public static func incidentScenario(_ scenario: IncidentScenario) -> (DashboardModel, IncidentModel) {
        let dashboard = model(.complete)
        dashboard.selection = .incidents
        let engine = PreviewEngine()
        let incidents: IncidentModel
        switch scenario {
        case .incidents:
            incidents = IncidentModel(client: engine, state: incidentState())
            incidents.selectedID = "INC-0001"
        case .missed:
            incidents = IncidentModel(client: engine, state: incidentState(gaps: [IncidentGap(start: "2026-10-20", end: "2026-10-21")]))
            incidents.selectedID = "INC-0001"
        case .failed:
            incidents = IncidentModel(client: engine, state: incidentState(failed: true))
            incidents.selectedID = "INC-0001"
        case .checking:
            incidents = IncidentModel(client: engine, state: incidentState(), isChecking: true,
                                      progress: RefreshProgress(done: 1, total: 3, source: "Google / Gmail"))
            incidents.selectedID = "INC-0001"
        case .empty:
            incidents = IncidentModel(client: engine, state: incidentState(incidents: []))
        case .hibp:
            incidents = IncidentModel(client: engine, state: incidentState(incidents: hibpIncidents() + incidentList))
            incidents.selectedID = "INC-0010"
        case .hibpNew:
            incidents = IncidentModel(client: engine, state: incidentState(incidents: hibpIncidents(new: true) + incidentList))
            incidents.selectedID = "INC-0010"
        case .hibpFailed:
            // The check failed. The earlier breach rows stay.
            incidents = IncidentModel(client: engine, state: incidentState(incidents: hibpIncidents() + incidentList,
                                                                           hibpFailed: true))
            incidents.selectedID = "INC-0010"
        case .hibpNone:
            incidents = IncidentModel(client: engine, state: incidentState())
            incidents.selectedID = "INC-0001"
        }
        return (dashboard, incidents)
    }
}
