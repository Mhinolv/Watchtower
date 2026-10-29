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
                                  "Restart the dev server after the update."]),
        FindingRecord(id: "SEC-0002", package: "minimist", title: "Prototype Pollution in minimist",
                      severity: .critical, advisoryIds: ["CVE-2021-44906", "GHSA-xvch-5gv4-984h", "OSV-2021-1"],
                      fixedIn: "1.2.6", firstSeen: days(3), lastSeen: ago(2), sourceAt: ago(6),
                      paths: [path("web", "package-lock.json", "1.2.5", via: ["mkdirp", "minimist"])],
                      nextSteps: ["Update minimist to 1.2.6 or later in the lockfile.",
                                  "Restart the dev server after the update."]),
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
    ]

    public static func coverage(at time: Date, failing: Set<String> = []) -> [CoverageRecord] {
        [("homebrew", "Homebrew"), ("apps", "Applications"), ("macos", "macOS"), ("osv", "OSV")].map { source, label in
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
        case findings
        case findingOpen = "finding-open"
        case findingDeferred = "finding-deferred"
        case findingResolved = "finding-resolved"
        case findingPartial = "finding-partial"
        case findingsEmpty = "findings-empty"
        case failed
        case chipSelected = "chip-selected"
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
        case .findings, .findingOpen, .findingDeferred, .findingResolved, .findingPartial, .findingsEmpty:
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
        let sample = state(status: partial ? .partial : .complete, finished: ago(2),
                           lastComplete: partial ? ago(26) : ago(2), failing: partial ? ["osv"] : [],
                           findings: scenario == .findingsEmpty ? [] : findings)
        let model = DashboardModel(engine: engine, state: sample, projects: projects, clock: clock)
        model.selection = .findings
        switch scenario {
        case .findingOpen, .findingPartial: model.selectedItemKey = "SEC-0001"
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
        }
        let model = UpdateModel(client: engine, step: scenario == .log ? .idle : step,
                                output: ["==> Upgrading 1 outdated package:", "git 2.46.0 -> 2.47.1",
                                         "==> Pouring git--2.47.1.arm64_sequoia.bottle.tar.gz"],
                                attempts: attempts)
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
