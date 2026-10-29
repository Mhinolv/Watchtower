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
        case findings
        case findingOpen = "finding-open"
        case findingDeferred = "finding-deferred"
        case findingResolved = "finding-resolved"
        case findingPartial = "finding-partial"
        case findingsEmpty = "findings-empty"
        case findingMalware = "finding-malware"
        case findingWithdrawn = "finding-withdrawn"
        case findingFeedFailed = "finding-feed-failed"
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
        case .findings, .findingOpen, .findingDeferred, .findingResolved, .findingPartial, .findingsEmpty,
             .findingMalware, .findingWithdrawn, .findingFeedFailed:
            return findingsModel(scenario, engine: engine, clock: clock)
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
