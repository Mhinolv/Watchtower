import Foundation
import Testing
@testable import WatchtowerCore

// MARK: - Helpers

private let now = Date(timeIntervalSince1970: 1_793_275_200)  // 2026-10-29 12:00 UTC
private let utcTime = TimeText(timeZone: TimeZone(identifier: "UTC")!)

private func hours(_ h: Double) -> Date { now.addingTimeInterval(-h * 3600) }

private func state(_ status: RefreshStatus, finished: Date?, lastComplete: Date?,
                   coverage: [CoverageState] = [.complete, .complete, .complete, .complete],
                   items: [ItemRecord] = [], findings: [FindingRecord] = []) -> EngineState {
    EngineState(
        schemaVersion: 1,
        refresh: RefreshRecord(id: 1, status: status, startedAt: (finished ?? now).addingTimeInterval(-60),
                               finishedAt: finished, lastCompleteAt: lastComplete),
        coverage: coverage.enumerated().map { i, s in
            CoverageRecord(source: "s\(i)", label: "Source \(i)", state: s, lastSuccessAt: hours(1))
        },
        items: items, findings: findings)
}

private func label(_ s: EngineState?, running: Bool = false, progress: RefreshProgress? = nil) -> RefreshLabel {
    RefreshLabel.make(state: s, running: running, progress: progress, now: now, time: utcTime)
}

/// Sync on purpose: `Thread.isMainThread` cannot be read in an async context.
private func onMainThread() -> Bool { Thread.isMainThread }

private actor Calls {
    var refreshOnMain: [Bool] = []
    var setProject: [(String, Bool)] = []
    var findingCalls: [String] = []
    func addRefresh(_ main: Bool) { refreshOnMain.append(main) }
    func addProject(_ path: String, _ active: Bool) { setProject.append((path, active)) }
    func addFinding(_ call: String) { findingCalls.append(call) }
}

private struct FakeEngine: EngineClient {
    enum Mode { case finish(EngineState), hang, fail(EngineError) }
    var mode: Mode
    var saved: EngineState? = nil
    var failProjects = false
    var failFindings = false
    var findings: [FindingRecord] = []
    let calls = Calls()

    func findingNamed(_ id: String) -> FindingRecord { findings.first { $0.id == id }! }

    func state() async throws -> EngineState {
        guard let saved else { throw EngineError.failed(message: "none", detail: nil) }
        return saved
    }

    func refresh(progress: @escaping @Sendable (RefreshProgress) -> Void) async throws -> EngineState {
        await calls.addRefresh(onMainThread())
        progress(RefreshProgress(done: 1, total: 4, source: "Applications"))
        switch mode {
        case .finish(let s): return s
        case .hang:
            try await Task.sleep(for: .seconds(60))
            Issue.record("the hanging refresh was not cancelled")
            throw CancellationError()
        case .fail(let e): throw e
        }
    }

    func projects() async throws -> ProjectList {
        ProjectList(schemaVersion: 1, projects: [], rootErrors: [], skipped: [])
    }

    func setProject(path: String, active: Bool) async throws -> ProjectRecord {
        await calls.addProject(path, active)
        if failProjects { throw EngineError.reported(message: "The project choices file is not valid.", detail: nil) }
        return ProjectRecord(name: "web", path: path, root: "~/Projects", manifests: [],
                             state: active ? "active" : "inactive")
    }
}

extension FakeEngine {
    private func changed(_ id: String, _ call: String, _ change: (inout FindingRecord) -> Void) async throws
        -> FindingRecord {
        await calls.addFinding(call)
        if failFindings { throw EngineError.reported(message: "There is no finding \(id).", detail: nil) }
        var finding = findingNamed(id)
        change(&finding)
        return finding
    }

    func deferFinding(id: String, days: Int) async throws -> FindingRecord {
        try await changed(id, "defer \(id) \(days)") {
            $0.status = .deferred
            $0.deferredUntil = now.addingTimeInterval(Double(days) * 86400)
        }
    }

    func moveFindingToBacklog(id: String) async throws -> FindingRecord {
        try await changed(id, "backlog \(id)") { $0.status = .backlog }
    }

    func reopenFinding(id: String) async throws -> FindingRecord {
        try await changed(id, "reopen \(id)") { $0.status = .open }
    }
}

private let web = ProjectRecord(name: "web", path: "/Users/me/Projects/web", root: "~/Projects",
                                manifests: ["package-lock.json"], state: "active")
private let old = ProjectRecord(name: "old", path: "/Users/me/Projects/old", root: "~/Projects",
                                manifests: ["Cargo.lock"], state: "inactive")

// MARK: - Refresh label

@Test func labelNeverRefreshed() {
    #expect(label(nil) == RefreshLabel(text: "Never refreshed. Click Refresh.", tone: .secondary))
    let onlyCancelled = state(.cancelled, finished: hours(1), lastComplete: nil)
    #expect(label(onlyCancelled).text == "Never refreshed. Click Refresh.")
}

@Test func labelUnder24HoursShowsAge() {
    #expect(label(state(.complete, finished: hours(2), lastComplete: hours(2)))
        == RefreshLabel(text: "Last refresh: 2 h ago", tone: .secondary))
    #expect(label(state(.complete, finished: hours(0.5), lastComplete: hours(0.5))).text == "Last refresh: 30 min ago")
    #expect(label(state(.complete, finished: hours(0.001), lastComplete: hours(0.001))).text
        == "Last refresh: just now")
    #expect(label(state(.complete, finished: hours(23.9), lastComplete: hours(23.9))).text
        == "Last refresh: 23 h ago")
}

@Test func labelStaleFromStoredCompletionTime() {
    // 2026-10-27 09:14 UTC, more than 24 h before `now`.
    let completed = Date(timeIntervalSince1970: 1_793_092_440)
    #expect(label(state(.complete, finished: completed, lastComplete: completed))
        == RefreshLabel(text: "Stale: last refresh Oct 27, 09:14", tone: .orange))
    #expect(label(state(.complete, finished: hours(24), lastComplete: hours(24))).tone == .orange)
    // A cancelled refresh keeps the label of the last complete one.
    #expect(label(state(.cancelled, finished: hours(1), lastComplete: hours(30))).text.hasPrefix("Stale:"))
    #expect(label(state(.cancelled, finished: hours(1), lastComplete: hours(3))).text == "Last refresh: 3 h ago")
}

@Test func labelPartialCountsFailedSources() {
    let s = state(.partial, finished: hours(1), lastComplete: hours(30),
                  coverage: [.complete, .failed, .partial, .complete, .notRun])
    #expect(label(s) == RefreshLabel(text: "Partial: 2 of 5 sources failed", tone: .orange))
    // An old partial refresh is stale.
    let oldPartial = state(.partial, finished: hours(25), lastComplete: hours(30), coverage: [.failed])
    #expect(label(oldPartial).text.hasPrefix("Stale: last refresh"))
}

@Test func labelFailedShowsDataTime() {
    let lastGood = Date(timeIntervalSince1970: 1_793_210_520)  // 2026-10-28 18:02 UTC
    #expect(label(state(.failed, finished: hours(1), lastComplete: lastGood))
        == RefreshLabel(text: "Refresh failed. Showing data from Oct 28, 18:02", tone: .red))
    #expect(label(state(.failed, finished: hours(1), lastComplete: nil)).tone == .red)
    // A stored `running` refresh never finished: it reads as failed.
    #expect(label(state(.running, finished: nil, lastComplete: lastGood)).tone == .red)
}

@Test func labelRunningShowsProgress() {
    let s = state(.complete, finished: hours(2), lastComplete: hours(2))
    #expect(label(s, running: true, progress: RefreshProgress(done: 2, total: 5, source: "x"))
        == RefreshLabel(text: "Refreshing… 3 of 5 sources", tone: .secondary, showsProgress: true))
    #expect(label(s, running: true).text == "Refreshing…")
    #expect(label(s, running: true, progress: RefreshProgress(done: 5, total: 5, source: "")).text
        == "Refreshing… 5 of 5 sources")
}

@Test func staleThresholdIs24Hours() {
    #expect(staleAfter == 86_400)
}

// MARK: - Status badge and sections

@Test func statusBadgeTextAndSymbols() {
    let all = ItemState.allCases.map { StatusStyle($0) }
    #expect(all.map(\.text) == ["Up to date", "Update available", "Vulnerable", "Unknown", "Error", "Pinned",
                                "Manual update"])
    #expect(all.map(\.symbol) == ["checkmark.circle", "arrow.up.circle", "exclamationmark.shield",
                                  "questionmark.circle", "exclamationmark.triangle", "pin", "hand.raised"])
    #expect(all.map(\.tone) == [.green, .blue, .red, .gray, .orange, .gray, .gray])
}

@Test func sidebarOrderAndShortcuts() {
    #expect(SidebarSection.allCases.map(\.title) == ["Apps", "Homebrew", "Projects", "Findings", "Backlog",
                                                     "Incidents", "Update Log"])
    #expect(SidebarSection.allCases.map(\.shortcutDigit) == ["1", "2", "3", "4", "5", "6", "7"])
}

@Test func coverageRowsShowStateAndLastSuccess() {
    let rows = CoverageRow.rows([
        CoverageRecord(source: "homebrew", label: "Homebrew", state: .complete, lastSuccessAt: hours(2)),
        CoverageRecord(source: "osv", label: "OSV", state: .stale, lastSuccessAt: nil,
                       error: "OSV database is 9 days old. Results can miss new advisories."),
    ], time: utcTime)
    #expect(rows.map(\.stateText) == ["Complete", "Stale"])
    #expect(rows[0].lastSuccess == "Last success Oct 29, 10:00")
    #expect(rows[1].lastSuccess == "No success yet")
    #expect(rows[1].error == "OSV database is 9 days old. Results can miss new advisories.")
}

@MainActor
@Test func sectionsFilterSortAndCount() {
    let items = [
        ItemRecord(id: "formula:b", source: "homebrew", name: "b", state: .upToDate),
        ItemRecord(id: "formula:a", source: "homebrew", name: "a", state: .upToDate),
        ItemRecord(id: "formula:z", source: "homebrew", name: "z", state: .updateAvailable),
        ItemRecord(id: "app:s", source: "apps", name: "Slack", state: .upToDate),
        ItemRecord(id: "macos", source: "macos", name: "macOS", state: .manual),
    ]
    let findings = [
        finding("SEC-0001", package: "x", path: web.path),
        finding("SEC-0002", package: "y", path: old.path),
        finding("SEC-0003", package: "z", status: .resolved, path: nil),
    ]
    let model = DashboardModel(engine: FakeEngine(mode: .hang),
                               state: state(.complete, finished: hours(1), lastComplete: hours(1), items: items,
                                            findings: findings),
                               projects: [web, old], clock: { now })
    #expect(model.items(in: .homebrew).map(\.name) == ["z", "a", "b"])
    #expect(model.items(in: .apps).map(\.name) == ["macOS", "Slack"])
    // A finding only in an inactive project is part of the Backlog. A resolved one has no path.
    #expect(model.findingsInScope.map(\.id) == ["SEC-0001", "SEC-0003"])
    #expect(SidebarSection.allCases.map { model.count($0) } == [2, 3, 1, 1, 1, 0, 0])
    #expect(model.hasOpenFindings)
    model.searchText = "Z"
    #expect(model.visibleItems(in: .homebrew).map(\.name) == ["z"])
    model.searchText = "ol"
    #expect(model.visibleProjects(in: .backlog).map(\.name) == ["old"])
}

// MARK: - Model: refresh, stop, projects

@MainActor
@Test func refreshRunsOffTheMainThreadAndSavesState() async {
    let newState = state(.complete, finished: now, lastComplete: now)
    let engine = FakeEngine(mode: .finish(newState))
    let model = DashboardModel(engine: engine, clock: { now })
    model.refresh()
    #expect(model.isRefreshing)
    #expect(model.refreshLabel.showsProgress)
    await model.waitForRefresh()
    #expect(!model.isRefreshing)
    #expect(model.state == newState)
    #expect(model.progress == nil)
    #expect(await engine.calls.refreshOnMain == [false])
}

@MainActor
@Test func stopKeepsThePreviousResults() async {
    let previous = state(.complete, finished: hours(3), lastComplete: hours(3))
    let model = DashboardModel(engine: FakeEngine(mode: .hang), state: previous, clock: { now })
    model.refresh()
    try? await Task.sleep(for: .milliseconds(50))
    let started = Date()
    model.stop()
    await model.waitForRefresh()
    #expect(Date().timeIntervalSince(started) < 5)
    #expect(!model.isRefreshing)
    #expect(model.state == previous)
    #expect(model.lastError == nil)
    #expect(model.refreshLabel.text == "Last refresh: 3 h ago")
}

@MainActor
@Test func aFailedRefreshShowsTheErrorAndTheSavedState() async {
    let saved = state(.failed, finished: now, lastComplete: hours(5))
    let error = EngineError.reported(message: "A newer Watchtower wrote this data.", detail: nil)
    let model = DashboardModel(engine: FakeEngine(mode: .fail(error), saved: saved), clock: { now })
    model.refresh()
    await model.waitForRefresh()
    #expect(model.lastError == error)
    #expect(model.state == saved)
    #expect(model.refreshLabel.tone == .red)
}

@MainActor
@Test func secondRefreshWhileRunningIsIgnored() async {
    let engine = FakeEngine(mode: .hang)
    let model = DashboardModel(engine: engine, clock: { now })
    model.refresh()
    model.refresh()
    try? await Task.sleep(for: .milliseconds(50))
    model.stop()
    await model.waitForRefresh()
    #expect(await engine.calls.refreshOnMain.count == 1)
}

@MainActor
@Test func turningAProjectOffMovesItToBacklogAndSavesIt() async {
    let engine = FakeEngine(mode: .hang)
    let model = DashboardModel(engine: engine, projects: [web, old], clock: { now })
    await model.setProject(web, active: false)
    #expect(model.backlogProjects.map(\.name) == ["web", "old"])
    #expect(model.activeProjects.isEmpty)
    let calls = await engine.calls.setProject
    #expect(calls.count == 1 && calls[0].0 == web.path && calls[0].1 == false)
}

@MainActor
@Test func aProjectChoiceThatFailsToSaveIsUndone() async {
    var engine = FakeEngine(mode: .hang)
    engine.failProjects = true
    let model = DashboardModel(engine: engine, projects: [web], clock: { now })
    await model.setProject(web, active: false)
    #expect(model.activeProjects == [web])
    #expect(model.lastError?.message == "The project choices file is not valid.")
}

@MainActor
@Test func sourceAgeText() {
    let item = ItemRecord(id: "formula:git", source: "homebrew", name: "git", state: .upToDate,
                          sourceAt: hours(3))
    let s = EngineState(schemaVersion: 1, refresh: nil,
                        coverage: [CoverageRecord(source: "homebrew", label: "Homebrew", state: .complete)],
                        items: [item])
    let model = DashboardModel(engine: FakeEngine(mode: .hang), state: s, clock: { now })
    #expect(model.sourceAgeText(for: item) == "Homebrew data: 3 h old")
}

// MARK: - Engine bridge

private struct FakeRunner: CommandRunner {
    var result: ProcessResult
    var stderrLines: [String] = []
    let seen = Seen()

    actor Seen {
        var args: [[String]] = []
        func add(_ a: [String]) { args.append(a) }
    }

    func run(_ executable: URL, _ arguments: [String], environment: [String: String],
             onStderrLine: @escaping @Sendable (String) -> Void) async throws -> ProcessResult {
        await seen.add(arguments)
        stderrLines.forEach(onStderrLine)
        return result
    }
}

private let command = EngineCommand(executable: URL(fileURLWithPath: "/usr/bin/python3"),
                                    arguments: ["-s", "-m", "watchtower_engine.cli"], environment: [:])

private func fixture(_ name: String) throws -> Data {
    let url = try #require(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures"))
    return try Data(contentsOf: url)
}

private final class ProgressBox: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [RefreshProgress] = []
    func add(_ p: RefreshProgress) { lock.withLock { items.append(p) } }
    var all: [RefreshProgress] { lock.withLock { items } }
}

@Test func engineRefreshDecodesStateAndProgress() async throws {
    let runner = FakeRunner(
        result: ProcessResult(status: 0, stdout: try fixture("state-partial"), stderr: Data()),
        stderrLines: [#"{"schema_version": 1, "progress": {"done": 0, "total": 4, "source": "Homebrew"}}"#,
                      "not json", #"{"schema_version": 1, "progress": {"done": 4, "total": 4, "source": ""}}"#])
    let box = ProgressBox()
    let result = try await Engine(command: command, runner: runner).refresh { box.add($0) }
    #expect(result.refresh?.status == .partial)
    #expect(box.all.map(\.done) == [0, 4])
    #expect(await runner.seen.args == [["-s", "-m", "watchtower_engine.cli", "refresh"]])
}

@Test func engineErrorComesFromTheLastStderrJSONLine() async throws {
    let stderr = """
    {"schema_version": 1, "progress": {"done": 0, "total": 4, "source": "Homebrew"}}
    {"schema_version": 1, "error": "A newer Watchtower wrote this data.", "detail": "Store schema 99"}

    """
    let runner = FakeRunner(result: ProcessResult(status: 1, stdout: Data(), stderr: Data(stderr.utf8)))
    await #expect(throws: EngineError.reported(message: "A newer Watchtower wrote this data.",
                                                detail: "Store schema 99")) {
        try await Engine(command: command, runner: runner).state()
    }
    let crash = FakeRunner(result: ProcessResult(status: 1, stdout: Data(), stderr: Data("Traceback".utf8)))
    do {
        _ = try await Engine(command: command, runner: crash).state()
        Issue.record("expected an error")
    } catch let error as EngineError {
        #expect(error.message == "The engine stopped with an error.")
    }
}

@Test func engineRejectsUnreadableOutput() async {
    let runner = FakeRunner(result: ProcessResult(status: 0, stdout: Data("{".utf8), stderr: Data()))
    do {
        _ = try await Engine(command: command, runner: runner).state()
        Issue.record("expected an error")
    } catch let error as EngineError {
        #expect(error.message == "The engine output was not readable.")
    } catch {
        Issue.record("unexpected \(error)")
    }
}

@Test func engineProjectCalls() async throws {
    let list = #"{"schema_version": 1, "projects": [{"name": "web", "path": "/Users/me/Projects/web", "root": "~/Projects", "manifests": ["package-lock.json"], "state": "active"}], "root_errors": [{"root": "~/Real", "kind": "missing", "message": "~/Real does not exist."}], "skipped": []}"#
    let runner = FakeRunner(result: ProcessResult(status: 0, stdout: Data(list.utf8), stderr: Data()))
    let projects = try await Engine(command: command, runner: runner).projects()
    #expect(projects.projects.map(\.name) == ["web"])
    #expect(projects.rootErrors.first?.kind == "missing")

    let one = #"{"schema_version": 1, "project": {"name": "web", "path": "/Users/me/Projects/web", "root": "~/Projects", "manifests": [], "state": "inactive"}}"#
    let setter = FakeRunner(result: ProcessResult(status: 0, stdout: Data(one.utf8), stderr: Data()))
    let saved = try await Engine(command: command, runner: setter).setProject(path: "/Users/me/Projects/web",
                                                                               active: false)
    #expect(!saved.isActive)
    #expect(await setter.seen.args.last?.suffix(3) == ["project-state", "/Users/me/Projects/web", "inactive"])
}

@Test func developmentCommandFindsPythonAndEngine() {
    let cmd = EngineCommand.development(
        environment: ["WATCHTOWER_ENGINE_DIR": "/repo/engine", "WATCHTOWER_DATA_DIR": "/tmp/data", "HOME": "/Users/me"],
        fileExists: { $0 == "/opt/homebrew/bin/python3" })
    #expect(cmd.executable.path == "/opt/homebrew/bin/python3")
    #expect(cmd.arguments == ["-s", "-m", "watchtower_engine.cli"])
    #expect(cmd.environment["PYTHONPATH"] == "/repo/engine")
    #expect(cmd.environment["WATCHTOWER_DATA_DIR"] == "/tmp/data")
    let venv = EngineCommand.development(environment: ["WATCHTOWER_ENGINE_DIR": "/repo/engine"],
                                         fileExists: { _ in true })
    #expect(venv.executable.path == "/repo/engine/.venv/bin/python")
}

@Test func displayPathUsesTilde() {
    #expect(DisplayPath.abbreviate("/Users/me/Projects/x", home: "/Users/me") == "~/Projects/x")
    #expect(DisplayPath.abbreviate("/Applications/Zed.app", home: "/Users/me") == "/Applications/Zed.app")
}

// The real process runner tests are in EngineProcessTests.swift (serialized, with a time limit, #52).


// MARK: - Findings

private func finding(_ id: String, package: String = "lodash", severity: Severity = .high,
                     status: FindingStatus = .open, lastSeen: Date? = nil, path: String? = web.path,
                     title: String = "A title", ids: [String] = ["GHSA-1"],
                     deferredUntil: Date? = nil) -> FindingRecord {
    FindingRecord(id: id, package: package, title: title, severity: severity, advisoryIds: ids, status: status,
                  deferredUntil: deferredUntil, firstSeen: hours(240), lastSeen: lastSeen ?? hours(2),
                  resolvedScanAt: status == .resolved ? hours(5) : nil,
                  paths: path.map { [FindingPath(project: "web", projectPath: $0, lockfile: "package-lock.json",
                                                 version: "4.17.20")] } ?? [])
}

@MainActor
private func findingsModel(_ findings: [FindingRecord], engine: FakeEngine? = nil,
                           coverage: [CoverageState] = [.complete]) -> DashboardModel {
    var engine = engine ?? FakeEngine(mode: .hang)
    engine.findings = findings
    let model = DashboardModel(
        engine: engine,
        state: state(.complete, finished: hours(1), lastComplete: hours(1), coverage: coverage, findings: findings),
        projects: [web, old], clock: { now })
    return model
}

@MainActor
@Test func findingsSortBySeverityThenNewestAndDefaultToOpen() {
    let model = findingsModel([
        finding("SEC-0001", package: "a", severity: .high, lastSeen: hours(30)),
        finding("SEC-0002", package: "b", severity: .critical, lastSeen: hours(50)),
        finding("SEC-0003", package: "c", severity: .high, lastSeen: hours(1)),
        finding("SEC-0004", package: "d", severity: .low, lastSeen: hours(1)),
        finding("SEC-0005", package: "e", severity: .critical, status: .resolved),
        finding("SEC-0006", package: "f", status: .deferred, deferredUntil: now.addingTimeInterval(86400)),
        finding("SEC-0007", package: "g", status: .backlog),
    ])
    #expect(model.findingFilter == .open)
    #expect(model.visibleFindings.map(\.id) == ["SEC-0002", "SEC-0003", "SEC-0001", "SEC-0004"])
    model.findingFilter = .deferred
    #expect(model.visibleFindings.map(\.id) == ["SEC-0006", "SEC-0007"])  // Backlog findings sit here
    model.findingFilter = .resolved
    #expect(model.visibleFindings.map(\.id) == ["SEC-0005"])
    model.findingFilter = .all
    #expect(model.visibleFindings.count == 7)
    #expect(model.count(.findings) == 4)  // Open findings only
}

@MainActor
@Test func findingSearchMatchesIdPackageTitleAndAliases() {
    let model = findingsModel([
        finding("SEC-0001", package: "lodash", title: "Command Injection", ids: ["CVE-2021-23337", "GHSA-35jh"]),
        finding("SEC-0002", package: "minimist", title: "Prototype Pollution", ids: ["CVE-2021-44906"]),
    ])
    for (query, expected) in [("sec-0002", ["SEC-0002"]), ("LODASH", ["SEC-0001"]), ("pollution", ["SEC-0002"]),
                              ("ghsa-35", ["SEC-0001"]), ("cve-2021", ["SEC-0001", "SEC-0002"]), ("none", [])] {
        model.searchText = query
        #expect(model.visibleFindings.map(\.id).sorted() == expected, "query \(query)")
    }
}

@MainActor
@Test func selectedFindingAndProjectFindings() {
    let model = findingsModel([
        finding("SEC-0001", path: web.path),
        finding("SEC-0002", status: .resolved, path: nil),
        finding("SEC-0003", status: .deferred, path: web.path),
    ])
    model.selectedItemKey = "SEC-0001"
    #expect(model.selectedFinding?.id == "SEC-0001")
    model.selectedItemKey = "nope"
    #expect(model.selectedFinding == nil)
    // Only open findings count for a project. The project path is a display path.
    #expect(model.findings(in: web).map(\.id) == ["SEC-0001"])
    #expect(model.findings(in: old).isEmpty)
}

@Test func findingStatusTextFollowsTheDesignTable() {
    let utc = TimeText(timeZone: TimeZone(identifier: "UTC")!)
    let until = Date(timeIntervalSince1970: 1_793_879_999)  // 2026-11-05 11:59:59 UTC
    let open = FindingStatusText(finding("a"), time: utc)
    #expect((open.text, open.tone) == ("Open", .red))
    let deferred = FindingStatusText(finding("a", status: .deferred, deferredUntil: until), time: utc)
    #expect((deferred.text, deferred.tone) == ("Deferred until Nov 5", .gray))
    #expect(FindingStatusText(finding("a", status: .backlog), time: utc).text == "Backlog")
    let resolved = FindingStatusText(finding("a", status: .resolved), time: utc)
    #expect((resolved.text, resolved.tone) == ("Resolved: not found in complete scan of Oct 29", .green))
    #expect(FindingStatusText(finding("a", status: .resolved), full: false, time: utc).text == "Resolved")
}

@Test func severityStylesAlwaysHaveText() {
    #expect(Severity.allCases.map { SeverityStyle($0).text } == ["Critical", "High", "Medium", "Low", "Unknown"])
    #expect(Severity.allCases.map(\.rank) == [0, 1, 2, 3, 4])
}

@MainActor
private func osvModel(_ coverage: CoverageState, _ findings: [FindingRecord]) -> DashboardModel {
    var s = state(.complete, finished: hours(1), lastComplete: hours(1), findings: findings)
    s.coverage = [CoverageRecord(source: "osv", label: "OSV", state: coverage, lastSuccessAt: hours(1))]
    return DashboardModel(engine: FakeEngine(mode: .hang), state: s, projects: [web], clock: { now })
}

@MainActor
@Test func partialBannerShowsOnlyForAnOpenFindingAfterAnIncompleteScan() {
    let open = finding("SEC-0001")
    let deferred = finding("SEC-0002", status: .deferred)
    let resolved = finding("SEC-0003", status: .resolved)
    for s in [CoverageState.partial, .failed, .stale, .notRun] {
        #expect(osvModel(s, [open]).showsPartialBanner(for: open), "\(s)")
    }
    let complete = osvModel(.complete, [open])
    #expect(!complete.showsPartialBanner(for: open))
    let partial = osvModel(.partial, [open, deferred, resolved])
    #expect(!partial.showsPartialBanner(for: deferred))
    #expect(!partial.showsPartialBanner(for: resolved))
}

@MainActor
@Test func findingActionsCallTheEngineAndUpdateTheRow() async {
    let engine = FakeEngine(mode: .hang)
    let model = findingsModel([finding("SEC-0001"), finding("SEC-0002")], engine: engine)
    let first = model.state!.findings[0]
    await model.deferFinding(first, days: 7)
    #expect(model.state?.findings[0].status == .deferred)
    #expect(model.state?.findings[0].deferredUntil == now.addingTimeInterval(7 * 86400))
    #expect(model.state?.findings[1].status == .open)
    #expect(model.visibleFindings.map(\.id) == ["SEC-0002"])  // It left the Open filter
    await model.moveToBacklog(model.state!.findings[0])
    #expect(model.state?.findings[0].status == .backlog)
    await model.reopen(model.state!.findings[0])
    #expect(model.state?.findings[0].status == .open)
    #expect(await engine.calls.findingCalls == ["defer SEC-0001 7", "backlog SEC-0001", "reopen SEC-0001"])
    #expect(model.lastError == nil)
}

@MainActor
@Test func failedFindingActionKeepsTheRowAndShowsTheError() async {
    var engine = FakeEngine(mode: .hang)
    engine.failFindings = true
    let model = findingsModel([finding("SEC-0001")], engine: engine)
    await model.moveToBacklog(model.state!.findings[0])
    #expect(model.state?.findings[0].status == .open)
    #expect(model.lastError?.message == "There is no finding SEC-0001.")
}

@Test func advisoryLinksGoToTheSourcePage() {
    #expect(AdvisoryLink.url(for: "CVE-2021-23337")?.absoluteString == "https://nvd.nist.gov/vuln/detail/CVE-2021-23337")
    #expect(AdvisoryLink.url(for: "GHSA-35jh-r3h4-6jhm")?.absoluteString
        == "https://github.com/advisories/GHSA-35jh-r3h4-6jhm")
    #expect(AdvisoryLink.url(for: "PYSEC-2024-1")?.absoluteString == "https://osv.dev/vulnerability/PYSEC-2024-1")
    #expect(AdvisoryLink.url(for: "OSV-2021-1/../x")?.absoluteString == "https://osv.dev/vulnerability/OSV-2021-1/../x")
    let ids = finding("a", ids: ["PYSEC-1", "GHSA-b", "CVE-2", "CVE-1", "GHSA-a"]).sortedAdvisoryIds
    #expect(ids == ["CVE-1", "CVE-2", "GHSA-a", "GHSA-b", "PYSEC-1"])
}

@Test func findingPathReachesTheLockfileInFinder() {
    let path = FindingPath(project: "web", projectPath: "~/Projects/web", lockfile: "app/package-lock.json",
                           version: "1")
    #expect(path.lockfileURL.path == NSHomeDirectory() + "/Projects/web/app/package-lock.json")
}


// MARK: - Feed marks (#9)

private let kevMark = KevMark(cve: "CVE-1", dateAdded: "2026-10-22", dueDate: "2026-11-12")

@MainActor
@Test func findingsSortMalwareThenKnownExploitedThenSeverity() {
    var low = finding("SEC-0001", package: "low", severity: .low)
    var kevLow = finding("SEC-0002", package: "kevlow", severity: .low)
    kevLow.kev = kevMark
    let crit = finding("SEC-0003", package: "crit", severity: .critical)
    var malwareLow = finding("SEC-0004", package: "mal", severity: .low)
    malwareLow.malware = MalwareMark(advisoryId: "GHSA-mal1-ware-0001")
    var kevCrit = finding("SEC-0005", package: "kevcrit", severity: .critical, lastSeen: hours(1))
    kevCrit.kev = kevMark
    low.withdrawnAt = hours(5)  // A withdrawn mark does not change the order.
    let model = findingsModel([low, kevLow, crit, malwareLow, kevCrit])
    #expect(model.visibleFindings.map(\.package) == ["mal", "kevcrit", "kevlow", "crit", "low"])
}

@Test func feedBadgesHaveTheDesignTextSymbolToneAndHelp() {
    let utc = TimeText(timeZone: TimeZone(identifier: "UTC")!)
    var f = finding("SEC-0001")
    #expect(FeedBadge.badges(for: f, time: utc).isEmpty)
    f.kev = kevMark
    f.malware = MalwareMark(advisoryId: "GHSA-mal1-ware-0001")
    f.withdrawnAt = Date(timeIntervalSince1970: 1_793_275_200)  // 2026-10-29
    let badges = FeedBadge.badges(for: f, time: utc)
    #expect(badges.map(\.text) == ["Malware", "Known exploited", "Withdrawn"])
    #expect(badges.map(\.symbol) == ["exclamationmark.octagon.fill", "flame.fill", "minus.circle"])
    #expect(badges.map(\.tone) == [.red, .red, .gray])
    #expect(badges.map(\.help) == [
        "GitHub lists this package as malware.",
        "Listed in CISA KEV on Oct 22. Due date Nov 12.",
        "The source withdrew this advisory on Oct 29.",
    ])
    f.kev = KevMark(cve: "CVE-1")
    #expect(FeedBadge.badges(for: f, time: utc)[1].help == "Listed in CISA KEV.")
}

@Test func feedBadgeTextNeverClaimsExposureFromAProductName() {
    var f = finding("SEC-0001")
    f.kev = kevMark
    f.malware = MalwareMark(advisoryId: "x")
    f.withdrawnAt = now
    for badge in FeedBadge.badges(for: f) {
        let text = (badge.text + " " + badge.help).lowercased()
        #expect(!text.contains("exposed") && !text.contains("affected"), "\(badge.text)")
    }
}

@Test func kevDatesReadAsMonthAndDay() {
    let utc = TimeText(timeZone: TimeZone(identifier: "UTC")!)
    #expect(utc.day("2026-10-22") == "Oct 22")
    #expect(utc.day("2026-01-05") == "Jan 5")
    #expect(utc.day("not a date") == "not a date")
}

@Test func sourceRowsFollowTheDesignTextForEachFeedState() {
    let utc = TimeText(timeZone: TimeZone(identifier: "UTC")!)
    func row(_ source: String, _ label: String, _ state: CoverageState, at: Date? = nil, note: String? = nil) -> FindingSourceRow {
        FindingSourceRow.make(CoverageRecord(source: source, label: label, state: state, lastSuccessAt: nil,
                                             sourceAt: at, note: note), time: utc)
    }
    let at = Date(timeIntervalSince1970: 1_793_275_200)  // 2026-10-29 12:00 UTC
    #expect(row("kev", "CISA KEV", .complete, at: at).text == "CISA KEV: retrieved Oct 29, 12:00")
    #expect(row("kev", "CISA KEV", .complete, at: at, note: "official mirror").text
        == "CISA KEV: retrieved from the official mirror")
    #expect(!row("kev", "CISA KEV", .complete, at: at).isProblem)
    let failed = row("github", "GitHub Advisories", .failed, at: at.addingTimeInterval(-86400), note: "rate limit")
    #expect(failed.text == "GitHub Advisories: failed (rate limit). Data from Oct 28.")
    #expect(failed.isProblem)
    #expect(row("github", "GitHub Advisories", .failed).text == "GitHub Advisories: failed (error). No data yet.")
    #expect(row("github", "GitHub Advisories", .partial, at: at, note: "pagination stopped").text
        == "GitHub Advisories: incomplete. Some advisories can be missing.")
    #expect(row("osv", "OSV", .stale, at: at).text == "OSV: stale. Data from Oct 29.")
    #expect(row("kev", "CISA KEV", .notRun).isProblem)
}

@MainActor
@Test func findingSourceRowsListOnlyTheFeedsThatRanInOrder() {
    var s = state(.complete, finished: hours(1), lastComplete: hours(1), findings: [finding("SEC-0001")])
    s.coverage = [
        CoverageRecord(source: "github", label: "GitHub Advisories", state: .complete, sourceAt: hours(3)),
        CoverageRecord(source: "homebrew", label: "Homebrew", state: .complete),
        CoverageRecord(source: "osv", label: "OSV", state: .complete, sourceAt: hours(2)),
    ]
    let model = DashboardModel(engine: FakeEngine(mode: .hang), state: s, projects: [web], clock: { now })
    #expect(model.findingSourceRows.map(\.id) == ["osv", "github"])  // No KEV row: KEV did not run.
}
