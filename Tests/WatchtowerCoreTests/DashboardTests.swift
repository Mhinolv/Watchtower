import Foundation
import Testing
@testable import WatchtowerCore

// MARK: - Helpers

private let now = Date(timeIntervalSince1970: 1_793_275_200)  // 2026-10-29 12:00 UTC
private let utcTime = TimeText(timeZone: TimeZone(identifier: "UTC")!)

private func hours(_ h: Double) -> Date { now.addingTimeInterval(-h * 3600) }

private func state(_ status: RefreshStatus, finished: Date?, lastComplete: Date?,
                   coverage: [CoverageState] = [.complete, .complete, .complete, .complete],
                   items: [ItemRecord] = []) -> EngineState {
    EngineState(
        schemaVersion: 1,
        refresh: RefreshRecord(id: 1, status: status, startedAt: (finished ?? now).addingTimeInterval(-60),
                               finishedAt: finished, lastCompleteAt: lastComplete),
        coverage: coverage.enumerated().map { i, s in
            CoverageRecord(source: "s\(i)", label: "Source \(i)", state: s, lastSuccessAt: hours(1))
        },
        items: items)
}

private func label(_ s: EngineState?, running: Bool = false, progress: RefreshProgress? = nil) -> RefreshLabel {
    RefreshLabel.make(state: s, running: running, progress: progress, now: now, time: utcTime)
}

/// Sync on purpose: `Thread.isMainThread` cannot be read in an async context.
private func onMainThread() -> Bool { Thread.isMainThread }

private actor Calls {
    var refreshOnMain: [Bool] = []
    var setProject: [(String, Bool)] = []
    func addRefresh(_ main: Bool) { refreshOnMain.append(main) }
    func addProject(_ path: String, _ active: Bool) { setProject.append((path, active)) }
}

private struct FakeEngine: EngineClient {
    enum Mode { case finish(EngineState), hang, fail(EngineError) }
    var mode: Mode
    var saved: EngineState? = nil
    var failProjects = false
    let calls = Calls()

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
    #expect(SidebarSection.allCases.map(\.title) == ["Apps", "Homebrew", "Projects", "Findings", "Backlog"])
    #expect(SidebarSection.allCases.map(\.shortcutDigit) == ["1", "2", "3", "4", "5"])
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
        ItemRecord(id: "npm:x", source: "osv", name: "x", state: .vulnerable, project: "web"),
        ItemRecord(id: "npm:y", source: "osv", name: "y", state: .vulnerable, project: "old"),
    ]
    let model = DashboardModel(engine: FakeEngine(mode: .hang),
                               state: state(.complete, finished: hours(1), lastComplete: hours(1), items: items),
                               projects: [web, old], clock: { now })
    #expect(model.items(in: .homebrew).map(\.name) == ["z", "a", "b"])
    #expect(model.items(in: .apps).map(\.name) == ["macOS", "Slack"])
    #expect(model.items(in: .findings).map(\.name) == ["x"])  // the inactive project is in Backlog
    #expect(SidebarSection.allCases.map { model.count($0) } == [2, 3, 1, 1, 1])
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

// MARK: - Real process runner (/bin/sh only)

private final class Lines: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String] = []
    func add(_ s: String) { lock.withLock { items.append(s) } }
    var all: [String] { lock.withLock { items } }
}

@Test func processRunnerReturnsOutputAndStreamsStderrLines() async throws {
    let lines = Lines()
    let result = try await ProcessCommandRunner().run(
        URL(fileURLWithPath: "/bin/sh"), ["-c", "printf 'one\\ntwo\\n' >&2; printf '{\"a\": 1}'; printf 'last' >&2; exit 3"],
        environment: [:], onStderrLine: { lines.add($0) })
    #expect(result.status == 3)
    #expect(String(decoding: result.stdout, as: UTF8.self) == #"{"a": 1}"#)
    #expect(lines.all == ["one", "two", "last"])
}

@Test func processRunnerCancelStopsTheProcess() async {
    let task = Task {
        try await ProcessCommandRunner().run(URL(fileURLWithPath: "/bin/sh"), ["-c", "exec sleep 30"],
                                             environment: [:], onStderrLine: { _ in })
    }
    try? await Task.sleep(for: .milliseconds(200))
    let started = Date()
    task.cancel()
    let result = await task.result
    #expect(Date().timeIntervalSince(started) < 5)
    if case .success = result { Issue.record("a cancelled run must throw") }
}
