import Darwin
import Foundation
import Testing
@testable import WatchtowerCore

// Tests that start real processes, with /bin/sh as a stand-in engine (#33, #52).
// Rules: every wait has a deadline, every stand-in is killed when its test ends, the tests run
// one at a time, and each test has a time limit. A failure ends the test, it never hangs CI.

@Suite("Engine processes", .serialized, .timeLimit(.minutes(1)))
struct EngineProcessTests {
    /// A stand-in engine: writes its pid, then waits like a long refresh. A second start exits at once.
    static func standIn(_ pidFile: URL, seconds: Int = 20) -> [String] {
        ["-c", "[ -e '\(pidFile.path)' ] && exit 3; echo $$ > '\(pidFile.path)'; exec sleep \(seconds)"]
    }

    static func pidFile() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("wt-proc-\(UUID().uuidString).pid")
    }

    /// The pid that the stand-in wrote, or nil after `seconds`.
    static func waitForPid(_ url: URL, seconds: TimeInterval = 5) async -> pid_t? {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if let text = try? String(contentsOf: url, encoding: .utf8),
               let pid = pid_t(text.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 0 {
                return pid
            }
            try? await Task.sleep(for: .milliseconds(20))
        }
        return nil
    }

    static func alive(_ pid: pid_t) -> Bool { kill(pid, 0) == 0 }

    /// Waits until `pid` is gone, at most `seconds`. Returns true if it is gone.
    static func waitGone(_ pid: pid_t, seconds: TimeInterval = 5) async -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while alive(pid), Date() < deadline { try? await Task.sleep(for: .milliseconds(20)) }
        return !alive(pid)
    }

    /// Never leave a stand-in behind, also when the test failed.
    static func cleanUp(_ pid: pid_t?, _ file: URL) {
        if let pid, alive(pid) { kill(pid, SIGKILL) }
        try? FileManager.default.removeItem(at: file)
    }

    static let sh = URL(fileURLWithPath: "/bin/sh")

    // MARK: Runner

    @Test func runnerReturnsOutputAndStreamsStderrLines() async throws {
        let lines = ProcessLines()
        let result = try await ProcessCommandRunner(registry: EngineProcesses()).run(
            Self.sh, ["-c", "printf 'one\\ntwo\\n' >&2; printf '{\"a\": 1}'; printf 'last' >&2; exit 3"],
            environment: [:], onStderrLine: { lines.add($0) })
        #expect(result.status == 3)
        #expect(String(decoding: result.stdout, as: UTF8.self) == #"{"a": 1}"#)
        #expect(lines.all == ["one", "two", "last"])
    }

    @Test func cancelStopsTheProcess() async throws {
        let file = Self.pidFile()
        var pid: pid_t?
        defer { Self.cleanUp(pid, file) }
        let task = Task {
            try await ProcessCommandRunner(registry: EngineProcesses()).run(
                Self.sh, Self.standIn(file), environment: [:], onStderrLine: { _ in })
        }
        pid = await Self.waitForPid(file)
        let started = try #require(pid, "the stand-in did not start within 5 s")
        task.cancel()
        #expect(await Self.waitGone(started), "cancel did not stop the process within 5 s")
        if case .success = await task.result { Issue.record("a cancelled run must throw") }
    }

    // MARK: Quit (#33)

    @Test func quitTerminatesARunningEngineProcess() async throws {
        let registry = EngineProcesses()
        let file = Self.pidFile()
        var pid: pid_t?
        defer { Self.cleanUp(pid, file) }
        let run = Task {
            try await ProcessCommandRunner(registry: registry).run(Self.sh, Self.standIn(file), environment: [:],
                                                                   onStderrLine: { _ in })
        }
        pid = await Self.waitForPid(file)
        let started = try #require(pid, "the stand-in did not start within 5 s")
        #expect(Self.alive(started))
        #expect(registry.terminateAll(wait: 3) == 1)
        #expect(await Self.waitGone(started), "the engine process still runs after quit")
        if case .success = await run.result { Issue.record("a run stopped by quit must throw") }
        #expect(registry.count == 0)
    }

    @Test func quitWithNoRefreshRunningDoesNothing() {
        let registry = EngineProcesses()
        let started = Date()
        #expect(registry.terminateAll(wait: 3) == 0)
        #expect(Date().timeIntervalSince(started) < 0.5)
    }

    @Test func finishedProcessesLeaveTheRegistry() async throws {
        let registry = EngineProcesses()
        let result = try await ProcessCommandRunner(registry: registry).run(
            Self.sh, ["-c", "exit 0"], environment: [:], onStderrLine: { _ in })
        #expect(result.status == 0)
        #expect(registry.count == 0)
    }

    @MainActor
    @Test func quitDuringADashboardRefreshKeepsThePreviousState() async throws {
        let registry = EngineProcesses()
        let file = Self.pidFile()
        var pid: pid_t?
        defer { Self.cleanUp(pid, file) }
        let engine = Engine(command: EngineCommand(executable: Self.sh, arguments: Self.standIn(file), environment: [:]),
                            runner: ProcessCommandRunner(registry: registry))
        let previous = EngineState(schemaVersion: 1,
                                   refresh: RefreshRecord(id: 1, status: .complete,
                                                          startedAt: Date(timeIntervalSince1970: 0),
                                                          finishedAt: Date(timeIntervalSince1970: 60),
                                                          lastCompleteAt: Date(timeIntervalSince1970: 60)),
                                   coverage: [], items: [])
        let model = DashboardModel(engine: engine, state: previous)
        model.refresh()
        pid = await Self.waitForPid(file)
        let started = try #require(pid, "the stand-in did not start within 5 s")
        registry.terminateAll(wait: 3)
        #expect(await Self.waitGone(started))
        await model.waitForRefresh()  // bounded: the stand-in is gone, and a second start exits at once
        #expect(!model.isRefreshing)
        #expect(model.state == previous)  // never shown as a new complete refresh
    }
}

private final class ProcessLines: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String] = []
    func add(_ s: String) { lock.withLock { items.append(s) } }
    var all: [String] { lock.withLock { items } }
}
