import Darwin
import Foundation
import Testing
@testable import WatchtowerCore

// Bug #33: Quit during a refresh left the engine process running. The app calls
// `EngineProcesses.terminateAll` when it quits. These tests use /bin/sh as a stand-in engine.

private func pidFile() -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent("wt-quit-\(UUID().uuidString).pid")
}

private func waitForPid(_ url: URL) async -> pid_t? {
    for _ in 0..<100 {
        if let text = try? String(contentsOf: url, encoding: .utf8),
           let pid = pid_t(text.trimmingCharacters(in: .whitespacesAndNewlines)) {
            return pid
        }
        try? await Task.sleep(for: .milliseconds(50))
    }
    return nil
}

private func alive(_ pid: pid_t) -> Bool { kill(pid, 0) == 0 }

@Test func quitTerminatesARunningEngineProcess() async throws {
    let registry = EngineProcesses()
    let runner = ProcessCommandRunner(registry: registry)
    let file = pidFile()
    defer { try? FileManager.default.removeItem(at: file) }
    let run = Task {
        try await runner.run(URL(fileURLWithPath: "/bin/sh"), ["-c", "echo $$ > '\(file.path)'; exec sleep 30"],
                             environment: [:], onStderrLine: { _ in })
    }
    let pid = try #require(await waitForPid(file))
    #expect(alive(pid))
    let started = Date()
    let stopped = registry.terminateAll(wait: 3)
    #expect(stopped == 1)
    #expect(!alive(pid), "the engine process still runs after quit")
    let result = await run.result
    #expect(Date().timeIntervalSince(started) < 5)
    if case .success = result { Issue.record("a run stopped by quit must throw") }
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
        URL(fileURLWithPath: "/bin/sh"), ["-c", "exit 0"], environment: [:], onStderrLine: { _ in })
    #expect(result.status == 0)
    #expect(registry.count == 0)
}

@MainActor
@Test func quitDuringADashboardRefreshKeepsThePreviousState() async throws {
    // The stand-in engine writes its pid, then waits like a long refresh.
    let registry = EngineProcesses()
    let file = pidFile()
    defer { try? FileManager.default.removeItem(at: file) }
    let script = "echo $$ > '\(file.path)'; exec sleep 30"
    let engine = Engine(command: EngineCommand(executable: URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", script],
                                               environment: [:]),
                        runner: ProcessCommandRunner(registry: registry))
    let previous = EngineState(schemaVersion: 1,
                               refresh: RefreshRecord(id: 1, status: .complete, startedAt: Date(timeIntervalSince1970: 0),
                                                      finishedAt: Date(timeIntervalSince1970: 60),
                                                      lastCompleteAt: Date(timeIntervalSince1970: 60)),
                               coverage: [], items: [])
    let model = DashboardModel(engine: engine, state: previous)
    model.refresh()
    let pid = try #require(await waitForPid(file))
    registry.terminateAll(wait: 3)
    #expect(!alive(pid))
    await model.waitForRefresh()
    #expect(!model.isRefreshing)
    #expect(model.state == previous)  // never shown as a new complete refresh
}
