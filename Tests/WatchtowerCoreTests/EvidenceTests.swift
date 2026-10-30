import Foundation
import Testing
@testable import WatchtowerCore

// #17: running version and container metadata. The fixture `running.json` comes from the real engine code
// (engine/tests/test_running.py fixtures, no process list of a real Mac). No test uses the network.

private struct Capture: Decodable {
    var now: Date
    var on: [ItemRecord]
    var off: [ItemRecord]
    var denied: [ItemRecord]
    var projects: [ProjectRecord]
    var settings: EngineSettings
}

private let utc = TimeText(timeZone: TimeZone(identifier: "UTC")!)

private func capture() throws -> Capture {
    let url = try #require(Bundle.module.url(forResource: "running", withExtension: "json", subdirectory: "Fixtures"))
    return try EngineJSON.makeDecoder().decode(Capture.self, from: Data(contentsOf: url))
}

private func app(_ attributes: [String: String], installed: String = "2.5.0", build: String? = nil) -> ItemRecord {
    var attributes = attributes
    if let build { attributes["build"] = build }
    return ItemRecord(id: "app:slack", source: "apps", name: "Slack", state: .manual, kind: "app",
                      installedVersion: installed, attributes: attributes)
}

private func finding(paths: [FindingPath]) -> FindingRecord {
    FindingRecord(id: "SEC-0001", package: "lodash", title: "t", severity: .high, advisoryIds: [], firstSeen: Date(),
                  lastSeen: Date(), paths: paths)
}

private func path(_ project: String, version: String = "4.17.20") -> FindingPath {
    FindingPath(project: project, projectPath: "~/Projects/\(project)", lockfile: "package-lock.json", version: version)
}

// The engine output decodes

@Test func theEngineFixtureDecodesAndKeepsTheRunningVersionApartFromTheInstalledOne() throws {
    let data = try capture()
    #expect(data.settings.checkRunningVersions)  // On by default.
    let build = try #require(data.on.first { $0.name == "Slack" })
    #expect(build.installedVersion == "1.2.0")
    let running = try #require(RunningEvidence(build, time: utc))
    #expect(running.state == .known && running.version == "30" && running.kind == "build")
    #expect(running.differs && running.needsRestart)
    #expect(running.text == "Running build 30 differs from installed build 31. Restart Slack.")
    let node = try #require(data.on.first { $0.name == "node" })
    #expect(try #require(RunningEvidence(node, time: utc)).text == "Running: 22.9.0")
    #expect(node.installedVersion == "22.9.0")
}

@Test func theFixtureShowsNoProcessFoundWithTheTimeOfTheCheck() throws {
    let wget = try #require(try capture().on.first { $0.name == "wget" })
    #expect(try #require(RunningEvidence(wget, time: utc)).text == "Running: no process found at Oct 29, 09:12")
}

@Test func aDeniedProbeIsNotKnownAndNeverNoProcess() throws {
    for item in try capture().denied {
        let running = try #require(RunningEvidence(item, time: utc))
        #expect(running.state == .denied && running.version == nil)
        #expect(running.text == "Running: not known (permission denied)")
        #expect(!running.text.lowercased().contains("not running"))
    }
}

@Test func aSkippedProbeShowsNotChecked() throws {
    for item in try capture().off {
        #expect(try #require(RunningEvidence(item, time: utc)).text == "Running: not checked")
    }
}

// The toggle hides old data at once

@Test func turningTheCheckOffShowsNotCheckedEvenForOldRunningData() throws {
    let item = app(["runningState": "known", "runningVersion": "2.4.1", "runningKind": "version"])
    let on = try #require(RunningEvidence(item, enabled: true, time: utc))
    let off = try #require(RunningEvidence(item, enabled: false, time: utc))
    #expect(on.isOlder)
    #expect(off.text == "Running: not checked" && !off.needsRestart && off.version == nil)
    #expect(Evidence.rows(for: item, enabled: false).first { $0.label == "Running" }?.value == "not checked")
}

@Test func anItemWithoutAProbeHasNoRunningRow() {
    let mac = ItemRecord(id: "macos", source: "macos", name: "macOS", state: .manual, kind: "os", installedVersion: "15.7")
    #expect(RunningEvidence(mac) == nil)
    #expect(Evidence.rows(for: mac).map(\.label) == ["Installed", "Deployment"])
}

// Older running version

@Test func anOlderRunningVersionIsOrangeAndSaysRestart() throws {
    let item = app(["runningState": "known", "runningVersion": "2.4.1", "runningKind": "version"])
    let running = try #require(RunningEvidence(item, time: utc))
    #expect(running.text == "Running 2.4.1 is older than installed 2.5.0. Restart Slack.")
    #expect(running.tone == .orange && running.restartText == "Restart Slack.")
    let row = try #require(Evidence.rows(for: item).first { $0.label == "Running" })
    #expect(row.tone == .orange)
}

@Test func theSameOrANewerRunningVersionIsNotAWarning() throws {
    for version in ["2.5.0", "2.10.0"] {
        let item = app(["runningState": "known", "runningVersion": version, "runningKind": "version"])
        let running = try #require(RunningEvidence(item, time: utc))
        #expect(!running.needsRestart && running.tone == .secondary && running.restartText == nil)
        #expect(running.text == "Running: \(version)")
    }
}

@Test func versionsCompareNumberByNumber() {
    #expect(RunningEvidence.compare("2.9.9", "2.10.0") < 0)
    #expect(RunningEvidence.compare("2.5", "2.5.0") == 0)
    #expect(RunningEvidence.compare("3.15.0_1", "3.15.0") > 0)
    #expect(RunningEvidence.compare("1.0.0-beta", "1.0.0") != 0)
}

@Test func aBuildNumberIsNeverCalledOlder() throws {
    let item = app(["runningState": "known", "runningVersion": "29", "runningKind": "build"], installed: "1.2.0", build: "31")
    let running = try #require(RunningEvidence(item, time: utc))
    #expect(!running.isOlder && running.differs)
    #expect(!running.text.contains("older"))
}

@Test func aProcessWithoutAVersionSaysSo() throws {
    let item = app(["runningState": "unknown_version"])
    #expect(try #require(RunningEvidence(item, time: utc)).text == "Running: process found, version not known")
}

// Rows, in this order

@Test func theRowsOfAnAppAreInstalledRunningDeployment() throws {
    let item = app(["runningState": "known", "runningVersion": "2.5.0", "runningKind": "version"])
    let rows = Evidence.rows(for: item, time: utc)
    #expect(rows.map(\.label) == ["Installed", "Running", "Deployment"])
    #expect(rows.map(\.value) == ["2.5.0", "2.5.0", "Unknown"])
}

@Test func deploymentStaysUnknownInEveryState() throws {
    for state in ["known", "none", "denied", "not_checked", "unknown_version"] {
        let rows = Evidence.rows(for: app(["runningState": state, "runningVersion": "2.4.1"]), time: utc)
        #expect(rows.last?.value == "Unknown")
    }
}

@Test func theRowsOfAFindingAreInstalledLockfileRunningContainerDeployment() throws {
    let data = try capture()
    let rows = Evidence.rows(for: finding(paths: [path("web")]), projects: data.projects)
    #expect(rows.map(\.label) == ["Installed", "Lockfile", "Running", "Container image", "Deployment"])
    #expect(rows.map(\.value) == ["not checked", "4.17.20", "not known", "node:20.11", "Unknown"])
}

@Test func theRunningRowOfAFindingFollowsTheToggle() throws {
    let rows = Evidence.rows(for: finding(paths: [path("web")]), projects: [], enabled: false)
    #expect(rows.first { $0.label == "Running" }?.value == "not checked")
}

// Container metadata

@Test func noImagesIsNoneFoundOnlyWhenEveryProjectWasRead() throws {
    let data = try capture()
    func image(_ finding: FindingRecord, _ projects: [ProjectRecord]) -> String? {
        Evidence.rows(for: finding, projects: projects).first { $0.label == "Container image" }?.value
    }
    #expect(image(finding(paths: [path("api")]), data.projects) == "None found")  // Read: the list is empty.
    #expect(image(finding(paths: [path("missing")]), data.projects) == "Unknown")  // Not in the project list.
    var unread = data.projects
    unread[0].containerImages = nil
    #expect(image(finding(paths: [path("api")]), unread) == "Unknown")  // Not read: nil is not empty.
    #expect(image(finding(paths: [path("web"), path("api")]), data.projects) == "node:20.11")
}

// Settings

@MainActor @Test func theSettingIsOnByDefault() {
    #expect(EngineSettings().checkRunningVersions)
    #expect(DashboardModel(engine: NoEngine()).checkRunningVersions)
}

private actor Saved {
    var value: Bool?
    func set(_ on: Bool) { value = on }
}

private struct SettingsEngine: EngineClient {
    let saved: Saved
    var fail = false
    func state() async throws -> EngineState { throw CancellationError() }
    func refresh(progress: @escaping @Sendable (RefreshProgress) -> Void) async throws -> EngineState { throw CancellationError() }
    func projects() async throws -> ProjectList { ProjectList(schemaVersion: 1, projects: [], rootErrors: [], skipped: []) }
    func setProject(path: String, active: Bool) async throws -> ProjectRecord { throw CancellationError() }
    func deferFinding(id: String, days: Int) async throws -> FindingRecord { throw CancellationError() }
    func moveFindingToBacklog(id: String) async throws -> FindingRecord { throw CancellationError() }
    func reopenFinding(id: String) async throws -> FindingRecord { throw CancellationError() }
    func settings() async throws -> EngineSettings { EngineSettings(checkRunningVersions: false) }
    func setCheckRunningVersions(_ on: Bool) async throws -> EngineSettings {
        if fail { throw EngineError.failed(message: "no", detail: nil) }
        await saved.set(on)
        return EngineSettings(checkRunningVersions: on)
    }
}

private struct NoEngine: EngineClient {
    func state() async throws -> EngineState { throw CancellationError() }
    func refresh(progress: @escaping @Sendable (RefreshProgress) -> Void) async throws -> EngineState { throw CancellationError() }
    func projects() async throws -> ProjectList { ProjectList(schemaVersion: 1, projects: [], rootErrors: [], skipped: []) }
    func setProject(path: String, active: Bool) async throws -> ProjectRecord { throw CancellationError() }
    func deferFinding(id: String, days: Int) async throws -> FindingRecord { throw CancellationError() }
    func moveFindingToBacklog(id: String) async throws -> FindingRecord { throw CancellationError() }
    func reopenFinding(id: String) async throws -> FindingRecord { throw CancellationError() }
}

@MainActor @Test func loadReadsTheSettingAndTheToggleSavesIt() async {
    let saved = Saved()
    let model = DashboardModel(engine: SettingsEngine(saved: saved))
    await model.load()
    #expect(!model.checkRunningVersions)  // The engine says off.
    await model.setCheckRunningVersions(true)
    #expect(model.checkRunningVersions)
    #expect(await saved.value == true)
}

@MainActor @Test func aFailedSaveKeepsTheOldValue() async {
    let model = DashboardModel(engine: SettingsEngine(saved: Saved(), fail: true))
    await model.setCheckRunningVersions(false)
    #expect(model.checkRunningVersions)
    #expect(model.lastError != nil)
}

@MainActor @Test func theGenericAttributeListLeavesTheRunningKeysOut() {
    let item = app(["path": "/Applications/Slack.app", "runningState": "known", "runningVersion": "2.5.0"])
    #expect(item.attributesWithoutRunning == ["path": "/Applications/Slack.app"])
}
