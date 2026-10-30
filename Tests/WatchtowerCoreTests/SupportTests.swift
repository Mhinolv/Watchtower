import Foundation
import Testing
@testable import WatchtowerCore

// #59: the vendor support status of macOS and the runtimes, from endoflife.date. The fixtures come from the real engine
// code with the recorded endoflife.date answers. No test uses the network.

private struct NoEngine: EngineClient {
    func state() async throws -> EngineState { throw CancellationError() }
    func refresh(progress: @escaping @Sendable (RefreshProgress) -> Void) async throws -> EngineState { throw CancellationError() }
    func projects() async throws -> ProjectList { ProjectList(schemaVersion: 1, projects: [], rootErrors: [], skipped: []) }
    func setProject(path: String, active: Bool) async throws -> ProjectRecord { throw CancellationError() }
    func deferFinding(id: String, days: Int) async throws -> FindingRecord { throw CancellationError() }
    func moveFindingToBacklog(id: String) async throws -> FindingRecord { throw CancellationError() }
    func reopenFinding(id: String) async throws -> FindingRecord { throw CancellationError() }
}

private struct Capture: Decodable {
    var now: Date
    var items: [ItemRecord]
    var coverage: CoverageRecord
}

private let utc = TimeText(timeZone: TimeZone(identifier: "UTC")!)

private func capture(_ name: String) throws -> Capture {
    let url = try #require(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures"))
    return try EngineJSON.makeDecoder().decode(Capture.self, from: Data(contentsOf: url))
}

private func status(_ capture: Capture, _ name: String, _ version: String) throws -> SupportStatus {
    let item = try #require(capture.items.first { $0.name == name && $0.installedVersion == version })
    return try #require(SupportStatus(item, now: capture.now, time: utc))
}

private func item(_ attributes: [String: String], name: String = "Node.js", version: String? = "22.9.0") -> ItemRecord {
    ItemRecord(id: "runtime:test:\(name)", source: "runtimes", name: name, state: .manual, kind: "runtime",
               installedVersion: version, attributes: attributes)
}

private func day(_ text: String, hour: Int = 8) -> Date {
    ISO8601DateFormatter().date(from: "\(text)T0\(hour):00:00Z")!
}

@Test func theFirstRunFixtureGivesTheLabelOfEachState() throws {
    let data = try capture("support-first-run")
    #expect(try status(data, "Node.js", "26.1.0").label == "Supported until Apr 30, 2029")
    #expect(try status(data, "Node.js", "24.9.0").label == "Security fixes only until Apr 30, 2028")
    #expect(try status(data, "Node.js", "25.2.0").label == "End of life since Jun 1, 2026")
    #expect(try status(data, "Python", "3.13.7").label == "Security fixes only until Oct 31, 2029")
    #expect(try status(data, "Python", "3.10.14").label == "End of life since Oct 1, 2026")
    #expect(try status(data, "Ruby", "3.3.6").label == "Support ends Mar 31 (44 days)")
    #expect(try status(data, "Java", "21.0.4").label == "endoflife.date has no entry for Java.")
    #expect(try status(data, "Go", "1.26.1").label == "Supported")
    #expect(try status(data, "macOS", "15.7.9").label == "Supported")
}

@Test func theShortTextSymbolAndToneFollowTheState() throws {
    let data = try capture("support-first-run")
    let table: [(String, String, String, String, String, Tone)] = [
        ("Node.js", "26.1.0", "Supported", "checkmark.circle", "supported", .green),
        ("Ruby", "3.3.6", "Ends Mar 31", "clock", "ends", .orange),
        ("Node.js", "24.9.0", "Security only", "shield.lefthalf.filled", "security", .orange),
        ("Node.js", "25.2.0", "End of life", "xmark.circle", "eol", .red),
        ("Java", "21.0.4", "—", "questionmark.circle", "unknown", .gray),
    ]
    for (name, version, short, symbol, _, tone) in table {
        let support = try status(data, name, version)
        #expect(support.shortText == short)
        #expect(support.symbol == symbol)
        #expect(support.tone == tone)
    }
}

@Test func theReleaseLineAndTheDataTextShowWhereTheStateCameFrom() throws {
    let data = try capture("support-first-run")
    let node = try status(data, "Node.js", "24.9.0")
    #expect(node.cycle == "24")
    #expect(node.releaseLine(product: "Node.js") == "Node.js 24")
    #expect(node.dataText == "endoflife.date, retrieved Feb 10, 08:00")
    #expect(try status(data, "Java", "21.0.4").releaseLine(product: "Java") == nil)
    #expect(try status(data, "Java", "21.0.4").dataText == nil)
    #expect(try status(data, "macOS", "15.7.9").releaseLine(product: "macOS") == "macOS 15")
}

@Test func theAppDecidesTheStateAgainFromTheDateSoAnOldScanNeverShowsSupportedAfterTheEnd() {
    // The engine stored `supported` on 2026-12-01 for a line that ends 2027-03-31.
    let stored = item(["eolState": "supported", "eolEnd": "2027-03-31", "eolCycle": "3.3"], name: "Ruby", version: "3.3.6")
    #expect(SupportStatus(stored, now: day("2026-12-01"), time: utc)?.state == .supported)
    #expect(SupportStatus(stored, now: day("2027-02-15"), time: utc)?.state == .endsSoon)
    #expect(SupportStatus(stored, now: day("2027-03-30"), time: utc)?.label == "Support ends Mar 31 (1 day)")
    #expect(SupportStatus(stored, now: day("2027-03-31"), time: utc)?.state == .endOfLife)
    #expect(SupportStatus(stored, now: day("2027-04-02"), time: utc)?.label == "End of life since Mar 31, 2027")
}

@Test func theEndsSoonWindowIsNinetyDays() {
    let stored = item(["eolState": "supported", "eolEnd": "2027-05-16", "eolCycle": "22"])
    #expect(SupportStatus(stored, now: day("2027-02-15"), time: utc)?.daysLeft == 90)
    #expect(SupportStatus(stored, now: day("2027-02-15"), time: utc)?.state == .endsSoon)
    #expect(SupportStatus(stored, now: day("2027-02-14"), time: utc)?.daysLeft == 91)
    #expect(SupportStatus(stored, now: day("2027-02-14"), time: utc)?.state == .supported)
    #expect(SupportStatus.endsSoonDays == 90)
}

@Test func theSecurityOnlyPhaseEndsAtTheEndDateAndAnEndedStateStays() {
    let security = item(["eolState": "security_only", "eolEnd": "2027-04-30", "eolCycle": "24"])
    #expect(SupportStatus(security, now: day("2027-04-29"), time: utc)?.state == .securityOnly)
    #expect(SupportStatus(security, now: day("2027-04-30"), time: utc)?.state == .endOfLife)
    let ended = item(["eolState": "end_of_life", "eolEnd": "2030-01-01", "eolCycle": "18"])
    #expect(SupportStatus(ended, now: day("2027-02-15"), time: utc)?.state == .endOfLife)
}

@Test func anItemWithoutASupportStateHasNoStatus() {
    #expect(SupportStatus(item([:]), now: day("2027-02-15"), time: utc) == nil)
    #expect(SupportStatus(item(["eolState": "not-a-state"]), now: day("2027-02-15"), time: utc) == nil)
    let sdk = ItemRecord(id: "sdk:x", source: "runtimes", name: "macOS SDK", state: .manual, kind: "sdk", installedVersion: "15.5")
    #expect(SupportStatus(sdk, now: day("2027-02-15"), time: utc) == nil)
}

@Test func anApiErrorKeepsTheEarlierLabelAndAddsTheFailureText() throws {
    let data = try capture("support-api-error")
    let go = try status(data, "Go", "1.26.1")
    #expect(go.state == .supported)
    #expect(go.label == "Supported")
    #expect(go.failed)
    #expect(go.failureText == "endoflife.date did not respond. Data from Feb 10.")
    #expect(go.dataText == "endoflife.date, retrieved Feb 10, 08:00")
    #expect(try status(data, "Node.js", "24.9.0").failureText == nil)
}

@Test func aFailureWithoutAnyEarlierDataSaysOnlyThatTheRequestFailed() {
    let none = item(["eolState": "unknown", "eolError": "endoflife.date did not respond."])
    let support = SupportStatus(none, now: day("2027-02-15"), time: utc)
    #expect(support?.label == "endoflife.date did not respond.")
    #expect(support?.failureText == "endoflife.date did not respond.")
    #expect(support?.dataText == nil)
}

@Test func theAttributeListLeavesTheSupportKeysOut() throws {
    let data = try capture("support-first-run")
    let node = try #require(data.items.first { $0.name == "Node.js" })
    let rest = node.attributesWithoutSupport
    #expect(rest["eolProduct"] == "nodejs")
    #expect(SupportStatus.keys.allSatisfy { rest[$0] == nil })
}

@MainActor
@Test func theRuntimesListShowsSupportAndPutsEndOfLifeFirstInsideAGroup() throws {
    let data = try capture("support-first-run")
    let state = EngineState(schemaVersion: 1,
                            refresh: RefreshRecord(id: 1, status: .complete, startedAt: data.now, finishedAt: data.now,
                                                   lastCompleteAt: data.now),
                            coverage: [data.coverage], items: data.items)
    let model = DashboardModel(engine: NoEngine(), state: state, clock: { data.now })
    let runtimes = try #require(model.runtimeSections.first { $0.group == .runtime })
    let eol = runtimes.rows.prefix { $0.support?.state == .endOfLife }.map { "\($0.name) \($0.version)" }
    #expect(Set(eol) == ["Node.js 25.2.0", "Python 3.10.14"])
    #expect(runtimes.rows.count == 8)
    #expect(runtimes.rows.dropFirst(2).allSatisfy { $0.support?.state != .endOfLife })
    let java = try #require(runtimes.rows.first { $0.name == "Java" })
    #expect(java.support?.shortText == "—")
}

@MainActor
@Test func theCoverageListShowsEndoflifeDateAsPartialAfterAFailure() throws {
    let data = try capture("support-api-error")
    let state = EngineState(schemaVersion: 1,
                            refresh: RefreshRecord(id: 1, status: .partial, startedAt: data.now, finishedAt: data.now,
                                                   lastCompleteAt: data.now),
                            coverage: [data.coverage], items: data.items)
    let model = DashboardModel(engine: NoEngine(), state: state, clock: { data.now })
    let row = try #require(model.coverageRows.first { $0.label == "endoflife.date" })
    #expect(row.stateText == "Partial")
    #expect(row.tone == .orange)
    #expect(row.error == "endoflife.date did not respond. Watchtower used the last copy.")
}
