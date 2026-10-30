import Foundation
import Testing
@testable import WatchtowerCore

// Vendor assessments (#18): shown apart from OSV, never change the status, stale after 90 days.

private let now = Date(timeIntervalSince1970: 1_793_275_200)
private func days(_ d: Double) -> Date { now.addingTimeInterval(-d * 86400) }
private let utc = TimeText(timeZone: TimeZone(identifier: "UTC")!)

private func note(_ id: String, verdict: String = "fixed", retrieved: Date = days(1), checked: Date? = nil,
                  withdrawn: Date? = nil, url: String = "https://security-tracker.debian.org/tracker/CVE-1") -> VendorNote {
    VendorNote(id: id, vendor: "Debian", verdict: verdict, statement: "Fixed by backport in 2.4.1-3.",
               affectedRange: "< 2.4.1-3", confidence: "high", sourceUrl: url, retrievedAt: retrieved,
               checkedAt: checked, withdrawnAt: withdrawn)
}

private func finding(_ notes: [VendorNote]?, status: FindingStatus = .open) -> FindingRecord {
    FindingRecord(id: "SEC-0001", package: "lodash", title: "x", severity: .high, advisoryIds: ["CVE-1"],
                  status: status, firstSeen: days(9), lastSeen: days(1), vendorNotes: notes)
}

private struct NoteEngine: EngineClient {
    func state() async throws -> EngineState { throw CancellationError() }
    func refresh(progress: @escaping @Sendable (RefreshProgress) -> Void) async throws -> EngineState {
        throw CancellationError()
    }
    func projects() async throws -> ProjectList { ProjectList(schemaVersion: 1, projects: [], rootErrors: [], skipped: []) }
    func setProject(path: String, active: Bool) async throws -> ProjectRecord { throw CancellationError() }
    func deferFinding(id: String, days: Int) async throws -> FindingRecord { throw CancellationError() }
    func moveFindingToBacklog(id: String) async throws -> FindingRecord { throw CancellationError() }
    func reopenFinding(id: String) async throws -> FindingRecord { throw CancellationError() }
    func checkVendorNote(id: String) async throws -> FindingRecord {
        finding([note(id, retrieved: days(120), checked: now)])
    }
}

@Test func decodesVendorNotesFromTheEngine() throws {
    let json = """
    {"id": "SEC-0001", "ecosystem": "npm", "package": "lodash", "title": "x", "severity": "high",
     "advisory_ids": ["CVE-1"], "fixed_in": null, "status": "open", "deferred_until": null,
     "first_seen": "2026-10-20T10:00:00Z", "last_seen": "2026-10-29T10:00:00Z", "resolved_at": null,
     "resolved_scan_at": null, "source": "OSV", "source_at": null, "paths": [], "next_steps": [],
     "vendor_notes": [{"id": "VN-0001", "vendor": "Debian", "verdict": "not_affected",
       "statement": "Fixed by backport.", "affected_range": "< 2.4.1-3", "confidence": "high",
       "source_url": "https://security-tracker.debian.org/tracker/CVE-1", "retrieved_at": "2026-10-29T09:12:00Z",
       "added_at": "2026-10-29T10:00:00Z", "checked_at": null, "withdrawn_at": null}]}
    """
    let f = try EngineJSON.makeDecoder().decode(FindingRecord.self, from: Data(json.utf8))
    let n = try #require(f.vendorNotes?.first)
    #expect(n.id == "VN-0001" && n.isNotAffected && n.affectedRange == "< 2.4.1-3")
    #expect(utc.absolute(n.retrievedAt) == "Oct 29, 09:12")
    #expect(f.source == "OSV")  // The vendor note is apart from the OSV data.
}

@Test func olderEngineWithoutVendorNotesStillDecodes() throws {
    let url = try #require(Bundle.module.url(forResource: "state-partial", withExtension: "json",
                                             subdirectory: "Fixtures"))
    let state = try EngineJSON.decode(EngineState.self, from: Data(contentsOf: url))
    #expect(state.findings.allSatisfy { ($0.vendorNotes ?? []).isEmpty })
    let missing = finding(nil)
    #expect(missing.vendorAssessment(now: now).isEmpty)
    #expect(missing.vendorAssessment(now: now).listText == nil)
}

@Test func staleAfterNinetyDaysAndCheckStartsTheDaysAgain() {
    #expect(VendorAssessment.staleAfter == 90 * 86400)
    #expect(!note("VN-1", retrieved: days(90)).isStale(now: now))
    #expect(note("VN-1", retrieved: days(90.01)).isStale(now: now))
    #expect(!note("VN-1", retrieved: days(200), checked: days(10)).isStale(now: now))
    #expect(!note("VN-1", retrieved: days(200), withdrawn: days(150)).isStale(now: now))
    let a = finding([note("VN-1", retrieved: days(120))]).vendorAssessment(now: now)
    #expect(a.asksForCheck)
    #expect(a.badges(a.current!).map(\.text) == ["Stale"])
    #expect(a.badges(a.current!).map(\.tone) == [.orange])
    #expect(VendorAssessment.stalePrompt == "This note is older than 90 days. Open the source and check it again.")
}

@Test func currentIsNewestNotWithdrawnAndHistoryKeepsEveryOtherNote() {
    let notes = [note("VN-0001", retrieved: days(150), withdrawn: days(121)),
                 note("VN-0003", retrieved: days(2), withdrawn: days(1)),
                 note("VN-0002", retrieved: days(120)),
                 note("VN-0004", retrieved: days(200))]
    let a = finding(notes).vendorAssessment(now: now)
    #expect(a.current?.id == "VN-0002")
    #expect(a.history.map(\.id) == ["VN-0003", "VN-0001", "VN-0004"])
    #expect(a.historyTitle == "History (3)")
    #expect(a.badges(a.history[0], time: utc).map(\.text) == ["Withdrawn Oct 28"])
    #expect(a.badges(a.history[0]).map(\.tone) == [.gray])
    #expect(a.badges(a.history[2]).map(\.text) == ["Stale"])
    // Every note withdrawn: no current note, and the history still shows all of them.
    let gone = finding([note("VN-1", withdrawn: days(1))]).vendorAssessment(now: now)
    #expect(gone.current == nil && gone.history.count == 1 && !gone.isEmpty && gone.listText == nil)
}

@Test func notAffectedShowsTheBannerAndNeverChangesTheStatus() {
    let f = finding([note("VN-1", verdict: "not_affected")])
    let a = f.vendorAssessment(now: now)
    #expect(a.showsNotAffectedBanner)
    #expect(f.status == .open)
    #expect(VendorAssessment.notAffectedBanner ==
            "The vendor says this version is not affected. The finding stays open until a complete scan resolves it.")
    #expect(!finding([note("VN-1")]).vendorAssessment(now: now).showsNotAffectedBanner)
    #expect(!finding([note("VN-1", verdict: "not_affected", withdrawn: days(1))]).vendorAssessment(now: now)
        .showsNotAffectedBanner)
}

@Test func listTextAndRows() {
    #expect(finding([note("VN-1")]).vendorAssessment(now: now).listText == "Vendor: backport")
    #expect(finding([note("VN-1", verdict: "not_affected")]).vendorAssessment(now: now).listText
            == "Vendor: not affected")
    #expect(finding([note("VN-1", verdict: "affected")]).vendorAssessment(now: now).listText == "Vendor: affected")
    let n = note("VN-1", retrieved: days(1), checked: days(0.5))
    #expect(VendorAssessment.rows(n).map(\.label) == ["Vendor", "Statement", "Affected range"])
    #expect(VendorAssessment.timeRows(n, time: utc).map(\.label) == ["Retrieved", "Checked again"])
    #expect(n.confidenceText == "High")
}

@Test func onlyWebSourceLinksOpen() {
    #expect(note("VN-1").sourceURL != nil)
    #expect(note("VN-1", url: "javascript:alert(1)").sourceURL == nil)
    #expect(note("VN-1", url: "file:///etc/passwd").sourceURL == nil)
}

@MainActor
@Test func markAsCheckedSavesTheFindingFromTheEngine() async {
    let state = EngineState(schemaVersion: 1, refresh: nil, coverage: [], items: [],
                            findings: [finding([note("VN-1", retrieved: days(120))])])
    let model = DashboardModel(engine: NoteEngine(), state: state, clock: { now })
    #expect(model.vendorAssessment(for: model.state!.findings[0]).asksForCheck)
    await model.checkVendorNote(note("VN-1"))
    let after = model.vendorAssessment(for: model.state!.findings[0])
    #expect(!after.asksForCheck)
    #expect(model.state!.findings[0].status == .open)
}
