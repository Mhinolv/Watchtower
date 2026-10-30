import Foundation
import Testing
@testable import WatchtowerCore

// #57: EPSS scores. The list shows a percent, the detail shows the percentile and the state of the data.

private let utc = TimeText(timeZone: TimeZone(identifier: "UTC")!)
private let now = Date(timeIntervalSince1970: 1_793_275_200)  // 2026-10-29 12:00 UTC
private func ago(days: Double) -> Date { now.addingTimeInterval(-days * 86400) }

private func finding(_ id: String = "SEC-0001", ids: [String] = ["CVE-2021-44228"], severity: Severity = .high,
                     epss: EpssMark? = nil, kev: KevMark? = nil, malware: MalwareMark? = nil) -> FindingRecord {
    FindingRecord(id: id, package: "p", title: "t", severity: severity, advisoryIds: ids, firstSeen: ago(days: 5),
                  lastSeen: ago(days: 1), kev: kev, malware: malware, epss: epss)
}

private func mark(_ score: Double?, _ percentile: Double? = 0.99, fetched: Date? = ago(days: 0.25)) -> EpssMark {
    EpssMark(cve: "CVE-2021-44228", score: score, percentile: percentile, scoreDate: "2026-10-29", fetchedAt: fetched)
}

private func coverage(_ state: CoverageState = .complete, at: Date? = ago(days: 0.25)) -> CoverageRecord {
    CoverageRecord(source: "epss", label: "EPSS", state: state, sourceAt: at)
}

@Test func scoresShowAsPercents() {
    #expect(EpssText.percent(0.94) == "94%")
    #expect(EpssText.percent(0.021) == "2.1%")
    #expect(EpssText.percent(0.00098) == "<0.1%")
    #expect(EpssText.percent(0.99999) == "100%")
    #expect(EpssText.percent(0.1) == "10%")
}

@Test func percentilesShowAsOrdinals() {
    #expect(EpssText.ordinal(0.99) == "99th")
    #expect(EpssText.ordinal(0.97) == "97th")
    #expect(EpssText.ordinal(0.01) == "1st")
    #expect(EpssText.ordinal(0.12) == "12th")
    #expect(EpssText.ordinal(0.22) == "22nd")
}

@Test func aKnownScoreShowsTheListTextTheHelpAndTheDetailRow() {
    let d = EpssDisplay.make(finding(epss: mark(0.94)), coverage: coverage(), now: now, time: utc)
    #expect(d.listText == "94%" && !d.listIsProblem)
    #expect(d.help == "Chance of exploit in the next 30 days. 99th percentile. EPSS, Oct 29.")
    #expect(d.detailText == "94% in the next 30 days, 99th percentile")
    #expect(d.voiceOver == "Exploit chance 94 percent")
    #expect(d.note == nil)
}

@Test func aFindingWithNoCveSaysEpssCoversCvesOnly() {
    let d = EpssDisplay.make(finding(ids: ["GHSA-xxxx-yyyy-zzzz"]), coverage: coverage(), now: now, time: utc)
    #expect(d.listText == "—" && d.detailText == nil)
    #expect(d.note == "EPSS covers CVEs only." && !d.noteIsProblem)
}

@Test func aCveThatIsNotInTheFileSaysSo() {
    let d = EpssDisplay.make(finding(epss: mark(nil, nil)), coverage: coverage(), now: now, time: utc)
    #expect(d.listText == "—" && d.detailText == nil)
    #expect(d.note == "This CVE is not in the EPSS file of Oct 29.")
}

@Test func dataOlderThanTwoDaysIsOrangeAndNamesItsDay() {
    let old = mark(0.94, fetched: ago(days: 3))
    let d = EpssDisplay.make(finding(epss: old), coverage: coverage(at: ago(days: 3)), now: now, time: utc)
    #expect(d.listText == "94%" && d.listIsProblem)
    #expect(d.note == "EPSS data is from Oct 26." && d.noteIsProblem)
    let fresh = EpssDisplay.make(finding(epss: mark(0.94, fetched: ago(days: 1.9))), coverage: coverage(), now: now,
                                 time: utc)
    #expect(!fresh.listIsProblem)  // 2 days is the limit.
}

@Test func aFailedDownloadKeepsTheEarlierValueAndSaysWhen() {
    let earlier = mark(0.94, fetched: ago(days: 1))
    let d = EpssDisplay.make(finding(epss: earlier), coverage: coverage(.partial, at: ago(days: 1)), now: now,
                             time: utc)
    #expect(d.listText == "94%" && d.listIsProblem)
    #expect(d.note == "EPSS download failed. Data from Oct 28." && d.noteIsProblem)
    let none = EpssDisplay.make(finding(), coverage: coverage(.failed, at: nil), now: now, time: utc)
    #expect(none.listText == "—" && none.note == "EPSS download failed.")
}

@Test func sortIsMalwareThenKevThenEpssThenSeverity() {
    let items = [
        finding("SEC-0001", severity: .low, epss: mark(0.9964)),
        finding("SEC-0002", severity: .critical, epss: mark(0.00098)),
        finding("SEC-0003", severity: .high, epss: mark(0.2133)),
        finding("SEC-0004", ids: ["GHSA-x"], severity: .critical),
        finding("SEC-0005", ids: ["GHSA-y"], severity: .medium),
        finding("SEC-0006", severity: .low, epss: mark(0.909), kev: KevMark(cve: "CVE-2021-44228")),
        finding("SEC-0007", severity: .low, malware: MalwareMark(advisoryId: "GHSA-m")),
    ]
    #expect(items.sorted(by: FindingRecord.listOrder).map(\.id)
        == ["SEC-0007", "SEC-0006", "SEC-0001", "SEC-0003", "SEC-0002", "SEC-0004", "SEC-0005"])
}

@Test func equalScoresFallBackToSeverityAndFindingsWithoutScoresKeepSeverityOrder() {
    let a = finding("SEC-0001", severity: .low, epss: mark(0.5))
    let b = finding("SEC-0002", severity: .critical, epss: mark(0.5))
    #expect([a, b].sorted(by: FindingRecord.listOrder).map(\.id) == ["SEC-0002", "SEC-0001"])
}

@Test func theEngineJsonDecodesTheEpssValue() throws {
    let json = """
    {"id":"SEC-0001","ecosystem":"npm","package":"p","title":"t","severity":"high","advisory_ids":["CVE-2021-44228"],
     "fixed_in":null,"status":"open","deferred_until":null,"first_seen":"2026-10-24T08:00:00Z",
     "last_seen":"2026-10-29T08:00:00Z","resolved_at":null,"resolved_scan_at":null,"source":"OSV","source_at":null,
     "paths":[],"next_steps":[],"kev":null,"malware":null,"withdrawn_at":null,
     "epss":{"cve":"CVE-2021-44228","score":0.99999,"percentile":1.0,"score_date":"2026-10-29",
             "fetched_at":"2026-10-29T08:00:00Z"}}
    """
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    decoder.dateDecodingStrategy = .iso8601
    let f = try decoder.decode(FindingRecord.self, from: Data(json.utf8))
    #expect(f.epss?.score == 0.99999 && f.epss?.percentile == 1.0 && f.epss?.scoreDate == "2026-10-29")
    #expect(f.epss?.fetchedAt != nil)
}

@Test func theSourceRowShowsTheRetrievalTimeAndTheFailedDownload() {
    let at = Date(timeIntervalSince1970: 1_793_257_200)  // 2026-10-29 07:00 UTC
    #expect(FindingSourceRow.make(coverage(at: at), time: utc).text == "EPSS: retrieved Oct 29, 07:00")
    let failed = FindingSourceRow.make(coverage(.partial, at: ago(days: 1)), time: utc)
    #expect(failed.text == "EPSS download failed. Data from Oct 28." && failed.isProblem)
}
