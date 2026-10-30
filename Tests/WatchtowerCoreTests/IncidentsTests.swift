import Foundation
import Testing
@testable import WatchtowerCore

private let now = Date(timeIntervalSince1970: 1_793_275_200)  // 2026-10-29 12:00 UTC
private let utc = TimeText(timeZone: TimeZone(identifier: "UTC")!)

private func hours(_ h: Double) -> Date { now.addingTimeInterval(-h * 3600) }

private func incident(_ id: String, _ service: String = "GitHub", title: String = "A title", status: IncidentStatus = .possible,
                      published: String? = "2026-10-27", url: String? = nil) -> IncidentRecord {
    IncidentRecord(id: id, source: "github", service: service, title: title, published: published, status: status,
                   sourceName: "GitHub security blog", url: url, firstSeen: hours(4), lastSeen: hours(4))
}

private func sources(google: IncidentSourceState = .complete) -> [IncidentSource] {
    [
        IncidentSource(source: "github", label: "GitHub", state: .complete, lastSuccessAt: hours(4)),
        IncidentSource(source: "google", label: "Google / Gmail", state: google, lastSuccessAt: hours(28),
                       error: google == .failed ? "Google / Gmail: check failed. The review is not complete." : nil,
                       note: google == .failed ? "HTTP 503" : nil),
        IncidentSource(source: "apple", label: "Apple security", state: .complete, lastSuccessAt: hours(4)),
    ]
}

private func state(_ incidents: [IncidentRecord] = [], google: IncidentSourceState = .complete,
                   windowEnd: Date? = hours(4), attempt: String? = "complete",
                   gaps: [IncidentGap] = []) -> IncidentState {
    IncidentState(incidents: incidents, sources: sources(google: google),
                  review: IncidentReview(windowStart: windowEnd.map { $0.addingTimeInterval(-7 * 86400) }, windowEnd: windowEnd,
                                         lastAttemptState: attempt, lastAttemptAt: hours(4)), gaps: gaps)
}

private actor Calls {
    var checks = 0
    func check() { checks += 1 }
}

private struct FakeClient: IncidentClient {
    var saved: IncidentState
    var checked: IncidentState
    var fail: EngineError? = nil
    var hang = false
    let calls = Calls()

    func incidents() async throws -> IncidentState { saved }

    func checkSources(progress: @escaping @Sendable (RefreshProgress) -> Void) async throws -> IncidentState {
        await calls.check()
        progress(RefreshProgress(done: 1, total: 3, source: "Google / Gmail"))
        if hang { try await Task.sleep(for: .seconds(60)) }
        if let fail { throw fail }
        return checked
    }
}

// MARK: - Contract

@Test func decodesTheEngineIncidentState() throws {
    let json = #"""
    {"schema_version": 1,
     "incidents": [{"id": "INC-0001", "source": "github", "service": "GitHub", "title": "Tokens reset",
       "summary": "We confirmed it.", "published": "2026-10-27", "status": "confirmed",
       "source_name": "GitHub security blog", "url": "https://github.blog/security/x", "cves": ["CVE-2026-1111"],
       "first_seen": "2026-10-29T08:00:00Z", "last_seen": "2026-10-29T08:00:00Z"},
      {"id": "INC-0002", "source": "google", "service": "Google / Gmail", "title": "Phishing", "summary": "",
       "published": null, "status": "possible", "source_name": "Google Workspace status", "url": null, "cves": [],
       "first_seen": "2026-10-29T08:00:00Z", "last_seen": "2026-10-29T08:00:00Z"}],
     "sources": [{"source": "github", "label": "GitHub", "state": "complete", "last_success_at": "2026-10-29T08:00:00Z",
       "error": null, "note": null, "detail": null, "checked_at": "2026-10-29T08:00:00Z"},
      {"source": "google", "label": "Google / Gmail", "state": "not_run", "last_success_at": null, "error": null,
       "note": null, "detail": null, "checked_at": null}],
     "review": {"window_start": "2026-10-22T08:00:00Z", "window_end": "2026-10-29T08:00:00Z",
       "last_attempt_state": "partial", "last_attempt_at": "2026-10-30T08:00:00Z"},
     "gaps": [{"start": "2026-10-20", "end": "2026-10-21"}]}
    """#
    let s = try EngineJSON.decode(IncidentState.self, from: Data(json.utf8))
    #expect(s.incidents.map(\.id) == ["INC-0001", "INC-0002"])
    #expect(s.incidents[0].status == .confirmed && s.incidents[0].cves == ["CVE-2026-1111"])
    #expect(s.incidents[0].link?.absoluteString == "https://github.blog/security/x")
    #expect(s.incidents[1].published == nil && s.incidents[1].link == nil && s.incidents[1].cves.isEmpty)
    #expect(s.sources.map(\.state) == [.complete, .notRun])
    #expect(s.review.lastAttemptState == "partial")
    #expect(s.gaps == [IncidentGap(start: "2026-10-20", end: "2026-10-21")])
}

@Test func onlyHttpsLinksOpen() {
    #expect(incident("a", url: "https://github.blog/x").link != nil)
    for bad in ["http://github.blog/x", "javascript:alert(1)", "file:///etc/passwd", "not a url", ""] {
        #expect(incident("a", url: bad).link == nil, "\(bad)")
    }
}

@Test func statusesHaveTheDesignTextToneAndMeaning() {
    #expect(IncidentStatus.allCases.map(\.text) == ["Confirmed", "Possible relevance", "Unconfirmed"])
    #expect(IncidentStatus.allCases.map(\.tone) == [.red, .orange, .gray])
    #expect(IncidentStatus.confirmed.meaning == "A primary source confirms it.")
    #expect(IncidentStatus.unconfirmed.meaning == "No primary source yet.")
}

// MARK: - Sidebar

@Test func incidentsSitAfterBacklogWithCommandSixAndUpdateLogStaysLast() {
    let all = SidebarSection.allCases
    #expect(all.firstIndex(of: .incidents) == all.firstIndex(of: .backlog)! + 1)
    #expect(all.last == .runtimes)  // #16: Runtimes (⌘8) comes after Update Log.
    #expect(all.firstIndex(of: .runtimes) == all.firstIndex(of: .updateLog)! + 1)
    #expect(SidebarSection.incidents.title == "Incidents")
    #expect(SidebarSection.incidents.shortcutDigit == "6")
    #expect(SidebarSection.incidents.symbol == "antenna.radiowaves.left.and.right")
    #expect(SidebarGroup.review.sections.last == .incidents)
}

@Test func theButtonAndScreenAreNotCalledResearch() {
    // `Research` is kept for the v2 Claude research (owner decision 2026-10-29).
    #expect(!SidebarSection.allCases.map(\.title).contains("Research"))
}

// MARK: - Label, rows and banners

@MainActor
@Test func labelShowsTheReviewedDaysAndKeepsTheOldEndAfterAFailure() {
    let ok = IncidentModel(client: FakeClient(saved: state(), checked: state()), state: state())
    #expect(ok.label(time: utc) == IncidentLabel(text: "Reviewed Oct 22 – Oct 29", tone: .secondary, showsProgress: false))
    // A failed source: the last attempt is partial, and the end date is still the last complete review.
    let partial = state(google: .failed, windowEnd: hours(28), attempt: "partial")
    let failed = IncidentModel(client: FakeClient(saved: partial, checked: partial), state: partial)
    #expect(failed.label(time: utc) == IncidentLabel(text: "Reviewed Oct 21 – Oct 28", tone: .orange, showsProgress: false))
    let never = IncidentModel(client: FakeClient(saved: state(windowEnd: nil, attempt: nil), checked: state()),
                              state: state(windowEnd: nil, attempt: nil))
    #expect(never.label().text == "Not checked yet. Click Check Sources.")
}

@MainActor
@Test func labelCountsTheSourcesWhileChecking() {
    let model = IncidentModel(client: FakeClient(saved: state(), checked: state()), state: state(), isChecking: true,
                              progress: RefreshProgress(done: 1, total: 3, source: "Google / Gmail"))
    #expect(model.label() == IncidentLabel(text: "Checking 2 of 3 sources…", tone: .secondary, showsProgress: true))
    let start = IncidentModel(client: FakeClient(saved: state(), checked: state()), state: state(), isChecking: true)
    #expect(start.label().text == "Checking sources…")
}

@MainActor
@Test func sourceRowsShowStateLastSuccessAndTheErrorText() {
    let model = IncidentModel(client: FakeClient(saved: state(google: .failed), checked: state()), state: state(google: .failed))
    let rows = model.sourceRows(time: utc)
    #expect(rows.map(\.label) == ["GitHub", "Google / Gmail", "Apple security"])
    #expect(rows.map(\.badge) == ["Checked", "Failed", "Checked"])
    #expect(rows[0].lastSuccess == "Last success Oct 29, 08:00")
    #expect(rows[1].error == "Google / Gmail: check failed. The review is not complete.")
    #expect(rows[1].tone == .orange && rows[0].error == nil)
    let fresh = IncidentSource(source: "x", label: "X", state: .notRun)
    #expect(IncidentSourceRow.make(fresh, checking: false).lastSuccess == "No success yet")
    #expect(IncidentSourceRow.make(fresh, checking: false).badge == "Not checked")
}

@MainActor
@Test func sourcesThatTheCheckHasNotFinishedShowChecking() {
    let model = IncidentModel(client: FakeClient(saved: state(), checked: state()), state: state(), isChecking: true,
                              progress: RefreshProgress(done: 1, total: 3, source: "Google / Gmail"))
    #expect(model.sourceRows().map(\.badge) == ["Checked", "Checking", "Checking"])
}

@MainActor
@Test func gapBannersNameTheMissedDays() {
    let gaps = [IncidentGap(start: "2026-10-20", end: "2026-10-21"), IncidentGap(start: "2026-10-05", end: "2026-10-05")]
    let model = IncidentModel(client: FakeClient(saved: state(gaps: gaps), checked: state()), state: state(gaps: gaps))
    #expect(model.gapBanners() == ["No review for Oct 20 – Oct 21.", "No review for Oct 5."])
    #expect(IncidentModel(client: FakeClient(saved: state(), checked: state()), state: state()).gapBanners().isEmpty)
}

@MainActor
@Test func theEmptyResultNeverClaimsSafety() {
    let model = IncidentModel(client: FakeClient(saved: state(), checked: state()), state: state())
    #expect(model.showsEmptyResult)
    #expect(IncidentModel.emptyTitle == "No incidents found in reviewed sources.")
    #expect(IncidentModel.emptyText == "This does not prove that no breach happened.")
    let before = IncidentModel(client: FakeClient(saved: state(), checked: state()), state: state(windowEnd: nil, attempt: nil))
    #expect(!before.showsEmptyResult)  // No complete review: it is not a result.
    let some = IncidentModel(client: FakeClient(saved: state([incident("a")]), checked: state()), state: state([incident("a")]))
    #expect(!some.showsEmptyResult)
}

@MainActor
@Test func incidentsWithoutACveStayInTheListAndSearchFindsThem() {
    let list = [incident("INC-0001", "GitHub", title: "Tokens reset"), incident("INC-0002", "Google / Gmail", title: "Phishing campaign"),
                incident("INC-0003", "Apple", title: "Kernel flaw")]
    let model = IncidentModel(client: FakeClient(saved: state(list), checked: state()), state: state(list))
    #expect(model.count == 3 && model.visibleIncidents(search: "").count == 3)
    for (query, ids) in [("gmail", ["INC-0002"]), ("KERNEL", ["INC-0003"]), ("inc-0001", ["INC-0001"]),
                         ("security blog", ["INC-0001", "INC-0002", "INC-0003"]), ("zzz", [])] {
        #expect(model.visibleIncidents(search: query).map(\.id) == ids, "\(query)")
    }
    model.selectedID = "INC-0002"
    #expect(model.selectedIncident?.title == "Phishing campaign")
    model.selectedID = "nope"
    #expect(model.selectedIncident == nil)
}

// MARK: - Check

@MainActor
@Test func checkSourcesReplacesTheStateAndStartsNoRefresh() async {
    let fresh = state([incident("INC-0001")])
    let client = FakeClient(saved: state(), checked: fresh)
    let model = IncidentModel(client: client, state: state())
    model.check()
    #expect(model.isChecking)
    await model.waitForCheck()
    #expect(!model.isChecking && model.progress == nil)
    #expect(model.state == fresh)
    #expect(await client.calls.checks == 1)
}

@MainActor
@Test func aSecondCheckWhileOneRunsIsIgnored() async {
    var client = FakeClient(saved: state(), checked: state())
    client.hang = true
    let model = IncidentModel(client: client, state: state())
    model.check()
    model.check()
    try? await Task.sleep(for: .milliseconds(50))
    #expect(model.isChecking && model.progress?.done == 1)
    model.stop()
    await model.waitForCheck()
    #expect(await client.calls.checks == 1 && !model.isChecking)
    #expect(model.state == state())  // Stop keeps the saved records.
}

@MainActor
@Test func aFailedCheckShowsTheErrorAndReadsTheSavedRecordsAgain() async {
    var client = FakeClient(saved: state([incident("INC-0009")]), checked: state())
    client.fail = .reported(message: "The check did not finish.", detail: nil)
    let model = IncidentModel(client: client, state: state())
    model.check()
    await model.waitForCheck()
    #expect(model.lastError?.message == "The check did not finish.")
    #expect(model.state?.incidents.map(\.id) == ["INC-0009"])
}

@MainActor
@Test func loadReadsTheSavedStateAndNeverChecks() async {
    let client = FakeClient(saved: state([incident("INC-0001")]), checked: state())
    let model = IncidentModel(client: client)
    await model.load()
    #expect(model.count == 1 && !model.isChecking)
    #expect(await client.calls.checks == 0)
}

// MARK: - Have I Been Pwned (#60)

private func breachRow(_ id: String = "INC-0010", new: Bool? = nil, verified: Bool = true) -> IncidentRecord {
    IncidentRecord(id: id, source: "hibp", service: "GitHub", title: "GitHub data breach", published: "2024-06-04",
                   status: verified ? .possible : .unconfirmed, sourceName: "Have I Been Pwned",
                   url: "https://haveibeenpwned.com/PwnedWebsites#GitHub", firstSeen: hours(4), lastSeen: hours(4),
                   breach: BreachDetails(breachDate: "2024-06-04", addedDate: "2026-10-27",
                                         dataClasses: ["Email addresses", "Passwords"], pwnCount: 1_200_000,
                                         domain: "github.com", verified: verified), isNew: new)
}

private func hibpSource(_ state: IncidentSourceState = .complete) -> IncidentSource {
    IncidentSource(source: "hibp", label: "Have I Been Pwned", state: state, lastSuccessAt: hours(30),
                   error: state == .failed ? "Have I Been Pwned: check failed. The review is not complete." : nil)
}

@MainActor
private func model(_ incidents: [IncidentRecord], hibp: IncidentSourceState = .complete) -> IncidentModel {
    var s = state(incidents)
    s.sources.append(hibpSource(hibp))
    return IncidentModel(client: FakeClient(saved: s, checked: s), state: s)
}

@Test func breachJsonFromTheEngineDecodes() throws {
    let json = """
    {"id":"INC-0010","source":"hibp","service":"GitHub","title":"GitHub data breach","summary":"s","published":"2024-06-04",
     "status":"possible","source_name":"Have I Been Pwned","url":"https://haveibeenpwned.com/PwnedWebsites#GitHub","cves":[],
     "first_seen":"2026-10-29T08:00:00Z","last_seen":"2026-10-29T08:00:00Z",
     "breach":{"breach_date":"2024-06-04","added_date":"2026-10-27","data_classes":["Email addresses"],"pwn_count":1200000,
               "domain":"github.com","verified":true},"is_new":true}
    """
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    decoder.dateDecodingStrategy = .iso8601
    let record = try decoder.decode(IncidentRecord.self, from: Data(json.utf8))
    #expect(record.breach?.pwnCount == 1_200_000 && record.breach?.addedDate == "2026-10-27" && record.isNew == true)
    // An older engine sends neither key.
    let old = json.replacingOccurrences(of: "\"breach\":{", with: "\"x\":{").replacingOccurrences(of: ",\"is_new\":true", with: "")
    #expect(try decoder.decode(IncidentRecord.self, from: Data(old.utf8)).breach == nil)
}

@Test func theDateColumnShowsTheBreachDateAndWhenHibpAddedIt() {
    let row = breachRow()
    #expect(row.dateText(time: utc) == "Jun 4")
    #expect(row.addedText(time: utc) == "Added to HIBP Oct 27")
    #expect(incident("INC-0001").addedText(time: utc) == nil)
}

@MainActor
@Test func theDetailRowsAreTheBreachFacts() {
    let m = model([breachRow()])
    let rows = m.breachRows(breachRow(), time: utc)
    #expect(rows.map(\.label) == ["Breach date", "Data exposed", "Accounts", "Domain", "Data"])
    #expect(rows[0].value == "Jun 4, 2024" && rows[1].value == "Email addresses, Passwords")
    #expect(rows[2].value == "1,200,000" && rows[3].value == "github.com")
    #expect(rows[4].value.hasPrefix("Have I Been Pwned, retrieved Oct 28,"))
}

@MainActor
@Test func theEmptyNoteShowsOnlyAfterACompleteCheckWithNoBreach() {
    #expect(model([incident("INC-0001")]).hibpEmptyNote
        == "No breaches listed for GitHub or Google / Gmail. This does not prove that no breach happened.")
    #expect(model([breachRow()]).hibpEmptyNote == nil)
    #expect(model([incident("INC-0001")], hibp: .failed).hibpEmptyNote == nil)
}

@Test func aFailedFetchNamesTheDayOfTheEarlierData() {
    let row = IncidentSourceRow.make(hibpSource(.failed), checking: false, time: utc)
    #expect(row.error == "Have I Been Pwned: check failed. Data from Oct 28." && row.tone == .orange)
    let none = IncidentSource(source: "hibp", label: "Have I Been Pwned", state: .failed)
    #expect(IncidentSourceRow.make(none, checking: false, time: utc).error == "Have I Been Pwned: check failed.")
}

@Test func fullDaysReadAsMonthDayYear() {
    #expect(utc.fullDay("2024-06-04") == "Jun 4, 2024")
    #expect(utc.fullDay("not a date") == "not a date")
}
