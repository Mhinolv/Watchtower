import Foundation
import Testing
@testable import WatchtowerCore

// MARK: - Claude web research (#19)

private let start = Date(timeIntervalSince1970: 1_793_275_200)
private let ready = ResearchStatus(state: "ready", topics: ["GitHub", "Google Gmail", "Apple"],
                                   limits: IncidentModel.researchLimits)
private let review = IncidentReview(windowStart: nil, windowEnd: nil, lastAttemptState: nil, lastAttemptAt: nil)

private func claim(_ id: String, primary: String? = nil) -> IncidentRecord {
    IncidentRecord(id: id, source: "claude", service: "GitHub", title: "Claim \(id)", published: "2026-10-25",
                   status: .unconfirmed, sourceName: "Web research", firstSeen: start, lastSeen: start, primaryUrl: primary)
}

private struct ResearchClient: IncidentClient {
    var status = ready
    var result = IncidentState(incidents: [claim("INC-0001")], sources: [], review: review,
                               research: ResearchRun(state: "done", text: "1 claim saved as Unconfirmed.", claims: 1, new: 1))

    func incidents() async throws -> IncidentState { result }
    func checkSources(progress: @escaping @Sendable (RefreshProgress) -> Void) async throws -> IncidentState { result }
    func researchStatus() async throws -> ResearchStatus { status }
    func runResearch() async throws -> IncidentState { result }
}

@Test func decodesTheResearchRunAndThePrimaryLink() throws {
    let json = #"""
    {"schema_version": 1, "incidents": [
      {"id": "INC-0021", "source": "claude", "service": "Apple", "title": "Fix", "summary": "s", "published": null,
       "status": "unconfirmed", "source_name": "Web research", "url": "https://news.example.com/a", "cves": [],
       "first_seen": "2026-10-30T10:00:00Z", "last_seen": "2026-10-30T10:00:00Z", "breach": null, "is_new": false,
       "primary_url": "https://support.apple.com/en-us/149225"}],
     "sources": [], "review": {"window_start": null, "window_end": null, "last_attempt_state": null,
                               "last_attempt_at": null}, "gaps": [],
     "research": {"state": "time_limit", "text": "Research stopped at 5 minutes. Nothing was saved.", "claims": 0,
                  "new": 0, "dropped": 0, "detail": null, "finished_at": "2026-10-30T10:05:00Z"}}
    """#
    let state = try EngineJSON.decode(IncidentState.self, from: Data(json.utf8))
    let record = try #require(state.incidents.first)
    #expect(record.isWebResearch && record.status == .unconfirmed)
    #expect(record.primarySourceText == "https://support.apple.com/en-us/149225 (not checked)")
    #expect(state.research?.state == "time_limit" && state.research?.tone == .orange)
    var none = record
    none.primaryUrl = nil
    #expect(none.primarySourceText == "none")
}

@Test func decodesAnIncidentStateWithoutResearch() throws {
    let json = #"""
    {"schema_version": 1, "incidents": [], "sources": [],
     "review": {"window_start": null, "window_end": null, "last_attempt_state": null, "last_attempt_at": null},
     "gaps": []}
    """#
    #expect(try EngineJSON.decode(IncidentState.self, from: Data(json.utf8)).research == nil)
}

@MainActor
@Test func elapsedTextAndTheMinuteVoiceOverText() {
    let model = IncidentModel(client: ResearchClient(), researchStatus: ready, researchStartedAt: start,
                              clock: { start })
    #expect(model.isResearching)
    #expect(model.researchElapsedText(at: start.addingTimeInterval(72)) == "Researching… 1:12 of 5:00")
    #expect(model.researchElapsedText(at: start.addingTimeInterval(400)) == "Researching… 5:00 of 5:00")
    #expect(model.researchAccessibilityText(at: start.addingTimeInterval(72)) == "Researching. 1 minute of 5.")
    #expect(model.researchAccessibilityText(at: start.addingTimeInterval(59)) == "Researching. 0 minutes of 5.")
}

@MainActor
@Test func researchIsOffUntilClaudeIsReady() async {
    let off = IncidentModel(client: ResearchClient(status: ResearchStatus(
        state: "not_installed", text: "Install Claude Code to use Research.", topics: [], limits: "")))
    #expect(off.researchBlock == "Checking for Claude Code…")
    await off.loadResearchStatus()
    #expect(off.researchBlock == "Install Claude Code to use Research.")
    off.askResearch()
    #expect(!off.showsResearchConfirm)
    let signedOut = IncidentModel(client: ResearchClient(), researchStatus: ResearchStatus(
        state: "signed_out", text: "Sign in to Claude Code, then try again.", topics: [], limits: ""))
    #expect(signedOut.researchNotice == "Sign in to Claude Code, then try again.")
    #expect(signedOut.researchBlock == "Sign in to Claude Code, then try again.")
}

@MainActor
@Test func researchAsksFirstThenRunsAndKeepsClaimsUnconfirmed() async {
    let model = IncidentModel(client: ResearchClient(), researchStatus: ready)
    model.askResearch()
    #expect(model.showsResearchConfirm && !model.isResearching)  // Nothing runs before Run Research.
    model.runResearch()
    #expect(!model.showsResearchConfirm && model.isResearching)
    await model.waitForResearch()
    #expect(!model.isResearching && model.researchStartedAt == nil)
    #expect(model.state?.incidents.map(\.status) == [.unconfirmed])
    #expect(model.researchResult?.text == "1 claim saved as Unconfirmed.")
    #expect(model.researchResult?.tone == .secondary)
}

@Test func theLimitsTextMatchesTheOwnerDecision() {
    #expect(IncidentModel.researchLimits == "5 minutes. Web search and web fetch only. No MCP, no hooks.")
}
