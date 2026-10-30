import Foundation
import Observation

// On-demand vendor incident records (#12). The engine checks public sources and keeps the records.
// The sidebar item and the screen are `Incidents`, the button is `Check Sources`. The word
// `Research` is kept for the v2 Claude research. Feed text is untrusted: this code shows it as text only.

public enum IncidentStatus: String, Codable, Sendable, CaseIterable {
    case confirmed, possible, unconfirmed

    /// `Confirmed`, `Possible relevance`, `Unconfirmed`.
    public var text: String {
        switch self {
        case .confirmed: "Confirmed"
        case .possible: "Possible relevance"
        case .unconfirmed: "Unconfirmed"
        }
    }

    public var symbol: String {
        switch self {
        case .confirmed: "exclamationmark.shield"
        case .possible, .unconfirmed: "questionmark.circle"
        }
    }

    public var tone: Tone {
        switch self {
        case .confirmed: .red
        case .possible: .orange
        case .unconfirmed: .gray
        }
    }

    /// What the status means, for the help text.
    public var meaning: String {
        switch self {
        case .confirmed: "A primary source confirms it."
        case .possible: "The service matches. The impact on you is not known."
        case .unconfirmed: "No primary source yet."
        }
    }
}

/// The details of a Have I Been Pwned breach (#60). The text comes from a public list: show it as text only.
public struct BreachDetails: Codable, Hashable, Sendable {
    /// `2024-06-04`.
    public var breachDate: String?
    /// The day HIBP added the breach: `2026-10-27`.
    public var addedDate: String?
    public var dataClasses: [String]
    public var pwnCount: Int?
    public var domain: String?
    public var verified: Bool

    public init(breachDate: String? = nil, addedDate: String? = nil, dataClasses: [String] = [],
                pwnCount: Int? = nil, domain: String? = nil, verified: Bool = true) {
        self.breachDate = breachDate
        self.addedDate = addedDate
        self.dataClasses = dataClasses
        self.pwnCount = pwnCount
        self.domain = domain
        self.verified = verified
    }
}

public struct IncidentRecord: Codable, Hashable, Sendable, Identifiable {
    /// `INC-0001`.
    public var id: String
    public var source: String
    /// `GitHub`, `Google / Gmail` or `Apple`.
    public var service: String
    public var title: String
    public var summary: String
    /// A date as the source gives it, in UTC: `2026-10-27`. nil if the source gives none.
    public var published: String?
    public var status: IncidentStatus
    public var sourceName: String
    public var url: String?
    public var cves: [String]
    public var firstSeen: Date
    public var lastSeen: Date
    /// Have I Been Pwned rows only (#60).
    public var breach: BreachDetails?
    /// A breach row that the newest check added. nil for an older engine.
    public var isNew: Bool?
    /// A vendor link that Claude web research named (#19). Not checked: it never confirms the claim by itself.
    public var primaryUrl: String?

    public init(id: String, source: String, service: String, title: String, summary: String = "",
                published: String?, status: IncidentStatus, sourceName: String, url: String? = nil,
                cves: [String] = [], firstSeen: Date, lastSeen: Date, breach: BreachDetails? = nil,
                isNew: Bool? = nil, primaryUrl: String? = nil) {
        self.primaryUrl = primaryUrl
        self.id = id
        self.source = source
        self.service = service
        self.title = title
        self.summary = summary
        self.published = published
        self.status = status
        self.sourceName = sourceName
        self.url = url
        self.cves = cves
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.breach = breach
        self.isNew = isNew
    }

    /// A claim from Claude web research (#19). It is `Unconfirmed` until a primary source confirms it.
    public var isWebResearch: Bool { source == "claude" }

    /// `Primary source: none`, or the vendor link to check.
    public var primarySourceText: String {
        primaryUrl.map { "\($0) (not checked)" } ?? "none"
    }

    /// The Date column: the breach date for a breach row, else the date of the source.
    public func dateText(time: TimeText = TimeText()) -> String {
        published.map { time.day($0) } ?? "—"
    }

    /// The second line of the Date column: `Added to HIBP Oct 27`.
    public func addedText(time: TimeText = TimeText()) -> String? {
        breach?.addedDate.map { "Added to HIBP \(time.day($0))" }
    }

    /// The link, only if it is an https link. The engine already checks the host.
    public var link: URL? {
        guard let url, let parsed = URL(string: url), parsed.scheme == "https" else { return nil }
        return parsed
    }
}

public enum IncidentSourceState: String, Codable, Sendable {
    case complete, failed
    case notRun = "not_run"
}

public struct IncidentSource: Codable, Hashable, Sendable, Identifiable {
    public var source: String
    public var label: String
    public var state: IncidentSourceState
    public var lastSuccessAt: Date?
    /// `Google / Gmail: check failed. The review is not complete.`
    public var error: String?
    /// A short reason, for example `rate limit`.
    public var note: String?
    public var detail: String?
    public var checkedAt: Date?

    public var id: String { source }

    public init(source: String, label: String, state: IncidentSourceState, lastSuccessAt: Date? = nil,
                error: String? = nil, note: String? = nil, detail: String? = nil, checkedAt: Date? = nil) {
        self.source = source
        self.label = label
        self.state = state
        self.lastSuccessAt = lastSuccessAt
        self.error = error
        self.note = note
        self.detail = detail
        self.checkedAt = checkedAt
    }
}

public struct IncidentReview: Codable, Hashable, Sendable {
    /// The window of the last complete review. nil before the first complete review.
    public var windowStart: Date?
    public var windowEnd: Date?
    /// `complete`, `partial` or `failed`: the newest check, complete or not.
    public var lastAttemptState: String?
    public var lastAttemptAt: Date?

    public init(windowStart: Date? = nil, windowEnd: Date? = nil, lastAttemptState: String? = nil,
                lastAttemptAt: Date? = nil) {
        self.windowStart = windowStart
        self.windowEnd = windowEnd
        self.lastAttemptState = lastAttemptState
        self.lastAttemptAt = lastAttemptAt
    }
}

/// Days that no review covers. Dates as `2026-10-20`.
public struct IncidentGap: Codable, Hashable, Sendable {
    public var start: String
    public var end: String

    public init(start: String, end: String) {
        self.start = start
        self.end = end
    }
}

/// Output of `watchtower incidents` and `watchtower incidents-check`.
public struct IncidentState: Codable, Hashable, Sendable {
    public var schemaVersion: Int
    public var incidents: [IncidentRecord]
    public var sources: [IncidentSource]
    public var review: IncidentReview
    public var gaps: [IncidentGap]
    /// The last Claude web research run (#19). nil: never run.
    public var research: ResearchRun?

    public init(schemaVersion: Int = 1, incidents: [IncidentRecord], sources: [IncidentSource],
                review: IncidentReview, gaps: [IncidentGap] = [], research: ResearchRun? = nil) {
        self.research = research
        self.schemaVersion = schemaVersion
        self.incidents = incidents
        self.sources = sources
        self.review = review
        self.gaps = gaps
    }
}

// MARK: - Claude web research (#19)

/// The outcome of the last research run, as the engine saved it.
public struct ResearchRun: Codable, Hashable, Sendable {
    /// `done`, `no_claims`, `time_limit`, `invalid`, `signed_out`, `not_installed`, `failed` or `stopped`.
    public var state: String
    public var text: String
    public var claims: Int
    public var new: Int
    public var dropped: Int
    public var detail: String?
    public var finishedAt: Date?

    public init(state: String, text: String, claims: Int = 0, new: Int = 0, dropped: Int = 0, detail: String? = nil,
                finishedAt: Date? = nil) {
        self.state = state
        self.text = text
        self.claims = claims
        self.new = new
        self.dropped = dropped
        self.detail = detail
        self.finishedAt = finishedAt
    }

    /// Gray for a normal result, orange for a stop, a limit or a failure.
    public var tone: Tone { ["done", "no_claims"].contains(state) ? .secondary : .orange }
}

/// Whether Research can run, and what the confirm sheet lists.
public struct ResearchStatus: Codable, Hashable, Sendable {
    /// `ready`, `not_installed` or `signed_out`.
    public var state: String
    public var text: String?
    public var topics: [String]
    public var limits: String
    public var timeLimitSeconds: Int

    public init(state: String, text: String? = nil, topics: [String], limits: String, timeLimitSeconds: Int = 300) {
        self.state = state
        self.text = text
        self.topics = topics
        self.limits = limits
        self.timeLimitSeconds = timeLimitSeconds
    }

    public var isReady: Bool { state == "ready" }
}

// MARK: - Engine calls

public protocol IncidentClient: Sendable {
    func incidents() async throws -> IncidentState
    func checkSources(progress: @escaping @Sendable (RefreshProgress) -> Void) async throws -> IncidentState
    /// `research-status`: Claude installed and signed in, the topics and the limits (#19).
    func researchStatus() async throws -> ResearchStatus
    /// `research-run`: one Claude web research run. Cancel stops it and saves nothing.
    func runResearch() async throws -> IncidentState
}

public extension IncidentClient {
    func researchStatus() async throws -> ResearchStatus {
        ResearchStatus(state: "not_installed", text: "Install Claude Code to use Research.", topics: [],
                       limits: IncidentModel.researchLimits)
    }

    func runResearch() async throws -> IncidentState { try await incidents() }
}

private struct IncidentProgressLine: Decodable {
    var progress: RefreshProgress
}

extension Engine: IncidentClient {
    public func incidents() async throws -> IncidentState {
        try await call(["incidents"], as: IncidentState.self)
    }

    public func researchStatus() async throws -> ResearchStatus {
        try await call(["research-status"], as: ResearchStatus.self)
    }

    public func runResearch() async throws -> IncidentState {
        try await call(["research-run"], as: IncidentState.self)
    }

    public func checkSources(progress: @escaping @Sendable (RefreshProgress) -> Void) async throws -> IncidentState {
        try await call(["incidents-check"], as: IncidentState.self) { line in
            if let data = line.data(using: .utf8),
               let parsed = try? EngineJSON.makeDecoder().decode(IncidentProgressLine.self, from: data) {
                progress(parsed.progress)
            }
        }
    }
}

// MARK: - Texts

/// One source card: name, state badge, last success and error text.
public struct IncidentSourceRow: Equatable, Sendable, Identifiable {
    public var id: String
    public var label: String
    public var badge: String
    public var tone: Tone
    public var symbol: String
    public var lastSuccess: String
    public var error: String?

    /// `checking` is true for a source that the running check has not reached yet, or is on now.
    public static func make(_ s: IncidentSource, checking: Bool, time: TimeText = TimeText()) -> IncidentSourceRow {
        let last = s.lastSuccessAt.map { "Last success \(time.absolute($0))" } ?? "No success yet"
        if checking {
            return IncidentSourceRow(id: s.source, label: s.label, badge: "Checking", tone: .gray,
                                     symbol: "arrow.clockwise", lastSuccess: last, error: nil)
        }
        switch s.state {
        case .complete:
            return IncidentSourceRow(id: s.source, label: s.label, badge: "Checked", tone: .green,
                                     symbol: "checkmark.circle", lastSuccess: last, error: nil)
        case .failed where s.source == "hibp":
            // The earlier rows stay. The text names the day of the data that they come from.
            let data = s.lastSuccessAt.map { " Data from \(time.day($0))." } ?? ""
            return IncidentSourceRow(id: s.source, label: s.label, badge: "Failed", tone: .orange,
                                     symbol: "exclamationmark.triangle", lastSuccess: last,
                                     error: "Have I Been Pwned: check failed.\(data)")
        case .failed:
            return IncidentSourceRow(id: s.source, label: s.label, badge: "Failed", tone: .orange,
                                     symbol: "exclamationmark.triangle", lastSuccess: last,
                                     error: s.error ?? "\(s.label): check failed. The review is not complete.")
        case .notRun:
            return IncidentSourceRow(id: s.source, label: s.label, badge: "Not checked", tone: .gray,
                                     symbol: "minus.circle", lastSuccess: last, error: nil)
        }
    }
}

public struct IncidentLabel: Equatable, Sendable {
    public var text: String
    public var tone: Tone
    public var showsProgress: Bool
}

// MARK: - Model

@MainActor
@Observable
public final class IncidentModel {
    public private(set) var state: IncidentState?
    public private(set) var isChecking = false
    public private(set) var progress: RefreshProgress?
    public private(set) var lastError: EngineError?
    public var selectedID: String?
    /// Claude web research (#19): availability, the confirm sheet and a running run.
    public private(set) var researchStatus: ResearchStatus?
    public var showsResearchConfirm = false
    public private(set) var isResearching = false
    public private(set) var researchStartedAt: Date?

    @ObservationIgnored private let client: any IncidentClient
    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var researchTask: Task<Void, Never>?
    @ObservationIgnored let clock: @Sendable () -> Date

    public init(client: any IncidentClient, state: IncidentState? = nil, isChecking: Bool = false,
                progress: RefreshProgress? = nil, researchStatus: ResearchStatus? = nil,
                researchStartedAt: Date? = nil, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.client = client
        self.state = state
        self.isChecking = isChecking
        self.progress = progress
        self.researchStatus = researchStatus
        self.researchStartedAt = researchStartedAt
        self.isResearching = researchStartedAt != nil
        self.clock = clock
    }

    public nonisolated static let researchLimits = "5 minutes. Web search and web fetch only. No MCP, no hooks."

    /// Read whether Research can run. It starts no research.
    public func loadResearchStatus() async {
        researchStatus = try? await client.researchStatus()
    }

    /// `Research` opens the confirm sheet first. Nothing runs before `Run Research`.
    public func askResearch() {
        guard researchStatus?.isReady == true, !isResearching else { return }
        showsResearchConfirm = true
    }

    /// `Run Research` in the confirm sheet: one run of at most 5 minutes. `Check Sources` stays available.
    public func runResearch() {
        showsResearchConfirm = false
        guard !isResearching else { return }
        isResearching = true
        researchStartedAt = clock()
        lastError = nil
        let client = self.client
        researchTask = Task {
            do {
                state = try await client.runResearch()
            } catch is CancellationError {
                // Stop ends the Claude process. Nothing is saved.
            } catch {
                lastError = (error as? EngineError) ?? .failed(message: "Research did not finish.", detail: "\(error)")
            }
            if let saved = try? await client.incidents() { state = saved }
            isResearching = false
            researchStartedAt = nil
            researchTask = nil
        }
    }

    public func stopResearch() {
        researchTask?.cancel()
    }

    public func waitForResearch() async {
        await researchTask?.value
    }

    /// `Researching… 1:12 of 5:00`.
    public func researchElapsedText(at now: Date? = nil) -> String {
        let limit = researchStatus?.timeLimitSeconds ?? 300
        let seconds = min(limit, max(0, Int((now ?? clock()).timeIntervalSince(researchStartedAt ?? clock()))))
        return "Researching… \(Self.minutes(seconds)) of \(Self.minutes(limit))"
    }

    /// VoiceOver reads the elapsed time each minute, not each second.
    public func researchAccessibilityText(at now: Date? = nil) -> String {
        let seconds = max(0, Int((now ?? clock()).timeIntervalSince(researchStartedAt ?? clock())))
        let minutes = seconds / 60
        return "Researching. \(minutes) \(minutes == 1 ? "minute" : "minutes") of 5."
    }

    private static func minutes(_ seconds: Int) -> String {
        String(format: "%d:%02d", seconds / 60, seconds % 60)
    }

    /// Why `Research` is off, or nil. The help text of the button.
    public var researchBlock: String? {
        guard let status = researchStatus else { return "Checking for Claude Code…" }
        return status.isReady ? nil : status.text
    }

    /// `Sign in to Claude Code, then try again.` when Claude Code is installed but not signed in.
    public var researchNotice: String? {
        researchStatus?.state == "signed_out" ? researchStatus?.text : nil
    }

    /// The result line of the last run: `5 claims saved as Unconfirmed.` and the others of the Design notes.
    public var researchResult: (text: String, tone: Tone)? {
        guard !isResearching, let run = state?.research else { return nil }
        return (run.text, run.tone)
    }

    /// Read the saved records and whether Research can run. It never starts a check or a research run.
    public func load() async {
        await loadResearchStatus()
        do {
            state = try await client.incidents()
        } catch let error as EngineError {
            lastError = error
        } catch {}
    }

    /// `Check Sources`. It does not start a refresh, and a refresh does not start it.
    public func check() {
        guard !isChecking else { return }
        isChecking = true
        progress = nil
        lastError = nil
        let client = self.client
        task = Task {
            do {
                state = try await client.checkSources { step in
                    Task { @MainActor in self.apply(step) }
                }
            } catch is CancellationError {
                // Stop keeps the saved records.
            } catch {
                lastError = (error as? EngineError) ?? .failed(message: "The check did not finish.", detail: "\(error)")
                if let saved = try? await client.incidents() { state = saved }
            }
            isChecking = false
            progress = nil
            task = nil
        }
    }

    private func apply(_ step: RefreshProgress) {
        guard isChecking else { return }
        progress = step
    }

    public func stop() {
        task?.cancel()
    }

    public func waitForCheck() async {
        await task?.value
    }

    // Derived values

    public var count: Int { state?.incidents.count ?? 0 }

    /// Newest first (the engine sorts them). The search box matches service, title and source.
    public func visibleIncidents(search: String) -> [IncidentRecord] {
        let query = search.trimmingCharacters(in: .whitespaces)
        let all = state?.incidents ?? []
        guard !query.isEmpty else { return all }
        return all.filter {
            $0.service.localizedCaseInsensitiveContains(query) || $0.title.localizedCaseInsensitiveContains(query)
                || $0.sourceName.localizedCaseInsensitiveContains(query) || $0.id.localizedCaseInsensitiveContains(query)
        }
    }

    public var selectedIncident: IncidentRecord? {
        guard let id = selectedID else { return nil }
        return state?.incidents.first { $0.id == id }
    }

    /// `Reviewed Oct 22 – Oct 29`. During a check: `Checking 2 of 3 sources…`. The end date stays the
    /// date of the last complete review: a failed source does not move it.
    public func label(time: TimeText = TimeText()) -> IncidentLabel {
        if isChecking {
            if let progress, progress.total > 0 {
                let current = min(progress.done + 1, progress.total)
                return IncidentLabel(text: "Checking \(current) of \(progress.total) sources…", tone: .secondary,
                                     showsProgress: true)
            }
            return IncidentLabel(text: "Checking sources…", tone: .secondary, showsProgress: true)
        }
        guard let start = state?.review.windowStart, let end = state?.review.windowEnd else {
            return IncidentLabel(text: "Not checked yet. Click Check Sources.", tone: .secondary, showsProgress: false)
        }
        let incomplete = state?.review.lastAttemptState != "complete"
        return IncidentLabel(text: "Reviewed \(time.day(start)) – \(time.day(end))", tone: incomplete ? .orange : .secondary,
                             showsProgress: false)
    }

    /// One card for each source. While a check runs, the sources that it has not finished show `Checking`.
    public func sourceRows(time: TimeText = TimeText()) -> [IncidentSourceRow] {
        let done = progress?.done ?? 0
        return (state?.sources ?? []).enumerated().map { index, s in
            IncidentSourceRow.make(s, checking: isChecking && index >= done, time: time)
        }
    }

    /// `No review for Oct 20 – Oct 21.` One line for each gap.
    public func gapBanners() -> [String] {
        let time = TimeText()
        return (state?.gaps ?? []).map { gap in
            let start = time.day(gap.start), end = time.day(gap.end)
            return start == end ? "No review for \(start)." : "No review for \(start) – \(end)."
        }
    }

    /// True if a complete review found no incident: the empty text then says so.
    public var showsEmptyResult: Bool {
        guard let state else { return false }
        return state.incidents.isEmpty && state.review.windowEnd != nil
    }

    /// The Have I Been Pwned check finished and no breach is listed for a watched service (#60).
    public var hibpEmptyNote: String? {
        guard let state, let hibp = state.sources.first(where: { $0.source == "hibp" }), hibp.state == .complete,
              !state.incidents.contains(where: { $0.source == "hibp" }) else { return nil }
        return "No breaches listed for GitHub or Google / Gmail. This does not prove that no breach happened."
    }

    /// The rows of the detail pane of a breach: date, data, accounts, domain and where the data comes from.
    public func breachRows(_ incident: IncidentRecord, time: TimeText = TimeText()) -> [(label: String, value: String)] {
        guard let breach = incident.breach else { return [] }
        var rows: [(String, String)] = []
        rows.append(("Breach date", breach.breachDate.map { time.fullDay($0) } ?? "Not given"))
        rows.append(("Data exposed", breach.dataClasses.isEmpty ? "Not given" : breach.dataClasses.joined(separator: ", ")))
        rows.append(("Accounts", breach.pwnCount.map { $0.formatted(.number.grouping(.automatic)) } ?? "Not given"))
        rows.append(("Domain", breach.domain ?? "Not given"))
        let source = state?.sources.first { $0.source == incident.source }
        let when = (source?.lastSuccessAt).map { ", retrieved \(time.absolute($0))" } ?? ""
        rows.append(("Data", "Have I Been Pwned\(when)"))
        return rows.map { (label: $0.0, value: $0.1) }
    }

    public static let emptyTitle = "No incidents found in reviewed sources."
    public static let emptyText = "This does not prove that no breach happened."
}
