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

    public init(id: String, source: String, service: String, title: String, summary: String = "",
                published: String?, status: IncidentStatus, sourceName: String, url: String? = nil,
                cves: [String] = [], firstSeen: Date, lastSeen: Date) {
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

    public init(schemaVersion: Int = 1, incidents: [IncidentRecord], sources: [IncidentSource],
                review: IncidentReview, gaps: [IncidentGap] = []) {
        self.schemaVersion = schemaVersion
        self.incidents = incidents
        self.sources = sources
        self.review = review
        self.gaps = gaps
    }
}

// MARK: - Engine calls

public protocol IncidentClient: Sendable {
    func incidents() async throws -> IncidentState
    func checkSources(progress: @escaping @Sendable (RefreshProgress) -> Void) async throws -> IncidentState
}

private struct IncidentProgressLine: Decodable {
    var progress: RefreshProgress
}

extension Engine: IncidentClient {
    public func incidents() async throws -> IncidentState {
        try await call(["incidents"], as: IncidentState.self)
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

    @ObservationIgnored private let client: any IncidentClient
    @ObservationIgnored private var task: Task<Void, Never>?

    public init(client: any IncidentClient, state: IncidentState? = nil, isChecking: Bool = false,
                progress: RefreshProgress? = nil) {
        self.client = client
        self.state = state
        self.isChecking = isChecking
        self.progress = progress
    }

    /// Read the saved records. It never starts a check.
    public func load() async {
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

    public static let emptyTitle = "No incidents found in reviewed sources."
    public static let emptyText = "This does not prove that no breach happened."
}
