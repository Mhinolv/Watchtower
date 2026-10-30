import Foundation
import Observation

// Dashboard logic that the views use. It holds no SwiftUI, so tests can check it.

/// A refresh older than this shows as stale (owner decision 2026-10-29).
public let staleAfter: TimeInterval = 24 * 60 * 60

public enum Tone: Sendable, Equatable {
    case secondary, green, blue, red, orange, gray
}

// MARK: - Sidebar

public enum SidebarSection: String, CaseIterable, Identifiable, Sendable {
    case apps, homebrew, projects, findings, backlog, incidents, updateLog

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .apps: "Apps"
        case .homebrew: "Homebrew"
        case .projects: "Projects"
        case .findings: "Findings"
        case .backlog: "Backlog"
        case .incidents: "Incidents"
        case .updateLog: "Update Log"
        }
    }

    public var symbol: String {
        switch self {
        case .apps: "app.badge"
        case .homebrew: "mug"
        case .projects: "folder"
        case .findings: "exclamationmark.shield"
        case .backlog: "archivebox"
        case .incidents: "antenna.radiowaves.left.and.right"
        case .updateLog: "list.bullet.rectangle"
        }
    }

    /// ⌘1 to ⌘6, and ⌘7 for Update Log (Design notes of #5, #6 and #12).
    public var shortcutDigit: Character {
        switch self {
        case .apps: "1"
        case .homebrew: "2"
        case .projects: "3"
        case .findings: "4"
        case .backlog: "5"
        case .incidents: "6"
        case .updateLog: "7"
        }
    }

    /// True for sections that list items. Projects and Backlog list projects.
    public var listsItems: Bool { self == .apps || self == .homebrew || self == .findings }
}

// MARK: - Status badge

public struct StatusStyle: Equatable, Sendable {
    public var text: String
    public var symbol: String
    public var tone: Tone

    public init(_ state: ItemState) {
        switch state {
        case .upToDate: (text, symbol, tone) = ("Up to date", "checkmark.circle", .green)
        case .updateAvailable: (text, symbol, tone) = ("Update available", "arrow.up.circle", .blue)
        case .vulnerable: (text, symbol, tone) = ("Vulnerable", "exclamationmark.shield", .red)
        case .unknown: (text, symbol, tone) = ("Unknown", "questionmark.circle", .gray)
        case .error: (text, symbol, tone) = ("Error", "exclamationmark.triangle", .orange)
        case .pinned: (text, symbol, tone) = ("Pinned", "pin", .gray)
        case .manual: (text, symbol, tone) = ("Manual update", "hand.raised", .gray)
        }
    }
}

extension ItemState {
    /// Sort order in lists: what needs action first.
    public var rank: Int {
        switch self {
        case .vulnerable: 0
        case .updateAvailable: 1
        case .error: 2
        case .unknown: 3
        case .manual: 4
        case .pinned: 5
        case .upToDate: 6
        }
    }
}

// MARK: - Findings

public struct SeverityStyle: Equatable, Sendable {
    public var text: String
    public var symbol: String
    public var tone: Tone

    public init(_ severity: Severity) {
        switch severity {
        case .critical: (text, symbol, tone) = ("Critical", "exclamationmark.octagon", .red)
        case .high: (text, symbol, tone) = ("High", "exclamationmark.triangle", .red)
        case .medium: (text, symbol, tone) = ("Medium", "exclamationmark.circle", .orange)
        case .low: (text, symbol, tone) = ("Low", "info.circle", .blue)
        case .unknown: (text, symbol, tone) = ("Unknown", "questionmark.circle", .gray)
        }
    }
}

extension FindingRecord {
    /// Malware first, then known exploited, then EPSS high to low (no score last), then worst severity,
    /// then newest, then id.
    public static func listOrder(_ a: FindingRecord, _ b: FindingRecord) -> Bool {
        let left: [Int] = [a.malware == nil ? 1 : 0, a.kev == nil ? 1 : 0]
        let right: [Int] = [b.malware == nil ? 1 : 0, b.kev == nil ? 1 : 0]
        if left != right { return left.lexicographicallyPrecedes(right) }
        if let first = epssPrecedes(a, b) { return first }
        if a.severity.rank != b.severity.rank { return a.severity.rank < b.severity.rank }
        if a.lastSeen != b.lastSeen { return a.lastSeen > b.lastSeen }
        return a.id < b.id
    }
}

/// The badges that come from the feeds, with their help text (#9).
public enum FeedBadge: Equatable, Sendable {
    case knownExploited(String), malware, withdrawn(String)

    public var text: String {
        switch self {
        case .knownExploited: "Known exploited"
        case .malware: "Malware"
        case .withdrawn: "Withdrawn"
        }
    }

    public var symbol: String {
        switch self {
        case .knownExploited: "flame.fill"
        case .malware: "exclamationmark.octagon.fill"
        case .withdrawn: "minus.circle"
        }
    }

    public var tone: Tone {
        if case .withdrawn = self { return .gray }
        return .red
    }

    public var help: String {
        switch self {
        case .knownExploited(let text): text
        case .malware: "GitHub lists this package as malware."
        case .withdrawn(let text): text
        }
    }

    /// The badges of a finding, in the order that they show: Malware, Known exploited, Withdrawn.
    public static func badges(for finding: FindingRecord, time: TimeText = TimeText()) -> [FeedBadge] {
        var out: [FeedBadge] = []
        if finding.malware != nil { out.append(.malware) }
        if let kev = finding.kev {
            let added = kev.dateAdded.map { "Listed in CISA KEV on \(time.day($0))." } ?? "Listed in CISA KEV."
            let due = kev.dueDate.map { " Due date \(time.day($0))." } ?? ""
            out.append(.knownExploited(added + due))
        }
        if let withdrawn = finding.withdrawnAt {
            out.append(.withdrawn("The source withdrew this advisory on \(time.day(withdrawn))."))
        }
        return out
    }
}

/// One row of the `Source` section of a finding: one feed.
public struct FindingSourceRow: Equatable, Sendable, Identifiable {
    public var id: String
    public var text: String
    /// True if the feed has a problem: shown in orange with a warning symbol.
    public var isProblem: Bool

    /// The text for each state of a feed, from the Design notes of #9.
    public static func make(_ c: CoverageRecord, time: TimeText = TimeText()) -> FindingSourceRow {
        let at = c.sourceAt ?? c.lastSuccessAt
        let data = at.map { "Data from \(time.day($0))." } ?? "No data yet."
        switch c.state {
        case .complete:
            let text = c.note == "official mirror" ? "\(c.label): retrieved from the official mirror"
                : at.map { "\(c.label): retrieved \(time.absolute($0))" } ?? "\(c.label): retrieved"
            return FindingSourceRow(id: c.source, text: text, isProblem: false)
        case .partial where c.source == "epss":
            return FindingSourceRow(id: c.source, text: "EPSS download failed. \(data)", isProblem: true)
        case .partial:
            return FindingSourceRow(id: c.source, text: "\(c.label): incomplete. Some advisories can be missing.",
                                    isProblem: true)
        case .stale:
            return FindingSourceRow(id: c.source, text: "\(c.label): stale. \(data)", isProblem: true)
        case .failed where c.source == "epss":
            return FindingSourceRow(id: c.source, text: "EPSS download failed. \(data)", isProblem: true)
        case .failed:
            return FindingSourceRow(id: c.source, text: "\(c.label): failed (\(c.note ?? "error")). \(data)",
                                    isProblem: true)
        case .notRun:
            return FindingSourceRow(id: c.source, text: "\(c.label): not run.", isProblem: true)
        }
    }
}

/// The status of a finding as text: `Open`, `Deferred until Nov 5`, `Backlog`, `Resolved: …`.
public struct FindingStatusText: Equatable, Sendable {
    public var text: String
    public var symbol: String
    public var tone: Tone

    /// `full` is the long form for the detail view. The table uses the short form.
    public init(_ finding: FindingRecord, full: Bool = true, time: TimeText = TimeText()) {
        switch finding.status {
        case .open:
            (text, symbol, tone) = ("Open", "exclamationmark.shield", .red)
        case .deferred:
            let until = finding.deferredUntil.map { " until \(time.day($0))" } ?? ""
            (text, symbol, tone) = ("Deferred\(until)", "clock", .gray)
        case .backlog:
            (text, symbol, tone) = ("Backlog", "archivebox", .gray)
        case .resolved:
            let day = (finding.resolvedScanAt ?? finding.resolvedAt).map { time.day($0) }
            let long = day.map { "Resolved: not found in complete scan of \($0)" } ?? "Resolved"
            (text, symbol, tone) = (full ? long : "Resolved", "checkmark.circle", .green)
        }
    }
}

/// The filter control above the findings table.
public enum FindingFilter: String, CaseIterable, Identifiable, Sendable {
    case open, deferred, resolved, all

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .open: "Open"
        case .deferred: "Deferred"
        case .resolved: "Resolved"
        case .all: "All"
        }
    }

    /// `Deferred` shows deferred findings only. A finding in the backlog is in the Backlog section,
    /// and `All` still shows it (#40).
    public func matches(_ finding: FindingRecord) -> Bool {
        switch self {
        case .open: finding.status == .open
        case .deferred: finding.status == .deferred
        case .resolved: finding.status == .resolved
        case .all: true
        }
    }
}

// MARK: - Time text

public struct TimeText: Sendable {
    public var timeZone: TimeZone

    public init(timeZone: TimeZone = .current) {
        self.timeZone = timeZone
    }

    /// `Oct 27, 09:14` in local time.
    public func absolute(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = timeZone
        formatter.dateFormat = "MMM d, HH:mm"
        return formatter.string(from: date)
    }

    /// `Oct 29` in local time.
    public func day(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = timeZone
        formatter.dateFormat = "MMM d"
        return formatter.string(from: date)
    }

    /// `2024-06-04` as `Jun 4, 2024`. Other text comes back as it is.
    public func fullDay(_ text: String) -> String {
        let parser = DateFormatter()
        parser.locale = Locale(identifier: "en_US_POSIX")
        parser.timeZone = TimeZone(identifier: "UTC")
        parser.dateFormat = "yyyy-MM-dd"
        guard let date = parser.date(from: text) else { return text }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "MMM d, yyyy"
        return formatter.string(from: date)
    }

    /// `2026-10-22` (the date of a KEV entry) as `Oct 22`. Other text comes back as it is.
    public func day(_ text: String) -> String {
        let parser = DateFormatter()
        parser.locale = Locale(identifier: "en_US_POSIX")
        parser.timeZone = TimeZone(identifier: "UTC")
        parser.dateFormat = "yyyy-MM-dd"
        guard let date = parser.date(from: text) else { return text }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "MMM d"
        return formatter.string(from: date)
    }

    /// `2 h`, `5 min`, `3 days`. Under one minute: `less than 1 min`.
    public static func duration(_ seconds: TimeInterval) -> String {
        let s = max(0, seconds)
        if s < 60 { return "less than 1 min" }
        if s < 3600 { return "\(Int(s / 60)) min" }
        if s < 2 * 86400 { return "\(Int(s / 3600)) h" }
        return "\(Int(s / 86400)) days"
    }
}

// MARK: - Refresh label

public struct RefreshLabel: Equatable, Sendable {
    public var text: String
    public var tone: Tone
    public var showsProgress: Bool

    public init(text: String, tone: Tone, showsProgress: Bool = false) {
        self.text = text
        self.tone = tone
        self.showsProgress = showsProgress
    }

    public static func make(state: EngineState?, running: Bool, progress: RefreshProgress?,
                            now: Date, time: TimeText = TimeText()) -> RefreshLabel {
        if running {
            if let progress, progress.total > 0 {
                let current = min(progress.done + 1, progress.total)
                return RefreshLabel(text: "Refreshing… \(current) of \(progress.total) sources", tone: .secondary,
                                    showsProgress: true)
            }
            return RefreshLabel(text: "Refreshing…", tone: .secondary, showsProgress: true)
        }
        guard let refresh = state?.refresh else {
            return RefreshLabel(text: "Never refreshed. Click Refresh.", tone: .secondary)
        }
        switch refresh.status {
        case .failed, .running:  // `running` here means a refresh that never finished.
            if let last = refresh.lastCompleteAt {
                return RefreshLabel(text: "Refresh failed. Showing data from \(time.absolute(last))", tone: .red)
            }
            return RefreshLabel(text: "Refresh failed. Click Refresh to try again.", tone: .red)
        case .partial:
            if let finished = refresh.finishedAt, now.timeIntervalSince(finished) < staleAfter {
                let coverage = state?.coverage ?? []
                let failed = coverage.filter { $0.state == .failed || $0.state == .partial }.count
                return RefreshLabel(text: "Partial: \(failed) of \(coverage.count) sources failed", tone: .orange)
            }
        case .complete, .cancelled:
            break
        }
        let reference = refresh.lastCompleteAt ?? (refresh.status == .partial ? refresh.finishedAt : nil)
        guard let reference else {
            return RefreshLabel(text: "Never refreshed. Click Refresh.", tone: .secondary)
        }
        let age = now.timeIntervalSince(reference)
        if age >= staleAfter {
            return RefreshLabel(text: "Stale: last refresh \(time.absolute(reference))", tone: .orange)
        }
        if age < 60 {
            return RefreshLabel(text: "Last refresh: just now", tone: .secondary)
        }
        return RefreshLabel(text: "Last refresh: \(TimeText.duration(age)) ago", tone: .secondary)
    }
}

/// One row of the Coverage popover.
public struct CoverageRow: Equatable, Sendable, Identifiable {
    public var id: String
    public var label: String
    public var stateText: String
    public var tone: Tone
    public var lastSuccess: String
    public var error: String?

    public static func rows(_ coverage: [CoverageRecord], time: TimeText = TimeText()) -> [CoverageRow] {
        coverage.map { c in
            let (text, tone): (String, Tone) = switch c.state {
            case .complete: ("Complete", .green)
            case .partial: ("Partial", .orange)
            case .failed: ("Failed", .red)
            case .stale: ("Stale", .orange)
            case .notRun: ("Not run", .gray)
            }
            let last = c.lastSuccessAt.map { "Last success \(time.absolute($0))" } ?? "No success yet"
            // `Sparkle feeds: 12 of 14 read` (#14). Other sources keep the plain label.
            let counted = c.source == "sparkle" && c.state != .notRun
            let label = counted ? c.note.map { "\(c.label): \($0)" } ?? c.label : c.label
            return CoverageRow(id: c.source, label: label, stateText: text, tone: tone, lastSuccess: last,
                               error: c.error)
        }
    }
}

// MARK: - Backlog

/// One row of the Backlog section: an inactive project or a finding that the owner moved there.
public enum BacklogEntry: Identifiable, Equatable, Sendable {
    case project(ProjectRecord)
    case finding(FindingRecord)

    /// The path of a project, or the id of a finding (`SEC-0008`). It is the selection key.
    public var id: String {
        switch self {
        case .project(let p): p.path
        case .finding(let f): f.id
        }
    }

    /// `old-site`, or `SEC-0008 yaml-tools`.
    public var name: String {
        switch self {
        case .project(let p): p.name
        case .finding(let f): "\(f.id) \(f.package)"
        }
    }

    /// The path of a project, or the title of a finding. Secondary text under the name.
    public var secondary: String {
        switch self {
        case .project(let p): p.displayPath
        case .finding(let f): f.title
        }
    }

    public var kind: String {
        switch self {
        case .project: "Project"
        case .finding: "Finding"
        }
    }

    public var symbol: String {
        switch self {
        case .project: "folder"
        case .finding: "exclamationmark.shield"
        }
    }

    /// The status column. The engine does not keep the day that an item moved here.
    public var statusText: String {
        switch self {
        case .project: "Inactive"
        case .finding(let f): f.status == .backlog ? "In the backlog" : "Inactive project"
        }
    }

    public static let emptyTitle = "Backlog is empty"
    public static let emptyText = "Inactive projects and findings you move here appear in this list."
    public static let headline = "Items you moved here. They stay here until you move them back."
}

// MARK: - Model

@MainActor
@Observable
public final class DashboardModel {
    public private(set) var state: EngineState?
    public private(set) var projects: [ProjectRecord]
    public private(set) var isRefreshing = false
    public private(set) var progress: RefreshProgress?
    public private(set) var lastError: EngineError?
    public var selection: SidebarSection? = .apps
    public var selectedItemKey: String?
    public var searchText = ""
    public var findingFilter: FindingFilter = .open
    /// The selected filter chip above the item list.
    public var itemFilter: ItemFilter = .all

    @ObservationIgnored private let engine: any EngineClient
    @ObservationIgnored private let clock: @Sendable () -> Date
    @ObservationIgnored private var refreshTask: Task<Void, Never>?

    public init(engine: any EngineClient, state: EngineState? = nil, projects: [ProjectRecord] = [],
                isRefreshing: Bool = false, progress: RefreshProgress? = nil,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.engine = engine
        self.state = state
        self.projects = projects
        self.isRefreshing = isRefreshing
        self.progress = progress
        self.clock = clock
    }

    // Engine calls

    /// Read the stored state and the project list. Never runs a refresh.
    public func load() async {
        do {
            state = try await engine.state()
        } catch let error as EngineError {
            lastError = error
        } catch {}
        await loadProjects()
    }

    public func loadProjects() async {
        do {
            projects = try await engine.projects().projects
        } catch let error as EngineError {
            lastError = error
        } catch {}
    }

    /// Start a refresh. The engine runs in another process, off the main thread.
    public func refresh() {
        guard !isRefreshing else { return }
        isRefreshing = true
        progress = nil
        lastError = nil
        let engine = self.engine
        refreshTask = Task {
            do {
                let newState = try await engine.refresh { step in
                    Task { @MainActor in self.applyProgress(step) }
                }
                state = newState
            } catch is CancellationError {
                // Stop keeps the previous results on screen.
            } catch {
                lastError = (error as? EngineError) ?? .failed(message: "The refresh failed.", detail: "\(error)")
                if let saved = try? await engine.state() { state = saved }
            }
            isRefreshing = false
            progress = nil
            refreshTask = nil
        }
    }

    private func applyProgress(_ step: RefreshProgress) {
        guard isRefreshing else { return }
        progress = step
    }

    /// Stop a running refresh. The previous results stay.
    public func stop() {
        refreshTask?.cancel()
    }

    /// Wait for the running refresh to end. For tests and for quit.
    public func waitForRefresh() async {
        await refreshTask?.value
    }

    /// Turn a project on or off. An inactive project moves to Backlog at once.
    public func setProject(_ project: ProjectRecord, active: Bool) async {
        if let i = projects.firstIndex(where: { $0.path == project.path }) {
            projects[i].state = active ? "active" : "inactive"
        }
        do {
            let saved = try await engine.setProject(path: project.path, active: active)
            if let i = projects.firstIndex(where: { $0.path == project.path }) { projects[i] = saved }
        } catch {
            if let i = projects.firstIndex(where: { $0.path == project.path }) { projects[i] = project }
            lastError = (error as? EngineError) ?? .failed(message: "The project choice was not saved.",
                                                           detail: "\(error)")
        }
    }

    // Derived values

    public var refreshLabel: RefreshLabel {
        RefreshLabel.make(state: state, running: isRefreshing, progress: progress, now: clock())
    }

    public var coverageRows: [CoverageRow] { CoverageRow.rows(state?.coverage ?? []) }

    public var activeProjects: [ProjectRecord] { projects.filter(\.isActive) }
    public var backlogProjects: [ProjectRecord] { projects.filter { !$0.isActive } }

    /// Items for a section, before the search filter. Action first, then by name.
    public func items(in section: SidebarSection) -> [ItemRecord] {
        let all = state?.items ?? []
        let picked: [ItemRecord] = switch section {
        case .apps: all.filter { $0.source == "apps" || $0.source == "macos" }
        case .homebrew: all.filter { $0.source == "homebrew" }
        case .findings: []  // Findings are not items. See `visibleFindings`.
        case .projects, .backlog, .incidents, .updateLog: []
        }
        return picked.sorted {
            ($0.state.rank, $0.name.lowercased(), $0.key) < ($1.state.rank, $1.name.lowercased(), $1.key)
        }
    }

    /// Items after the filter chip and the search text.
    public func visibleItems(in section: SidebarSection) -> [ItemRecord] {
        let query = searchText.trimmingCharacters(in: .whitespaces)
        let list = items(in: section).filter(itemFilter.matches)
        guard !query.isEmpty else { return list }
        return list.filter { $0.name.localizedCaseInsensitiveContains(query) }
    }

    public func visibleProjects(in section: SidebarSection) -> [ProjectRecord] {
        let list = section == .backlog ? backlogProjects : activeProjects
        let query = searchText.trimmingCharacters(in: .whitespaces)
        guard !query.isEmpty else { return list }
        return list.filter { $0.name.localizedCaseInsensitiveContains(query) }
    }

    public func count(_ section: SidebarSection) -> Int {
        switch section {
        case .apps, .homebrew: items(in: section).count
        case .findings: findingsInScope.filter(\.isOpen).count
        case .projects: activeProjects.count
        case .backlog: backlogProjects.count + backlogFindings.count
        case .incidents, .updateLog: 0  // The counts come from IncidentModel and UpdateModel.
        }
    }

    public var hasOpenFindings: Bool { count(.findings) > 0 }

    public var selectedItem: ItemRecord? {
        guard let key = selectedItemKey else { return nil }
        return state?.items.first { $0.key == key }
    }

    // Findings

    /// A finding belongs to a project by the project's display path.
    private var inactivePaths: Set<String> { Set(backlogProjects.map(\.displayPath)) }

    /// Findings that have at least one path in an active project, and findings with no path (resolved).
    /// A finding that is only in inactive projects is part of the Backlog.
    public var findingsInScope: [FindingRecord] {
        let inactive = inactivePaths
        return (state?.findings ?? []).filter { f in
            f.paths.isEmpty || f.paths.contains { !inactive.contains($0.projectPath) }
        }
    }

    /// Findings that the owner moved to the backlog, and findings that are only in inactive projects.
    /// A resolved finding is not part of the Backlog.
    public var backlogFindings: [FindingRecord] {
        let inactive = inactivePaths
        return (state?.findings ?? []).filter { f in
            guard f.status != .resolved else { return false }
            return f.status == .backlog || (!f.paths.isEmpty && f.paths.allSatisfy { inactive.contains($0.projectPath) })
        }
    }

    /// The rows of the Backlog section: projects first (by name), then findings (by id). The search box
    /// matches names, paths, ids, packages and titles.
    public func visibleBacklog() -> [BacklogEntry] {
        let query = searchText.trimmingCharacters(in: .whitespaces)
        let projects = backlogProjects.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
            .map(BacklogEntry.project)
        let findings = backlogFindings.sorted { $0.id < $1.id }.map(BacklogEntry.finding)
        let all = projects + findings
        guard !query.isEmpty else { return all }
        return all.filter { entry in
            [entry.name, entry.secondary].contains { $0.localizedCaseInsensitiveContains(query) }
        }
    }

    /// The findings that pass the filter control and the search box. Malware first, then known
    /// exploited, then worst severity, then newest.
    public var visibleFindings: [FindingRecord] {
        let query = searchText.trimmingCharacters(in: .whitespaces)
        return findingsInScope
            .filter { findingFilter.matches($0) }
            .filter { f in
                query.isEmpty || f.id.localizedCaseInsensitiveContains(query)
                    || f.package.localizedCaseInsensitiveContains(query)
                    || f.title.localizedCaseInsensitiveContains(query)
                    || f.advisoryIds.contains { $0.localizedCaseInsensitiveContains(query) }
            }
            .sorted(by: FindingRecord.listOrder)
    }

    public var selectedFinding: FindingRecord? {
        guard let id = selectedItemKey else { return nil }
        return state?.findings.first { $0.id == id }
    }

    /// Open findings in one project.
    public func findings(in project: ProjectRecord) -> [FindingRecord] {
        findingsInScope.filter { $0.isOpen && $0.paths.contains { $0.projectPath == project.displayPath } }
    }

    /// True if the last OSV scan was not complete. An open finding then stays open and the
    /// detail view says so.
    public func showsPartialBanner(for finding: FindingRecord) -> Bool {
        guard finding.isOpen else { return false }
        return state?.coverage.first { $0.source == finding.source.lowercased() }?.state != .complete
    }

    /// One row for each feed that ran: OSV, CISA KEV and GitHub Advisories.
    public var findingSourceRows: [FindingSourceRow] {
        ["osv", "kev", "github", "epss"].compactMap { source in
            state?.coverage.first { $0.source == source }.map { FindingSourceRow.make($0) }
        }
    }

    /// The EPSS text of one finding, with the `epss` coverage row and the clock of the model.
    public func epssDisplay(for finding: FindingRecord) -> EpssDisplay {
        EpssDisplay.make(finding, coverage: state?.coverage.first { $0.source == "epss" }, now: clock())
    }

    public func deferFinding(_ finding: FindingRecord, days: Int) async {
        await changeFinding("The finding was not deferred.") { try await $0.deferFinding(id: finding.id, days: days) }
    }

    public func moveToBacklog(_ finding: FindingRecord) async {
        await changeFinding("The finding was not moved.") { try await $0.moveFindingToBacklog(id: finding.id) }
    }

    public func reopen(_ finding: FindingRecord) async {
        await changeFinding("The finding was not opened.") { try await $0.reopenFinding(id: finding.id) }
    }

    private func changeFinding(_ message: String, _ act: (any EngineClient) async throws -> FindingRecord) async {
        do {
            let saved = try await act(engine)
            if let i = state?.findings.firstIndex(where: { $0.id == saved.id }) { state?.findings[i] = saved }
        } catch {
            lastError = (error as? EngineError) ?? .failed(message: message, detail: "\(error)")
        }
    }

    /// `Homebrew data: 3 h old`, from the source time of the item.
    public func sourceAgeText(for item: ItemRecord) -> String? {
        guard let at = item.sourceAt ?? item.seenAt else { return nil }
        let label = state?.coverage.first { $0.source == item.source }?.label ?? item.source
        return "\(label) data: \(TimeText.duration(clock().timeIntervalSince(at))) old"
    }
}
