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
    case apps, homebrew, projects, findings, backlog, updateLog

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .apps: "Apps"
        case .homebrew: "Homebrew"
        case .projects: "Projects"
        case .findings: "Findings"
        case .backlog: "Backlog"
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
        case .updateLog: "list.bullet.rectangle"
        }
    }

    /// ⌘1 to ⌘5, and ⌘7 for Update Log (Design notes of #5 and #6).
    public var shortcutDigit: Character {
        switch self {
        case .apps: "1"
        case .homebrew: "2"
        case .projects: "3"
        case .findings: "4"
        case .backlog: "5"
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
            return CoverageRow(id: c.source, label: c.label, stateText: text, tone: tone, lastSuccess: last,
                               error: c.error)
        }
    }
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

    private var inactiveNames: Set<String> { Set(backlogProjects.map(\.name)) }

    /// Items for a section, before the search filter. Action first, then by name.
    public func items(in section: SidebarSection) -> [ItemRecord] {
        let all = state?.items ?? []
        let inactive = inactiveNames
        let picked: [ItemRecord] = switch section {
        case .apps: all.filter { $0.source == "apps" || $0.source == "macos" }
        case .homebrew: all.filter { $0.source == "homebrew" }
        case .findings: all.filter { $0.state == .vulnerable && !inactive.contains($0.project ?? "") }
        case .projects, .backlog, .updateLog: []
        }
        return picked.sorted {
            ($0.state.rank, $0.name.lowercased(), $0.key) < ($1.state.rank, $1.name.lowercased(), $1.key)
        }
    }

    public func visibleItems(in section: SidebarSection) -> [ItemRecord] {
        let query = searchText.trimmingCharacters(in: .whitespaces)
        let list = items(in: section)
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
        case .apps, .homebrew, .findings: items(in: section).count
        case .projects: activeProjects.count
        case .backlog: backlogProjects.count
        case .updateLog: 0  // The update log count comes from UpdateModel.
        }
    }

    public var hasOpenFindings: Bool { count(.findings) > 0 }

    public var selectedItem: ItemRecord? {
        guard let key = selectedItemKey else { return nil }
        return state?.items.first { $0.key == key }
    }

    /// Findings in one project.
    public func findings(in project: ProjectRecord) -> [ItemRecord] {
        (state?.items ?? []).filter { $0.state == .vulnerable && $0.project == project.name }
    }

    /// `Homebrew data: 3 h old`, from the source time of the item.
    public func sourceAgeText(for item: ItemRecord) -> String? {
        guard let at = item.sourceAt ?? item.seenAt else { return nil }
        let label = state?.coverage.first { $0.source == item.source }?.label ?? item.source
        return "\(label) data: \(TimeText.duration(clock().timeIntervalSince(at))) old"
    }
}
