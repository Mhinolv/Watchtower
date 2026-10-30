import Foundation
import Testing
@testable import WatchtowerCore

private let now = Date(timeIntervalSince1970: 1_793_275_200)
private func hours(_ h: Double) -> Date { now.addingTimeInterval(-h * 3600) }

private struct NoEngine: EngineClient {
    func state() async throws -> EngineState { throw CancellationError() }
    func refresh(progress: @escaping @Sendable (RefreshProgress) -> Void) async throws -> EngineState {
        throw CancellationError()
    }
    func projects() async throws -> ProjectList { ProjectList(schemaVersion: 1, projects: [], rootErrors: [], skipped: []) }
    func setProject(path: String, active: Bool) async throws -> ProjectRecord { throw CancellationError() }
    func deferFinding(id: String, days: Int) async throws -> FindingRecord { throw CancellationError() }
    func moveFindingToBacklog(id: String) async throws -> FindingRecord { throw CancellationError() }
    func reopenFinding(id: String) async throws -> FindingRecord { throw CancellationError() }
}

private func item(_ id: String, _ name: String, _ state: ItemState, source: String = "apps") -> ItemRecord {
    ItemRecord(id: id, source: source, name: name, state: state, installedVersion: "1.0")
}

private let web = ProjectRecord(name: "web", path: NSHomeDirectory() + "/Projects/web", root: "~/Projects",
                                manifests: ["package-lock.json"], state: "active")

private func finding(_ id: String, _ package: String, status: FindingStatus = .open) -> FindingRecord {
    FindingRecord(id: id, package: package, title: "x", severity: .high, advisoryIds: ["GHSA-1"], status: status,
                  firstSeen: hours(48), lastSeen: hours(2),
                  paths: [FindingPath(project: "web", projectPath: "~/Projects/web", lockfile: "package-lock.json",
                                      version: "4.17.20")])
}

@MainActor
private func model(_ status: RefreshStatus? = .complete, finished: Double = 2, items: [ItemRecord] = [],
                   findings: [FindingRecord] = []) -> DashboardModel {
    let state = status.map {
        EngineState(schemaVersion: 1,
                    refresh: RefreshRecord(id: 1, status: $0, startedAt: hours(finished + 0.1), finishedAt: hours(finished),
                                           lastCompleteAt: $0 == .complete ? hours(finished) : hours(30)),
                    coverage: [CoverageRecord(source: "apps", label: "Applications", state: .complete)],
                    items: items, findings: findings)
    }
    return DashboardModel(engine: NoEngine(), state: state, projects: [web], clock: { now })
}

// MARK: - Tokens (design/system.md)

@Test func tokensMatchSystemMd() {
    #expect(DesignTokens.accent == ColorPair(light: 0x5B4FD9, dark: 0x8E86FF))
    #expect(DesignTokens.green == ColorPair(light: 0x1F7A3A, dark: 0x5FDC7D))
    #expect(DesignTokens.blue == ColorPair(light: 0x0B5FD6, dark: 0x6CB0FF))
    #expect(DesignTokens.red == ColorPair(light: 0xC4271D, dark: 0xFF7A70))
    #expect(DesignTokens.orange == ColorPair(light: 0x9A5200, dark: 0xFFB340))
    #expect(DesignTokens.gray == ColorPair(light: 0x5C5C63, dark: 0xA8A8AE))
    #expect((0.12...0.20).contains(DesignTokens.badgeFill))
    #expect(DesignTokens.badgeHeight == 21 && DesignTokens.badgeFontSize == 11.5)
    #expect(DesignTokens.tableRowHeight == 36 && DesignTokens.rowIconSize == 22 && DesignTokens.rowIconRadius == 5)
    #expect(DesignTokens.popoverWidth == 330)
}

@Test func badgeTonesUseSystemColors() {
    #expect(DesignTokens.pair(StatusStyle(.upToDate).tone) == DesignTokens.green)
    #expect(DesignTokens.pair(StatusStyle(.updateAvailable).tone) == DesignTokens.blue)
    #expect(DesignTokens.pair(StatusStyle(.vulnerable).tone) == DesignTokens.red)
    #expect(DesignTokens.pair(StatusStyle(.error).tone) == DesignTokens.orange)
    for state in [ItemState.unknown, .pinned, .manual] {
        #expect(DesignTokens.pair(StatusStyle(state).tone) == DesignTokens.gray)
    }
}

// MARK: - Sidebar

@Test func sidebarGroupsFollowTheMockup() {
    #expect(SidebarGroup.allCases.map(\.title) == ["Inventory", "Review", "History"])
    #expect(SidebarGroup.allCases.flatMap(\.sections) == SidebarSection.allCases)
    #expect(SidebarGroup.inventory.sections == [.apps, .homebrew, .projects])
    #expect(SidebarGroup.review.sections == [.findings, .backlog, .incidents])
}

// MARK: - Filter chips

@MainActor
@Test func chipsShowCountsAndHideZero() {
    let m = model(items: [item("a", "A", .vulnerable), item("b", "B", .updateAvailable), item("c", "C", .updateAvailable),
                          item("d", "D", .upToDate)])
    let chips = m.filterChips(in: .apps)
    #expect(chips.map(\.filter) == [.all, .vulnerable, .updateAvailable])  // no Error chip: 0 errors
    #expect(chips.map(\.count) == [4, 1, 2])
    #expect(chips.first?.selected == true)
    let none = model(items: [item("d", "D", .upToDate)]).filterChips(in: .apps)
    #expect(none.map(\.filter) == [.all])  // All always shows
}

@MainActor
@Test func chipsAndSearchFilterTogether() {
    let m = model(items: [item("a", "Alpha", .updateAvailable), item("b", "Beta", .updateAvailable),
                          item("c", "Alpine", .upToDate)])
    m.toggleFilter(.updateAvailable)
    #expect(m.itemFilter == .updateAvailable)
    #expect(m.visibleItems(in: .apps).map(\.name) == ["Alpha", "Beta"])
    m.searchText = "al"
    #expect(m.visibleItems(in: .apps).map(\.name) == ["Alpha"])
    m.toggleFilter(.updateAvailable)  // a second click returns to All
    #expect(m.itemFilter == .all)
    #expect(m.visibleItems(in: .apps).map(\.name) == ["Alpha", "Alpine"])
    m.toggleFilter(.error)
    #expect(m.visibleItems(in: .apps).isEmpty)
}

// MARK: - Refresh label symbol

@Test func refreshLabelSymbolsForStalePartialFailed() {
    #expect(RefreshLabel(text: "Stale: x", tone: .orange).symbol == "exclamationmark.triangle")
    #expect(RefreshLabel(text: "Refresh failed.", tone: .red).symbol == "xmark.octagon")
    #expect(RefreshLabel(text: "Last refresh: 2 h ago", tone: .secondary).symbol == nil)
    #expect(RefreshLabel(text: "Refreshing…", tone: .secondary, showsProgress: true).symbol == nil)
}

// MARK: - Menu bar popover

@MainActor
@Test func popoverNeverRefreshed() {
    let s = model(nil).menuBarSummary
    #expect(s.mode == .never && !s.alertIcon)
}

@MainActor
@Test func popoverAllClearNeedsACompleteRecentScan() {
    let clear = model(items: [item("a", "A", .upToDate), item("b", "B", .pinned)]).menuBarSummary
    #expect(clear.mode == .allClear && (clear.vulnerable, clear.updates, clear.errors) == (0, 0, 0))
    // An old scan is never shown as fresh: tiles instead of "all clear".
    #expect(model(finished: 30, items: [item("a", "A", .upToDate)]).menuBarSummary.mode == .attention)
    #expect(model(.partial, finished: 1).menuBarSummary.mode == .attention)
}

@MainActor
@Test func popoverRowsVulnerableFirstAtMostThree() {
    let m = model(items: [item("u1", "Chrome", .updateAvailable), item("e1", "Obsidian", .error),
                          item("u2", "Docker", .updateAvailable), item("v1", "Quillnote", .vulnerable),
                          item("g", "git", .updateAvailable, source: "homebrew")],
                  findings: [finding("SEC-0001", "lodash"), finding("SEC-0002", "minimist", status: .deferred)])
    let s = m.menuBarSummary
    #expect(s.mode == .attention)
    #expect((s.vulnerable, s.updates, s.errors) == (2, 3, 1))
    #expect(s.rows.map(\.name) == ["lodash", "Quillnote", "Chrome"])
    #expect(s.rows.map(\.state) == [.vulnerable, .vulnerable, .updateAvailable])
    #expect(s.alertIcon)
}

@MainActor
@Test func popoverRowOpensTheItemInTheWindow() {
    let m = model(items: [item("g", "git", .updateAvailable, source: "homebrew")], findings: [finding("SEC-0001", "lodash")])
    m.itemFilter = .error
    m.searchText = "zzz"
    let rows = m.menuBarSummary.rows
    m.reveal(rows[1])
    #expect(m.selection == .homebrew && m.selectedItemKey == "homebrew/g" && m.itemFilter == .all && m.searchText.isEmpty)
    m.reveal(rows[0])
    #expect(m.selection == .findings && m.selectedItemKey == "SEC-0001")
}

@MainActor
@Test func noVulnerableItemMeansTheNormalIcon() {
    #expect(!model(items: [item("u", "U", .updateAvailable)]).menuBarSummary.alertIcon)
}

// MARK: - Update dialog result texts (update-dialog.html)

@Test func resultSecondLines() {
    func attempt(_ status: UpdateStatus, after: String?) -> UpdateAttempt {
        UpdateAttempt(id: 1, itemKey: "homebrew/formula:git", name: "git", kind: "formula", command: ["brew"],
                      beforeVersion: "2.46.0", targetVersion: "2.47.1", afterVersion: after, status: status,
                      exitCode: status == .failed ? 1 : 0, output: "", error: nil, startedAt: now)
    }
    #expect(UpdateResultStyle(attempt(.verified, after: "2.47.1")).detail
        == "Watchtower read the version again after the command.")
    #expect(UpdateResultStyle(attempt(.notVerified, after: "2.46.0")).detail
        == "Watchtower does not count this update as done.")
    #expect(UpdateResultStyle(attempt(.failed, after: "2.46.0")).detail == "Watchtower did not confirm any change.")
    #expect(UpdateResultStyle(attempt(.planChanged, after: nil)).detail == nil)
}
