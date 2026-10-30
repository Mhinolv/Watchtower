import Foundation
import Testing
@testable import WatchtowerCore

// #16: runtimes, SDKs and editor extensions. They sit in their own section and never in Projects.

private struct NoEngine: EngineClient {
    func state() async throws -> EngineState { throw CancellationError() }
    func refresh(progress: @escaping @Sendable (RefreshProgress) -> Void) async throws -> EngineState { throw CancellationError() }
    func projects() async throws -> ProjectList { ProjectList(schemaVersion: 1, projects: [], rootErrors: [], skipped: []) }
    func setProject(path: String, active: Bool) async throws -> ProjectRecord { throw CancellationError() }
    func deferFinding(id: String, days: Int) async throws -> FindingRecord { throw CancellationError() }
    func moveFindingToBacklog(id: String) async throws -> FindingRecord { throw CancellationError() }
    func reopenFinding(id: String) async throws -> FindingRecord { throw CancellationError() }
}

private let home = "/Users/me"
private let now = Date(timeIntervalSince1970: 1_793_275_200)

private func install(_ kind: String, _ name: String, _ version: String?, _ source: String, _ path: String, family: String,
                     old: Bool = false, editor: String? = nil) -> ItemRecord {
    var attributes = ["path": home + "/" + path, "family": family, "copies": "1"]
    if old { attributes["oldCopy"] = "true" }
    if let editor { attributes["editor"] = editor }
    return ItemRecord(id: "\(kind):\(source):~/\(path)", source: "runtimes", name: name,
                      state: version == nil || old ? .unknown : .manual, kind: kind, installedVersion: version, origin: source,
                      note: version == nil ? "Version not found in package.json." : (old ? "Old copy" : nil), attributes: attributes)
}

private let items = [
    install("runtime", "Node.js", "22.9.0", "nvm", ".nvm/versions/node/v22.9.0", family: "nodejs"),
    install("runtime", "Node.js", "20.17.0", "nvm", ".nvm/versions/node/v20.17.0", family: "nodejs", old: true),
    install("sdk", "macOS SDK", "15.5", "Xcode", "sdk/15.5", family: "macosx:Xcode"),
    install("extension", "ms-python.python", "2026.8.0", "VS Code", ".vscode/extensions/a", family: "ms-python.python:VS Code",
            editor: "VS Code"),
    install("extension", "acme.tool", nil, "Cursor", ".cursor/extensions/b", family: "acme.tool:Cursor", editor: "Cursor"),
    ItemRecord(id: "formula:git", source: "homebrew", name: "git", state: .upToDate, kind: "formula", installedVersion: "2.47.1"),
]

@MainActor
private func model(coverage: [CoverageRecord] = [], search: String = "") -> DashboardModel {
    let state = EngineState(schemaVersion: 1, refresh: RefreshRecord(id: 1, status: .complete, startedAt: now, finishedAt: now,
                                                                     lastCompleteAt: now),
                            coverage: coverage, items: items)
    let m = DashboardModel(engine: NoEngine(), state: state, clock: { now })
    m.searchText = search
    return m
}

@Test func runtimesSitAfterUpdateLogWithCommandEightAndOtherShortcutsStay() {
    let all = SidebarSection.allCases
    #expect(all.last == .runtimes && SidebarSection.runtimes.title == "Runtimes")
    #expect(SidebarSection.runtimes.shortcutDigit == "8" && all.map(\.shortcutDigit).prefix(7) == ["1", "2", "3", "4", "5", "6", "7"])
    #expect(SidebarGroup.history.sections == [.updateLog, .runtimes])
}

@MainActor
@Test func theGroupsKeepTheEngineOrderAndOtherSourcesAreLeftOut() {
    let sections = model().runtimeSections
    #expect(sections.map(\.group) == [.runtime, .sdk, .extension])
    #expect(sections.map(\.group.title) == ["Runtimes", "SDKs", "Editor extensions"])
    #expect(sections[0].rows.map(\.version) == ["22.9.0", "20.17.0"])
    #expect(model().count(.runtimes) == 5)  // The Homebrew item is not counted.
    #expect(model().items(in: .apps).isEmpty && model().items(in: .homebrew).count == 1)
}

@MainActor
@Test func rowsShowTheOldCopyTheEditorAndTheUnknownBadge() {
    let rows = model().runtimeSections.flatMap(\.rows)
    let node = rows.filter { $0.name == "Node.js" }
    #expect(node[0].badge == nil && node[0].secondary == nil && node[0].isOld == false)
    #expect(node[1].badge == .unknown && node[1].secondary == "Old copy" && node[1].isOld)
    let python = rows.first { $0.name == "ms-python.python" }!
    #expect(python.secondary == "VS Code" && python.source == "VS Code")
    let unreadable = rows.first { $0.name == "acme.tool" }!
    #expect(unreadable.version == "—" && unreadable.badge == .unknown && unreadable.note == "Version not found in package.json.")
}

@MainActor
@Test func rootErrorsShowAboveTheirGroupAndTheOtherGroupsStay() {
    let coverage = [CoverageRecord(source: "runtimes", label: "Runtimes", state: .partial,
                                   detail: "Runtimes: Cannot read ~/.nvm: permission denied.\nSDKs: Cannot read ~/Library/x: read error.\nRuntimes: Rust ~/a: Version not found in b.")]
    let sections = model(coverage: coverage).runtimeSections
    #expect(sections[0].rootErrors == ["Cannot read ~/.nvm: permission denied."])
    #expect(sections[1].rootErrors == ["Cannot read ~/Library/x: read error."])
    #expect(sections[2].rootErrors.isEmpty && !sections[2].rows.isEmpty)
}

@MainActor
@Test func aGroupWithOnlyAnErrorStillShows() {
    var state = model().state!
    state.items = []
    state.coverage = [CoverageRecord(source: "runtimes", label: "Runtimes", state: .failed,
                                     detail: "Runtimes: Cannot read ~/.pyenv: permission denied.")]
    let m = DashboardModel(engine: NoEngine(), state: state, clock: { now })
    #expect(m.runtimeSections.map(\.group) == [.runtime] && m.runtimeSections[0].rows.isEmpty)
}

@MainActor
@Test func searchMatchesNameVersionPathAndSource() {
    #expect(model(search: "nvm").runtimeSections.flatMap(\.rows).count == 2)
    #expect(model(search: "2026.8").runtimeSections.flatMap(\.rows).map(\.name) == ["ms-python.python"])
    #expect(model(search: "zzz").runtimeSections.isEmpty)
}

@MainActor
@Test func copiesOfTheSameThingAreListedForTheDetailPane() {
    let m = model()
    let first = items[0]
    #expect(m.runtimeCopies(of: first).map(\.installedVersion) == ["22.9.0", "20.17.0"])
    #expect(first.copiesText(3) == "3 versions installed" && first.copiesText(1) == nil)
    #expect(m.runtimeCopies(of: items[2]).count == 1)
}

@MainActor
@Test func runtimesAreNeverProjects() {
    let m = model()
    #expect(m.activeProjects.isEmpty && m.backlogProjects.isEmpty)
    #expect(!SidebarSection.runtimes.listsItems)
}

@Test func theEngineJsonDecodesARuntimeItem() throws {
    let json = """
    {"id":"runtime:nvm:~/.nvm/versions/node/v22.9.0","source":"runtimes","name":"Node.js","state":"manual","kind":"runtime",
     "installed_version":"22.9.0","origin":"nvm","note":"Watchtower does not check updates for this install yet.",
     "attributes":{"product":"nodejs","eolProduct":"nodejs","path":"/Users/me/.nvm/versions/node/v22.9.0","family":"nodejs",
                   "group":"Runtimes","copies":"3"}}
    """
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    let item = try decoder.decode(ItemRecord.self, from: Data(json.utf8))
    #expect(item.installedVersion == "22.9.0" && item.attributes?["product"] == "nodejs" && item.attributes?["eolProduct"] == "nodejs")
    #expect(RuntimeRow(item, home: "/Users/me").path == "~/.nvm/versions/node/v22.9.0")
}
