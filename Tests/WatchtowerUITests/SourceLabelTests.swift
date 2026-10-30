import Foundation
import Testing
@testable import WatchtowerCore
@testable import WatchtowerUI

// Bug #33: the macOS row showed Source "Os" (later "System"). Each kind maps to a fixed label.

@MainActor
private func table(items: [ItemRecord]) -> ItemTable {
    let state = EngineState(schemaVersion: 1, refresh: nil,
                            coverage: [CoverageRecord(source: "apps", label: "Applications", state: .complete),
                                       CoverageRecord(source: "homebrew", label: "Homebrew", state: .complete)],
                            items: items)
    return ItemTable(model: DashboardModel(engine: PreviewEngine(), state: state), section: .apps)
}

@MainActor
@Test func sourceLabelUsesFixedTextForEachKind() {
    let t = table(items: [])
    func label(_ kind: String?, source: String = "apps", origin: String? = nil, project: String? = nil) -> String {
        t.sourceText(ItemRecord(id: "x", source: source, name: "X", state: .upToDate, kind: kind,
                                project: project, origin: origin))
    }
    #expect(label("os", source: "macos") == "macOS")
    #expect(label("app") == "App")
    #expect(label("formula", source: "homebrew") == "Formula")
    #expect(label("cask", source: "homebrew") == "Cask")
    #expect(label("cask", source: "homebrew", origin: "acme/casks") == "Cask · acme/casks")
    #expect(label("formula", source: "homebrew", origin: "acme/tools") == "Formula · acme/tools")
}

@MainActor
@Test func unknownKindUsesTheEngineSourceLabelUnchanged() {
    let t = table(items: [])
    #expect(t.sourceText(ItemRecord(id: "x", source: "apps", name: "X", state: .upToDate, kind: "widget"))
        == "Applications")
    #expect(t.sourceText(ItemRecord(id: "x", source: "apps", name: "X", state: .upToDate)) == "Applications")
    // No coverage row for the source: the raw source id, never title-cased.
    #expect(t.sourceText(ItemRecord(id: "x", source: "osv", name: "X", state: .upToDate, kind: "npm")) == "osv")
}
