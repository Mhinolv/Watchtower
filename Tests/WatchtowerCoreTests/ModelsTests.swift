import Foundation
import Testing
@testable import WatchtowerCore

// The fixtures come from the engine (engine/tests/contract.py). The engine tests check
// that the engine still prints them, so these tests check the real contract.

private func fixture(_ name: String) throws -> Data {
    let url = try #require(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures"))
    return try Data(contentsOf: url)
}

private func utc(_ text: String) -> Date {
    ISO8601DateFormatter().date(from: text)!
}

@Test func decodesPartialStateFixture() throws {
    let state = try EngineJSON.decode(EngineState.self, from: fixture("state-partial"))
    #expect(state.schemaVersion == 1)

    let refresh = try #require(state.refresh)
    #expect(refresh.id == 2)
    #expect(refresh.status == .partial)
    #expect(refresh.startedAt == utc("2026-10-29T08:30:00Z"))
    #expect(refresh.finishedAt == utc("2026-10-29T08:31:45Z"))
    #expect(refresh.lastCompleteAt == utc("2026-10-28T09:02:10Z"))
    #expect(refresh.error == "Some sources did not finish.")
    #expect(refresh.detail == "apps: scan stopped early")

    let apps = try #require(state.coverage.first { $0.source == "apps" })
    #expect(apps.label == "Applications")
    #expect(apps.state == .failed)
    #expect(apps.lastSuccessAt == utc("2026-10-28T09:02:10Z"))
    #expect(apps.error == "App folder scan stopped early.")
    #expect(apps.detail?.contains("PermissionError") == true)
    #expect(apps.id == "apps")

    let git = try #require(state.items.first { $0.key == "homebrew/formula:git" })
    #expect(git.name == "git")
    #expect(git.state == .updateAvailable)
    #expect(git.kind == "formula")
    #expect(git.installedVersion == "2.46.0")
    #expect(git.latestVersion == "2.47.1")
    #expect(git.project == nil)
    #expect(git.seenAt == utc("2026-10-29T08:31:45Z"))

    let leftPad = try #require(state.items.first { $0.id == "npm:left-pad" })
    #expect(leftPad.project == "watchtower")
    #expect(leftPad.sourceAt == nil)
}

@Test func decodesItemOriginSourceAgeAndNote() throws {
    let state = try EngineJSON.decode(EngineState.self, from: fixture("state-partial"))
    let git = try #require(state.items.first { $0.key == "homebrew/formula:git" })
    #expect(git.sourceAt == utc("2026-10-29T08:30:40Z"))
    #expect(git.origin == nil)
    #expect(git.note == nil)

    let node = try #require(state.items.first { $0.key == "homebrew/formula:node" })
    #expect(node.state == .pinned)
    #expect(node.note == "Pinned with brew pin. Watchtower does not update pinned items.")

    let widget = try #require(state.items.first { $0.key == "homebrew/formula:acme/tools/widget" })
    #expect(widget.state == .manual)
    #expect(widget.origin == "acme/tools")
    #expect(widget.latestVersion == nil)
    #expect(widget.note == "Watchtower cannot check tap acme/tools.")
}

@Test func partialFixtureUsesEveryCoverageAndItemState() throws {
    let state = try EngineJSON.decode(EngineState.self, from: fixture("state-partial"))
    #expect(Set(state.coverage.map(\.state)) == Set(CoverageState.allCases))
    #expect(Set(state.items.map(\.state)) == Set(ItemState.allCases))
    #expect(Set(state.items.map(\.key)).count == state.items.count)
}

@Test func decodesEmptyStateFixture() throws {
    let state = try EngineJSON.decode(EngineState.self, from: fixture("state-empty"))
    #expect(state.refresh == nil)
    #expect(state.coverage.isEmpty)
    #expect(state.items.isEmpty)
}

@Test func decodesVersionFixture() throws {
    let version = try EngineJSON.decode(EngineVersion.self, from: fixture("version"))
    #expect(version.schemaVersion == EngineSchema.version)
    #expect(!version.engine.isEmpty)
}

@Test func decodesErrorFixture() throws {
    let report = try EngineJSON.decode(EngineErrorReport.self, from: fixture("error"))
    #expect(report.error == "A newer Watchtower wrote this data.")
    #expect(report.detail == "Store schema 99 is newer than engine schema 1.")
}

@Test func rawValuesMatchEngineNames() {
    #expect(RefreshStatus.allCases.map(\.rawValue) == ["running", "complete", "partial", "failed", "cancelled"])
    #expect(CoverageState.allCases.map(\.rawValue) == ["complete", "partial", "failed", "stale", "not_run"])
    #expect(ItemState.allCases.map(\.rawValue) == [
        "up_to_date", "update_available", "vulnerable", "unknown", "error", "pinned", "manual",
    ])
}

@Test func refusesNewerSchema() throws {
    let json = Data(#"{"schema_version": 2, "refresh": null, "coverage": [], "items": []}"#.utf8)
    #expect(throws: EngineContractError.unsupportedSchema(2)) {
        try EngineJSON.decode(EngineState.self, from: json)
    }
}

@Test func refusesUnknownStateValue() {
    let json = Data(#"""
    {"schema_version": 1, "refresh": {"id": 1, "status": "done", "started_at": "2026-10-29T08:30:00Z"},
     "coverage": [], "items": []}
    """#.utf8)
    #expect(throws: DecodingError.self) {
        try EngineJSON.decode(EngineState.self, from: json)
    }
}

@Test func missingOptionalFieldsDecodeAsNil() throws {
    let json = Data(#"""
    {"schema_version": 1, "refresh": {"id": 1, "status": "running", "started_at": "2026-10-29T08:30:00Z"},
     "coverage": [{"source": "osv", "label": "OSV", "state": "not_run"}],
     "items": [{"id": "a", "source": "apps", "name": "A", "state": "unknown"}]}
    """#.utf8)
    let state = try EngineJSON.decode(EngineState.self, from: json)
    #expect(state.refresh?.finishedAt == nil)
    #expect(state.refresh?.lastCompleteAt == nil)
    #expect(state.coverage.first?.lastSuccessAt == nil)
    #expect(state.items.first?.installedVersion == nil)
}

@Test func decodesItemAttributes() throws {
    let state = try EngineJSON.decode(EngineState.self, from: fixture("state-partial"))
    let slack = try #require(state.items.first { $0.key == "apps/com.tinyspeck.slackmacgap" })
    #expect(slack.attributes?["bundleId"] == "com.tinyspeck.slackmacgap")
    #expect(slack.attributes?["electron"] == "30.1.2")
    #expect(slack.attributes?["node"] == "20")

    let legacy = try #require(state.items.first { $0.key == "apps/com.example.legacy" })
    #expect(legacy.origin == "Manual")
    #expect(legacy.attributes?["path"] == "/Applications/Legacy Tool.app")

    let git = try #require(state.items.first { $0.key == "homebrew/formula:git" })
    #expect(git.attributes == nil)
}
