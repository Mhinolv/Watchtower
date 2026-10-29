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
    #expect(apps.sourceAt == nil)

    let homebrew = try #require(state.coverage.first { $0.source == "homebrew" })
    #expect(homebrew.sourceAt == utc("2026-10-29T08:30:40Z"))

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

@Test func decodesFindingsFromTheEngineFixture() throws {
    let state = try EngineJSON.decode(EngineState.self, from: fixture("state-partial"))
    #expect(state.findings.map(\.id).sorted() == ["SEC-0001", "SEC-0002", "SEC-0003"])

    let lodash = try #require(state.findings.first { $0.id == "SEC-0001" })
    #expect(lodash.package == "lodash")
    #expect(lodash.severity == .high)
    #expect(lodash.status == .open)
    #expect(lodash.fixedIn == "4.17.21")
    #expect(lodash.advisoryIds == ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"])
    #expect(lodash.paths.count == 2)
    #expect(lodash.projectNames == ["admin", "web"])
    let web = try #require(lodash.paths.first { $0.project == "web" })
    #expect(web.dependencyPath == ["web", "lodash"])
    #expect(web.lockfile == "package-lock.json" && web.version == "4.17.20")
    let admin = try #require(lodash.paths.first { $0.project == "admin" })
    #expect(admin.dependencyPath == nil)
    #expect(lodash.firstSeen == utc("2026-10-28T09:02:10Z"))
    #expect(lodash.sourceAt == utc("2026-10-28T06:00:00Z"))
    #expect(lodash.nextSteps.count == 2)

    let deferred = try #require(state.findings.first { $0.id == "SEC-0002" })
    #expect(deferred.status == .deferred)
    #expect(deferred.deferredUntil == utc("2099-01-01T00:00:00Z"))
    #expect(deferred.fixedIn == nil)

    let resolved = try #require(state.findings.first { $0.id == "SEC-0003" })
    #expect(resolved.status == .resolved && resolved.severity == .critical)
    #expect(resolved.resolvedScanAt == utc("2026-10-28T09:02:10Z"))
    #expect(resolved.paths.isEmpty)
}

@Test func stateWithoutFindingsKeyDecodesAsEmpty() throws {
    let json = #"{"schema_version": 1, "refresh": null, "coverage": [], "items": []}"#
    let state = try EngineJSON.decode(EngineState.self, from: Data(json.utf8))
    #expect(state.findings.isEmpty)
    let empty = try EngineJSON.decode(EngineState.self, from: fixture("state-empty"))
    #expect(empty.findings.isEmpty)
}

@Test func refusesAnUnknownFindingSeverity() throws {
    let json = #"""
    {"schema_version": 1, "refresh": null, "coverage": [], "items": [], "findings": [
     {"id": "SEC-0001", "ecosystem": "npm", "package": "x", "title": "t", "severity": "catastrophic",
      "advisory_ids": [], "fixed_in": null, "status": "open", "deferred_until": null,
      "first_seen": "2026-10-28T09:02:10Z", "last_seen": "2026-10-28T09:02:10Z", "resolved_at": null,
      "resolved_scan_at": null, "source": "OSV", "source_at": null, "paths": [], "next_steps": []}]}
    """#
    #expect(throws: DecodingError.self) { try EngineJSON.decode(EngineState.self, from: Data(json.utf8)) }
}

@Test func decodesKevMalwareAndWithdrawnMarksAndFeedCoverageNotes() throws {
    let state = try EngineJSON.decode(EngineState.self, from: fixture("state-partial"))
    let lodash = try #require(state.findings.first { $0.id == "SEC-0001" })
    #expect(lodash.kev == KevMark(cve: "CVE-2021-23337", dateAdded: "2026-10-22", dueDate: "2026-11-12"))
    #expect(lodash.malware == nil && lodash.withdrawnAt == nil)
    let withdrawn = try #require(state.findings.first { $0.id == "SEC-0002" })
    #expect(withdrawn.withdrawnAt == utc("2026-10-28T08:00:00Z") && withdrawn.kev == nil)
    let malware = try #require(state.findings.first { $0.id == "SEC-0003" })
    #expect(malware.malware == MalwareMark(advisoryId: "GHSA-mal1-ware-0001"))

    let kev = try #require(state.coverage.first { $0.source == "kev" })
    #expect((kev.label, kev.state, kev.note) == ("CISA KEV", .complete, "official mirror"))
    let github = try #require(state.coverage.first { $0.source == "github" })
    #expect((github.state, github.note, github.sourceAt) == (.failed, "rate limit", utc("2026-10-28T08:30:20Z")))
    #expect(try #require(state.coverage.first { $0.source == "homebrew" }).note == nil)
}

@Test func findingWithoutFeedMarksDecodesWithNone() throws {
    let json = #"""
    {"schema_version": 1, "refresh": null, "coverage": [], "items": [], "findings": [
     {"id": "SEC-0001", "ecosystem": "npm", "package": "x", "title": "t", "severity": "low",
      "advisory_ids": [], "fixed_in": null, "status": "open", "deferred_until": null,
      "first_seen": "2026-10-28T09:02:10Z", "last_seen": "2026-10-28T09:02:10Z", "resolved_at": null,
      "resolved_scan_at": null, "source": "OSV", "source_at": null, "paths": [], "next_steps": []}]}
    """#
    let finding = try #require(EngineJSON.decode(EngineState.self, from: Data(json.utf8)).findings.first)
    #expect(finding.kev == nil && finding.malware == nil && finding.withdrawnAt == nil)
}
