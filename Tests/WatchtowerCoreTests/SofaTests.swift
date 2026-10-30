import Foundation
import Testing
@testable import WatchtowerCore

private let utc = TimeText(timeZone: TimeZone(identifier: "UTC")!)

/// The macOS item as `sofa.apply` writes it. Attribute keys are camelCase, as in `apps.py`.
private func engineItem(error: String? = nil) throws -> ItemRecord {
    let error = error.map { "\"\($0)\"" } ?? "null"
    let json = """
    {"id": "macos", "source": "macos", "name": "macOS", "state": "vulnerable", "kind": "os",
     "installed_version": "15.7.9", "latest_version": "15.8.2", "origin": "SOFA", "error": \(error),
     "note": "15.8.2 fixes 1 actively exploited CVE.",
     "attributes": {"build": "24G830", "sofaLatest": "15.8.2 (24H232)", "sofaReleased": "2026-10-26",
     "sofaFixedCves": "CVE-2026-86950, CVE-2026-112410", "sofaExploited": "CVE-2026-86950",
     "sofaChecked": "2026-10-28T08:00:00Z"}}
    """
    return try EngineJSON.makeDecoder().decode(ItemRecord.self, from: Data(json.utf8))
}

@Test func securityReleasesShowLatestCvesAndData() throws {
    let detail = try #require(SofaDetail(try engineItem(), time: utc))
    #expect(detail.latest == "15.8.2 (24H232), released Oct 26")
    #expect(detail.fixedCves == ["CVE-2026-86950", "CVE-2026-112410"])
    #expect(detail.exploited == ["CVE-2026-86950"])
    #expect(detail.data == "SOFA, retrieved Oct 28, 08:00")
    #expect(detail.failure == nil)
    #expect(SofaDetail.primarySource.absoluteString == "https://support.apple.com/en-us/100100")
}

@Test func anExploitedCveAddsTheKnownExploitedBadge() throws {
    let badge = try #require(SofaDetail(try engineItem(), time: utc)?.badge)
    #expect(badge.text == "Known exploited" && badge.symbol == "flame.fill")
    #expect(badge.help == "Apple lists 1 actively exploited CVE that a newer release fixes.")
}

@Test func noBadgeWithoutAnExploitedCve() {
    let item = ItemRecord(id: "macos", source: "macos", name: "macOS", state: .upToDate,
                          attributes: ["sofaLatest": "15.8.2 (24H232)"])
    #expect(SofaDetail(item, time: utc)?.badge == nil)
    #expect(SofaDetail(item, time: utc)?.fixedCves == [])
}

@Test func sofaFailedFeedNamesTheDateOfTheKeptData() throws {
    let detail = try #require(SofaDetail(try engineItem(error: "SOFA feed did not load."), time: utc))
    #expect(detail.failure == "SOFA feed did not load. Data from Oct 28.")
    #expect(detail.latest == "15.8.2 (24H232), released Oct 26")
}

@Test func sofaFailedFeedWithoutEarlierDataSaysOnlyThatItFailed() {
    let item = ItemRecord(id: "macos", source: "macos", name: "macOS", state: .manual,
                          error: "SOFA feed did not load.", attributes: ["build": "24G830"])
    let detail = SofaDetail(item, time: utc)
    #expect(detail?.failure == "SOFA feed did not load.")
    #expect(detail?.latest == nil)
}

@Test func otherItemsHaveNoSecurityReleasesSection() {
    let item = ItemRecord(id: "formula:git", source: "homebrew", name: "git", state: .updateAvailable)
    #expect(SofaDetail(item) == nil)
}

@Test func sofaKeysLeaveTheGenericRows() throws {
    #expect(SofaDetail.otherAttributes(try engineItem()).map(\.key) == ["build"])
}

@Test func macosAndSafariUseSoftwareUpdate() {
    let mac = ItemRecord(id: "macos", source: "macos", name: "macOS", state: .manual)
    let safari = ItemRecord(id: "com.apple.Safari", source: "apps", name: "Safari", state: .manual,
                            attributes: ["bundleId": "com.apple.Safari"])
    let slack = ItemRecord(id: "com.tinyspeck.slackmacgap", source: "apps", name: "Slack", state: .manual,
                           attributes: ["bundleId": "com.tinyspeck.slackmacgap"])
    #expect(SofaDetail.usesSoftwareUpdate(mac) && SofaDetail.usesSoftwareUpdate(safari))
    #expect(!SofaDetail.usesSoftwareUpdate(slack))
    #expect(SofaDetail.softwareUpdate.scheme == "x-apple.systempreferences")
}

@Test func sofaSourceLineAndCoverageRow() {
    #expect(SourceLabel.text(kind: "os", sourceLabel: "macOS", origin: "SOFA", project: nil) == "macOS · SOFA")
    #expect(SourceLabel.text(kind: "app", sourceLabel: "Applications", origin: "SOFA", project: nil) == "App · SOFA")
    let rows = CoverageRow.rows([CoverageRecord(source: "sofa", label: "SOFA", state: .partial,
                                                error: "SOFA did not load. Watchtower used the last copy.")],
                                time: utc)
    #expect(rows.map(\.label) == ["SOFA"] && rows.map(\.stateText) == ["Partial"])
}
