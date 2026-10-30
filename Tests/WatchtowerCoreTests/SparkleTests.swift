import Foundation
import Testing
@testable import WatchtowerCore

private let utc = TimeText(timeZone: TimeZone(identifier: "UTC")!)

/// An app item as `sparkle.apply` writes it. Attribute keys are camelCase, as in `apps.py`.
private func engineItem(error: String? = nil, extra: String = "") throws -> ItemRecord {
    let error = error.map { "\"\($0)\"" } ?? "null"
    let json = """
    {"id": "com.example.acme-notes", "source": "apps", "name": "Acme Notes", "state": "update_available",
     "kind": "app", "installed_version": "3.3.0", "latest_version": "3.4.1", "origin": "Sparkle feed",
     "error": \(error), "attributes": {"path": "/Applications/Acme Notes.app", "bundleId": "com.example.acme-notes",
     "sparkleFeed": "https://example.com/appcast.xml", "sparkleLatest": "3.4.1 (341)",
     "sparkleChannel": "Stable", "sparkleMinimumOs": "14.0", "sparkleChecked": "2026-10-28T09:12:00Z"\(extra)}}
    """
    return try EngineJSON.makeDecoder().decode(ItemRecord.self, from: Data(json.utf8))
}

@Test func sparkleSectionShowsFeedEvidence() throws {
    let detail = try #require(SparkleDetail(try engineItem(), time: utc))
    #expect(detail.rows.map(\.label) == ["Feed", "Latest", "Channel", "Minimum macOS", "Checked"])
    #expect(detail.rows.map(\.value) == ["https://example.com/appcast.xml", "3.4.1 (341)", "Stable", "14.0",
                                         "Oct 28, 09:12"])
    #expect(detail.feed == "https://example.com/appcast.xml")
    #expect(detail.failure == nil)
}

@Test func sparkleKeysLeaveTheGenericRows() throws {
    let item = try engineItem()
    #expect(SparkleDetail.otherAttributes(item).map(\.key) == ["bundleId", "path"])
}

@Test func noSparkleSectionWithoutFeedData() {
    let item = ItemRecord(id: "com.example.legacy", source: "apps", name: "Legacy Tool", state: .manual,
                          attributes: ["path": "/Applications/Legacy Tool.app"])
    #expect(SparkleDetail(item) == nil)
}

@Test func failedFeedNamesTheDateOfTheKeptData() throws {
    let detail = try #require(SparkleDetail(try engineItem(error: "Feed check failed."), time: utc))
    #expect(detail.failure == "Feed check failed. Data from Oct 28.")
    // The earlier evidence is still on the rows.
    #expect(detail.rows.first { $0.label == "Latest" }?.value == "3.4.1 (341)")
}

@Test func failedFeedWithoutEarlierDataSaysOnlyThatItFailed() {
    let item = ItemRecord(id: "a", source: "apps", name: "A", state: .manual, error: "Feed check failed.",
                          attributes: ["sparkleFeed": "https://example.com/appcast.xml"])
    #expect(SparkleDetail(item, time: utc)?.failure == "Feed check failed.")
}

@Test func rejectedFeedShowsOnlyTheAddress() {
    let item = ItemRecord(id: "a", source: "apps", name: "A", state: .unknown,
                          note: "Watchtower reads HTTPS feeds only.",
                          attributes: ["sparkleFeed": "http://example.com/appcast.xml"])
    let detail = SparkleDetail(item, time: utc)
    #expect(detail?.rows == [SparkleDetail.Row(label: "Feed", value: "http://example.com/appcast.xml")])
}

@Test func coverageRowCountsSparkleFeeds() {
    let rows = CoverageRow.rows([
        CoverageRecord(source: "sparkle", label: "Sparkle feeds", state: .partial, lastSuccessAt: nil,
                       error: "Some Sparkle feeds did not load.", note: "12 of 14 read"),
        CoverageRecord(source: "kev", label: "CISA KEV", state: .complete, note: "official mirror"),
        CoverageRecord(source: "sparkle", label: "Sparkle feeds", state: .notRun, note: "No app has a Sparkle feed."),
    ], time: utc)
    #expect(rows.map(\.label) == ["Sparkle feeds: 12 of 14 read", "CISA KEV", "Sparkle feeds"])
}
