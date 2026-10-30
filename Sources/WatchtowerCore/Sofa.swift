import Foundation

/// The `Security releases` section of the macOS and Safari detail panes (#58).
///
/// The engine puts the SOFA evidence in item attributes (`sofaLatest`, `sofaFixedCves`, …).
/// The engine writes attribute keys in camelCase, as for `bundleId`.
public struct SofaDetail: Equatable, Sendable {
    /// Attribute keys that this section shows. The generic attribute rows leave them out.
    public static let keys: Set<String> = ["sofaLatest", "sofaReleased", "sofaFixedCves", "sofaExploited",
                                           "sofaChecked"]
    /// The engine error for a feed that did not load (`sofa.ERROR_FAILED`).
    public static let failedError = "SOFA feed did not load."
    /// The primary source. SOFA is a summary of this page.
    public static let primarySource = URL(string: "https://support.apple.com/en-us/100100")!
    /// The Software Update pane of System Settings.
    public static let softwareUpdate = URL(string: "x-apple.systempreferences:com.apple.Software-Update-Settings.extension")!

    /// `15.1.1 (24B91), released Nov 4`.
    public var latest: String?
    /// The CVEs that the newer releases fix.
    public var fixedCves: [String]
    /// The CVEs that Apple lists as actively exploited, fixed in a newer release.
    public var exploited: [String]
    /// `SOFA, retrieved Oct 29, 08:00`.
    public var data: String?
    /// `SOFA feed did not load. Data from Oct 28.` Nil if the last check did not fail.
    public var failure: String?

    /// Nil if the item has no SOFA data and no SOFA error.
    public init?(_ item: ItemRecord, time: TimeText = TimeText()) {
        let a = item.attributes ?? [:]
        guard !Self.keys.isDisjoint(with: a.keys) || item.error == Self.failedError else { return nil }
        let checked = a["sofaChecked"].flatMap { ISO8601DateFormatter().date(from: $0) }
        let released = a["sofaReleased"].map { ", released \(time.day($0))" } ?? ""
        latest = a["sofaLatest"].map { $0 + released }
        fixedCves = Self.list(a["sofaFixedCves"])
        exploited = Self.list(a["sofaExploited"])
        data = checked.map { "SOFA, retrieved \(time.absolute($0))" }
        if item.error == Self.failedError {
            failure = checked.map { "\(Self.failedError) Data from \(time.day($0))." } ?? Self.failedError
        }
    }

    private static func list(_ text: String?) -> [String] {
        (text ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    /// `Known exploited` next to `Vulnerable`, if a newer release fixes an actively exploited CVE.
    public var badge: FeedBadge? {
        guard !exploited.isEmpty else { return nil }
        let count = exploited.count == 1 ? "1 actively exploited CVE" : "\(exploited.count) actively exploited CVEs"
        return .knownExploited("Apple lists \(count) that a newer release fixes.")
    }

    /// macOS and Safari update through Software Update, not through Watchtower.
    public static func usesSoftwareUpdate(_ item: ItemRecord) -> Bool {
        item.source == "macos" || (item.source == "apps"
                                   && item.attributes?["bundleId"]?.lowercased() == "com.apple.safari")
    }

    /// The attributes for the generic rows, sorted by key, without the SOFA keys.
    public static func otherAttributes(_ item: ItemRecord) -> [(key: String, value: String)] {
        (item.attributes ?? [:]).filter { !keys.contains($0.key) }.sorted { $0.key < $1.key }
            .map { (key: $0.key, value: $0.value) }
    }
}
