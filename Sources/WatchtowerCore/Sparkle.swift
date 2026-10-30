import Foundation

/// The `Sparkle feed` section of an app's detail pane (#14).
///
/// The engine puts the appcast evidence in item attributes (`sparkleFeed`, `sparkleLatest`, …).
/// The engine writes attribute keys in camelCase, as for `bundleId`.
public struct SparkleDetail: Equatable, Sendable {
    public struct Row: Equatable, Sendable {
        public var label: String
        public var value: String
    }

    /// Attribute keys that this section shows. The generic attribute rows leave them out.
    public static let keys: Set<String> = ["sparkleFeed", "sparkleLatest", "sparkleChannel", "sparkleMinimumOs",
                                           "sparkleChecked"]
    /// The engine error for a feed that did not load (`sparkle.ERROR_FAILED`).
    public static let failedError = "Feed check failed."

    /// Feed, Latest, Channel, Minimum macOS, Checked: only the rows that have a value.
    public var rows: [Row]
    /// The feed address. The detail pane makes it selectable.
    public var feed: String?
    /// `Feed check failed. Data from Oct 28.` Nil if the last check did not fail.
    public var failure: String?

    /// Nil if the item has no Sparkle attributes.
    public init?(_ item: ItemRecord, time: TimeText = TimeText()) {
        let a = item.attributes ?? [:]
        guard !Self.keys.isDisjoint(with: a.keys) else { return nil }
        let checked = a["sparkleChecked"].flatMap { ISO8601DateFormatter().date(from: $0) }
        feed = a["sparkleFeed"]
        rows = [("Feed", feed), ("Latest", a["sparkleLatest"]), ("Channel", a["sparkleChannel"]),
                ("Minimum macOS", a["sparkleMinimumOs"]), ("Checked", checked.map(time.absolute))]
            .compactMap { label, value in value.map { Row(label: label, value: $0) } }
        if item.error == Self.failedError {
            failure = checked.map { "\(Self.failedError) Data from \(time.day($0))." } ?? Self.failedError
        }
    }

    /// The attributes for the generic rows, sorted by key, without the Sparkle keys.
    public static func otherAttributes(_ item: ItemRecord) -> [(key: String, value: String)] {
        (item.attributes ?? [:]).filter { !keys.contains($0.key) }.sorted { $0.key < $1.key }
            .map { (key: $0.key, value: $0.value) }
    }
}
