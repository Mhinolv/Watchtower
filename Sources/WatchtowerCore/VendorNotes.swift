import Foundation

// Vendor assessments (#18): a vendor (for example Debian) says that a fix is backported, or that a version is
// not affected. A note is extra evidence. It never replaces the OSV or GitHub data and never changes the status
// of a finding. Notes are never hidden: withdrawn and stale notes stay in the history.

/// One vendor note, as the engine writes it. The text comes from a vendor page: show it as plain text only.
public struct VendorNote: Codable, Hashable, Sendable, Identifiable {
    /// `VN-0001`.
    public var id: String
    public var vendor: String
    /// `fixed`, `not_affected` or `affected`.
    public var verdict: String
    public var statement: String
    public var affectedRange: String?
    /// `high`, `medium` or `low`.
    public var confidence: String
    public var sourceUrl: String
    /// When the vendor page was read.
    public var retrievedAt: Date
    public var addedAt: Date
    /// When the owner last checked the source again. The 90 days start again from here.
    public var checkedAt: Date?
    public var withdrawnAt: Date?

    public init(id: String, vendor: String, verdict: String, statement: String, affectedRange: String? = nil,
                confidence: String, sourceUrl: String, retrievedAt: Date, addedAt: Date? = nil,
                checkedAt: Date? = nil, withdrawnAt: Date? = nil) {
        self.id = id
        self.vendor = vendor
        self.verdict = verdict
        self.statement = statement
        self.affectedRange = affectedRange
        self.confidence = confidence
        self.sourceUrl = sourceUrl
        self.retrievedAt = retrievedAt
        self.addedAt = addedAt ?? retrievedAt
        self.checkedAt = checkedAt
        self.withdrawnAt = withdrawnAt
    }

    public var isWithdrawn: Bool { withdrawnAt != nil }
    public var isNotAffected: Bool { verdict == "not_affected" }

    /// The source page, only if it is an http or https address.
    public var sourceURL: URL? {
        guard let url = URL(string: sourceUrl), ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
              url.host != nil else { return nil }
        return url
    }

    /// The last time someone read the source: the retrieval, or the last check by the owner.
    public var lastRead: Date { max(retrievedAt, checkedAt ?? retrievedAt) }

    /// Older than 90 days (owner decision, 2026-10-29). A withdrawn note is never stale: it is already history.
    public func isStale(now: Date) -> Bool {
        !isWithdrawn && now.timeIntervalSince(lastRead) > VendorAssessment.staleAfter
    }

    /// `High`, `Medium` or `Low`.
    public var confidenceText: String { confidence.prefix(1).uppercased() + confidence.dropFirst().lowercased() }

    /// The short verdict for the list: `backport`, `not affected`, `affected`.
    public var verdictText: String {
        switch verdict {
        case "fixed": "backport"
        case "not_affected": "not affected"
        case "affected": "affected"
        default: verdict.replacingOccurrences(of: "_", with: " ")
        }
    }
}

/// What the `Vendor assessment` section and the list show for one finding.
public struct VendorAssessment: Sendable {
    /// A note is stale after 90 days. The app then asks the owner to check it again (owner decision, 2026-10-29).
    public static let staleAfter: TimeInterval = 90 * 86400

    public static let notAffectedBanner =
        "The vendor says this version is not affected. The finding stays open until a complete scan resolves it."
    public static let stalePrompt = "This note is older than 90 days. Open the source and check it again."

    /// The newest note that is not withdrawn. nil if there is none.
    public var current: VendorNote?
    /// Every other note, newest retrieval first. Withdrawn and stale notes are here.
    public var history: [VendorNote]
    public var now: Date

    public init(_ finding: FindingRecord, now: Date) {
        let notes = (finding.vendorNotes ?? []).sorted {
            $0.retrievedAt != $1.retrievedAt ? $0.retrievedAt > $1.retrievedAt : $0.id > $1.id
        }
        let current = notes.first { !$0.isWithdrawn }
        self.current = current
        history = notes.filter { $0.id != current?.id }
        self.now = now
    }

    public var isEmpty: Bool { current == nil && history.isEmpty }

    /// Show the not-affected banner. The status of the finding does not change.
    public var showsNotAffectedBanner: Bool { current?.isNotAffected ?? false }

    /// The current note is old: ask the owner to check the source again.
    public var asksForCheck: Bool { current?.isStale(now: now) ?? false }

    /// `History (2)`.
    public var historyTitle: String { "History (\(history.count))" }

    /// The secondary text in the `Package` cell: `Vendor: backport`. nil without a current note.
    public var listText: String? { current.map { "Vendor: \($0.verdictText)" } }

    /// The text rows above `Confidence` and `Source`: Vendor, Statement, Affected range.
    public static func rows(_ note: VendorNote) -> [(label: String, value: String)] {
        var rows: [(label: String, value: String)] = [("Vendor", note.vendor), ("Statement", note.statement)]
        if let range = note.affectedRange { rows.append(("Affected range", range)) }
        return rows
    }

    /// The time rows below `Source`: Retrieved, and Checked again after the owner checked the source.
    public static func timeRows(_ note: VendorNote, time: TimeText = TimeText()) -> [(label: String, value: String)] {
        [("Retrieved", time.absolute(note.retrievedAt))] + (note.checkedAt.map { [("Checked again", time.absolute($0))] } ?? [])
    }

    /// `Withdrawn Oct 29` or `Stale`, gray and orange. Empty for a current note that is not old.
    public func badges(_ note: VendorNote, time: TimeText = TimeText()) -> [(text: String, tone: Tone)] {
        if let at = note.withdrawnAt { return [("Withdrawn \(time.day(at))", .gray)] }
        return note.isStale(now: now) ? [("Stale", .orange)] : []
    }
}

extension FindingRecord {
    /// The vendor notes of the finding with the clock of the caller.
    public func vendorAssessment(now: Date) -> VendorAssessment { VendorAssessment(self, now: now) }
}
