import Foundation

// EPSS (#57): the chance that a CVE is exploited in the next 30 days. The engine reads FIRST's daily bulk file.

/// The EPSS value of one finding: the CVE with the highest score.
public struct EpssMark: Codable, Hashable, Sendable {
    public var cve: String
    /// 0 to 1. nil if the CVE is not in the EPSS file.
    public var score: Double?
    public var percentile: Double?
    /// The day of the scores, as the file writes it: `2026-10-29`.
    public var scoreDate: String?
    /// When Watchtower downloaded the file.
    public var fetchedAt: Date?

    public init(cve: String, score: Double? = nil, percentile: Double? = nil, scoreDate: String? = nil,
                fetchedAt: Date? = nil) {
        self.cve = cve
        self.score = score
        self.percentile = percentile
        self.scoreDate = scoreDate
        self.fetchedAt = fetchedAt
    }
}

public enum EpssText {
    /// EPSS data counts as old after 2 days (orchestrator decision, #57). FIRST publishes a file each day.
    public static let staleAfter: TimeInterval = 2 * 86400

    /// The score as a percent: `94%`, `2.1%`, `<0.1%`.
    public static func percent(_ score: Double) -> String {
        let value = score * 100
        if value < 0.1 { return "<0.1%" }
        if value < 10 { return String(format: "%.1f%%", (value * 10).rounded() / 10) }
        return "\(Int(value.rounded()))%"
    }

    /// `99th`, `1st`, `11th`.
    public static func ordinal(_ percentile: Double) -> String {
        let n = Int((percentile * 100).rounded())
        let suffix: String
        switch (n % 100, n % 10) {
        case (11...13, _): suffix = "th"
        case (_, 1): suffix = "st"
        case (_, 2): suffix = "nd"
        case (_, 3): suffix = "rd"
        default: suffix = "th"
        }
        return "\(n)\(suffix)"
    }
}

/// What the list and the detail pane show for the EPSS value of a finding. Text only, no color of its own:
/// orange marks a problem with the data.
public struct EpssDisplay: Equatable, Sendable {
    /// The list cell: `94%`, or `—`.
    public var listText: String
    /// The list cell is orange: the data is old or the download failed.
    public var listIsProblem: Bool
    /// Help text of the list cell: `Chance of exploit in the next 30 days. 97th percentile. EPSS, Oct 29.`
    public var help: String?
    /// The detail row `Exploit chance (EPSS)`: `94% in the next 30 days, 99th percentile`.
    public var detailText: String?
    /// The line below the row, and whether it is a problem (orange).
    public var note: String?
    public var noteIsProblem: Bool
    /// What VoiceOver reads for the cell: `Exploit chance 94 percent`.
    public var voiceOver: String

    /// `coverage` is the `epss` coverage row. `now` decides if the data is old.
    public static func make(_ finding: FindingRecord, coverage: CoverageRecord?, now: Date,
                            time: TimeText = TimeText()) -> EpssDisplay {
        let hasCVE = finding.advisoryIds.contains { $0.hasPrefix("CVE-") }
        let failed = coverage.map { $0.state == .partial || $0.state == .failed } ?? false
        let mark = finding.epss
        let at = mark?.fetchedAt
        var out = EpssDisplay(listText: "—", listIsProblem: false, help: nil, detailText: nil, note: nil,
                              noteIsProblem: false, voiceOver: "Exploit chance not known")
        guard hasCVE else {
            out.note = "EPSS covers CVEs only."
            return out
        }
        // A failed download shows the earlier value. It never clears it.
        if failed {
            let when = (at ?? coverage?.sourceAt).map { " Data from \(time.day($0))." } ?? ""
            out.note = "EPSS download failed.\(when)"
            out.noteIsProblem = true
        }
        guard let mark, let fetched = at else { return out }
        let day = time.day(fetched)
        guard let score = mark.score else {
            if !failed { out.note = "This CVE is not in the EPSS file of \(day)." }
            return out
        }
        let percent = EpssText.percent(score)
        let rank = mark.percentile.map { "\(EpssText.ordinal($0)) percentile" }
        out.listText = percent
        out.help = (["Chance of exploit in the next 30 days.", rank.map { $0 + "." }].compactMap { $0 }
                    + ["EPSS, \(day)."]).joined(separator: " ")
        out.detailText = "\(percent) in the next 30 days" + (rank.map { ", " + $0 } ?? "")
        out.voiceOver = "Exploit chance \(Int((score * 100).rounded())) percent"
        if now.timeIntervalSince(fetched) > EpssText.staleAfter {
            out.listIsProblem = true
            if !failed {
                out.note = "EPSS data is from \(day)."
                out.noteIsProblem = true
            }
        }
        out.listIsProblem = out.listIsProblem || failed
        return out
    }
}

extension FindingRecord {
    /// EPSS high to low. A finding with no score comes after every finding that has one.
    static func epssPrecedes(_ a: FindingRecord, _ b: FindingRecord) -> Bool? {
        switch (a.epss?.score, b.epss?.score) {
        case let (x?, y?): return x == y ? nil : x > y
        case (nil, _?): return false
        case (_?, nil): return true
        default: return nil
        }
    }
}
