import Foundation

// The vendor support status of macOS and of each runtime (#59), from endoflife.date. It is separate from
// `StatusBadge`: a supported but outdated runtime is still `Update available`, and an end-of-life runtime is not
// `Vulnerable`. The engine writes the facts into item attributes (`eolState`, `eolEnd`, `eolCycle`, `eolChecked`,
// `eolError`). The app decides the state again from the end date and today's date, so an old scan never shows
// `Supported` for a line that has ended since (the 90-day window is the owner decision of 2026-10-30).

public enum SupportState: String, Sendable, Equatable, CaseIterable {
    case supported
    case endsSoon = "ends_soon"
    case securityOnly = "security_only"
    case endOfLife = "end_of_life"
    case unknown
}

public struct SupportStatus: Equatable, Sendable {
    /// The window for `Support ends …`, in days.
    public static let endsSoonDays = 90
    /// The engine failure text (`endoflife.date did not respond.`).
    public static let failedText = "endoflife.date did not respond."
    /// The attribute keys of this status. Other attribute lists leave them out.
    public static let keys: Set<String> = ["eolState", "eolEnd", "eolCycle", "eolChecked", "eolError"]

    public var state: SupportState
    /// `2027-04-30`. nil if endoflife.date has no end date.
    public var end: String?
    /// The release line: `22`, `3.12`, `15`.
    public var cycle: String?
    /// When endoflife.date answered. nil if it never did.
    public var checked: Date?
    /// True if the last request failed. Earlier data may still show.
    public var failed: Bool
    /// Days from today to `end`. Negative after the end.
    public var daysLeft: Int?
    /// The product name for the text of an unknown state: `Node.js`.
    public var name: String
    private let timeZone: TimeZone
    private var time: TimeText { TimeText(timeZone: timeZone) }

    /// nil if the item has no support attributes (an SDK, an extension, or a scan from before #59).
    public init?(_ item: ItemRecord, now: Date = Date(), time: TimeText = TimeText()) {
        let a = item.attributes ?? [:]
        guard let raw = a["eolState"], let stored = SupportState(rawValue: raw) else { return nil }
        timeZone = time.timeZone
        name = item.name
        end = a["eolEnd"]
        cycle = a["eolCycle"]
        checked = a["eolChecked"].flatMap { ISO8601DateFormatter().date(from: $0) }
        failed = a["eolError"] != nil
        daysLeft = end.flatMap { Self.days(until: $0, now: now, time: time) }
        state = Self.state(stored, daysLeft: daysLeft)
    }

    /// The state on today's date. A date that has passed beats the stored state.
    static func state(_ stored: SupportState, daysLeft: Int?) -> SupportState {
        guard let left = daysLeft else { return stored }
        switch stored {
        case .supported, .endsSoon: return left <= 0 ? .endOfLife : left <= endsSoonDays ? .endsSoon : .supported
        case .securityOnly: return left <= 0 ? .endOfLife : .securityOnly
        case .endOfLife, .unknown: return stored
        }
    }

    /// Whole days from today (in the local time zone) to the date `end`. Both are plain calendar days.
    static func days(until end: String, now: Date, time: TimeText) -> Int? {
        let utc = TimeZone(identifier: "UTC")!
        let format = DateFormatter()
        format.locale = Locale(identifier: "en_US_POSIX")
        format.dateFormat = "yyyy-MM-dd"
        format.timeZone = time.timeZone
        let todayText = format.string(from: now)
        format.timeZone = utc
        guard let endDay = format.date(from: end), let today = format.date(from: todayText) else { return nil }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = utc
        return calendar.dateComponents([.day], from: today, to: endDay).day
    }

    // MARK: Text

    /// The full label: `Supported until Apr 30, 2027`. The color never stands alone.
    public var label: String {
        let date = end.map { time.fullDay($0) }
        switch state {
        case .supported: return date.map { "Supported until \($0)" } ?? "Supported"
        case .endsSoon: return "Support ends \(end.map { time.day($0) } ?? "soon") (\(Self.dayCount(daysLeft ?? 0)))"
        case .securityOnly: return date.map { "Security fixes only until \($0)" } ?? "Security fixes only"
        case .endOfLife: return date.map { "End of life since \($0)" } ?? "End of life"
        case .unknown: return failed ? Self.failedText : "endoflife.date has no entry for \(name)."
        }
    }

    /// The short text of the list column: `Supported`, `Ends Dec 13`, `Security only`, `End of life`, `—`.
    public var shortText: String {
        switch state {
        case .supported: "Supported"
        case .endsSoon: "Ends \(end.map { time.day($0) } ?? "soon")"
        case .securityOnly: "Security only"
        case .endOfLife: "End of life"
        case .unknown: "—"
        }
    }

    static func dayCount(_ days: Int) -> String { days == 1 ? "1 day" : "\(days) days" }

    public var symbol: String {
        switch state {
        case .supported: "checkmark.circle"
        case .endsSoon: "clock"
        case .securityOnly: "shield.lefthalf.filled"
        case .endOfLife: "xmark.circle"
        case .unknown: "questionmark.circle"
        }
    }

    public var tone: Tone {
        switch state {
        case .supported: .green
        case .endsSoon, .securityOnly: .orange
        case .endOfLife: .red
        case .unknown: .gray
        }
    }

    /// `Node.js 22`. nil if the line is not known.
    public func releaseLine(product: String) -> String? { cycle.map { "\(product) \($0)" } }

    /// `endoflife.date, retrieved Oct 29, 08:00`. nil if endoflife.date never answered.
    public var dataText: String? { checked.map { "endoflife.date, retrieved \(time.absolute($0))" } }

    /// `endoflife.date did not respond. Data from Oct 28.` nil if the last request worked.
    public var failureText: String? {
        guard failed else { return nil }
        return checked.map { "\(Self.failedText) Data from \(time.day($0))." } ?? Self.failedText
    }

    public var accessibilityText: String { "Support: \(label)" }
}

extension ItemRecord {
    /// The attributes for a generic list, without the support keys.
    public var attributesWithoutSupport: [String: String] {
        (attributes ?? [:]).filter { !SupportStatus.keys.contains($0.key) }
    }
}
