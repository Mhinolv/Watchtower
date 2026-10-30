import Foundation

// The approved visual system (design/system.md, owner decision 2026-10-29) as data,
// so tests can check it. The UI module turns these values into colors.

/// One color for light and one for dark, as `0xRRGGBB`.
public struct ColorPair: Equatable, Sendable {
    public var light: UInt32
    public var dark: UInt32

    public init(light: UInt32, dark: UInt32) {
        self.light = light
        self.dark = dark
    }
}

public enum DesignTokens {
    /// Watchtower Indigo.
    public static let accent = ColorPair(light: 0x5B4FD9, dark: 0x8E86FF)
    public static let green = ColorPair(light: 0x1F7A3A, dark: 0x5FDC7D)
    public static let blue = ColorPair(light: 0x0B5FD6, dark: 0x6CB0FF)
    public static let red = ColorPair(light: 0xC4271D, dark: 0xFF7A70)
    public static let orange = ColorPair(light: 0x9A5200, dark: 0xFFB340)
    public static let gray = ColorPair(light: 0x5C5C63, dark: 0xA8A8AE)

    /// Badge background: the symbol color at this opacity (12 to 20 percent).
    public static let badgeFill = 0.16
    public static let badgeHeight = 21.0
    public static let badgeFontSize = 11.5
    public static let tableRowHeight = 36.0
    public static let rowIconSize = 22.0
    public static let rowIconRadius = 5.0
    public static let detailIconSize = 52.0
    public static let detailTitleSize = 20.0
    public static let sidebarWidth = 210.0
    public static let listWidth = 620.0
    public static let popoverWidth = 330.0

    public static func pair(_ tone: Tone) -> ColorPair? {
        switch tone {
        case .green: green
        case .blue: blue
        case .red: red
        case .orange: orange
        case .gray: gray
        case .secondary: nil
        }
    }
}

// MARK: - Sidebar groups

public enum SidebarGroup: String, CaseIterable, Sendable, Identifiable {
    case inventory, review, history

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .inventory: "Inventory"
        case .review: "Review"
        case .history: "History"
        }
    }

    public var sections: [SidebarSection] {
        switch self {
        case .inventory: [.apps, .homebrew, .projects]
        case .review: [.findings, .backlog, .incidents]
        case .history: [.updateLog]
        }
    }
}

// MARK: - Filter chips

/// The chips above the item list. Chips and search filter together.
public enum ItemFilter: String, CaseIterable, Sendable, Identifiable {
    case all, vulnerable, updateAvailable, error

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .all: "All"
        case .vulnerable: "Vulnerable"
        case .updateAvailable: "Update available"
        case .error: "Error"
        }
    }

    public var symbol: String? {
        switch self {
        case .all: nil
        case .vulnerable: "exclamationmark.shield"
        case .updateAvailable: "arrow.up.circle"
        case .error: "exclamationmark.triangle"
        }
    }

    public func matches(_ item: ItemRecord) -> Bool {
        switch self {
        case .all: true
        case .vulnerable: item.state == .vulnerable
        case .updateAvailable: item.state == .updateAvailable
        case .error: item.state == .error
        }
    }
}

public struct FilterChip: Equatable, Sendable, Identifiable {
    public var filter: ItemFilter
    public var count: Int
    public var selected: Bool
    public var id: ItemFilter { filter }

    /// The chips to show. `All` always shows. A chip with no items hides.
    public static func chips(for items: [ItemRecord], selected: ItemFilter) -> [FilterChip] {
        ItemFilter.allCases.compactMap { filter in
            let count = items.filter(filter.matches).count
            guard filter == .all || count > 0 else { return nil }
            return FilterChip(filter: filter, count: count, selected: filter == selected)
        }
    }
}

// MARK: - Refresh label symbol

extension RefreshLabel {
    /// Stale, partial and failed states add a symbol to the label (system.md).
    public var symbol: String? {
        if showsProgress { return nil }
        switch tone {
        case .orange: return "exclamationmark.triangle"
        case .red: return "xmark.octagon"
        default: return nil
        }
    }
}

// MARK: - Menu bar popover

public struct AttentionRow: Equatable, Sendable, Identifiable {
    public var id: String
    public var name: String
    public var version: String?
    public var state: ItemState
    /// Where a click goes in the main window.
    public var section: SidebarSection
    public var selectionKey: String
}

public struct MenuBarSummary: Equatable, Sendable {
    public enum Mode: Equatable, Sendable {
        /// `Never refreshed. Click Refresh.` and no tiles.
        case never
        /// `Everything is up to date`.
        case allClear
        /// Tiles and `Needs attention`.
        case attention
    }

    public var mode: Mode
    public var vulnerable: Int
    public var updates: Int
    public var errors: Int
    /// Up to 3 rows, vulnerable first.
    public var rows: [AttentionRow]
    /// The alert template icon while an item is vulnerable.
    public var alertIcon: Bool
}

extension DashboardModel {
    public var menuBarSummary: MenuBarSummary {
        let items = (state?.items ?? []).filter { $0.source != "osv" }
        let openFindings = findingsInScope.filter(\.isOpen)
        var vulnerableRows = openFindings.map { f in
            AttentionRow(id: "finding/\(f.id)", name: f.package, version: f.paths.first?.version, state: .vulnerable,
                         section: .findings, selectionKey: f.id)
        }
        func rows(_ state: ItemState) -> [AttentionRow] {
            items.filter { $0.state == state }
                .sorted { ($0.name.lowercased(), $0.key) < ($1.name.lowercased(), $1.key) }
                .map { item in
                    AttentionRow(id: item.key, name: item.name, version: item.installedVersion, state: state,
                                 section: item.source == "homebrew" ? .homebrew : .apps, selectionKey: item.key)
                }
        }
        vulnerableRows += rows(.vulnerable)
        let updateRows = rows(.updateAvailable)
        let errorRows = rows(.error)
        let vulnerable = vulnerableRows.count
        let open = vulnerable + updateRows.count + errorRows.count
        let label = refreshLabel
        let mode: MenuBarSummary.Mode
        if state?.refresh == nil {
            mode = .never
        } else if open == 0, state?.refresh?.status == .complete, label.tone == .secondary {
            mode = .allClear
        } else {
            mode = .attention
        }
        return MenuBarSummary(mode: mode, vulnerable: vulnerable, updates: updateRows.count, errors: errorRows.count,
                              rows: Array((vulnerableRows + updateRows + errorRows).prefix(3)),
                              alertIcon: vulnerable > 0)
    }

    /// Open the main window on one row of the popover.
    public func reveal(_ row: AttentionRow) {
        selection = row.section
        itemFilter = .all
        searchText = ""
        selectedItemKey = row.selectionKey
    }

    /// Chips for the current section, before the search filter.
    public func filterChips(in section: SidebarSection) -> [FilterChip] {
        FilterChip.chips(for: items(in: section), selected: itemFilter)
    }

    /// A click on a chip. A second click on the selected chip returns to `All`.
    public func toggleFilter(_ filter: ItemFilter) {
        itemFilter = (itemFilter == filter) ? .all : filter
    }
}

// MARK: - Source column

public enum SourceLabel {
    /// Fixed labels for the item kinds that the engine sends today.
    public static let kinds: [String: String] = ["os": "macOS", "app": "App", "formula": "Formula", "cask": "Cask"]

    /// `macOS`, `Cask · acme/casks`. An unknown kind shows the engine's source label unchanged.
    public static func text(kind: String?, sourceLabel: String, origin: String?, project: String?) -> String {
        let base = kind.flatMap { kinds[$0] } ?? sourceLabel
        if let extra = origin ?? project { return "\(base) · \(extra)" }
        return base
    }
}
