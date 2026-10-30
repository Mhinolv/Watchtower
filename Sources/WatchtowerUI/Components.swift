import AppKit
import SwiftUI
import WatchtowerCore

// Colors and shapes from design/system.md.

extension Color {
    /// A color that follows light and dark mode.
    public init(_ pair: ColorPair) {
        self.init(nsColor: NSColor(name: nil) { appearance in
            let dark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            let hex = dark ? pair.dark : pair.light
            return NSColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
                           blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
        })
    }

    /// Watchtower Indigo. The app bundle also sets it as `AccentColor` in the asset catalog.
    public static let watchtowerAccent = Color(DesignTokens.accent)
}

extension Tone {
    public var color: Color {
        DesignTokens.pair(self).map(Color.init) ?? .secondary
    }
}

/// The shared status badge: a capsule with symbol and word. The word is always shown.
public struct StatusBadge: View {
    let style: StatusStyle

    public init(_ state: ItemState) {
        style = StatusStyle(state)
    }

    public var body: some View {
        Capsule(text: style.text, symbol: style.symbol, color: style.tone.color)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Status: \(style.text)")
    }

    /// 21 pt high, 11.5 pt semibold, symbol color at 16 percent behind.
    struct Capsule: View {
        let text: String
        let symbol: String
        let color: Color

        var body: some View {
            HStack(spacing: 4) {
                Image(systemName: symbol).imageScale(.small)
                Text(text).lineLimit(1)
            }
            .font(.system(size: DesignTokens.badgeFontSize, weight: .semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 8)
            .frame(height: DesignTokens.badgeHeight)
            .background(color.opacity(DesignTokens.badgeFill), in: SwiftUI.Capsule())
            .fixedSize()
        }
    }
}

/// A letter tile for an item: 22 pt in a row (5 pt radius), 52 pt in the detail header.
public struct ItemIcon: View {
    let name: String
    let size: Double

    public init(name: String, size: Double = DesignTokens.rowIconSize) {
        self.name = name
        self.size = size
    }

    static let palette: [Color] = [
        Color(red: 0.42, green: 0.36, blue: 0.91), Color(red: 0.91, green: 0.45, blue: 0.10),
        Color(red: 0.16, green: 0.47, blue: 0.86), Color(red: 0.49, green: 0.23, blue: 0.85),
        Color(red: 0.80, green: 0.27, blue: 0.20), Color(red: 0.13, green: 0.55, blue: 0.47),
        Color(red: 0.29, green: 0.33, blue: 0.40),
    ]

    public var body: some View {
        let hash = name.unicodeScalars.reduce(0) { ($0 &* 31 &+ Int($1.value)) & 0xFFFF }
        RoundedRectangle(cornerRadius: size <= 24 ? DesignTokens.rowIconRadius : size * 0.22)
            .fill(Self.palette[hash % Self.palette.count])
            .frame(width: size, height: size)
            .overlay {
                Text(String(name.prefix(1)).uppercased())
                    .font(.system(size: size * 0.5, weight: .bold))
                    .foregroundStyle(.white)
            }
            .accessibilityHidden(true)
    }
}

/// A count in a gray capsule. Red when `alert` is set (Findings above 0).
struct CountCapsule: View {
    let count: Int
    var alert = false

    var body: some View {
        Text("\(count)")
            .font(.system(size: 11, weight: .semibold).monospacedDigit())
            .foregroundStyle(alert ? Tone.red.color : .secondary)
            .padding(.horizontal, 7)
            .frame(minWidth: 24, minHeight: 17)
            .background((alert ? Tone.red.color : Color.gray).opacity(alert ? 0.16 : 0.18), in: SwiftUI.Capsule())
    }
}

/// A capsule outline drawn as a filled ring: the outer capsule minus the inner one, filled with the
/// even-odd rule. A 0.5 pt `strokeBorder` of a capsule drew a vertical hairline at both ends in
/// offscreen snapshots (#40), so the border is a fill, not a stroke.
struct CapsuleRing: Shape {
    var width: CGFloat = 0.5

    func path(in rect: CGRect) -> Path {
        var path = SwiftUI.Capsule().path(in: rect)
        path.addPath(SwiftUI.Capsule().path(in: rect.insetBy(dx: width, dy: width)))
        return path
    }
}

/// One filter chip above the item list. The selected chip has the accent tint.
struct FilterChipButton: View {
    let chip: FilterChip
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Text("\(chip.count)").fontWeight(.semibold).monospacedDigit()
                if let symbol = chip.filter.symbol { Image(systemName: symbol).imageScale(.small) }
                Text(chip.filter.title)
            }
            .font(.system(size: 12.5))
            .foregroundStyle(chip.selected ? Color.watchtowerAccent : .primary)
            .padding(.horizontal, 10)
            .frame(height: 26)
            // One capsule for fill and border (#40). Unselected: a 0.5 pt border and no fill. Selected: the
            // accent tint and no border. The border is a filled ring, not a stroke (see `CapsuleRing`).
            .background {
                if chip.selected {
                    SwiftUI.Capsule().fill(Color.watchtowerAccent.opacity(0.16))
                } else {
                    CapsuleRing().fill(Color.secondary.opacity(0.45), style: FillStyle(eoFill: true))
                }
            }
            .contentShape(SwiftUI.Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(chip.filter.title), \(chip.count)")
        .accessibilityAddTraits(chip.selected ? .isSelected : [])
    }
}

/// The refresh label. A click opens the Coverage popover.
public struct RefreshLabelView: View {
    let model: DashboardModel
    @State private var showsCoverage = false

    public init(model: DashboardModel) {
        self.model = model
    }

    public var body: some View {
        let label = model.refreshLabel
        Button {
            showsCoverage.toggle()
        } label: {
            HStack(spacing: 6) {
                if label.showsProgress {
                    ProgressView().controlSize(.small)
                }
                if let symbol = label.symbol {
                    Image(systemName: symbol).foregroundStyle(label.tone.color)
                }
                Text(label.text).foregroundStyle(label.tone.color)
            }
        }
        .buttonStyle(.plain)
        .help("Show coverage for each source")
        .accessibilityLabel("\(label.text). Show coverage.")
        .popover(isPresented: $showsCoverage, arrowEdge: .bottom) {
            CoverageView(rows: model.coverageRows)
        }
    }
}

/// One row for each source, with its state and last success time.
public struct CoverageView: View {
    let rows: [CoverageRow]

    public init(rows: [CoverageRow]) {
        self.rows = rows
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Coverage").font(.headline)
            if rows.isEmpty {
                Text("No source has run yet.").foregroundStyle(.secondary)
            }
            ForEach(rows) { row in
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(row.label).bold()
                        Spacer()
                        Text(row.stateText).foregroundStyle(row.tone.color)
                    }
                    Text(row.lastSuccess).font(.caption).foregroundStyle(.secondary)
                    if let error = row.error {
                        Text(error).font(.caption).foregroundStyle(row.tone.color)
                    }
                }
                .accessibilityElement(children: .combine)
            }
        }
        .padding()
        .frame(width: 320, alignment: .leading)
    }
}

/// Row wrapper: item ids are unique only inside a source.
struct ItemRow: Identifiable {
    let item: ItemRecord
    var id: String { item.key }
}

/// The vendor support label (#59): symbol, color and text. It is not a `StatusBadge`. The text is always shown.
struct SupportLabel: View {
    let status: SupportStatus
    var short = false

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 4) {
            Image(systemName: status.symbol).imageScale(.small)
            Text(short ? status.shortText : status.label)
                .lineLimit(short ? 1 : nil)
                .fixedSize(horizontal: false, vertical: !short)
        }
        .foregroundStyle(status.tone.color)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(status.accessibilityText)
        .help(status.label)
    }
}

/// The `Evidence` section of a detail pane (#17): Installed, Lockfile, Running, Container image and Deployment.
/// Unknown stays `Unknown`. An older running version is orange and says what to do.
struct EvidenceSection: View {
    let rows: [EvidenceRow]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Evidence").font(.headline)
            Grid(alignment: .topLeading, horizontalSpacing: 16, verticalSpacing: 6) {
                ForEach(rows, id: \.label) { row in
                    GridRow {
                        Text(row.label).foregroundStyle(.secondary)
                        if row.tone == .orange {
                            Label(row.value, systemImage: "exclamationmark.triangle")
                                .foregroundStyle(Tone.orange.color)
                        } else {
                            Text(row.value).textSelection(.enabled)
                        }
                    }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(row.accessibilityText)
                }
            }
            if rows.contains(where: { $0.label == "Container image" }) {
                Text("Container image is metadata from project files. Watchtower starts no container.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}
