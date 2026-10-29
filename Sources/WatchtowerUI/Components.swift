import SwiftUI
import WatchtowerCore

extension Tone {
    public var color: Color {
        switch self {
        case .secondary: .secondary
        case .green: .green
        case .blue: .blue
        case .red: .red
        case .orange: .orange
        case .gray: .gray
        }
    }
}

/// The shared status badge: symbol, text and color. The text is always shown.
public struct StatusBadge: View {
    let style: StatusStyle

    public init(_ state: ItemState) {
        style = StatusStyle(state)
    }

    public var body: some View {
        Label(style.text, systemImage: style.symbol)
            .foregroundStyle(style.tone.color)
            .labelStyle(.titleAndIcon)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Status: \(style.text)")
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
