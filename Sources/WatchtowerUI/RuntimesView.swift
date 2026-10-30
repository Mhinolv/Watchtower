import SwiftUI
import WatchtowerCore

// The `Runtimes` screen (#16): installs grouped as Runtimes, SDKs and Editor extensions. It never starts a
// program. Old copies show `Old copy` and the Unknown badge. A root that cannot be read shows its error above
// its group, and the other groups still show.

struct RuntimesView: View {
    @Bindable var model: DashboardModel

    var body: some View {
        let sections = model.runtimeSections
        if sections.isEmpty {
            empty
        } else {
            List(selection: $model.selectedItemKey) {
                ForEach(sections) { section in
                    Section {
                        ForEach(section.rootErrors, id: \.self) { error in
                            Label(error, systemImage: "exclamationmark.triangle")
                                .foregroundStyle(Tone.orange.color)
                                .listRowSeparator(.hidden)
                        }
                        ForEach(section.rows) { row in
                            RuntimeRowView(row: row).tag(row.id)
                        }
                    } header: {
                        HStack(spacing: 8) {
                            Text(section.group.title).font(.headline)
                            Text("\(section.rows.count)").foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .safeAreaInset(edge: .top, spacing: 0) { ColumnHeader() }
        }
    }

    @ViewBuilder private var empty: some View {
        if !model.searchText.isEmpty {
            ContentUnavailableView.search(text: model.searchText)
        } else if model.state?.refresh == nil {
            ContentUnavailableView("Never refreshed", systemImage: "arrow.clockwise",
                                   description: Text("Click Refresh to look for runtimes, SDKs and editor extensions."))
        } else {
            ContentUnavailableView("No runtimes found", systemImage: "cpu",
                                   description: Text("Watchtower found no runtime, SDK or editor extension in its known folders."))
        }
    }
}

private enum Column {
    static let name: CGFloat = 170, version: CGFloat = 80, source: CGFloat = 96, status: CGFloat = 84
}

private struct ColumnHeader: View {
    var body: some View {
        HStack(spacing: 10) {
            Text("Name").frame(width: Column.name, alignment: .leading)
            Text("Version").frame(width: Column.version, alignment: .leading)
            Text("Path").frame(maxWidth: .infinity, alignment: .leading)
            Text("Source").frame(width: Column.source, alignment: .leading)
            Text("Status").frame(width: Column.status, alignment: .leading)
        }
        .font(.caption.weight(.semibold))
        .foregroundStyle(.secondary)
        .padding(.horizontal, 24)
        .padding(.vertical, 6)
        .background(.bar)
    }
}

private struct RuntimeRowView: View {
    let row: RuntimeRow

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 1) {
                Text(row.name).lineLimit(1)
                if let secondary = row.secondary {
                    Text(secondary).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            .frame(width: Column.name, alignment: .leading)
            Text(row.version).monospacedDigit().frame(width: Column.version, alignment: .leading)
            Text(row.path).font(.callout.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                .truncationMode(.middle).frame(maxWidth: .infinity, alignment: .leading)
            Text(row.source).foregroundStyle(.secondary).lineLimit(1).frame(width: Column.source, alignment: .leading)
            Group {
                if let badge = row.badge { StatusBadge(badge) } else { Text("") }
            }
            .frame(width: Column.status, alignment: .leading)
        }
        .frame(minHeight: DesignTokens.tableRowHeight)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(row.name), \(row.version), \(row.source)\(row.isOld ? ", old copy" : "")")
    }
}

/// The detail pane of one install: path, version, source, the time of the check and the other copies.
struct RuntimeDetail: View {
    let model: DashboardModel
    let item: ItemRecord
    private let time = TimeText()

    var body: some View {
        let copies = model.runtimeCopies(of: item)
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(item.name).font(.system(size: DesignTokens.detailTitleSize, weight: .bold)).textSelection(.enabled)
                    if let editor = item.attributes?["editor"] { Text(editor).foregroundStyle(.secondary) }
                    if item.state != .manual { StatusBadge(item.state).padding(.top, 4) }
                }
                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                    row("Version", item.installedVersion ?? "—")
                    row("Path", DisplayPath.abbreviate(item.attributes?["path"] ?? ""))
                    row("Source", item.origin ?? "—")
                    if let seen = item.seenAt { row("Observed", time.absolute(seen)) }
                }
                if let note = item.note, item.state == .unknown { Text(note) }
                if let text = item.copiesText(copies.count) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(text).font(.headline)
                        ForEach(copies, id: \.key) { copy in
                            HStack {
                                Text(copy.installedVersion ?? "—").monospacedDigit()
                                Text(DisplayPath.abbreviate(copy.attributes?["path"] ?? "")).font(.callout.monospaced())
                                    .foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                                if copy.attributes?["oldCopy"] == "true" { Text("Old copy").font(.caption).foregroundStyle(.secondary) }
                            }
                        }
                    }
                }
                Text("Watchtower only reads versions here. It never runs these programs.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled)
        }
    }
}
