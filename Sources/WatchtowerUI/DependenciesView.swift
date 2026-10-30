import SwiftUI
import WatchtowerCore

// The `Dependencies` table of the Projects detail (#81): one section for each manifest, one row for each direct
// dependency. `Update…` opens the plan of the requirements.txt (#30) or Cargo (#15) adapter for the latest version.
// A row that the adapter would refuse has `Update…` off with the reason. There is no "update all".

struct DependenciesView: View {
    let model: DashboardModel
    let project: ProjectRecord
    @Environment(DependencyModel.self) private var dependencies: DependencyModel?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Dependencies").font(.headline)
            switch dependencies?.load(for: project.path) {
            case .loading, nil:
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Reading dependencies…").foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
            case .failed(let error):
                Label(error.message, systemImage: "exclamationmark.triangle").foregroundStyle(Tone.orange.color)
            case .loaded(let list):
                if !list.supported {
                    Text(DependencyList.unsupportedText).foregroundStyle(.secondary)
                }
                if list.pending > 0 { pendingLine(list.pending) }
                ForEach(list.sections) { SectionView(model: model, section: $0) }
            }
        }
        .task(id: project.path) { await dependencies?.load(project) }
    }

    /// While the model asks the registries: the count that is left. After a stop: a button to ask for the rest.
    @ViewBuilder private func pendingLine(_ count: Int) -> some View {
        HStack(spacing: 8) {
            if dependencies?.isChecking(project.path) == true {
                ProgressView().controlSize(.small)
                Text("Checking latest versions… \(count) left").foregroundStyle(.secondary)
            } else {
                Text("\(count) \(count == 1 ? "package is" : "packages are") not checked yet.").foregroundStyle(.secondary)
                Button("Check the rest") { Task { await dependencies?.load(project) } }.controlSize(.small)
            }
        }
        .font(.callout)
        .accessibilityElement(children: .combine)
    }
}

private enum Column {
    // The detail pane is about 460 points wide: the badge and the Update… button share the last column.
    static let declared: CGFloat = 84, installed: CGFloat = 60, latest: CGFloat = 56, status: CGFloat = 130
}

private struct SectionView: View {
    let model: DashboardModel
    let section: DependencySection
    private let time = TimeText()

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(section.header).font(.subheadline.weight(.semibold)).foregroundStyle(.secondary)
            if let refusal = section.refusal {
                Label(refusal, systemImage: "hand.raised").font(.callout).foregroundStyle(Tone.orange.color)
            }
            if section.rows.isEmpty {
                if section.refusal == nil { Text(section.emptyText).foregroundStyle(.secondary) }
            } else {
                header
                Divider()
                ForEach(section.rows) { row in
                    RowView(model: model, row: row, help: section.latestSource.helpText(time: time))
                    Divider()
                }
            }
        }
    }

    private var header: some View {
        HStack(spacing: 8) {
            Text("Package").frame(maxWidth: .infinity, alignment: .leading)
            Text("Declared").frame(width: Column.declared, alignment: .leading)
            Text("Installed").frame(width: Column.installed, alignment: .leading)
            Text("Latest").frame(width: Column.latest, alignment: .leading)
            Text("Status").frame(width: Column.status, alignment: .leading)
        }
        .font(.caption.bold())
        .foregroundStyle(.secondary)
    }
}

private struct RowView: View {
    let model: DashboardModel
    let row: DependencyRow
    let help: String
    @Environment(UpdateModel.self) private var updates: UpdateModel?

    var body: some View {
        HStack(alignment: .center, spacing: 8) {
            Text(row.packageText).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading)
            VStack(alignment: .leading, spacing: 1) {
                Text(row.declaredText).font(.callout.monospaced()).lineLimit(1).minimumScaleFactor(0.8)
                Text(row.evidenceText).font(.caption).foregroundStyle(row.evidence == "exact_pin" ? Color.primary : Color.secondary)
            }
            .frame(width: Column.declared, alignment: .leading)
            VStack(alignment: .leading, spacing: 1) {
                Text(row.installed ?? "—").font(.callout.monospaced())
                if row.installed != nil { Text(row.installedLabel).font(.caption).foregroundStyle(.secondary) }
            }
            .frame(width: Column.installed, alignment: .leading)
            Group {
                if row.latest == nil, row.latestReason != nil {  // Not checked yet, no stable release, or a failure.
                    Text(row.latestText).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                } else {
                    Text(row.latestText).font(.callout.monospaced())
                }
            }
            .help(row.latestReason ?? help)
            .frame(width: Column.latest, alignment: .leading)
            VStack(alignment: .leading, spacing: 4) {
                statusCell
                updateButton
            }
            .frame(width: Column.status, alignment: .leading)
        }
        .padding(.vertical, 4)
        .frame(minHeight: 34)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(row.accessibilityText)
    }

    /// `Vulnerable` opens the finding. The other states are plain badges.
    @ViewBuilder private var statusCell: some View {
        if row.status == .vulnerable, let id = row.findingId {
            Button { model.openFinding(id) } label: { StatusBadge(.vulnerable) }
                .buttonStyle(.plain)
                .help("Open \(id) in Findings")
        } else {
            StatusBadge(row.status)
        }
    }

    @ViewBuilder private var updateButton: some View {
        switch row.update {
        case .plan(let key):
            Button("Update…") { Task { await updates?.start(itemKey: key, name: row.package) } }
                .controlSize(.small)
                .disabled(updates == nil)
                .help("Show the update plan for \(row.package) \(row.latest ?? ""). Nothing runs before you confirm.")
        case .off(let reason):
            Button("Update…") {}.controlSize(.small).disabled(true).help(reason)
        }
    }
}
