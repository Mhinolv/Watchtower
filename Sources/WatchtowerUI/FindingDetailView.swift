import AppKit
import SwiftUI
import WatchtowerCore

/// Severity: symbol, text and color. The text is always shown.
struct SeverityBadge: View {
    let severity: Severity

    var body: some View {
        let style = SeverityStyle(severity)
        Label(style.text, systemImage: style.symbol)
            .foregroundStyle(style.tone.color)
            .labelStyle(.titleAndIcon)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Severity: \(style.text)")
    }
}

/// Finding status: symbol, text and color.
struct FindingStatusBadge: View {
    let finding: FindingRecord
    var full = true

    var body: some View {
        let style = FindingStatusText(finding, full: full)
        Label(style.text, systemImage: style.symbol)
            .foregroundStyle(style.tone.color)
            .labelStyle(.titleAndIcon)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Status: \(style.text)")
    }
}

/// The detail of one finding: where it is, the fix, the aliases and when it was seen.
public struct FindingDetailView: View {
    let model: DashboardModel
    let finding: FindingRecord
    private let time = TimeText()

    public init(model: DashboardModel, finding: FindingRecord) {
        self.model = model
        self.finding = finding
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if model.showsPartialBanner(for: finding) {
                    Label("The last scan was partial. This finding stays open.", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
                }
                header
                actions
                affected
                facts
                source
                if !finding.nextSteps.isEmpty {
                    section("Next steps") {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(finding.nextSteps, id: \.self) { Text($0) }
                        }
                    }
                }
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // Header

    /// `SEC-0001 lodash@4.17.20`, the title, then severity and status.
    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(finding.id).font(.callout.monospaced().bold())
                Text(packageAtVersion).foregroundStyle(.secondary)
            }
            Text(finding.title).font(.title2).bold().textSelection(.enabled)
            HStack(spacing: 14) {
                SeverityBadge(severity: finding.severity)
                FindingStatusBadge(finding: finding)
            }
        }
    }

    /// The version is shown when every path has the same one.
    private var packageAtVersion: String {
        let versions = Set(finding.paths.map(\.version))
        return versions.count == 1 ? "\(finding.package)@\(versions.first!)" : finding.package
    }

    /// No Mark Resolved button: only a complete scan resolves a finding. The `Update…` button is
    /// not here: no update adapter exists for lockfiles yet (#10, #11).
    @ViewBuilder private var actions: some View {
        HStack {
            switch finding.status {
            case .open:
                Menu("Defer") {
                    Button("7 Days") { Task { await model.deferFinding(finding, days: 7) } }
                    Button("30 Days") { Task { await model.deferFinding(finding, days: 30) } }
                }
                .fixedSize()
                Button("Move to Backlog") { Task { await model.moveToBacklog(finding) } }
            case .deferred, .backlog:
                Button("Reopen") { Task { await model.reopen(finding) } }
                if finding.status == .deferred {
                    Button("Move to Backlog") { Task { await model.moveToBacklog(finding) } }
                }
            case .resolved:
                EmptyView()
            }
        }
    }

    // Sections

    @ViewBuilder private var affected: some View {
        section("Affected (\(finding.paths.count))") {
            if finding.paths.isEmpty {
                Text("No local path has this package any more.").foregroundStyle(.secondary)
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(finding.paths.enumerated()), id: \.element.id) { index, path in
                        if index > 0 { Divider() }
                        HStack(alignment: .center) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(path.projectPath).bold()
                                Text(path.lockfile).font(.caption.monospaced()).foregroundStyle(.secondary)
                                Text("\(finding.package)@\(path.version)")
                                    .font(.caption.monospaced()).foregroundStyle(.secondary)
                                Text(path.dependencyPath.map { "Path: " + $0.joined(separator: " › ") }
                                     ?? "Dependency path not available.")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            .textSelection(.enabled)
                            Spacer()
                            Button("Reveal in Finder", systemImage: "folder") {
                                NSWorkspace.shared.activateFileViewerSelecting([path.lockfileURL])
                            }
                            .controlSize(.small)
                            .help("Show \(path.lockfile) in Finder")
                        }
                        .padding(10)
                        .accessibilityElement(children: .contain)
                    }
                }
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(.separator))
            }
        }
    }

    /// Fixed in, Aliases and Seen as label and value rows.
    private var facts: some View {
        Grid(alignment: .topLeading, horizontalSpacing: 16, verticalSpacing: 6) {
            GridRow {
                Text("Fixed in").foregroundStyle(.secondary)
                Text(finding.fixedIn ?? "No fixed version is known.")
                    .foregroundStyle(finding.fixedIn == nil ? .secondary : .primary)
                    .textSelection(.enabled)
            }
            GridRow {
                Text("Aliases").foregroundStyle(.secondary)
                aliases
            }
            GridRow {
                Text("Seen").foregroundStyle(.secondary)
                Text("First seen \(time.day(finding.firstSeen)). Last seen \(time.day(finding.lastSeen)).")
            }
        }
    }

    /// Selectable ids. Each one links to its source page.
    private var aliases: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(finding.sortedAdvisoryIds, id: \.self) { id in
                HStack(spacing: 6) {
                    Text(id).font(.callout.monospaced()).textSelection(.enabled)
                    if let url = AdvisoryLink.url(for: id) {
                        Link(destination: url) { Image(systemName: "arrow.up.right.square") }
                            .help("Open \(id) at its source")
                            .accessibilityLabel("Open \(id) at its source")
                    }
                }
            }
        }
    }

    /// The source line: green check if the last scan was complete, else an orange warning.
    private var source: some View {
        section("Source") {
            let at = finding.sourceAt.map { "retrieved \(time.absolute($0))" } ?? "no retrieval time"
            let complete = model.state?.coverage.first { $0.source == finding.source.lowercased() }?.state == .complete
            Label("\(finding.source): \(at)", systemImage: complete ? "checkmark.circle" : "exclamationmark.triangle")
                .foregroundStyle(complete ? Color.primary : .orange)
                .symbolRenderingMode(.hierarchical)
                .labelStyle(.titleAndIcon)
        }
    }

    private func section<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            content()
        }
    }
}

/// The findings table with the filter control above it.
struct FindingTable: View {
    @Bindable var model: DashboardModel
    private let time = TimeText()

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("Show", selection: $model.findingFilter) {
                    ForEach(FindingFilter.allCases) { Text($0.title).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .accessibilityLabel("Show findings")
                .frame(maxWidth: 260)
                Spacer()
                Text("Sorted by severity, then last seen").font(.caption).foregroundStyle(.secondary)
            }
            .padding(10)
            let rows = model.visibleFindings
            if rows.isEmpty {
                emptyState.frame(maxHeight: .infinity)
            } else {
                Table(rows, selection: $model.selectedItemKey) {
                    TableColumn("ID") { f in
                        Text(f.id).font(.body.monospaced())
                            .accessibilityLabel("\(f.id), \(f.package), \(SeverityStyle(f.severity).text) severity, "
                                                + FindingStatusText(f, full: false).text)
                    }
                    .width(min: 62, ideal: 70)
                    TableColumn("Package") { f in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(f.package)
                            Text(packageDetail(f)).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .width(min: 80, ideal: 100)
                    TableColumn("Severity") { f in SeverityBadge(severity: f.severity) }
                        .width(min: 78, ideal: 86)
                    TableColumn("Projects") { f in Text(f.projectNames.isEmpty ? "—" : "\(f.projectNames.count)") }
                        .width(min: 46, ideal: 52)
                    TableColumn("Status") { f in FindingStatusBadge(finding: f, full: false) }
                        .width(min: 136, ideal: 146)
                    TableColumn("Last seen") { f in Text(time.day(f.lastSeen)) }
                        .width(min: 62, ideal: 70)
                }
            }
        }
    }

    /// `4.17.20 · npm`. The version is left out if the paths have different versions.
    private func packageDetail(_ f: FindingRecord) -> String {
        let versions = Set(f.paths.map(\.version))
        return [versions.count == 1 ? versions.first : nil, f.ecosystem].compactMap { $0 }.joined(separator: " · ")
    }

    @ViewBuilder private var emptyState: some View {
        if !model.searchText.isEmpty {
            ContentUnavailableView.search(text: model.searchText)
        } else if model.state?.refresh == nil {
            ContentUnavailableView("Never refreshed", systemImage: "arrow.clockwise",
                                   description: Text("Click Refresh to check this Mac."))
        } else {
            ContentUnavailableView("No findings", systemImage: "checkmark.shield",
                                   description: Text(model.findingFilter == .open
                                                     ? "No scanned lockfile has a known vulnerability."
                                                     : "Nothing matches this filter."))
        }
    }
}
