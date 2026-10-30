import SwiftUI
import WatchtowerCore

// The `Incidents` screen (#12). The file name follows the issue. The screen and its sidebar item are
// `Incidents`, and the button is `Check Sources`: `Research` is kept for the v2 Claude research.

/// A status badge for an incident: Confirmed (red), Possible relevance (orange), Unconfirmed (gray).
struct IncidentStatusBadge: View {
    let status: IncidentStatus

    var body: some View {
        StatusBadge.Capsule(text: status.text, symbol: status.symbol, color: status.tone.color)
            .help(status.meaning)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Status: \(status.text). \(status.meaning)")
    }
}

/// Check Sources (becomes Stop during a check) and the review label.
struct CheckSourcesBar: View {
    let model: IncidentModel

    var body: some View {
        let label = model.label()
        HStack(spacing: 12) {
            if model.isChecking {
                Button {
                    model.stop()
                } label: {
                    Label("Stop", systemImage: "stop.fill")
                }
                .buttonStyle(.bordered)
                .help("Stop the check. The saved records stay.")
            } else {
                Button {
                    model.check()
                } label: {
                    Label("Check Sources", systemImage: "antenna.radiowaves.left.and.right")
                }
                .buttonStyle(.bordered)
                .help("Check the vendor sources now. This does not start a refresh.")
            }
            HStack(spacing: 6) {
                if label.showsProgress { ProgressView().controlSize(.small) }
                Text(label.text).foregroundStyle(label.tone.color)
            }
            .accessibilityElement(children: .combine)
            Spacer()
        }
    }
}

/// One card for each source.
struct SourceCard: View {
    let row: IncidentSourceRow

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(row.label).fontWeight(.semibold).lineLimit(1)
            StatusBadge.Capsule(text: row.badge, symbol: row.symbol, color: row.tone.color)
            Text(row.lastSuccess).font(.caption).foregroundStyle(.secondary)
            if let error = row.error {
                Text(error).font(.caption).foregroundStyle(Tone.orange.color)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, minHeight: 104, alignment: .topLeading)
        .background(.background, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(.separator))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(row.label), \(row.badge). \(row.lastSuccess).\(row.error.map { " \($0)" } ?? "")")
    }
}

/// The list pane of `Incidents`: the bar, banners, source cards and the incident table.
public struct IncidentsView: View {
    @Bindable var model: IncidentModel
    let search: String

    public init(model: IncidentModel, search: String = "") {
        self.model = model
        self.search = search
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            CheckSourcesBar(model: model)
            ForEach(model.gapBanners(), id: \.self) { text in
                Label(text, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(Tone.orange.color)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Tone.orange.color.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
            }
            if let error = model.lastError {
                Label(error.message, systemImage: "exclamationmark.triangle").foregroundStyle(Tone.orange.color)
            }
            HStack(alignment: .top, spacing: 12) {
                ForEach(model.sourceRows()) { SourceCard(row: $0) }
            }
            Text("Incidents").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            table
        }
        .padding([.horizontal, .top], 16)
        .frame(maxHeight: .infinity, alignment: .top)
    }

    @ViewBuilder private var table: some View {
        let rows = model.visibleIncidents(search: search)
        if rows.isEmpty {
            empty
        } else {
            Table(rows, selection: $model.selectedID) {
                TableColumn("Service") { i in Text(i.service).fontWeight(.semibold).lineLimit(2) }
                    .width(min: 64, ideal: 78)
                TableColumn("Title") { i in Text(i.title).lineLimit(2) }
                    .width(min: 100, ideal: 150)
                TableColumn("Date") { i in
                    Text(i.published.map { TimeText().day($0) } ?? "—").foregroundStyle(.secondary)
                }
                .width(min: 44, ideal: 52)
                TableColumn("Status") { i in IncidentStatusBadge(status: i.status) }
                    .width(min: 128, ideal: 138)
                TableColumn("Source") { i in
                    Text(i.sourceName).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                }
                .width(min: 70, ideal: 84)
            }
        }
    }

    @ViewBuilder private var empty: some View {
        if !search.isEmpty {
            ContentUnavailableView.search(text: search)
        } else if model.showsEmptyResult {
            ContentUnavailableView(IncidentModel.emptyTitle, systemImage: "antenna.radiowaves.left.and.right",
                                   description: Text(IncidentModel.emptyText))
        } else if model.state?.review.lastAttemptState != nil {
            ContentUnavailableView("No incidents saved", systemImage: "antenna.radiowaves.left.and.right",
                                   description: Text("No review is complete yet. " + IncidentModel.emptyText))
        } else {
            ContentUnavailableView("Not checked yet", systemImage: "antenna.radiowaves.left.and.right",
                                   description: Text("Click Check Sources to read the vendor sources."))
        }
    }
}

/// The detail pane: the record as text. The title and the summary come from a feed. They are shown
/// as plain text, and the link opens only in the browser.
struct IncidentDetail: View {
    let incident: IncidentRecord
    private let time = TimeText()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text(incident.id).font(.callout.monospaced().bold()).foregroundStyle(.secondary)
                Text(incident.title).font(.system(size: DesignTokens.detailTitleSize, weight: .bold))
                    .textSelection(.enabled)
                IncidentStatusBadge(status: incident.status)
                Text(incident.status.meaning).foregroundStyle(.secondary)
                Grid(alignment: .topLeading, horizontalSpacing: 16, verticalSpacing: 6) {
                    row("Service", incident.service)
                    row("Date", incident.published.map { time.day($0) } ?? "Not given by the source")
                    row("Source", incident.sourceName)
                    row("First seen", time.absolute(incident.firstSeen))
                    if !incident.cves.isEmpty {
                        row("CVE", incident.cves.joined(separator: ", "))
                    } else {
                        row("CVE", "None named")
                    }
                }
                if !incident.summary.isEmpty {
                    Text(incident.summary).textSelection(.enabled)
                }
                if let link = incident.link {
                    Link(destination: link) { Label("Open the source page", systemImage: "arrow.up.right.square") }
                }
                Text("Watchtower does not know if this affects your accounts.")
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
