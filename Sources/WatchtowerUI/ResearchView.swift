import SwiftUI
import WatchtowerCore

// The `Incidents` screen (#12). The file name follows the issue. The screen and its sidebar item are
// `Incidents`. `Check Sources` reads the vendor sources. `Research` runs the optional Claude web research (#19).

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
            ResearchButton(model: model)
            HStack(spacing: 6) {
                if label.showsProgress { ProgressView().controlSize(.small) }
                Text(label.text).foregroundStyle(label.tone.color)
            }
            .accessibilityElement(children: .combine)
            Spacer()
        }
    }
}

/// `Research` (#19): the optional Claude web research. During a run: the elapsed time and `Stop` (⌘.).
struct ResearchButton: View {
    let model: IncidentModel

    var body: some View {
        if model.isResearching {
            // The timeline only redraws each second. The model clock gives the time, so previews stay fixed.
            TimelineView(.periodic(from: .now, by: 1)) { _ in
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text(model.researchElapsedText()).monospacedDigit()
                        .accessibilityLabel(model.researchAccessibilityText())
                    Button("Stop", systemImage: "stop.fill") { model.stopResearch() }
                        .buttonStyle(.bordered)
                        .keyboardShortcut(".", modifiers: .command)
                        .help("Stop the research. Nothing is saved.")
                }
                .fixedSize()
            }
        } else {
            Button {
                model.askResearch()
            } label: {
                Label("Research", systemImage: "magnifyingglass")
            }
            .buttonStyle(.bordered)
            .disabled(model.researchBlock != nil)
            .help(model.researchBlock ?? "Search public web news with Claude. You confirm the topics first.")
        }
    }
}

/// The confirm sheet before every research run: the exact topics sent and the limits.
public struct ResearchConfirmSheet: View {
    let model: IncidentModel

    public init(model: IncidentModel) {
        self.model = model
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Run Claude web research?").font(.title3.bold())
            Grid(alignment: .topLeading, horizontalSpacing: 16, verticalSpacing: 10) {
                GridRow {
                    Text("Topics sent").foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(model.researchStatus?.topics ?? [], id: \.self) { Text($0) }
                        Text("Nothing else leaves the Mac.").font(.callout).foregroundStyle(.secondary)
                    }
                }
                GridRow {
                    Text("Limits").foregroundStyle(.secondary)
                    Text(model.researchStatus?.limits ?? IncidentModel.researchLimits)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Text("Claims are saved as Unconfirmed. Only a primary source confirms them.")
                .font(.callout).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { model.showsResearchConfirm = false }
                    .keyboardShortcut(.cancelAction)
                Button("Run Research") { model.runResearch() }
            }
        }
        .padding(20)
        .frame(width: 440)
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
            if let notice = model.researchNotice {
                Label(notice, systemImage: "person.crop.circle.badge.exclamationmark").foregroundStyle(Tone.orange.color)
            }
            if let result = model.researchResult {
                Label(result.text, systemImage: "magnifyingglass").foregroundStyle(result.tone.color)
            }
            HStack(alignment: .top, spacing: 12) {
                ForEach(model.sourceRows()) { SourceCard(row: $0) }
            }
            if let note = model.hibpEmptyNote {
                Text(note).font(.callout).foregroundStyle(.secondary)
            }
            Text("Incidents").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            table
        }
        .padding([.horizontal, .top], 16)
        .frame(maxHeight: .infinity, alignment: .top)
        .sheet(isPresented: $model.showsResearchConfirm) { ResearchConfirmSheet(model: model) }
    }

    @ViewBuilder private var table: some View {
        let rows = model.visibleIncidents(search: search)
        if rows.isEmpty {
            empty
        } else {
            Table(rows, selection: $model.selectedID) {
                TableColumn("Service") { i in Text(i.service).fontWeight(.semibold).lineLimit(2) }
                    .width(min: 64, ideal: 78)
                TableColumn("Title") { i in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(i.title).lineLimit(2)
                        if i.isNew == true {
                            Text("New").font(.caption.weight(.semibold)).foregroundStyle(Color.watchtowerAccent)
                        }
                    }
                }
                .width(min: 100, ideal: 150)
                TableColumn("Date") { i in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(i.dateText()).foregroundStyle(.secondary)
                        if let added = i.addedText() {
                            Text(added).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                        }
                    }
                }
                .width(min: 84, ideal: 96)
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
    var breachRows: [(label: String, value: String)] = []
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
                    if incident.breach != nil {
                        ForEach(breachRows, id: \.label) { row($0.label, $0.value) }
                    } else {
                        row("Date", incident.published.map { time.day($0) } ?? "Not given by the source")
                        row("Source", incident.sourceName)
                        if incident.isWebResearch {
                            // Claude named this link. Watchtower did not check it, so it confirms nothing (#19).
                            row("Primary source", incident.primarySourceText)
                        }
                    }
                    row("First seen", time.absolute(incident.firstSeen))
                    if incident.breach == nil {
                        row("CVE", incident.cves.isEmpty ? "None named" : incident.cves.joined(separator: ", "))
                    }
                }
                if !incident.summary.isEmpty {
                    Text(incident.summary).textSelection(.enabled)
                }
                if let link = incident.link {
                    Link(destination: link) { Label("Open the source page", systemImage: "arrow.up.right.square") }
                }
                if incident.breach != nil {
                    // Watchtower never checks an account. The owner does that on the HIBP site.
                    (Text("Watchtower does not check your account. Visit ")
                        + Text("[haveibeenpwned.com](https://haveibeenpwned.com)")
                        + Text(" to check it yourself."))
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("Watchtower does not know if this affects your accounts.")
                        .font(.caption).foregroundStyle(.secondary)
                }
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
