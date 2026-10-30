import SwiftUI
import WatchtowerCore

/// The main window: sidebar, list, detail.
public struct DashboardView: View {
    @Bindable var model: DashboardModel
    @Environment(UpdateModel.self) private var updates: UpdateModel?
    @Environment(IncidentModel.self) private var incidents: IncidentModel?

    public init(model: DashboardModel) {
        self.model = model
    }

    public var body: some View {
        NavigationSplitView {
            List(selection: $model.selection) {
                ForEach(SidebarGroup.allCases) { group in
                    Section(group.title) {
                        ForEach(group.sections) { section in
                            SidebarRow(section: section, count: count(section))
                                .tag(section)
                        }
                    }
                }
            }
            .safeAreaInset(edge: .bottom) { SettingsRow() }
            .navigationSplitViewColumnWidth(min: 190, ideal: DesignTokens.sidebarWidth)
        } content: {
            ListPane(model: model, section: model.selection ?? .apps)
                .navigationSplitViewColumnWidth(min: 600, ideal: DesignTokens.listWidth)
        } detail: {
            DetailPane(model: model, section: model.selection ?? .apps)
                .navigationSplitViewColumnWidth(min: 320, ideal: 400)
        }
        .searchable(text: $model.searchText, placement: .toolbar, prompt: "Search")
        .toolbar {
            ToolbarItemGroup(placement: .navigation) {
                Text((model.selection ?? .apps).title)
                    .font(.system(size: 15, weight: .bold))
                    .padding(.horizontal, 6)
                    .accessibilityAddTraits(.isHeader)
                // Incidents has its own Check Sources button. A refresh does not run the check.
                if model.selection != .incidents {
                    RefreshButton(model: model)
                    RefreshLabelView(model: model)
                }
            }
        }
        .toolbar(removing: .title)
        .onChange(of: model.selection) {
            model.selectedItemKey = nil
            model.itemFilter = .all
        }
        .modifier(UpdateSheetHost())
        .tint(.watchtowerAccent)
    }

    func count(_ section: SidebarSection) -> Int? {
        if section == .incidents { return incidents?.count ?? 0 }
        return section == .updateLog ? nil : model.count(section)
    }
}

/// One sidebar row: symbol, title, count in a gray capsule (red for open findings), shortcut.
struct SidebarRow: View {
    let section: SidebarSection
    let count: Int?

    var body: some View {
        HStack(spacing: 8) {
            Label(section.title, systemImage: section.symbol)
            Spacer(minLength: 4)
            if let count {
                CountCapsule(count: count, alert: section == .findings && count > 0)
            }
            Text(verbatim: "⌘\(section.shortcutDigit)")
                .font(.system(size: 11))
                .foregroundStyle(.tertiary)
        }
        .frame(minHeight: 28)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(count.map { "\(section.title), \($0)" } ?? section.title)
    }
}

/// `Settings…` with ⌘, at the bottom of the sidebar.
struct SettingsRow: View {
    var body: some View {
        SettingsLink {
            HStack {
                Label("Settings…", systemImage: "gearshape")
                Spacer()
                Text("⌘,").font(.system(size: 11)).foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }
}

/// Refresh (⌘R). During a refresh it becomes Stop (⌘.).
public struct RefreshButton: View {
    let model: DashboardModel

    public init(model: DashboardModel) {
        self.model = model
    }

    public var body: some View {
        if model.isRefreshing {
            Button {
                model.stop()
            } label: {
                ToolbarButtonLabel(title: "Stop", symbol: "stop.fill", shortcut: "⌘.")
            }
            .buttonStyle(.bordered)
            .keyboardShortcut(".", modifiers: .command)
            .help("Stop the refresh. The previous results stay.")
        } else {
            Button {
                model.refresh()
            } label: {
                ToolbarButtonLabel(title: "Refresh", symbol: "arrow.clockwise", shortcut: "⌘R")
            }
            .buttonStyle(.bordered)
            .keyboardShortcut("r", modifiers: .command)
            .help("Check every source again")
        }
    }
}

// MARK: - List pane

struct ListPane: View {
    @Bindable var model: DashboardModel
    let section: SidebarSection
    @Environment(UpdateModel.self) private var updates: UpdateModel?
    @Environment(IncidentModel.self) private var incidents: IncidentModel?

    var body: some View {
        Group {
            if section == .incidents {
                if let incidents {
                    IncidentsView(model: incidents, search: model.searchText)
                } else {
                    ContentUnavailableView("Incidents are not available here.", systemImage: section.symbol)
                }
            } else if section == .updateLog {
                if let updates {
                    UpdateLogTable(model: updates)
                } else {
                    ContentUnavailableView("No updates yet", systemImage: section.symbol)
                }
            } else if section == .findings {
                FindingTable(model: model)
            } else if section == .backlog {
                BacklogTable(model: model)
            } else if section.listsItems {
                ItemTable(model: model, section: section)
            } else {
                ProjectTable(model: model, section: section)
            }
        }
        .navigationTitle(section.title)
    }
}

struct ItemTable: View {
    @Bindable var model: DashboardModel
    let section: SidebarSection
    @Environment(UpdateModel.self) private var updates: UpdateModel?

    var body: some View {
        let rows = model.visibleItems(in: section).map(ItemRow.init)
        let chips = model.filterChips(in: section)
        VStack(spacing: 0) {
            if model.state?.refresh != nil, !model.items(in: section).isEmpty {
                HStack(spacing: 8) {
                    ForEach(chips) { chip in
                        FilterChipButton(chip: chip) { model.toggleFilter(chip.filter) }
                    }
                    Spacer()
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                Divider()
            }
            if rows.isEmpty {
                emptyState
            } else {
                table(rows)
            }
        }
    }

    func table(_ rows: [ItemRow]) -> some View {
            Table(rows, selection: $model.selectedItemKey) {
                TableColumn("Name") { row in
                    HStack(spacing: 8) {
                        ItemIcon(name: row.item.name)
                        Text(row.item.name).fontWeight(.medium)
                    }
                    .frame(height: DesignTokens.tableRowHeight - 8)
                }
                    .width(min: 110, ideal: 130)
                TableColumn("Installed") { row in Text(row.item.installedVersion ?? "—") }
                    .width(min: 56, ideal: 70)
                TableColumn("Latest") { row in Text(row.item.latestVersion ?? "—") }
                    .width(min: 56, ideal: 70)
                TableColumn("Source") { row in Text(sourceText(row.item)) }
                    .width(min: 70, ideal: 90)
                TableColumn("Status") { row in StatusBadge(row.item.state) }
                    .width(min: 140, ideal: 150)
            }
            .contextMenu(forSelectionType: String.self) { keys in
                if keys.count == 1, let key = keys.first,
                   let item = model.state?.items.first(where: { $0.key == key }) {
                    Button("Update…") { Task { await updates?.start(item) } }
                        .disabled(updates == nil || UpdatePolicy.blockReason(item) != nil)
                }
            }
    }

    @ViewBuilder var emptyState: some View {
        if model.itemFilter != .all || (!model.searchText.isEmpty && !model.items(in: section).isEmpty) {
            ContentUnavailableView("No items match this filter.", systemImage: "line.3.horizontal.decrease.circle")
        } else if !model.searchText.isEmpty {
            ContentUnavailableView.search(text: model.searchText)
        } else if model.state?.refresh == nil {
            ContentUnavailableView("Never refreshed", systemImage: "arrow.clockwise",
                                   description: Text("Click Refresh to check this Mac."))
        } else {
            ContentUnavailableView("Nothing here", systemImage: section.symbol,
                                   description: Text("The last refresh found no \(section.title.lowercased())."))
        }
    }

    /// The Source column: a fixed label for each kind (#33), never a title-cased raw value.
    func sourceText(_ item: ItemRecord) -> String {
        let source = model.state?.coverage.first { $0.source == item.source }?.label ?? item.source
        return SourceLabel.text(kind: item.kind, sourceLabel: source, origin: item.origin, project: item.project)
    }
}

/// The Backlog section: inactive projects and findings in one table (Name, Kind, Status).
struct BacklogTable: View {
    @Bindable var model: DashboardModel

    var body: some View {
        let rows = model.visibleBacklog()
        VStack(alignment: .leading, spacing: 0) {
            Text(BacklogEntry.headline)
                .font(.callout)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
            Divider()
            if rows.isEmpty {
                empty.frame(maxHeight: .infinity)
            } else {
                Table(rows, selection: $model.selectedItemKey) {
                    TableColumn("Name") { entry in
                        HStack(spacing: 8) {
                            Image(systemName: entry.symbol)
                                .font(.system(size: 12))
                                .foregroundStyle(.white)
                                .frame(width: DesignTokens.rowIconSize, height: DesignTokens.rowIconSize)
                                .background(Tone.gray.color, in: RoundedRectangle(cornerRadius: DesignTokens.rowIconRadius))
                                .accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: 1) {
                                if case .finding(let f) = entry {
                                    (Text(f.id).font(.body.monospaced()) + Text(" \(f.package)")).lineLimit(1)
                                } else {
                                    Text(entry.name).lineLimit(1)
                                }
                                Text(entry.secondary).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                        }
                        .accessibilityElement(children: .ignore)
                        .accessibilityLabel("\(entry.kind) \(entry.name). \(entry.secondary). \(entry.statusText)")
                    }
                    .width(min: 200, ideal: 260)
                    TableColumn("Kind") { entry in Text(entry.kind) }
                        .width(min: 60, ideal: 70)
                    TableColumn("Status") { entry in Text(entry.statusText).foregroundStyle(.secondary) }
                        .width(min: 90, ideal: 120)
                }
            }
        }
    }

    @ViewBuilder private var empty: some View {
        if !model.searchText.isEmpty {
            ContentUnavailableView.search(text: model.searchText)
        } else {
            ContentUnavailableView(BacklogEntry.emptyTitle, systemImage: "archivebox",
                                   description: Text(BacklogEntry.emptyText))
        }
    }
}

struct ProjectTable: View {
    @Bindable var model: DashboardModel
    let section: SidebarSection

    var body: some View {
        let projects = model.visibleProjects(in: section)
        if projects.isEmpty {
            if !model.searchText.isEmpty {
                ContentUnavailableView.search(text: model.searchText)
            } else if section == .backlog {
                ContentUnavailableView("Backlog is empty", systemImage: "archivebox",
                                       description: Text("Turn a project off in Settings to move it here."))
            } else {
                ContentUnavailableView("No projects", systemImage: "folder",
                                       description: Text("Watchtower looks in ~/Projects and ~/Real."))
            }
        } else {
            Table(projects, selection: $model.selectedItemKey) {
                TableColumn("Name", value: \.name)
                TableColumn("Path") { p in Text(p.displayPath).foregroundStyle(.secondary) }
                TableColumn("Lockfiles") { p in Text("\(Lockfiles.count(p.manifests))") }
                TableColumn("Findings") { p in Text("\(model.findings(in: p).count)") }
            }
        }
    }
}

enum Lockfiles {
    static let names: Set<String> = [
        "package-lock.json", "uv.lock", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "poetry.lock",
        "Pipfile.lock", "Package.resolved", "Cargo.lock", "go.sum", "Gemfile.lock", "composer.lock",
    ]
    static let scanned: Set<String> = ["package-lock.json", "uv.lock"]

    static func list(_ manifests: [String]) -> [String] {
        manifests.filter { names.contains(($0 as NSString).lastPathComponent) }
    }

    static func count(_ manifests: [String]) -> Int { list(manifests).count }
}

// MARK: - Detail pane

struct DetailPane: View {
    @Bindable var model: DashboardModel
    let section: SidebarSection
    @Environment(UpdateModel.self) private var updates: UpdateModel?
    @Environment(IncidentModel.self) private var incidents: IncidentModel?

    var body: some View {
        if section == .incidents {
            if let incident = incidents?.selectedIncident {
                IncidentDetail(incident: incident)
            } else {
                ContentUnavailableView("No selection", systemImage: "sidebar.right",
                                       description: Text("Select an incident to see its record."))
            }
        } else if section == .updateLog, let attempt = updates?.selectedAttempt {
            UpdateLogDetail(attempt: attempt)
        } else if section == .updateLog {
            ContentUnavailableView("No selection", systemImage: "sidebar.right",
                                   description: Text("Select an update to see its command and output."))
        } else if section == .findings || (section == .backlog && model.selectedFinding != nil) {
            if let finding = model.selectedFinding {
                FindingDetailView(model: model, finding: finding)
            } else {
                ContentUnavailableView("No selection", systemImage: "sidebar.right",
                                       description: Text("Select a finding to see its details."))
            }
        } else if section.listsItems, let item = model.selectedItem {
            ItemDetail(model: model, item: item)
        } else if !section.listsItems,
                  let project = model.projects.first(where: { $0.path == model.selectedItemKey }) {
            ProjectDetail(model: model, project: project)
        } else {
            ContentUnavailableView("No selection", systemImage: "sidebar.right",
                                   description: Text("Select a row to see its details."))
        }
    }
}

struct ItemDetail: View {
    let model: DashboardModel
    let item: ItemRecord
    @State private var showsDetail = false
    @Environment(UpdateModel.self) private var updates: UpdateModel?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .top, spacing: 14) {
                    ItemIcon(name: item.name, size: DesignTokens.detailIconSize)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(item.name).font(.system(size: DesignTokens.detailTitleSize, weight: .bold))
                        Text(sourceLine).foregroundStyle(.secondary)
                        if let path = item.attributes?["path"] {
                            Text(DisplayPath.abbreviate(path)).font(.callout.monospaced()).foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                        StatusBadge(item.state).padding(.top, 4)
                    }
                    Spacer()
                    let blocked = updates == nil ? "Updates are not available here." : UpdatePolicy.blockReason(item)
                    if !item.isCatalogApp {
                        Button("Update…") { Task { await updates?.start(item) } }
                            .buttonStyle(.borderedProminent)
                            .disabled(blocked != nil)
                            .help(blocked ?? "Show the update plan. Nothing runs before you confirm.")
                    }
                }
                if item.source == "apps", item.vendorPageURL != nil || item.attributes?["path"] != nil {
                    HStack { appActions }
                }
                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                    row("Installed", item.installedVersion ?? "—")
                    row("Latest", item.latestVersion ?? "—")
                    if let from = item.latestFromText { row("Latest from", from) }
                    if let matched = item.matchedBy { row("Matched by", matched) }
                    if let kind = item.kind { row("Kind", kind) }
                    if let origin = item.origin { row(item.source == "apps" ? "Origin" : "Tap", origin) }
                    if let project = item.project { row("Project", project) }
                    ForEach((item.attributes ?? [:]).filter { !ItemRecord.catalogAttributeKeys.contains($0.key) }
                        .sorted(by: { $0.key < $1.key }), id: \.key) { pair in
                        row(pair.key, pair.value)
                    }
                }
                if let note = item.note {
                    Text(note)
                }
                if let error = item.error {
                    Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                    if let detail = item.detail {
                        DisclosureGroup("Details", isExpanded: $showsDetail) {
                            Text(detail).font(.callout.monospaced()).textSelection(.enabled)
                        }
                    }
                }
                Spacer(minLength: 20)
                if let age = model.sourceAgeText(for: item) {
                    Text(age).font(.caption).foregroundStyle(.secondary)
                }
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled)
        }
    }

    /// The manual route for an app (#55): the vendor page, if the cask has one, and Finder. Never `Update`.
    @ViewBuilder var appActions: some View {
        if let url = item.vendorPageURL {
            Button("Open Vendor Page", systemImage: "safari") { NSWorkspace.shared.open(url) }
                .help("Open \(url.host ?? url.absoluteString) in your browser")
        }
        if let path = item.attributes?["path"] {
            Button("Reveal in Finder", systemImage: "folder") {
                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
            }
            .help("Show the app in Finder")
        }
    }

    /// `Homebrew formula · acme/tools`, `Application`, `macOS`.
    var sourceLine: String {
        let kind: String = switch (item.source, item.kind) {
        case ("homebrew", "formula"): "Homebrew formula"
        case ("homebrew", "cask"): "Homebrew cask"
        case ("macos", _): "macOS"
        case ("apps", _): "Application"
        default: item.kind?.capitalized ?? item.source
        }
        return [kind, item.origin].compactMap { $0 }.joined(separator: " · ")
    }
}

/// Title, symbol and a quiet shortcut hint for a toolbar button.
struct ToolbarButtonLabel: View {
    let title: String
    let symbol: String
    let shortcut: String

    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: symbol)
            Text(title)
            Text(shortcut).font(.system(size: 11)).foregroundStyle(.tertiary)
        }
    }
}

struct ProjectDetail: View {
    let model: DashboardModel
    let project: ProjectRecord
    @Environment(UpdateModel.self) private var updates: UpdateModel?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text(project.name).font(.title2).bold()
                    Spacer()
                    if !project.isActive {
                        Button("Make active") {
                            Task { await model.setProject(project, active: true) }
                        }
                    }
                }
                Text(project.displayPath).foregroundStyle(.secondary).textSelection(.enabled)
                let lockfiles = Lockfiles.list(project.manifests)
                if lockfiles.isEmpty {
                    Text("No lockfile. Watchtower scans lockfiles only.")
                } else {
                    ForEach(lockfiles, id: \.self) { path in
                        let name = (path as NSString).lastPathComponent
                        Text(Lockfiles.scanned.contains(name) ? "\(path): scanned" : "\(path): not scanned (not supported yet)")
                    }
                }
                let findings = model.findings(in: project)
                if !findings.isEmpty {
                    Text("Findings").font(.headline)
                    ForEach(findings) { finding in
                        let path = finding.paths.first { $0.projectPath == project.displayPath }
                        HStack {
                            Text(finding.id).font(.callout.monospaced())
                            Text("\(finding.package) \(path?.version ?? "")")
                            Spacer()
                            SeverityBadge(severity: finding.severity)
                            if let path, UpdateKeys.forFinding(finding, path) != nil {
                                let block = updates == nil ? "Updates are not available here." : path.updateBlock
                                Button("Update…") { Task { await updates?.start(finding: finding, path: path) } }
                                    .controlSize(.small)
                                    .disabled(block != nil)
                                    .help(block ?? "Show the update plan for \(finding.package). Nothing runs before you confirm.")
                            }
                        }
                        if let path, let block = path.updateBlock, UpdateKeys.forFinding(finding, path) != nil {
                            Label(block, systemImage: "hand.raised").font(.caption).foregroundStyle(.orange)
                        }
                    }
                }
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
