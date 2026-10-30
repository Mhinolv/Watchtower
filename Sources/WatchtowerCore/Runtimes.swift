import Foundation

// Runtimes, SDKs and editor extensions that are installed on this Mac (#16). The engine lists folders and
// reads version files. It never runs a program. These items are not project manifests: the Projects list
// never shows them.

public enum RuntimeGroup: String, CaseIterable, Identifiable, Sendable {
    case runtime, sdk, `extension`

    public var id: String { rawValue }

    /// The section header: `Runtimes`, `SDKs`, `Editor extensions`.
    public var title: String {
        switch self {
        case .runtime: "Runtimes"
        case .sdk: "SDKs"
        case .extension: "Editor extensions"
        }
    }
}

/// One install: one row of the list.
public struct RuntimeRow: Identifiable, Equatable, Sendable {
    public var id: String
    /// The runtime name, or the extension id.
    public var name: String
    /// Under the name: `Old copy`, and for an extension the editor (`VS Code`, `Cursor`).
    public var secondary: String?
    public var version: String
    /// `~` form.
    public var path: String
    public var source: String
    /// nil for the newest copy: it shows normally. `Unknown` for an old copy or a version that cannot be read.
    public var badge: ItemState?
    /// `Version not found in <file>.` for an unreadable version.
    public var note: String?
    public var isOld: Bool
    /// The vendor support of a runtime (#59). nil for an SDK, an extension, or a scan from before #59.
    public var support: SupportStatus?
}

public struct RuntimeSection: Identifiable, Equatable, Sendable {
    public var group: RuntimeGroup
    public var rows: [RuntimeRow]
    /// `Cannot read ~/.nvm: permission denied.` Shown above the group.
    public var rootErrors: [String]

    public var id: String { group.id }
}

extension RuntimeRow {
    public init(_ item: ItemRecord, home: String = NSHomeDirectory(), now: Date = Date(), time: TimeText = TimeText()) {
        let attributes = item.attributes ?? [:]
        let old = attributes["oldCopy"] == "true"
        var secondary: [String] = []
        if item.kind == "extension", let editor = attributes["editor"] ?? item.origin { secondary.append(editor) }
        if old { secondary.append("Old copy") }
        self.init(id: item.key, name: item.name, secondary: secondary.isEmpty ? nil : secondary.joined(separator: " · "),
                  version: item.installedVersion ?? "—",
                  path: DisplayPath.abbreviate(attributes["path"] ?? "", home: home), source: item.origin ?? "—",
                  badge: item.state == .manual ? nil : item.state,
                  note: item.installedVersion == nil ? item.note : nil, isOld: old,
                  support: SupportStatus(item, now: now, time: time))
    }
}

extension DashboardModel {
    /// The three groups with their rows and root errors. A group with no row and no error is left out.
    public var runtimeSections: [RuntimeSection] {
        let query = searchText.trimmingCharacters(in: .whitespaces)
        let errors = runtimeRootErrors
        let now = currentDate
        let all = items(in: .runtimes)
        return RuntimeGroup.allCases.compactMap { group in
            let found = all.filter { $0.kind == group.rawValue }.map { RuntimeRow($0, now: now) }.filter { row in
                query.isEmpty || [row.name, row.version, row.path, row.source].contains { $0.localizedCaseInsensitiveContains(query) }
            }
            // `End of life` first inside a group (#59). The other order stays: name, then newest version.
            let rows = found.enumerated().sorted { a, b in
                let (x, y) = (a.element.support?.state == .endOfLife ? 0 : 1, b.element.support?.state == .endOfLife ? 0 : 1)
                return x == y ? a.offset < b.offset : x < y
            }.map(\.element)
            let own = errors[group] ?? []
            return rows.isEmpty && own.isEmpty ? nil : RuntimeSection(group: group, rows: rows, rootErrors: own)
        }
    }

    /// Root errors from the `runtimes` coverage detail: `Runtimes: Cannot read ~/.nvm: permission denied.`
    public var runtimeRootErrors: [RuntimeGroup: [String]] {
        guard let detail = state?.coverage.first(where: { $0.source == "runtimes" })?.detail else { return [:] }
        var out: [RuntimeGroup: [String]] = [:]
        for line in detail.split(separator: "\n") {
            for group in RuntimeGroup.allCases where line.hasPrefix(group.title + ": Cannot read") {
                out[group, default: []].append(String(line.dropFirst(group.title.count + 2)))
            }
        }
        return out
    }

    /// Every copy of the same thing: `3 versions installed`. Empty for an item that has no copies.
    public func runtimeCopies(of item: ItemRecord) -> [ItemRecord] {
        guard let family = item.attributes?["family"] else { return [] }
        return items(in: .runtimes).filter { $0.attributes?["family"] == family }
    }

    public var hasRuntimeItems: Bool { !items(in: .runtimes).isEmpty }
}

extension ItemRecord {
    /// `3 versions installed`, or nil for a single copy.
    public func copiesText(_ count: Int) -> String? {
        count > 1 ? "\(count) versions installed" : nil
    }
}
