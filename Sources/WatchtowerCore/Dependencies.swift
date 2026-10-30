import Foundation
import Observation

// The Projects `Dependencies` table (#81): the direct dependencies of one project, one section for each manifest
// (`requirements.txt`, `Cargo.toml`). The engine reads the files and asks PyPI or crates.io for the latest version.
// A row has the key of the update plan for the latest version, or the reason that the plan would refuse.
// This table replaces the first Cargo table of #15 and the planned table of #30.

/// Where the `Latest` column comes from.
public struct DependencyLatestSource: Codable, Hashable, Sendable {
    /// `PyPI` or `crates.io`.
    public var registry: String
    /// The oldest answer in use. nil if no answer was ever read.
    public var retrievedAt: Date?
    /// `PyPI did not respond.` if a request failed. An earlier answer may still show.
    public var error: String?

    public init(registry: String, retrievedAt: Date? = nil, error: String? = nil) {
        self.registry = registry
        self.retrievedAt = retrievedAt
        self.error = error
    }
}

public struct DependencyRow: Codable, Hashable, Sendable, Identifiable {
    public var package: String
    /// The requirement in the file: `==2.31.0`, `>=8.0,<9`, `1.0.190`. Empty for an unpinned requirement.
    public var declared: String
    /// `exact_pin`, `range`, `unpinned`, `git`, `path`, `workspace` or `other-registry`. A pin and a range are never merged.
    public var evidence: String
    public var installed: String?
    /// `.venv` or `locked`.
    public var installedLabel: String
    /// `dev-dependencies` or `build-dependencies`. nil: normal dependencies.
    public var table: String?
    public var latest: String?
    /// `PyPI did not respond.` if the request for this package failed.
    public var latestError: String?
    /// True if this read did not ask the registry for this package yet. Nothing failed.
    public var latestPending: Bool
    /// `No stable release.` if the registry answered and every release is a pre-release or yanked.
    public var latestNote: String?
    public var status: ItemState
    /// An open finding on this package in this project. The status is then `vulnerable`.
    public var findingId: String?
    public var severity: String?
    /// The key of the update plan for `latest`. nil if there is nothing to update or the plan would refuse.
    public var updateKey: String?
    /// The text of that refusal, as the plan gives it.
    public var updateRefusal: String?

    public var id: String { [table ?? "", package].joined(separator: "|") }

    public init(package: String, declared: String, evidence: String, installed: String?, installedLabel: String,
                table: String? = nil, latest: String?, latestError: String? = nil, latestPending: Bool = false,
                latestNote: String? = nil, status: ItemState, findingId: String? = nil, severity: String? = nil,
                updateKey: String? = nil, updateRefusal: String? = nil) {
        self.package = package
        self.declared = declared
        self.evidence = evidence
        self.installed = installed
        self.installedLabel = installedLabel
        self.table = table
        self.latest = latest
        self.latestError = latestError
        self.latestPending = latestPending
        self.latestNote = latestNote
        self.status = status
        self.findingId = findingId
        self.severity = severity
        self.updateKey = updateKey
        self.updateRefusal = updateRefusal
    }

    /// `Exact pin`, `Range`, `Unpinned`, `Git`, `Path`. Never one word for pins and ranges.
    public var evidenceText: String {
        switch evidence {
        case "exact_pin": "Exact pin"
        case "range": "Range"
        case "unpinned": "Unpinned"
        case "git": "Git"
        case "path": "Path"
        case "workspace": "Workspace"
        case "other-registry": "Other registry"
        default: evidence
        }
    }

    /// `serde`, or `memchr (dev)` for a dev or build dependency.
    public var packageText: String {
        switch table {
        case "dev-dependencies": "\(package) (dev)"
        case "build-dependencies": "\(package) (build)"
        default: package
        }
    }

    public var declaredText: String { declared.isEmpty ? "—" : declared }

    /// The `Latest` cell. A row that was not asked yet says so. A dash never stands for "not asked".
    public var latestText: String {
        if let latest { return latest }
        if latestPending { return "Not checked yet" }
        return latestNote == nil ? "—" : "No stable release"
    }

    /// The reason that no latest version shows: `Not checked yet.`, `No stable release.`, or the failure.
    public var latestReason: String? {
        if latest != nil { return nil }
        if latestPending { return "Not checked yet." }
        return latestError ?? latestNote
    }

    /// What the `Update…` button does: open the plan, or stay off with a reason.
    public enum Update: Equatable, Sendable {
        case plan(String)
        case off(String)
    }

    public var update: Update {
        if let key = updateKey { return .plan(key) }
        if let refusal = updateRefusal { return .off(refusal) }
        switch status {
        case .upToDate: return .off("Already the latest version.")
        case .vulnerable where latest != nil && latest == installed: return .off("Already the latest version.")
        default: return .off(latestReason ?? (latest == nil ? "The latest version is not known." : "No newer version is known."))
        }
    }

    /// VoiceOver: package, installed, latest and status of one row.
    public var accessibilityText: String {
        let state: String = switch status {
        case .vulnerable: "Vulnerable"
        case .updateAvailable: "Update available"
        case .upToDate: "Up to date"
        default: "Unknown"
        }
        return "\(package), declared \(declaredText), installed \(installed ?? "not known"), latest \(latest ?? (latestPending ? "not checked yet" : "not known")), \(state)"
    }
}

public struct DependencySection: Codable, Hashable, Sendable, Identifiable {
    /// The manifest, relative to the project folder: `requirements.txt`, `capture/Cargo.toml`.
    public var manifest: String
    /// `requirements` or `cargo`.
    public var kind: String
    public var rows: [DependencyRow]
    /// Why Update is off for the whole file: `requirements.txt with -r includes or hashes is not supported.`
    public var refusal: String?
    /// The rows that the registry was not asked for yet in this read.
    public var pending: Int
    public var latestSource: DependencyLatestSource

    public var id: String { manifest }

    public init(manifest: String, kind: String, rows: [DependencyRow], refusal: String? = nil, pending: Int = 0,
                latestSource: DependencyLatestSource) {
        self.manifest = manifest
        self.kind = kind
        self.rows = rows
        self.refusal = refusal
        self.pending = pending
        self.latestSource = latestSource
    }

    /// The manifest file name, the section header.
    public var header: String { manifest }

    /// `No direct dependencies in requirements.txt.`
    public var emptyText: String { "No direct dependencies in \((manifest as NSString).lastPathComponent)." }
}

/// Output of `watchtower dependencies <project>`.
public struct DependencyList: Codable, Hashable, Sendable {
    public var schemaVersion: Int
    public var project: String
    /// False if the project has no `requirements.txt` or `Cargo.toml`.
    public var supported: Bool
    public var sections: [DependencySection]
    /// The rows in all sections that the registry was not asked for yet. One read asks for at most 25 for each registry.
    public var pending: Int

    public init(schemaVersion: Int = 1, project: String, supported: Bool, sections: [DependencySection], pending: Int = 0) {
        self.schemaVersion = schemaVersion
        self.project = project
        self.supported = supported
        self.sections = sections
        self.pending = pending
    }

    public static let unsupportedText = "Watchtower lists dependencies for requirements.txt and Cargo.toml only."
}

extension DependencyLatestSource {
    /// The help text of the `Latest` column: `PyPI, retrieved Oct 30, 08:00`, or the failure with the age of the data.
    public func helpText(time: TimeText = TimeText()) -> String {
        if let error {
            let when = retrievedAt.map { " Data from \(time.day($0))." } ?? ""
            return error + when
        }
        return retrievedAt.map { "\(registry), retrieved \(time.absolute($0))" } ?? registry
    }
}

// MARK: - Engine call

public protocol DependencyClient: Sendable {
    func dependencies(projectPath: String) async throws -> DependencyList
}

extension Engine: DependencyClient {
    public func dependencies(projectPath: String) async throws -> DependencyList {
        try await call(["dependencies", projectPath], as: DependencyList.self)
    }
}

// MARK: - Model

/// The Dependencies tables that were read, one for each project. Reading a project asks the registries, so it
/// runs when the owner opens the project detail, not in a refresh. One engine call asks for a few packages only
/// (a project can have hundreds): the model calls again until no row is pending, and shows each answer at once.
@MainActor
@Observable
public final class DependencyModel {
    public enum Load: Equatable, Sendable {
        case loading
        case loaded(DependencyList)
        case failed(EngineError)
    }

    public private(set) var loads: [String: Load]
    /// The projects with a read in progress.
    public private(set) var checking: Set<String> = []
    @ObservationIgnored private let client: any DependencyClient

    public init(client: any DependencyClient, loads: [String: Load] = [:], checking: Set<String> = []) {
        self.client = client
        self.loads = loads
        self.checking = checking
    }

    public func load(for path: String) -> Load? { loads[path] }

    public func isChecking(_ path: String) -> Bool { checking.contains(path) }

    /// Read the table of one project. A complete table stays until `force`. A table with rows not checked yet
    /// continues where it stopped, also when the owner calls this again (`Check the rest`).
    public func load(_ project: ProjectRecord, force: Bool = false) async {
        let path = project.path
        if checking.contains(path) { return }
        if !force, case .loaded(let list)? = loads[path], list.pending == 0 { return }
        checking.insert(path)
        defer { checking.remove(path) }
        if force || loads[path] == nil { loads[path] = .loading }
        do {
            var list = try await client.dependencies(projectPath: path)
            loads[path] = .loaded(list)
            while list.pending > 0 {
                let next = try await client.dependencies(projectPath: path)
                loads[path] = .loaded(next)
                if next.pending >= list.pending { break }  // No progress: stop. The owner can ask again.
                list = next
            }
        } catch is CancellationError {
            if loads[path] == .loading { loads[path] = nil }
        } catch {
            if case .loaded? = loads[path] { return }  // Keep the rows read so far.
            loads[path] = .failed((error as? EngineError) ?? .failed(message: "Watchtower could not read the dependencies.",
                                                                     detail: "\(error)"))
        }
    }
}

extension DashboardModel {
    /// A click on `Vulnerable`: open the finding in Findings (#8).
    public func openFinding(_ id: String) {
        selection = .findings
        findingFilter = .open
        itemFilter = .all
        searchText = ""
        selectedItemKey = id
    }
}
