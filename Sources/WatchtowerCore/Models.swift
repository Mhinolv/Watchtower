import Foundation

// Records that the Python engine prints as JSON. The field names are a contract with
// `engine/watchtower_engine/models.py`. Fixtures in Tests/WatchtowerCoreTests/Fixtures
// come from the engine, and both test suites check them.

/// The JSON schema version that this app reads.
public enum EngineSchema {
    public static let version = 1
}

public enum RefreshStatus: String, Codable, Sendable, CaseIterable {
    case running, complete, partial, failed, cancelled
}

public enum CoverageState: String, Codable, Sendable, CaseIterable {
    case complete, partial, failed, stale
    case notRun = "not_run"
}

/// Maps 1:1 to the dashboard status badge.
public enum ItemState: String, Codable, Sendable, CaseIterable {
    case upToDate = "up_to_date"
    case updateAvailable = "update_available"
    case vulnerable, unknown, error, pinned, manual
}

public struct RefreshRecord: Codable, Hashable, Sendable {
    public var id: Int
    public var status: RefreshStatus
    public var startedAt: Date
    public var finishedAt: Date?
    /// Finish time of the newest `complete` refresh. Only a complete refresh changes it.
    public var lastCompleteAt: Date?
    /// One short sentence for the owner.
    public var error: String?
    /// Full error text. The UI shows it in a disclosure.
    public var detail: String?

    public init(id: Int, status: RefreshStatus, startedAt: Date, finishedAt: Date? = nil,
                lastCompleteAt: Date? = nil, error: String? = nil, detail: String? = nil) {
        self.id = id
        self.status = status
        self.startedAt = startedAt
        self.finishedAt = finishedAt
        self.lastCompleteAt = lastCompleteAt
        self.error = error
        self.detail = detail
    }
}

/// Coverage of one source, for example Homebrew.
public struct CoverageRecord: Codable, Hashable, Sendable, Identifiable {
    /// Stable id, for example `homebrew`.
    public var source: String
    /// UI string, for example `Homebrew`.
    public var label: String
    public var state: CoverageState
    public var lastSuccessAt: Date?
    public var error: String?
    public var detail: String?
    /// When the source's own data was fetched, for example the OSV database.
    public var sourceAt: Date?
    /// A short phrase for the Source row of a finding: `official mirror`, or why a feed failed
    /// or stopped early, for example `rate limit`. Not an error.
    public var note: String?

    public var id: String { source }

    public init(source: String, label: String, state: CoverageState, lastSuccessAt: Date? = nil,
                error: String? = nil, detail: String? = nil, sourceAt: Date? = nil, note: String? = nil) {
        self.source = source
        self.label = label
        self.state = state
        self.lastSuccessAt = lastSuccessAt
        self.error = error
        self.detail = detail
        self.sourceAt = sourceAt
        self.note = note
    }
}

/// One installed thing: a formula, cask, app or project dependency.
public struct ItemRecord: Codable, Hashable, Sendable {
    /// Stable inside its source. Use `key` where a unique id across sources is needed.
    public var id: String
    public var source: String
    public var name: String
    public var state: ItemState
    public var kind: String?
    public var installedVersion: String?
    public var latestVersion: String?
    public var project: String?
    public var seenAt: Date?
    public var error: String?
    public var detail: String?
    /// Where the item comes from inside its source, for example a Homebrew tap that is not core.
    public var origin: String?
    /// When the source data for `latestVersion` was fetched. Older than `seenAt` if a cache was used.
    public var sourceAt: Date?
    /// One sentence for the owner about the state, for example why an item is pinned. Not an error.
    public var note: String?
    /// Facts for the detail pane, as text. The keys depend on the source, for example `bundleId` for apps. Keys are camelCase because the decoder converts snake_case keys.
    public var attributes: [String: String]?

    public var key: String { "\(source)/\(id)" }

    public init(id: String, source: String, name: String, state: ItemState, kind: String? = nil,
                installedVersion: String? = nil, latestVersion: String? = nil, project: String? = nil,
                seenAt: Date? = nil, error: String? = nil, detail: String? = nil, origin: String? = nil,
                sourceAt: Date? = nil, note: String? = nil, attributes: [String: String]? = nil) {
        self.id = id
        self.source = source
        self.name = name
        self.state = state
        self.kind = kind
        self.installedVersion = installedVersion
        self.latestVersion = latestVersion
        self.project = project
        self.seenAt = seenAt
        self.error = error
        self.detail = detail
        self.origin = origin
        self.sourceAt = sourceAt
        self.note = note
        self.attributes = attributes
    }
}

// MARK: - Findings

public enum FindingStatus: String, Codable, Sendable, CaseIterable {
    case open, deferred, backlog, resolved
}

public enum Severity: String, Codable, Sendable, CaseIterable {
    case critical, high, medium, low, unknown

    /// Sort order: worst first.
    public var rank: Int {
        switch self {
        case .critical: 0
        case .high: 1
        case .medium: 2
        case .low: 3
        case .unknown: 4
        }
    }
}

/// One local place where a finding is present: a lockfile with the vulnerable package.
public struct FindingPath: Codable, Hashable, Sendable, Identifiable {
    public var project: String
    /// Display path of the project, for example `~/Projects/web`.
    public var projectPath: String
    /// Relative to the project, for example `web/package-lock.json`.
    public var lockfile: String
    public var version: String
    /// Packages from the project to the vulnerable one. nil if the scanner gives no path.
    public var dependencyPath: [String]?
    /// Why `Update…` is off for this lockfile, for example a uv project with no environment.
    public var updateBlock: String?

    public var id: String { "\(projectPath)/\(lockfile)@\(version)" }

    public init(project: String, projectPath: String, lockfile: String, version: String,
                dependencyPath: [String]? = nil, updateBlock: String? = nil) {
        self.project = project
        self.projectPath = projectPath
        self.lockfile = lockfile
        self.version = version
        self.dependencyPath = dependencyPath
        self.updateBlock = updateBlock
    }

    /// The lockfile in Finder. `~` in `projectPath` becomes the home folder.
    public var lockfileURL: URL {
        URL(fileURLWithPath: (projectPath as NSString).expandingTildeInPath).appendingPathComponent(lockfile)
    }
}

/// CISA lists the advisory in the Known Exploited Vulnerabilities catalog.
public struct KevMark: Codable, Hashable, Sendable {
    public var cve: String
    /// Dates as the catalog writes them: `2026-10-22`.
    public var dateAdded: String?
    public var dueDate: String?
    public var ransomware: Bool

    public init(cve: String, dateAdded: String? = nil, dueDate: String? = nil, ransomware: Bool = false) {
        self.cve = cve
        self.dateAdded = dateAdded
        self.dueDate = dueDate
        self.ransomware = ransomware
    }
}

/// GitHub lists the package as malware.
public struct MalwareMark: Codable, Hashable, Sendable {
    public var advisoryId: String

    public init(advisoryId: String) {
        self.advisoryId = advisoryId
    }
}

/// A stable finding: one advisory, with all its aliases, for one package.
public struct FindingRecord: Codable, Hashable, Sendable, Identifiable {
    /// `SEC-0001`. No later scan changes or reuses it.
    public var id: String
    public var ecosystem: String
    public var package: String
    public var title: String
    public var severity: Severity
    /// Every id of the advisory: CVE, GHSA and OSV ids.
    public var advisoryIds: [String]
    public var fixedIn: String?
    public var status: FindingStatus
    public var deferredUntil: Date?
    public var firstSeen: Date
    public var lastSeen: Date
    public var resolvedAt: Date?
    public var resolvedScanAt: Date?
    public var source: String
    public var sourceAt: Date?
    public var paths: [FindingPath]
    public var nextSteps: [String]
    /// Listed in CISA KEV. nil if not listed, or if the engine is older than the enrichment.
    public var kev: KevMark?
    public var malware: MalwareMark?
    /// When the source withdrew the advisory.
    public var withdrawnAt: Date?

    public var isOpen: Bool { status == .open }

    public init(id: String, ecosystem: String = "npm", package: String, title: String, severity: Severity,
                advisoryIds: [String], fixedIn: String? = nil, status: FindingStatus = .open,
                deferredUntil: Date? = nil, firstSeen: Date, lastSeen: Date, resolvedAt: Date? = nil,
                resolvedScanAt: Date? = nil, source: String = "OSV", sourceAt: Date? = nil,
                paths: [FindingPath] = [], nextSteps: [String] = [], kev: KevMark? = nil,
                malware: MalwareMark? = nil, withdrawnAt: Date? = nil) {
        self.id = id
        self.ecosystem = ecosystem
        self.package = package
        self.title = title
        self.severity = severity
        self.advisoryIds = advisoryIds
        self.fixedIn = fixedIn
        self.status = status
        self.deferredUntil = deferredUntil
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.resolvedAt = resolvedAt
        self.resolvedScanAt = resolvedScanAt
        self.source = source
        self.sourceAt = sourceAt
        self.paths = paths
        self.nextSteps = nextSteps
        self.kev = kev
        self.malware = malware
        self.withdrawnAt = withdrawnAt
    }

    /// Distinct projects that have this finding.
    public var projectNames: [String] {
        var seen = Set<String>()
        return paths.map(\.project).filter { seen.insert($0).inserted }
    }

    /// CVE ids first, then GHSA, then the rest.
    public var sortedAdvisoryIds: [String] {
        func rank(_ id: String) -> Int { id.hasPrefix("CVE-") ? 0 : id.hasPrefix("GHSA-") ? 1 : 2 }
        return advisoryIds.sorted { (rank($0), $0) < (rank($1), $1) }
    }
}

/// The page of an advisory at its source.
public enum AdvisoryLink {
    public static func url(for id: String) -> URL? {
        let allowed = CharacterSet.urlPathAllowed
        guard let path = id.addingPercentEncoding(withAllowedCharacters: allowed) else { return nil }
        if id.hasPrefix("CVE-") { return URL(string: "https://nvd.nist.gov/vuln/detail/\(path)") }
        if id.hasPrefix("GHSA-") { return URL(string: "https://github.com/advisories/\(path)") }
        return URL(string: "https://osv.dev/vulnerability/\(path)")
    }
}

/// Output of `watchtower state`.
public struct EngineState: Codable, Hashable, Sendable {
    public var schemaVersion: Int
    /// The newest refresh, or nil before the first refresh.
    public var refresh: RefreshRecord?
    public var coverage: [CoverageRecord]
    public var items: [ItemRecord]
    public var findings: [FindingRecord]

    public init(schemaVersion: Int, refresh: RefreshRecord?, coverage: [CoverageRecord], items: [ItemRecord],
                findings: [FindingRecord] = []) {
        self.schemaVersion = schemaVersion
        self.refresh = refresh
        self.coverage = coverage
        self.items = items
        self.findings = findings
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, refresh, coverage, items, findings
    }

    /// An engine that is older than the findings view sends no `findings` key.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try c.decode(Int.self, forKey: .schemaVersion)
        refresh = try c.decodeIfPresent(RefreshRecord.self, forKey: .refresh)
        coverage = try c.decode([CoverageRecord].self, forKey: .coverage)
        items = try c.decode([ItemRecord].self, forKey: .items)
        findings = try c.decodeIfPresent([FindingRecord].self, forKey: .findings) ?? []
    }
}

/// Output of `watchtower version`.
public struct EngineVersion: Codable, Hashable, Sendable {
    public var schemaVersion: Int
    public var engine: String
}

/// What the engine writes to stderr when a command fails. Stdout is then empty.
public struct EngineErrorReport: Codable, Hashable, Sendable, Error {
    public var schemaVersion: Int
    public var error: String
    public var detail: String?
}

public enum EngineContractError: Error, Equatable {
    /// The engine wrote a newer schema than this app reads.
    case unsupportedSchema(Int)
}

public enum EngineJSON {
    public static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    /// Decode one engine JSON object. Refuses a schema version newer than `EngineSchema.version`.
    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        let decoder = makeDecoder()
        let probe = try decoder.decode(SchemaProbe.self, from: data)
        guard probe.schemaVersion <= EngineSchema.version else {
            throw EngineContractError.unsupportedSchema(probe.schemaVersion)
        }
        return try decoder.decode(type, from: data)
    }

    private struct SchemaProbe: Decodable {
        var schemaVersion: Int
    }
}
