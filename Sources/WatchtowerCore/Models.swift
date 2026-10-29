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

    public var id: String { source }
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

    public var key: String { "\(source)/\(id)" }
}

/// Output of `watchtower state`.
public struct EngineState: Codable, Hashable, Sendable {
    public var schemaVersion: Int
    /// The newest refresh, or nil before the first refresh.
    public var refresh: RefreshRecord?
    public var coverage: [CoverageRecord]
    public var items: [ItemRecord]
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
