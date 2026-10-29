import Foundation

// Runs the Python engine (`python3 -m watchtower_engine.cli`) and decodes its JSON.
// Every call runs the process off the main thread. Task cancellation sends SIGTERM:
// the engine then saves a `cancelled` refresh and keeps the previous results.

/// Output of `watchtower projects`.
public struct ProjectList: Codable, Hashable, Sendable {
    public var schemaVersion: Int
    public var projects: [ProjectRecord]
    public var rootErrors: [RootError]
    public var skipped: [SkippedLink]

    public init(schemaVersion: Int, projects: [ProjectRecord], rootErrors: [RootError], skipped: [SkippedLink]) {
        self.schemaVersion = schemaVersion
        self.projects = projects
        self.rootErrors = rootErrors
        self.skipped = skipped
    }
}

public struct ProjectRecord: Codable, Hashable, Sendable, Identifiable {
    public var name: String
    /// Absolute folder path. Use `displayPath` in the UI.
    public var path: String
    public var root: String
    public var manifests: [String]
    /// `active`, `inactive` or `inaccessible`.
    public var state: String

    public var id: String { path }
    public var isActive: Bool { state != "inactive" }
    public var displayPath: String { DisplayPath.abbreviate(path) }

    public init(name: String, path: String, root: String, manifests: [String], state: String) {
        self.name = name
        self.path = path
        self.root = root
        self.manifests = manifests
        self.state = state
    }
}

public struct RootError: Codable, Hashable, Sendable {
    public var root: String
    public var kind: String
    public var message: String
}

public struct SkippedLink: Codable, Hashable, Sendable {
    public var path: String
    public var reason: String
}

struct ProjectStateResponse: Codable, Sendable {
    var schemaVersion: Int
    var project: ProjectRecord
}

/// One progress line from `watchtower refresh` on stderr.
public struct RefreshProgress: Codable, Hashable, Sendable {
    public var done: Int
    public var total: Int
    public var source: String

    public init(done: Int, total: Int, source: String) {
        self.done = done
        self.total = total
        self.source = source
    }
}

private struct ProgressLine: Decodable {
    var progress: RefreshProgress
}

public enum DisplayPath {
    /// `/Users/me/Projects/x` -> `~/Projects/x`.
    public static func abbreviate(_ path: String, home: String = NSHomeDirectory()) -> String {
        if path == home { return "~" }
        if path.hasPrefix(home + "/") { return "~" + path.dropFirst(home.count) }
        return path
    }
}

// MARK: - Errors

public enum EngineError: Error, Equatable, Sendable {
    /// The engine reported an error on stderr. `message` is one short sentence for the owner.
    case reported(message: String, detail: String?)
    /// The engine could not start, or its output was not valid.
    case failed(message: String, detail: String?)

    public var message: String {
        switch self {
        case .reported(let message, _), .failed(let message, _): return message
        }
    }

    public var detail: String? {
        switch self {
        case .reported(_, let detail), .failed(_, let detail): return detail
        }
    }
}

// MARK: - Client

/// What the app needs from the engine. Tests use a fake.
public protocol EngineClient: Sendable {
    func state() async throws -> EngineState
    func refresh(progress: @escaping @Sendable (RefreshProgress) -> Void) async throws -> EngineState
    func projects() async throws -> ProjectList
    func setProject(path: String, active: Bool) async throws -> ProjectRecord
}

/// How to start the engine.
public struct EngineCommand: Sendable, Equatable {
    public var executable: URL
    public var arguments: [String]
    public var environment: [String: String]

    public init(executable: URL, arguments: [String], environment: [String: String]) {
        self.executable = executable
        self.arguments = arguments
        self.environment = environment
    }

    /// The engine in this repository, run with the first Python 3 that exists.
    ///
    /// `WATCHTOWER_ENGINE_DIR` and `WATCHTOWER_PYTHON` override the defaults. The app bundle
    /// does not hold the engine yet, so the default is the `engine` folder next to the sources.
    public static func development(
        environment env: [String: String] = ProcessInfo.processInfo.environment,
        fileExists: (String) -> Bool = { FileManager.default.isExecutableFile(atPath: $0) }
    ) -> EngineCommand {
        let engineDir = env["WATCHTOWER_ENGINE_DIR"] ?? URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("engine").path
        let candidates = [env["WATCHTOWER_PYTHON"], engineDir + "/.venv/bin/python",
                          "/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"]
        let python = candidates.compactMap { $0 }.first(where: fileExists) ?? "/usr/bin/python3"
        var environment = [
            "PYTHONPATH": engineDir,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin",
            "HOME": env["HOME"] ?? NSHomeDirectory(),
        ]
        if let dataDir = env["WATCHTOWER_DATA_DIR"] { environment["WATCHTOWER_DATA_DIR"] = dataDir }
        return EngineCommand(executable: URL(fileURLWithPath: python),
                             arguments: ["-s", "-m", "watchtower_engine.cli"], environment: environment)
    }
}

/// The real engine client.
public struct Engine: EngineClient {
    public var command: EngineCommand
    public var runner: any CommandRunner

    public init(command: EngineCommand = .development(), runner: any CommandRunner = ProcessCommandRunner()) {
        self.command = command
        self.runner = runner
    }

    public func state() async throws -> EngineState {
        try await call(["state"], as: EngineState.self)
    }

    public func refresh(progress: @escaping @Sendable (RefreshProgress) -> Void) async throws -> EngineState {
        try await call(["refresh"], as: EngineState.self) { line in
            if let data = line.data(using: .utf8),
               let parsed = try? EngineJSON.makeDecoder().decode(ProgressLine.self, from: data) {
                progress(parsed.progress)
            }
        }
    }

    public func projects() async throws -> ProjectList {
        try await call(["projects"], as: ProjectList.self)
    }

    public func setProject(path: String, active: Bool) async throws -> ProjectRecord {
        try await call(["project-state", path, active ? "active" : "inactive"], as: ProjectStateResponse.self).project
    }

    func call<T: Decodable>(_ args: [String], as type: T.Type,
                            stderrLine: @escaping @Sendable (String) -> Void = { _ in }) async throws -> T {
        let result: ProcessResult
        do {
            result = try await runner.run(command.executable, command.arguments + args,
                                          environment: command.environment, onStderrLine: stderrLine)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw EngineError.failed(message: "Watchtower could not start its engine.", detail: "\(error)")
        }
        try Task.checkCancellation()
        guard result.status == 0 else {
            throw Self.reportedError(result)
        }
        do {
            return try EngineJSON.decode(type, from: result.stdout)
        } catch EngineContractError.unsupportedSchema(let version) {
            throw EngineError.failed(message: "The engine is newer than this app.",
                                     detail: "schema_version \(version)")
        } catch {
            throw EngineError.failed(message: "The engine output was not readable.", detail: "\(error)")
        }
    }

    /// The last JSON error line on stderr, else a generic message.
    static func reportedError(_ result: ProcessResult) -> EngineError {
        let text = String(decoding: result.stderr, as: UTF8.self)
        for line in text.split(separator: "\n").reversed() {
            if let report = try? EngineJSON.decode(EngineErrorReport.self, from: Data(line.utf8)) {
                return .reported(message: report.error, detail: report.detail)
            }
        }
        return .failed(message: "The engine stopped with an error.",
                       detail: "exit \(result.status): \(text.suffix(500))")
    }
}

// MARK: - Process

public struct ProcessResult: Sendable, Equatable {
    public var status: Int32
    public var stdout: Data
    public var stderr: Data

    public init(status: Int32, stdout: Data, stderr: Data) {
        self.status = status
        self.stdout = stdout
        self.stderr = stderr
    }
}

public protocol CommandRunner: Sendable {
    /// Run a program to its end. Cancel the task to stop it with SIGTERM.
    func run(_ executable: URL, _ arguments: [String], environment: [String: String],
             onStderrLine: @escaping @Sendable (String) -> Void) async throws -> ProcessResult
}

public struct ProcessCommandRunner: CommandRunner {
    public init() {}

    public func run(_ executable: URL, _ arguments: [String], environment: [String: String],
                    onStderrLine: @escaping @Sendable (String) -> Void) async throws -> ProcessResult {
        let box = ProcessBox()
        return try await withTaskCancellationHandler {
            try await Task.detached(priority: .userInitiated) {
                try box.runToEnd(executable, arguments, environment, onStderrLine)
            }.value
        } onCancel: {
            box.terminate()
        }
    }
}

/// Holds the running process so that a cancel from another thread can stop it.
final class ProcessBox: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var cancelled = false

    func terminate() {
        lock.withLock {
            cancelled = true
            if let process, process.isRunning { process.terminate() }
        }
    }

    func runToEnd(_ executable: URL, _ arguments: [String], _ environment: [String: String],
                  _ onStderrLine: @escaping @Sendable (String) -> Void) throws -> ProcessResult {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.environment = environment
        process.standardInput = FileHandle.nullDevice
        let out = Pipe(), err = Pipe()
        process.standardOutput = out
        process.standardError = err

        try lock.withLock {
            if cancelled { throw CancellationError() }
            self.process = process
            try process.run()
        }

        let stderr = StderrCollector(onLine: onStderrLine)
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            stderr.readAll(err.fileHandleForReading)
            group.leave()
        }
        let stdout = out.fileHandleForReading.readDataToEndOfFile()
        group.wait()
        process.waitUntilExit()

        if lock.withLock({ cancelled }) { throw CancellationError() }
        return ProcessResult(status: process.terminationStatus, stdout: stdout, stderr: stderr.data)
    }
}

/// Reads stderr to its end and reports each full line as it arrives.
final class StderrCollector: @unchecked Sendable {
    private(set) var data = Data()
    private var pending = Data()
    private let onLine: @Sendable (String) -> Void

    init(onLine: @escaping @Sendable (String) -> Void) {
        self.onLine = onLine
    }

    func readAll(_ handle: FileHandle) {
        while true {
            let chunk = handle.availableData
            if chunk.isEmpty { break }
            feed(chunk)
        }
        if !pending.isEmpty {
            onLine(String(decoding: pending, as: UTF8.self))
            pending.removeAll()
        }
    }

    func feed(_ chunk: Data) {
        data.append(chunk)
        pending.append(chunk)
        while let newline = pending.firstIndex(of: UInt8(ascii: "\n")) {
            let line = pending[pending.startIndex..<newline]
            onLine(String(decoding: line, as: UTF8.self))
            pending.removeSubrange(pending.startIndex...newline)
        }
    }
}
