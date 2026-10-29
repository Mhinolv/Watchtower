import Foundation
import Observation

// One confirmed update: plan, confirm, run, verify. The engine does the work and keeps the log.
// Owner rules: show the exact command, confirm first, no "update all", a separate confirmation
// for a major version and for install scripts, success only after the version is read again.

public struct PackageChange: Codable, Hashable, Sendable {
    public var name: String
    public var before: String?
    public var after: String?
    /// `upgrade` or `install`.
    public var change: String

    public init(name: String, before: String?, after: String?, change: String) {
        self.name = name
        self.before = before
        self.after = after
        self.change = change
    }
}

/// One more row of the plan step or the result step: a label, a value and an optional list.
public struct PlanRow: Codable, Hashable, Sendable {
    public var label: String
    public var value: String
    /// A list that opens under the value, for example the other packages that change.
    public var items: [String]?
    /// For a result row: true if this part of the update is verified, false if it is not. nil: no mark.
    public var ok: Bool?

    public init(label: String, value: String, items: [String]? = nil, ok: Bool? = nil) {
        self.label = label
        self.value = value
        self.items = items
        self.ok = ok
    }
}

public struct UpdatePlan: Codable, Hashable, Sendable, Identifiable {
    public var id: String
    public var itemKey: String
    public var name: String
    public var kind: String
    public var fullName: String
    public var installedVersion: String?
    public var targetVersion: String?
    public var command: [String]
    public var commandText: String
    public var alsoChanges: [PackageChange]
    public var majorChange: Bool
    /// Why the update needs install scripts or a build. Empty: scripts are disabled.
    public var scripts: [String]
    public var manualSteps: [String]
    /// Set when Watchtower must not run this plan. One sentence for the owner.
    public var refusal: String?
    public var detail: String?
    /// More plan rows. A uv plan has them: project, environment, files, groups, other packages, build.
    public var rows: [PlanRow]?
    /// The text of the scripts step, if it is not `<name> needs install scripts: <reasons>.`
    public var scriptsMessage: String?

    public init(id: String, itemKey: String, name: String, kind: String, fullName: String,
                installedVersion: String?, targetVersion: String?, command: [String], alsoChanges: [PackageChange] = [],
                majorChange: Bool = false, scripts: [String] = [], manualSteps: [String] = [],
                refusal: String? = nil, detail: String? = nil, rows: [PlanRow]? = nil,
                scriptsMessage: String? = nil) {
        self.id = id
        self.itemKey = itemKey
        self.name = name
        self.kind = kind
        self.fullName = fullName
        self.installedVersion = installedVersion
        self.targetVersion = targetVersion
        self.command = command
        self.commandText = command.joined(separator: " ")
        self.alsoChanges = alsoChanges
        self.majorChange = majorChange
        self.scripts = scripts
        self.manualSteps = manualSteps
        self.refusal = refusal
        self.detail = detail
        self.rows = rows
        self.scriptsMessage = scriptsMessage
    }

    /// `2.4.1 → 2.5.0`.
    public var versionLine: String {
        "\(installedVersion ?? "?") → \(targetVersion ?? "?")"
    }

    /// `2.x → 3.0 can break your setup.`
    public var majorWarning: String {
        let old = installedVersion.flatMap { $0.split(whereSeparator: { !$0.isNumber }).first }.map(String.init) ?? "?"
        return "\(old).x → \(targetVersion ?? "?") can break your setup."
    }

    /// `<name> needs install scripts: <reason>.`
    public var scriptsText: String {
        scriptsMessage ?? "\(name) needs install scripts: \(scripts.joined(separator: ", "))."
    }
}

public enum UpdateStatus: String, Codable, Sendable, CaseIterable {
    case running, verified, failed, refused, interrupted
    case notVerified = "not_verified"
    case planChanged = "plan_changed"

    public var text: String {
        switch self {
        case .running: "Running"
        case .verified: "Verified"
        case .notVerified: "Not verified"
        case .failed: "Failed"
        case .planChanged: "Plan changed"
        case .refused: "Not run"
        case .interrupted: "Interrupted"
        }
    }
}

public struct UpdateAttempt: Codable, Hashable, Sendable, Identifiable {
    public var id: Int
    public var itemKey: String
    public var name: String
    public var kind: String?
    public var command: [String]
    public var beforeVersion: String?
    public var targetVersion: String?
    public var afterVersion: String?
    public var status: UpdateStatus
    public var exitCode: Int?
    public var output: String
    public var error: String?
    public var manualSteps: [String]
    public var confirmedMajor: Bool
    public var confirmedScripts: Bool
    public var planId: String?
    public var startedAt: Date
    public var finishedAt: Date?
    /// Lines for the result step, for example `Lockfile: httpx 0.27.2` of a uv update.
    public var resultRows: [PlanRow]?

    public init(id: Int, itemKey: String, name: String, kind: String?, command: [String], beforeVersion: String?,
                targetVersion: String?, afterVersion: String?, status: UpdateStatus, exitCode: Int?, output: String,
                error: String?, manualSteps: [String] = [], confirmedMajor: Bool = false,
                confirmedScripts: Bool = false, planId: String? = nil, startedAt: Date, finishedAt: Date? = nil,
                resultRows: [PlanRow]? = nil) {
        self.id = id
        self.itemKey = itemKey
        self.name = name
        self.kind = kind
        self.command = command
        self.beforeVersion = beforeVersion
        self.targetVersion = targetVersion
        self.afterVersion = afterVersion
        self.status = status
        self.exitCode = exitCode
        self.output = output
        self.error = error
        self.manualSteps = manualSteps
        self.confirmedMajor = confirmedMajor
        self.confirmedScripts = confirmedScripts
        self.planId = planId
        self.startedAt = startedAt
        self.finishedAt = finishedAt
        self.resultRows = resultRows
    }

    public var commandText: String { command.joined(separator: " ") }
}

/// Symbol, color and text for the result step.
public struct UpdateResultStyle: Equatable, Sendable {
    public var symbol: String
    public var tone: Tone
    public var text: String
    /// The second line under the result, from the approved update-dialog mockup.
    public var detail: String? {
        switch symbol {
        case "checkmark.seal": "Watchtower read the version again after the command."
        case "xmark.octagon": "Watchtower did not confirm any change."
        case "exclamationmark.triangle" where text.hasPrefix("The command finished") || text.hasPrefix("Not verified:"):
            "Watchtower does not count this update as done."
        default: nil
        }
    }

    public init(_ attempt: UpdateAttempt) {
        switch attempt.status {
        case .verified:
            (symbol, tone, text) = ("checkmark.seal", .green,
                                    "Updated. Installed version is now \(attempt.afterVersion ?? "?").")
        case .notVerified:
            let text = if attempt.kind == "uv", let error = attempt.error {
                error  // The engine says what is not verified: the lockfile or the environment.
            } else if let after = attempt.afterVersion, after != attempt.beforeVersion {
                "The command finished, but the installed version is \(after), not \(attempt.targetVersion ?? "?")."
            } else {
                "The command finished, but the installed version is still \(attempt.afterVersion ?? "unknown")."
            }
            (symbol, tone, self.text) = ("exclamationmark.triangle", .orange, text)
        case .failed:
            (symbol, tone, text) = ("xmark.octagon", .red,
                                    "The update failed (exit code \(attempt.exitCode.map(String.init) ?? "none")).")
        case .planChanged:
            (symbol, tone, text) = ("arrow.triangle.2.circlepath", .orange, "The plan changed. Review the new plan.")
        case .refused:
            (symbol, tone, text) = ("hand.raised", .orange, attempt.error ?? "Watchtower did not run the update.")
        case .interrupted:
            (symbol, tone, text) = ("exclamationmark.triangle", .orange,
                                    "The update was interrupted. Refresh to see the installed version.")
        case .running:
            (symbol, tone, text) = ("hourglass", .secondary, "Running…")
        }
    }
}

/// The item key and the policy of the uv update, from a finding (#11).
public enum UVUpdate {
    /// `uv/httpx@0.27.2|~/Real/tool|uv.lock`. nil if this path has no uv update: another lockfile,
    /// another ecosystem, or no fixed version.
    public static func key(finding: FindingRecord, path: FindingPath) -> String? {
        guard finding.ecosystem == "PyPI", (path.lockfile as NSString).lastPathComponent == "uv.lock",
              let fixed = finding.fixedIn, !finding.package.isEmpty, finding.status != .resolved else { return nil }
        return "uv/\(finding.package)@\(fixed)|\(path.projectPath)|\(path.lockfile)"
    }

    /// Nil if `Update…` can open the plan, else why it is off.
    public static func blockReason(_ path: FindingPath) -> String? { path.updateBlock }
}

public enum UpdatePolicy {
    /// Nil if the Update button can open a plan for `item`, else why it is off.
    public static func blockReason(_ item: ItemRecord) -> String? {
        guard item.source == "homebrew", item.kind == "formula" || item.kind == "cask" else {
            return "Watchtower can update Homebrew formulae and casks only."
        }
        switch item.state {
        case .updateAvailable, .vulnerable: break
        case .pinned: return item.note ?? "Pinned with brew pin. Watchtower does not update pinned items."
        default: return "No update is available."
        }
        if item.origin != nil { return item.note ?? "Watchtower cannot check this tap." }
        if item.latestVersion == nil { return "The latest version is not known." }
        return nil
    }
}

// MARK: - Engine calls

struct UpdatePlanResponse: Decodable { var plan: UpdatePlan }
struct UpdateRunResponse: Decodable { var attempt: UpdateAttempt; var plan: UpdatePlan }
struct UpdateLogResponse: Decodable { var attempts: [UpdateAttempt] }
private struct OutputLine: Decodable { var output: String }

public protocol UpdateClient: Sendable {
    func updatePlan(itemKey: String) async throws -> UpdatePlan
    func runUpdate(itemKey: String, planID: String, confirmMajor: Bool, confirmScripts: Bool,
                   output: @escaping @Sendable (String) -> Void) async throws -> (UpdateAttempt, UpdatePlan)
    func updateLog() async throws -> [UpdateAttempt]
}

extension Engine: UpdateClient {
    public func updatePlan(itemKey: String) async throws -> UpdatePlan {
        try await call(["update-plan", itemKey], as: UpdatePlanResponse.self).plan
    }

    public func runUpdate(itemKey: String, planID: String, confirmMajor: Bool, confirmScripts: Bool,
                          output: @escaping @Sendable (String) -> Void) async throws -> (UpdateAttempt, UpdatePlan) {
        var args = ["update-run", itemKey, "--plan-id", planID]
        if confirmMajor { args.append("--confirm-major") }
        if confirmScripts { args.append("--confirm-scripts") }
        let response = try await call(args, as: UpdateRunResponse.self) { line in
            if let parsed = try? EngineJSON.makeDecoder().decode(OutputLine.self, from: Data(line.utf8)) {
                output(parsed.output)
            }
        }
        return (response.attempt, response.plan)
    }

    public func updateLog() async throws -> [UpdateAttempt] {
        try await call(["update-log"], as: UpdateLogResponse.self).attempts
    }
}

// MARK: - Model

@MainActor
@Observable
public final class UpdateModel {
    public enum Step: Equatable, Sendable {
        case idle
        case loading(String)
        case plan(UpdatePlan)
        case confirmMajor(UpdatePlan)
        case confirmScripts(UpdatePlan)
        case running(UpdatePlan)
        case result(UpdateAttempt, UpdatePlan)
        case failed(EngineError)
    }

    public private(set) var step: Step
    public private(set) var output: [String]
    public private(set) var attempts: [UpdateAttempt]
    public var selectedAttemptID: UpdateAttempt.ID?

    /// Called after a run ends, for example to read the dashboard state again.
    @ObservationIgnored public var onFinished: (@MainActor () -> Void)?
    /// Called by `View Log`.
    @ObservationIgnored public var onViewLog: (@MainActor () -> Void)?

    @ObservationIgnored private let client: any UpdateClient
    @ObservationIgnored private var majorConfirmed = false
    @ObservationIgnored private var scriptsConfirmed = false

    public init(client: any UpdateClient, step: Step = .idle, output: [String] = [], attempts: [UpdateAttempt] = []) {
        self.client = client
        self.step = step
        self.output = output
        self.attempts = attempts
    }

    public var isPresented: Bool {
        if case .idle = step { return false }
        return true
    }

    public var isRunning: Bool {
        if case .running = step { return true }
        return false
    }

    /// Open the sheet for one item and load its plan. Nothing runs yet.
    public func start(_ item: ItemRecord) async {
        await loadPlan(itemKey: item.key, name: item.name)
    }

    /// Open the sheet for one uv dependency of a finding. Nothing runs yet.
    public func start(finding: FindingRecord, path: FindingPath) async {
        guard let key = UVUpdate.key(finding: finding, path: path) else { return }
        await loadPlan(itemKey: key, name: finding.package)
    }

    func loadPlan(itemKey: String, name: String) async {
        majorConfirmed = false
        scriptsConfirmed = false
        output = []
        step = .loading(name)
        do {
            step = .plan(try await client.updatePlan(itemKey: itemKey))
        } catch {
            step = .failed((error as? EngineError) ?? .failed(message: "Watchtower could not plan the update.",
                                                             detail: "\(error)"))
        }
    }

    /// The `Update` button of the plan step. A major version or scripts ask first.
    public func confirm() async {
        guard case .plan(let plan) = step, plan.refusal == nil else { return }
        await advance(plan)
    }

    public func confirmMajor() async {
        guard case .confirmMajor(let plan) = step else { return }
        majorConfirmed = true
        await advance(plan)
    }

    public func confirmScripts() async {
        guard case .confirmScripts(let plan) = step else { return }
        scriptsConfirmed = true
        await advance(plan)
    }

    /// Back from the major or scripts question to the plan. Nothing runs.
    public func backToPlan() {
        switch step {
        case .confirmMajor(let plan), .confirmScripts(let plan): step = .plan(plan)
        default: break
        }
    }

    private func advance(_ plan: UpdatePlan) async {
        if plan.majorChange && !majorConfirmed {
            step = .confirmMajor(plan)
        } else if !plan.scripts.isEmpty && !scriptsConfirmed {
            step = .confirmScripts(plan)
        } else {
            await run(plan)
        }
    }

    private func run(_ plan: UpdatePlan) async {
        step = .running(plan)
        output = []
        let buffer = LineBuffer()
        do {
            let (attempt, checked) = try await client.runUpdate(
                itemKey: plan.itemKey, planID: plan.id, confirmMajor: majorConfirmed, confirmScripts: scriptsConfirmed,
                output: { line in
                    let lines = buffer.append(line)
                    Task { @MainActor in self.showOutput(lines) }
                })
            output = buffer.lines
            step = .result(attempt, checked)
        } catch {
            step = .failed((error as? EngineError) ?? .failed(message: "The update did not finish.",
                                                             detail: "\(error)"))
        }
        await loadLog()
        onFinished?()
    }

    private func showOutput(_ lines: [String]) {
        guard isRunning, lines.count > output.count else { return }
        output = lines
    }

    /// `Review` after a changed plan: show the new plan. Nothing runs.
    public func review() {
        guard case .result(let attempt, let plan) = step, attempt.status == .planChanged else { return }
        majorConfirmed = false
        scriptsConfirmed = false
        step = .plan(plan)
    }

    /// Cancel or Done. A running update cannot be closed.
    public func close() {
        guard !isRunning else { return }
        step = .idle
    }

    public func viewLog() {
        guard case .result(let attempt, _) = step else { return }
        selectedAttemptID = attempt.id
        close()
        onViewLog?()
    }

    public func loadLog() async {
        if let log = try? await client.updateLog() { attempts = log }
    }

    public var selectedAttempt: UpdateAttempt? {
        attempts.first { $0.id == selectedAttemptID }
    }
}

/// Output lines from the engine thread, in order.
final class LineBuffer: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String] = []

    func append(_ line: String) -> [String] {
        lock.withLock {
            items.append(line)
            return items
        }
    }

    var lines: [String] { lock.withLock { items } }
}
