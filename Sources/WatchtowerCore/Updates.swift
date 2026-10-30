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

/// One install script that needs the separate confirmation (npm, #10).
public struct ScriptDetail: Codable, Hashable, Sendable {
    public var package: String
    public var version: String?
    public var script: String

    public init(package: String, version: String?, script: String) {
        self.package = package
        self.version = version
        self.script = script
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
    /// The package and script for each line of the scripts step (npm). Nil for Homebrew and uv.
    public var scriptDetails: [ScriptDetail]?

    public init(id: String, itemKey: String, name: String, kind: String, fullName: String,
                installedVersion: String?, targetVersion: String?, command: [String], alsoChanges: [PackageChange] = [],
                majorChange: Bool = false, scripts: [String] = [], manualSteps: [String] = [],
                refusal: String? = nil, detail: String? = nil, rows: [PlanRow]? = nil,
                scriptsMessage: String? = nil, scriptDetails: [ScriptDetail]? = nil) {
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
        self.scriptDetails = scriptDetails
    }

    /// `2.4.1 → 2.5.0`. A requirements.txt package that `.venv` does not have: `not installed → 1.84.0` (#96).
    public var versionLine: String {
        "\(installedVersion ?? (kind == "requirements" ? "not installed" : "?")) → \(targetVersion ?? "?")"
    }

    /// The command, or what Watchtower does when no command runs (a requirements.txt pin only, #96).
    public var commandDisplay: String { UpdateCommand.display(command) }

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
    /// A Cargo update (#15): the lockfile is checked, but no installed crate can be read.
    case lockfileUpdated = "lockfile_updated"
    /// A requirements.txt pin of a package that `.venv` does not have (#96): the file is checked, nothing is installed.
    case pinUpdated = "pin_updated"

    public var text: String {
        switch self {
        case .running: "Running"
        case .verified: "Verified"
        case .notVerified: "Not verified"
        case .failed: "Failed"
        case .planChanged: "Plan changed"
        case .refused: "Not run"
        case .interrupted: "Interrupted"
        case .lockfileUpdated: "Lockfile updated"
        case .pinUpdated: "Pin updated"
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

    /// The command, or what Watchtower did when no command ran (a requirements.txt pin only, #96).
    public var commandDisplay: String { UpdateCommand.display(command) }
}

enum UpdateCommand {
    static func display(_ command: [String]) -> String {
        command.isEmpty ? "No command runs. Watchtower edits requirements.txt only." : command.joined(separator: " ")
    }
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
        case "checkmark.circle" where text.hasPrefix("requirements.txt now pins"):
            "Watchtower read requirements.txt again. Nothing was installed."
        case "checkmark.circle": "Watchtower read Cargo.lock again. Cargo builds the crate on next use."
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
            let text = if ["uv", "npm", "cargo", "requirements"].contains(attempt.kind), let error = attempt.error {
                error  // The engine says what is not verified: the lockfile or the installed package.
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
        case .lockfileUpdated:
            (symbol, tone, text) = ("checkmark.circle", .green, "Lockfile updated.")
        case .pinUpdated:
            (symbol, tone, text) = ("checkmark.circle", .green,
                                    "requirements.txt now pins \(attempt.name) \(attempt.targetVersion ?? "?").")
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

public enum CargoUpdate {
    /// `cargo/smallvec@1.6.1|~/Projects/tool|Cargo.lock` (#15). nil if this path has no Cargo update:
    /// another lockfile, another ecosystem, or no fixed version.
    public static func key(finding: FindingRecord, path: FindingPath) -> String? {
        guard finding.ecosystem == "crates.io", (path.lockfile as NSString).lastPathComponent == "Cargo.lock",
              let fixed = finding.fixedIn, !finding.package.isEmpty, finding.status != .resolved else { return nil }
        return "cargo/\(finding.package)@\(fixed)|\(path.projectPath)|\(path.lockfile)"
    }
}

public enum NPMUpdate {
    /// `npm|~/Projects/web/app|express|4.19.0`: the folder of the package-lock.json, the package and the
    /// fixed version (or `-`). nil if this path has no npm update: another lockfile, ecosystem, or resolved.
    public static func key(finding: FindingRecord, path: FindingPath) -> String? {
        guard finding.ecosystem == "npm", (path.lockfile as NSString).lastPathComponent == "package-lock.json",
              !finding.package.isEmpty, finding.status != .resolved else { return nil }
        let folder = (path.lockfile as NSString).deletingLastPathComponent
        let dir = folder.isEmpty ? path.projectPath : path.projectPath + "/" + folder
        return "npm|\(dir)|\(finding.package)|\(finding.fixedIn ?? "-")"
    }
}

public enum RequirementsUpdate {
    /// `requirements/requests@2.32.3|~/Real/script|requirements.txt` (#30): the package, the fixed version and
    /// the requirements file. nil if this path has no requirements update: another file, ecosystem, no fixed
    /// version, or resolved.
    public static func key(finding: FindingRecord, path: FindingPath) -> String? {
        guard finding.ecosystem == "PyPI", (path.lockfile as NSString).lastPathComponent == "requirements.txt",
              let fixed = finding.fixedIn, !finding.package.isEmpty, finding.status != .resolved else { return nil }
        return "requirements/\(finding.package)@\(fixed)|\(path.projectPath)|\(path.lockfile)"
    }
}

public enum UpdateKeys {
    /// The engine key for one finding path: uv (#11), npm (#10), Cargo (#15) or requirements (#30). nil if no adapter fits.
    public static func forFinding(_ finding: FindingRecord, _ path: FindingPath) -> String? {
        UVUpdate.key(finding: finding, path: path) ?? NPMUpdate.key(finding: finding, path: path)
            ?? CargoUpdate.key(finding: finding, path: path) ?? RequirementsUpdate.key(finding: finding, path: path)
    }

    /// Nil if `Update…` can open a plan for this path, else why it is off.
    public static func blockReason(_ finding: FindingRecord, _ path: FindingPath) -> String? {
        if let block = path.updateBlock { return block }
        if forFinding(finding, path) != nil { return nil }
        if finding.status == .resolved { return "This finding is resolved." }
        switch (path.lockfile as NSString).lastPathComponent {
        case "uv.lock", "Cargo.lock", "requirements.txt": return "No fixed version is known."
        default: return "Watchtower updates projects with package-lock.json, uv.lock, Cargo.lock or requirements.txt only."
        }
    }
}

extension ItemRecord {
    /// An app with a Mac App Store receipt (#13). The engine sets `origin` to `App Store`.
    public var isAppStoreApp: Bool { source == "apps" && origin == "App Store" }
}

public enum UpdatePolicy {
    /// `Check for Update…` for App Store apps: the outdated check runs in the plan step (#13).
    public static func buttonTitle(_ item: ItemRecord) -> String {
        item.isAppStoreApp ? "Check for Update…" : "Update…"
    }

    /// Nil if the Update button can open a plan for `item`, else why it is off.
    public static func blockReason(_ item: ItemRecord) -> String? {
        if item.isAppStoreApp {
            // The row state carries the mas limit: `error` for an unsupported mas, `manual` without mas.
            if item.state == .error { return item.error ?? "mas is not supported." }
            if item.attributes?["adamId"] == nil || item.state == .manual {
                return item.note ?? "Install mas with Homebrew to update App Store apps here."
            }
            return nil
        }
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
    /// The loading step is the App Store check: `Checking the App Store…` (#13).
    public private(set) var checkingStore = false
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
    /// The plan of a major-version alert that closed with no Cancel. `Update to …` can still go on (#98).
    @ObservationIgnored private var closedMajorQuestion: UpdatePlan?

    public init(client: any UpdateClient, step: Step = .idle, output: [String] = [], attempts: [UpdateAttempt] = [],
                checkingStore: Bool = false) {
        self.client = client
        self.step = step
        self.checkingStore = checkingStore
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
        checkingStore = item.isAppStoreApp
        await loadPlan(itemKey: item.key, name: item.name)
    }

    /// Open the sheet for one npm or uv dependency of a finding. Nothing runs yet.
    public func start(finding: FindingRecord, path: FindingPath) async {
        guard let key = UpdateKeys.forFinding(finding, path) else { return }
        checkingStore = false
        await loadPlan(itemKey: key, name: finding.package)
    }

    /// Open the sheet for an engine key. Nothing runs yet.
    public func start(itemKey: String, name: String) async {
        checkingStore = false
        await loadPlan(itemKey: itemKey, name: name)
    }

    func loadPlan(itemKey: String, name: String) async {
        majorConfirmed = false
        scriptsConfirmed = false
        closedMajorQuestion = nil
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
        closedMajorQuestion = nil
        await advance(plan)
    }

    /// `Update to …` in the major-version alert. SwiftUI closes the alert before this task runs (#98).
    public func confirmMajor() async {
        let plan: UpdatePlan
        switch step {
        case .confirmMajor(let p): plan = p
        case .plan(let p) where p == closedMajorQuestion: plan = p
        default: return
        }
        closedMajorQuestion = nil
        majorConfirmed = true
        await advance(plan)
    }

    public func confirmScripts() async {
        guard case .confirmScripts(let plan) = step else { return }
        scriptsConfirmed = true
        await advance(plan)
    }

    /// The major-version alert is open. The alert sets it to false when it closes.
    public var majorQuestionShown: Bool {
        get {
            if case .confirmMajor = step { return true }
            return false
        }
        set {
            // Only the major question closes here. A later step, for example the scripts question, stays.
            guard !newValue, case .confirmMajor(let plan) = step else { return }
            step = .plan(plan)
            closedMajorQuestion = plan
        }
    }

    /// Back from the major or scripts question to the plan. Nothing runs.
    public func backToPlan() {
        closedMajorQuestion = nil
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
        closedMajorQuestion = nil
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
