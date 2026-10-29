import Foundation
import Testing
@testable import WatchtowerCore

private let date = Date(timeIntervalSince1970: 1_793_275_200)

private func plan(major: Bool = false, scripts: [String] = [], refusal: String? = nil,
                  id: String = "aaaa", target: String = "2.47.1") -> UpdatePlan {
    UpdatePlan(id: id, itemKey: "homebrew/formula:git", name: "git", kind: "formula", fullName: "git",
               installedVersion: "2.46.0", targetVersion: major ? "3.0.0" : target,
               command: ["/opt/homebrew/bin/brew", "upgrade", "--formula", "git"], majorChange: major,
               scripts: scripts, refusal: refusal)
}

private func attempt(_ status: UpdateStatus, after: String? = "2.47.1", exit: Int? = 0,
                     error: String? = nil) -> UpdateAttempt {
    UpdateAttempt(id: 1, itemKey: "homebrew/formula:git", name: "git", kind: "formula",
                  command: ["brew", "upgrade", "--formula", "git"], beforeVersion: "2.46.0", targetVersion: "2.47.1",
                  afterVersion: after, status: status, exitCode: exit, output: "", error: error, startedAt: date)
}

/// Opens once. Lets a test hold a fake run in the `running` step.
private actor Gate {
    private var open = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func wait() async {
        if open { return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func release() {
        open = true
        waiters.forEach { $0.resume() }
        waiters = []
    }
}

private actor Record {
    var runs: [(String, Bool, Bool)] = []
    var planKeys: [String] = []
    func addKey(_ key: String) { planKeys.append(key) }
    func add(_ id: String, _ major: Bool, _ scripts: Bool) { runs.append((id, major, scripts)) }
}

private struct FakeUpdates: UpdateClient {
    var plans: [UpdatePlan]
    var result: UpdateAttempt = attempt(.verified)
    var resultPlan: UpdatePlan? = nil
    var planError: EngineError? = nil
    var gate: Gate? = nil
    let record = Record()
    let counter = Counter()

    actor Counter {
        var n = 0
        func next() -> Int { defer { n += 1 }; return n }
    }

    func updatePlan(itemKey: String) async throws -> UpdatePlan {
        await record.addKey(itemKey)
        if let planError { throw planError }
        let i = await counter.next()
        return plans[min(i, plans.count - 1)]
    }

    func runUpdate(itemKey: String, planID: String, confirmMajor: Bool, confirmScripts: Bool,
                   output: @escaping @Sendable (String) -> Void) async throws -> (UpdateAttempt, UpdatePlan) {
        await record.add(planID, confirmMajor, confirmScripts)
        output("==> Upgrading git")
        output("done")
        if let gate { await gate.wait() }
        return (result, resultPlan ?? plans[0])
    }

    func updateLog() async throws -> [UpdateAttempt] { [result] }
}

private let gitItem = ItemRecord(id: "formula:git", source: "homebrew", name: "git", state: .updateAvailable,
                                 kind: "formula", installedVersion: "2.46.0", latestVersion: "2.47.1")

// MARK: - Contract

@Test func decodesEnginePlanAndAttempt() throws {
    let planJSON = #"""
    {"schema_version": 1, "plan": {"item_key": "homebrew/formula:git", "name": "git", "kind": "formula",
     "full_name": "git", "installed_version": "2.46.0", "target_version": "2.47.1",
     "command": ["/fake/brew", "upgrade", "--formula", "git"], "command_text": "/fake/brew upgrade --formula git",
     "also_changes": [{"name": "pcre2", "before": null, "after": "10.44", "change": "install"}],
     "major_change": false, "scripts": [], "manual_steps": [], "refusal": null, "detail": null, "id": "1ccd979f00999dd7"}}
    """#
    let p = try EngineJSON.decode(UpdatePlanResponse.self, from: Data(planJSON.utf8)).plan
    #expect(p.id == "1ccd979f00999dd7" && p.commandText == "/fake/brew upgrade --formula git")
    #expect(p.alsoChanges == [PackageChange(name: "pcre2", before: nil, after: "10.44", change: "install")])

    let logJSON = #"""
    {"schema_version": 1, "attempts": [{"id": 3, "item_key": "homebrew/formula:git", "name": "git", "kind": "formula",
     "command": ["/fake/brew", "upgrade", "--formula", "git"], "before_version": "2.46.0", "target_version": "2.47.1",
     "after_version": "2.46.0", "status": "not_verified", "exit_code": 0, "output": "done",
     "error": "The command finished, but the installed version is still 2.46.0.", "manual_steps": [],
     "confirmed_major": false, "confirmed_scripts": false, "plan_id": "1ccd979f00999dd7",
     "started_at": "2026-10-29T10:00:00Z", "finished_at": "2026-10-29T10:01:00Z"}]}
    """#
    let a = try EngineJSON.decode(UpdateLogResponse.self, from: Data(logJSON.utf8)).attempts[0]
    #expect(a.status == .notVerified && a.afterVersion == "2.46.0" && a.exitCode == 0)
}

@Test func resultTextsMatchDesign() {
    #expect(UpdateResultStyle(attempt(.verified)).text == "Updated. Installed version is now 2.47.1.")
    #expect(UpdateResultStyle(attempt(.verified)).symbol == "checkmark.seal")
    let notVerified = UpdateResultStyle(attempt(.notVerified, after: "2.46.0"))
    #expect(notVerified.text == "The command finished, but the installed version is still 2.46.0.")
    #expect((notVerified.symbol, notVerified.tone) == ("exclamationmark.triangle", .orange))
    // Moved to a version that is not the plan target: no "still".
    #expect(UpdateResultStyle(attempt(.notVerified, after: "2.47.0")).text
        == "The command finished, but the installed version is 2.47.0, not 2.47.1.")
    let failed = UpdateResultStyle(attempt(.failed, after: "2.46.0", exit: 1))
    #expect((failed.text, failed.symbol, failed.tone) == ("The update failed (exit code 1).", "xmark.octagon", .red))
    let changed = UpdateResultStyle(attempt(.planChanged, after: nil, exit: nil))
    #expect((changed.text, changed.symbol) == ("The plan changed. Review the new plan.", "arrow.triangle.2.circlepath"))
}

@Test func planTexts() {
    #expect(plan().versionLine == "2.46.0 → 2.47.1")
    #expect(plan(major: true).majorWarning == "2.x → 3.0.0 can break your setup.")
    #expect(plan(scripts: ["the formula runs a post-install step"]).scriptsText
        == "git needs install scripts: the formula runs a post-install step.")
    #expect(plan().commandText == "/opt/homebrew/bin/brew upgrade --formula git")
}

@Test func updateButtonPolicy() {
    #expect(UpdatePolicy.blockReason(gitItem) == nil)
    var vulnerable = gitItem
    vulnerable.state = .vulnerable
    #expect(UpdatePolicy.blockReason(vulnerable) == nil)
    var current = gitItem
    current.state = .upToDate
    #expect(UpdatePolicy.blockReason(current) == "No update is available.")
    var pinned = gitItem
    pinned.state = .pinned
    #expect(UpdatePolicy.blockReason(pinned) != nil)
    var tap = gitItem
    tap.origin = "acme/tools"
    #expect(UpdatePolicy.blockReason(tap) != nil)
    let app = ItemRecord(id: "app:a", source: "apps", name: "A", state: .updateAvailable, latestVersion: "2")
    #expect(UpdatePolicy.blockReason(app) == "Watchtower can update Homebrew formulae and casks only.")
}

// MARK: - Flow

@MainActor
@Test func planThenConfirmRunsAndShowsTheVerifiedResult() async {
    let client = FakeUpdates(plans: [plan()])
    let model = UpdateModel(client: client)
    var finished = 0
    model.onFinished = { finished += 1 }
    await model.start(gitItem)
    #expect(model.step == .plan(plan()))
    #expect(await client.record.runs.isEmpty)  // nothing runs before the owner confirms
    await model.confirm()
    #expect(model.step == .result(attempt(.verified), plan()))
    #expect(model.output == ["==> Upgrading git", "done"])
    #expect(model.attempts == [attempt(.verified)])
    #expect(finished == 1)
    let runs = await client.record.runs
    #expect(runs.count == 1 && runs[0].0 == "aaaa" && !runs[0].1 && !runs[0].2)
}

@MainActor
@Test func majorVersionAsksFirstAndCancelRunsNothing() async {
    let client = FakeUpdates(plans: [plan(major: true)])
    let model = UpdateModel(client: client)
    await model.start(gitItem)
    await model.confirm()
    #expect(model.step == .confirmMajor(plan(major: true)))
    model.backToPlan()
    #expect(model.step == .plan(plan(major: true)))
    #expect(await client.record.runs.isEmpty)
    await model.confirm()
    await model.confirmMajor()
    let runs = await client.record.runs
    #expect(runs.count == 1 && runs[0].1 == true && runs[0].2 == false)
}

@MainActor
@Test func scriptsNeedASecondConfirmation() async {
    let client = FakeUpdates(plans: [plan(major: true, scripts: ["the formula runs a post-install step"])])
    let model = UpdateModel(client: client)
    await model.start(gitItem)
    await model.confirm()
    await model.confirmMajor()
    guard case .confirmScripts = model.step else {
        Issue.record("expected the scripts step, got \(model.step)")
        return
    }
    #expect(await client.record.runs.isEmpty)
    await model.confirmScripts()
    let runs = await client.record.runs
    #expect(runs.count == 1 && runs[0].1 && runs[0].2)
}

@MainActor
@Test func refusedPlanCannotRun() async {
    let client = FakeUpdates(plans: [plan(refusal: "Pinned with brew pin. Watchtower does not update pinned items.")])
    let model = UpdateModel(client: client)
    await model.start(gitItem)
    await model.confirm()
    #expect(await client.record.runs.isEmpty)
    guard case .plan = model.step else {
        Issue.record("expected the plan step")
        return
    }
}

@MainActor
@Test func runningUpdateCannotBeClosed() async {
    let gate = Gate()
    let model = UpdateModel(client: FakeUpdates(plans: [plan()], gate: gate))
    await model.start(gitItem)
    let run = Task { await model.confirm() }
    while !model.isRunning { await Task.yield() }
    model.close()
    #expect(model.isRunning && model.isPresented)
    await gate.release()
    await run.value
    model.close()
    #expect(!model.isPresented)
}

@MainActor
@Test func changedPlanOffersReviewOfTheNewPlan() async {
    let newer = plan(id: "bbbb", target: "2.47.2")
    let client = FakeUpdates(plans: [plan()], result: attempt(.planChanged, after: nil, exit: nil), resultPlan: newer)
    let model = UpdateModel(client: client)
    await model.start(gitItem)
    await model.confirm()
    model.review()
    #expect(model.step == .plan(newer))
}

@MainActor
@Test func viewLogSelectsTheAttempt() async {
    let model = UpdateModel(client: FakeUpdates(plans: [plan()]))
    var shown = false
    model.onViewLog = { shown = true }
    await model.start(gitItem)
    await model.confirm()
    model.viewLog()
    #expect(shown && !model.isPresented && model.selectedAttempt == attempt(.verified))
}

@MainActor
@Test func planErrorShowsTheEngineMessage() async {
    let error = EngineError.reported(message: "Homebrew is not installed.", detail: nil)
    var client = FakeUpdates(plans: [plan()])
    client.planError = error
    let model = UpdateModel(client: client)
    await model.start(gitItem)
    #expect(model.step == .failed(error))
}

// MARK: - Engine arguments

private struct ArgsRunner: CommandRunner {
    let stdout: String
    let seen = Seen()
    actor Seen {
        var args: [String] = []
        func set(_ a: [String]) { args = a }
    }

    func run(_ executable: URL, _ arguments: [String], environment: [String: String],
             onStderrLine: @escaping @Sendable (String) -> Void) async throws -> ProcessResult {
        await seen.set(arguments)
        onStderrLine(#"{"schema_version": 1, "output": "==> Upgrading git"}"#)
        return ProcessResult(status: 0, stdout: Data(stdout.utf8), stderr: Data())
    }
}

private final class Lines: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String] = []
    func add(_ s: String) { lock.withLock { items.append(s) } }
    var all: [String] { lock.withLock { items } }
}

@Test func engineRunPassesConfirmationsAndStreamsOutput() async throws {
    let body = #"""
    {"schema_version": 1, "attempt": {"id": 1, "item_key": "homebrew/formula:git", "name": "git", "kind": "formula",
     "command": ["brew"], "before_version": "2.46.0", "target_version": "3.0.0", "after_version": "3.0.0",
     "status": "verified", "exit_code": 0, "output": "", "error": null, "manual_steps": [], "confirmed_major": true,
     "confirmed_scripts": true, "plan_id": "x", "started_at": "2026-10-29T10:00:00Z", "finished_at": null},
     "plan": {"id": "x", "item_key": "homebrew/formula:git", "name": "git", "kind": "formula", "full_name": "git",
     "installed_version": "2.46.0", "target_version": "3.0.0", "command": ["brew"], "command_text": "brew",
     "also_changes": [], "major_change": true, "scripts": ["x"], "manual_steps": [], "refusal": null, "detail": null}}
    """#
    let runner = ArgsRunner(stdout: body)
    let engine = Engine(command: EngineCommand(executable: URL(fileURLWithPath: "/usr/bin/python3"),
                                               arguments: ["-m", "watchtower_engine.cli"], environment: [:]),
                        runner: runner)
    let lines = Lines()
    let (a, _) = try await engine.runUpdate(itemKey: "homebrew/formula:git", planID: "x", confirmMajor: true,
                                            confirmScripts: true, output: { lines.add($0) })
    #expect(a.status == .verified)
    #expect(await runner.seen.args == ["-m", "watchtower_engine.cli", "update-run", "homebrew/formula:git",
                                       "--plan-id", "x", "--confirm-major", "--confirm-scripts"])
    #expect(lines.all == ["==> Upgrading git"])
}


// MARK: - uv (#11)

private let httpx = FindingRecord(
    id: "SEC-0006", ecosystem: "PyPI", package: "httpx", title: "t", severity: .high, advisoryIds: ["GHSA-1"],
    fixedIn: "0.27.2", firstSeen: Date(timeIntervalSince1970: 0), lastSeen: Date(timeIntervalSince1970: 0))
private let uvPath = FindingPath(project: "tool", projectPath: "~/Real/tool", lockfile: "uv.lock", version: "0.26.0")

@Test func uvItemKeyComesFromTheFindingAndOnlyForUvLockfiles() {
    #expect(UVUpdate.key(finding: httpx, path: uvPath) == "uv/httpx@0.27.2|~/Real/tool|uv.lock")
    let nested = FindingPath(project: "tool", projectPath: "~/Real/tool", lockfile: "app/uv.lock", version: "1")
    #expect(UVUpdate.key(finding: httpx, path: nested) == "uv/httpx@0.27.2|~/Real/tool|app/uv.lock")
    let npm = FindingPath(project: "web", projectPath: "~/Projects/web", lockfile: "package-lock.json", version: "1")
    #expect(UVUpdate.key(finding: httpx, path: npm) == nil)
    var npmFinding = httpx
    npmFinding.ecosystem = "npm"
    #expect(UVUpdate.key(finding: npmFinding, path: uvPath) == nil)
    var noFix = httpx
    noFix.fixedIn = nil
    #expect(UVUpdate.key(finding: noFix, path: uvPath) == nil)
    var resolved = httpx
    resolved.status = .resolved
    #expect(UVUpdate.key(finding: resolved, path: uvPath) == nil)
}

@Test func updateIsOffWithTheReasonFromTheEngine() {
    #expect(UVUpdate.blockReason(uvPath) == nil)
    var blocked = uvPath
    blocked.updateBlock = "No environment found. Watchtower does not create environments."
    #expect(UVUpdate.blockReason(blocked) == "No environment found. Watchtower does not create environments.")
}

@Test func decodesUvPlanRowsAndResultRows() throws {
    let planJSON = #"""
    {"schema_version": 1, "plan": {"item_key": "uv/httpx@0.27.2|~/Real/tool|uv.lock", "name": "httpx", "kind": "uv",
     "full_name": "httpx", "installed_version": "0.26.0", "target_version": "0.27.2",
     "command": ["/uv", "sync"], "command_text": "/uv sync", "also_changes": [], "major_change": false,
     "scripts": ["httpx needs a source build: no wheel for this platform."], "manual_steps": [],
     "refusal": null, "detail": null,
     "rows": [{"label": "Project", "value": "~/Real/tool"},
              {"label": "Other packages", "value": "1 packages", "items": ["anyio 4.2.0 → 4.3.0"]}],
     "scripts_message": "httpx needs a source build: no wheel for this platform.",
     "scripts_command": ["/uv", "sync"], "fingerprint": "abc", "id": "1"}}
    """#
    let plan = try EngineJSON.decode(UpdatePlanResponse.self, from: Data(planJSON.utf8)).plan
    #expect(plan.rows == [PlanRow(label: "Project", value: "~/Real/tool"),
                          PlanRow(label: "Other packages", value: "1 packages", items: ["anyio 4.2.0 → 4.3.0"])])
    #expect(plan.scriptsText == "httpx needs a source build: no wheel for this platform.")

    let logJSON = #"""
    {"schema_version": 1, "attempts": [{"id": 3, "item_key": "uv/httpx@0.27.2|~/Real/tool|uv.lock", "name": "httpx",
     "kind": "uv", "command": ["/uv"], "before_version": "0.26.0", "target_version": "0.27.2",
     "after_version": "0.26.0", "status": "not_verified", "exit_code": 0, "output": "",
     "error": "Not verified: the environment still has 0.26.0.", "manual_steps": [],
     "confirmed_major": false, "confirmed_scripts": false, "plan_id": "1",
     "started_at": "2026-10-29T10:00:00Z", "finished_at": "2026-10-29T10:01:00Z",
     "result_rows": [{"label": "Lockfile", "value": "httpx 0.27.2"},
                     {"label": "Installed (.venv)", "value": "httpx 0.26.0"}]}]}
    """#
    let attempt = try EngineJSON.decode(UpdateLogResponse.self, from: Data(logJSON.utf8)).attempts[0]
    #expect(attempt.resultRows?.map(\.label) == ["Lockfile", "Installed (.venv)"])
    #expect(UpdateResultStyle(attempt).text == "Not verified: the environment still has 0.26.0.")
}

@Test func findingPathDecodesTheUpdateBlock() throws {
    let json = #"""
    {"project": "tool", "project_path": "~/Real/tool", "lockfile": "uv.lock", "version": "0.26.0",
     "dependency_path": null, "update_block": "Watchtower cannot update workspace projects yet."}
    """#
    let path = try EngineJSON.makeDecoder().decode(FindingPath.self, from: Data(json.utf8))
    #expect(path.updateBlock == "Watchtower cannot update workspace projects yet.")
    let old = try EngineJSON.makeDecoder().decode(FindingPath.self, from: Data(
        #"{"project": "a", "project_path": "~/a", "lockfile": "uv.lock", "version": "1"}"#.utf8))
    #expect(old.updateBlock == nil)
}

@Test func homebrewResultTextStaysTheSameWhenTheEngineGivesAnError() {
    var a = attempt(.notVerified, after: "2.46.0")
    a.error = "The command finished, but the installed version is still 2.46.0."
    #expect(UpdateResultStyle(a).text == "The command finished, but the installed version is still 2.46.0.")
    a.kind = "uv"
    a.error = "uv replaced the environment. Watchtower did not plan that."
    #expect(UpdateResultStyle(a).text == "uv replaced the environment. Watchtower did not plan that.")
}

@MainActor
@Test func startingFromAFindingOpensTheUvPlanWithoutRunningAnything() async {
    let client = FakeUpdates(plans: [plan()])
    let model = UpdateModel(client: client)
    await model.start(finding: httpx, path: uvPath)
    if case .plan(let p) = model.step { #expect(p.id == "aaaa") } else { Issue.record("no plan step") }
    #expect(await client.record.runs.isEmpty)
    let asked = await client.record.planKeys
    #expect(asked == ["uv/httpx@0.27.2|~/Real/tool|uv.lock"])
}
