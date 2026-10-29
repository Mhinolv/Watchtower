import Foundation
import Testing
@testable import WatchtowerCore

private let now = Date(timeIntervalSince1970: 1_793_275_200)

private func finding(ecosystem: String = "npm", status: FindingStatus = .open, lockfile: String = "package-lock.json",
                     fixedIn: String? = "4.19.0") -> (FindingRecord, FindingPath) {
    let path = FindingPath(project: "web", projectPath: "~/Projects/web", lockfile: lockfile, version: "4.17.1")
    let f = FindingRecord(id: "SEC-0001", ecosystem: ecosystem, package: "express", title: "x", severity: .high,
                          advisoryIds: ["GHSA-1"], fixedIn: fixedIn, status: status, firstSeen: now, lastSeen: now,
                          paths: [path])
    return (f, path)
}

@Test func npmKeyNamesTheLockfileFolder() {
    #expect(UpdateKeys.npm(projectPath: "~/Projects/web", lockfile: "package-lock.json", package: "express",
                           fixedIn: "4.19.0") == "npm|~/Projects/web|express|4.19.0")
    #expect(UpdateKeys.npm(projectPath: "~/Projects/mono", lockfile: "app/package-lock.json", package: "@acme/x",
                           fixedIn: nil) == "npm|~/Projects/mono/app|@acme/x|-")
}

@Test func npmUpdateButtonReasons() {
    let (open, path) = finding()
    #expect(UpdateKeys.npmBlockReason(open, path) == nil)
    let (pypi, p2) = finding(ecosystem: "PyPI", lockfile: "uv.lock")
    #expect(UpdateKeys.npmBlockReason(pypi, p2) == "Watchtower cannot update this ecosystem yet.")
    let (yarn, p3) = finding(lockfile: "yarn.lock")
    #expect(UpdateKeys.npmBlockReason(yarn, p3) == "Watchtower updates projects with package-lock.json only.")
    let (resolved, p4) = finding(status: .resolved)
    #expect(UpdateKeys.npmBlockReason(resolved, p4) != nil)
}

@Test func decodesNpmPlanRowsAndScriptDetails() throws {
    let json = #"""
    {"schema_version": 1, "plan": {"id": "abc", "item_key": "npm|~/Projects/web|express|4.19.0", "name": "express",
     "kind": "npm", "full_name": "express", "installed_version": "4.17.1", "target_version": "4.19.2",
     "command": ["/fake/bin/npm", "install", "express@^4.19.2"], "command_text": "/fake/bin/npm install express@^4.19.2",
     "also_changes": [{"name": "cookie", "before": "0.5.0", "after": "0.6.0", "change": "upgrade"}],
     "major_change": false, "scripts": ["esbuild needs its postinstall script"], "manual_steps": [],
     "refusal": null, "detail": null,
     "rows": [{"label": "Project", "value": "~/Projects/web"}],
     "changes_title": "Other packages", "scripts_off_text": "Disabled (--ignore-scripts)",
     "script_details": [{"package": "esbuild", "version": "0.21.5", "script": "postinstall"}]}}
    """#
    let plan = try EngineJSON.decode(UpdatePlanResponse.self, from: Data(json.utf8)).plan
    #expect(plan.rows == [PlanRow(label: "Project", value: "~/Projects/web")])
    #expect(plan.changesTitle == "Other packages" && plan.changesSummary == "1 package changes")
    #expect(plan.scriptsOffText == "Disabled (--ignore-scripts)")
    #expect(plan.scriptDetails == [ScriptDetail(package: "esbuild", version: "0.21.5", script: "postinstall")])
    #expect(plan.scriptsText == "esbuild needs its postinstall script.")
}

@Test func homebrewPlanWithoutNewFieldsStillDecodes() throws {
    let json = #"""
    {"schema_version": 1, "plan": {"id": "x", "item_key": "homebrew/formula:git", "name": "git", "kind": "formula",
     "full_name": "git", "installed_version": "2.46.0", "target_version": "2.47.1", "command": ["brew"],
     "command_text": "brew", "also_changes": [], "major_change": false, "scripts": [], "manual_steps": [],
     "refusal": null, "detail": null}}
    """#
    let plan = try EngineJSON.decode(UpdatePlanResponse.self, from: Data(json.utf8)).plan
    #expect(plan.rows == nil && plan.changesTitle == nil && plan.scriptDetails == nil)
}

@Test func npmResultUsesTheEngineTextAndSeparateChecks() {
    func attempt(_ status: UpdateStatus, error: String?, installedOK: Bool) -> UpdateAttempt {
        UpdateAttempt(id: 1, itemKey: "npm|~/Projects/web|express|-", name: "express", kind: "npm", command: ["npm"],
                      beforeVersion: "4.17.1", targetVersion: "4.19.2", afterVersion: "4.19.2", status: status,
                      exitCode: 0, output: "", error: error, startedAt: now,
                      checks: [UpdateCheck(label: "Lockfile", value: "express 4.19.2", ok: true),
                               UpdateCheck(label: "Installed (node_modules)", value: "express 4.17.1", ok: installedOK)])
    }
    let lockOnly = UpdateResultStyle(attempt(.notVerified, error: "Not verified: the installed package is still 4.17.1.",
                                             installedOK: false))
    #expect(lockOnly.text == "Not verified: the installed package is still 4.17.1.")
    #expect(lockOnly.tone == .orange && lockOnly.detail == "Watchtower does not count this update as done.")
    #expect(UpdateResultStyle(attempt(.verified, error: nil, installedOK: true)).text
        == "Updated. Installed version is now 4.19.2.")
}

@MainActor
@Test func startWithAKeyLoadsThatPlan() async {
    struct Client: UpdateClient {
        func updatePlan(itemKey: String) async throws -> UpdatePlan {
            UpdatePlan(id: "p", itemKey: itemKey, name: "express", kind: "npm", fullName: "express",
                       installedVersion: "4.17.1", targetVersion: "4.19.2", command: ["npm"])
        }
        func runUpdate(itemKey: String, planID: String, confirmMajor: Bool, confirmScripts: Bool,
                       output: @escaping @Sendable (String) -> Void) async throws -> (UpdateAttempt, UpdatePlan) {
            throw CancellationError()
        }
        func updateLog() async throws -> [UpdateAttempt] { [] }
    }
    let model = UpdateModel(client: Client())
    await model.start(itemKey: "npm|~/Projects/web|express|-", name: "express")
    guard case .plan(let plan) = model.step else {
        Issue.record("expected a plan")
        return
    }
    #expect(plan.itemKey == "npm|~/Projects/web|express|-")
}
