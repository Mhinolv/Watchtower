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
    let (f, path) = finding()
    #expect(NPMUpdate.key(finding: f, path: path) == "npm|~/Projects/web|express|4.19.0")
    let nested = FindingPath(project: "mono", projectPath: "~/Projects/mono", lockfile: "app/package-lock.json",
                             version: "4.17.1")
    let (noFix, _) = finding(fixedIn: nil)
    #expect(NPMUpdate.key(finding: noFix, path: nested) == "npm|~/Projects/mono/app|express|-")
}

@Test func findingKeysPickTheAdapter() {
    let (npmFinding, npmPath) = finding()
    #expect(UpdateKeys.forFinding(npmFinding, npmPath)?.hasPrefix("npm|") == true)
    let (pypi, uvPath) = finding(ecosystem: "PyPI", lockfile: "uv.lock", fixedIn: "0.27.2")
    #expect(UpdateKeys.forFinding(pypi, uvPath)?.hasPrefix("uv/") == true)
    let (yarn, yarnPath) = finding(lockfile: "yarn.lock")
    #expect(UpdateKeys.forFinding(yarn, yarnPath) == nil)
    #expect(UpdateKeys.blockReason(yarn, yarnPath) == "Watchtower updates projects with package-lock.json or uv.lock only.")
    let (resolved, resolvedPath) = finding(status: .resolved)
    #expect(UpdateKeys.forFinding(resolved, resolvedPath) == nil)
    #expect(UpdateKeys.blockReason(resolved, resolvedPath) == "This finding is resolved.")
    #expect(UpdateKeys.blockReason(npmFinding, npmPath) == nil)
}

@Test func decodesNpmPlanRowsAndScriptDetails() throws {
    let json = #"""
    {"schema_version": 1, "plan": {"id": "abc", "item_key": "npm|~/Projects/web|express|4.19.0", "name": "express",
     "kind": "npm", "full_name": "express", "installed_version": "4.17.1", "target_version": "4.19.2",
     "command": ["/fake/bin/npm", "install", "express@^4.19.2"], "command_text": "/fake/bin/npm install express@^4.19.2",
     "also_changes": [], "major_change": false, "scripts": ["esbuild needs its postinstall script"],
     "manual_steps": [], "refusal": null, "detail": null,
     "rows": [{"label": "Project", "value": "~/Projects/web"},
              {"label": "Other packages", "value": "1 package changes", "items": ["cookie 0.5.0 → 0.6.0"]},
              {"label": "Scripts", "value": "Disabled (--ignore-scripts)"}],
     "scripts_message": "esbuild needs its postinstall script.",
     "scripts_command": ["/fake/bin/npm", "rebuild", "esbuild"],
     "script_details": [{"package": "esbuild", "version": "0.21.5", "script": "postinstall"}],
     "fingerprint": "f00"}}
    """#
    let plan = try EngineJSON.decode(UpdatePlanResponse.self, from: Data(json.utf8)).plan
    #expect(plan.rows?.map(\.label) == ["Project", "Other packages", "Scripts"])
    #expect(plan.rows?[1].items == ["cookie 0.5.0 → 0.6.0"])
    #expect(plan.scriptDetails == [ScriptDetail(package: "esbuild", version: "0.21.5", script: "postinstall")])
    #expect(plan.scriptsText == "esbuild needs its postinstall script.")
}

@Test func npmResultUsesTheEngineTextAndSeparateRows() {
    func attempt(_ status: UpdateStatus, error: String?, installedOK: Bool) -> UpdateAttempt {
        UpdateAttempt(id: 1, itemKey: "npm|~/Projects/web|express|-", name: "express", kind: "npm", command: ["npm"],
                      beforeVersion: "4.17.1", targetVersion: "4.19.2", afterVersion: "4.19.2", status: status,
                      exitCode: 0, output: "", error: error, startedAt: now,
                      resultRows: [PlanRow(label: "Lockfile", value: "express 4.19.2", ok: true),
                                   PlanRow(label: "Installed (node_modules)", value: "express 4.17.1", ok: installedOK)])
    }
    let lockOnly = UpdateResultStyle(attempt(.notVerified, error: "Not verified: the installed package is still 4.17.1.",
                                             installedOK: false))
    #expect(lockOnly.text == "Not verified: the installed package is still 4.17.1.")
    #expect(lockOnly.tone == .orange && lockOnly.detail == "Watchtower does not count this update as done.")
    #expect(UpdateResultStyle(attempt(.verified, error: nil, installedOK: true)).text
        == "Updated. Installed version is now 4.19.2.")
}

@MainActor
@Test func startForAnNpmFindingLoadsItsPlan() async {
    actor Seen { var keys: [String] = []; func add(_ k: String) { keys.append(k) } }
    struct Client: UpdateClient {
        let seen: Seen
        func updatePlan(itemKey: String) async throws -> UpdatePlan {
            await seen.add(itemKey)
            return UpdatePlan(id: "p", itemKey: itemKey, name: "express", kind: "npm", fullName: "express",
                              installedVersion: "4.17.1", targetVersion: "4.19.2", command: ["npm"])
        }
        func runUpdate(itemKey: String, planID: String, confirmMajor: Bool, confirmScripts: Bool,
                       output: @escaping @Sendable (String) -> Void) async throws -> (UpdateAttempt, UpdatePlan) {
            throw CancellationError()
        }
        func updateLog() async throws -> [UpdateAttempt] { [] }
    }
    let seen = Seen()
    let model = UpdateModel(client: Client(seen: seen))
    let (f, path) = finding()
    await model.start(finding: f, path: path)
    #expect(await seen.keys == ["npm|~/Projects/web|express|4.19.0"])
    guard case .plan = model.step else {
        Issue.record("expected a plan")
        return
    }
}
