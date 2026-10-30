import Foundation
import Testing
@testable import WatchtowerCore

// MARK: - requirements.txt findings (#80)

private let pinPath = FindingPath(project: "script", projectPath: "~/Real/script", lockfile: "requirements.txt",
                                  version: "2.31.0",
                                  evidence: PathEvidence(declared: "requests==2.31.0", evidence: "Exact pin",
                                                         installed: "2.31.0"))
private let requests = FindingRecord(
    id: "SEC-0009", ecosystem: "PyPI", package: "requests", title: "t", severity: .medium,
    advisoryIds: ["GHSA-9hjg-9r4m-mvj7"], fixedIn: "2.32.4",
    firstSeen: Date(timeIntervalSince1970: 0), lastSeen: Date(timeIntervalSince1970: 0), paths: [pinPath])

@Test func aPinFindingShowsTheFileTheLineAndTheEvidenceType() {
    #expect(pinPath.isRequirements)
    #expect(pinPath.sourceText == "requirements.txt · requests==2.31.0 · Exact pin")
    #expect(pinPath.dependencyText == "Direct (requirements.txt)")
    #expect(pinPath.evidenceRows.map(\.label) == ["Declared", "Lockfile", "Installed"])
    #expect(pinPath.evidenceRows.map(\.value) == ["requests==2.31.0 (Exact pin)", "No lockfile.", "2.31.0 (.venv)"])
    #expect(pinPath.evidenceRows.map(\.quiet) == [false, true, false])
}

@Test func anUncheckedEnvironmentSaysNotChecked() {
    var path = pinPath
    path.evidence?.installed = nil
    #expect(path.evidenceRows.last?.value == "not checked")
    #expect(path.evidenceRows.last?.quiet == true)
}

@Test func lockfilePathsKeepTheirOldText() {
    let uv = FindingPath(project: "tool", projectPath: "~/Real/tool", lockfile: "uv.lock", version: "0.26.0",
                         dependencyPath: ["tool", "httpx"])
    #expect(!uv.isRequirements && uv.sourceText == "uv.lock")
    #expect(uv.dependencyText == "Path: tool › httpx" && uv.evidenceRows.isEmpty)
    let none = FindingPath(project: "tool", projectPath: "~/Real/tool", lockfile: "uv.lock", version: "0.26.0")
    #expect(none.dependencyText == "Dependency path not available.")
}

@Test func aPinFindingOpensTheRequirementsPlan() {
    #expect(UpdateKeys.forFinding(requests, pinPath) == "requirements/requests@2.32.4|~/Real/script|requirements.txt")
    var refused = pinPath
    refused.updateBlock = "No environment found. Watchtower does not create environments."
    #expect(UpdateKeys.blockReason(requests, refused) == "No environment found. Watchtower does not create environments.")
}

@Test func decodesTheEvidenceOfARequirementsPath() throws {
    let json = #"""
    {"project": "script", "project_path": "~/Real/script", "lockfile": "requirements.txt", "version": "2.31.0",
     "dependency_path": null, "update_block": null,
     "evidence": {"declared": "requests==2.31.0", "evidence": "Exact pin", "installed": null}}
    """#
    let path = try EngineJSON.makeDecoder().decode(FindingPath.self, from: Data(json.utf8))
    #expect(path.evidence == PathEvidence(declared: "requests==2.31.0", evidence: "Exact pin", installed: nil))
    let old = #"{"project": "w", "project_path": "~/w", "lockfile": "package-lock.json", "version": "1"}"#
    #expect(try EngineJSON.makeDecoder().decode(FindingPath.self, from: Data(old.utf8)).evidence == nil)
}

@Test func projectRequirementsTextNeverShowsARangeAsAVersion() throws {
    let json = #"""
    {"schema_version": 1, "projects": [
      {"name": "script", "path": "/Users/me/Real/script", "root": "~/Real", "manifests": ["requirements.txt"],
       "state": "active", "requirements": [{"file": "requirements.txt", "pins": 12, "other_lines": 3, "skipped": null}]},
      {"name": "legacy", "path": "/Users/me/Real/legacy", "root": "~/Real", "manifests": ["requirements.txt"],
       "state": "active", "requirements": [{"file": "requirements.txt", "pins": 0, "other_lines": 0,
                                           "skipped": "-r includes or hashes are not supported"}]}],
     "root_errors": [], "skipped": []}
    """#
    let list = try EngineJSON.decode(ProjectList.self, from: Data(json.utf8))
    let scanned = try #require(list.projects[0].requirements?.first)
    #expect(scanned.statusText == "requirements.txt: 12 exact pins scanned")
    #expect(scanned.rangeText == "3 lines use ranges. Watchtower scans exact pins only.")
    let skipped = try #require(list.projects[1].requirements?.first)
    #expect(skipped.statusText == "requirements.txt: not scanned (-r includes or hashes are not supported)")
    #expect(skipped.rangeText == nil)
    #expect(RequirementsFile(file: "requirements.txt", pins: 1, otherLines: 1).statusText
            == "requirements.txt: 1 exact pin scanned")
    #expect(RequirementsFile(file: "requirements.txt", pins: 1, otherLines: 1).rangeText
            == "1 line uses a range. Watchtower scans exact pins only.")
    #expect(RequirementsFile(file: "requirements.txt", pins: 4, otherLines: 0).rangeText == nil)
}

// MARK: - A pinned package that is not installed (#96)

private func requirementsPlan(installed: String?, command: [String]) -> UpdatePlan {
    UpdatePlan(id: "p", itemKey: "requirements/litellm@1.84.0|~/Projects/podcastfy|requirements.txt", name: "litellm",
               kind: "requirements", fullName: "litellm", installedVersion: installed, targetVersion: "1.84.0",
               command: command)
}

@Test func aRequirementsPlanSaysNotInstalledInsteadOfAQuestionMark() {
    #expect(requirementsPlan(installed: nil, command: []).versionLine == "not installed → 1.84.0")
    #expect(requirementsPlan(installed: "1.52.2", command: ["/uv", "pip", "install"]).versionLine == "1.52.2 → 1.84.0")
    let brew = UpdatePlan(id: "b", itemKey: "homebrew/formula:git", name: "git", kind: "formula", fullName: "git",
                          installedVersion: nil, targetVersion: "2.47.1", command: ["brew"])
    #expect(brew.versionLine == "? → 2.47.1")
}

@Test func aPinOnlyPlanShowsThatNoCommandRuns() {
    #expect(requirementsPlan(installed: nil, command: []).commandDisplay
            == "No command runs. Watchtower edits requirements.txt only.")
    #expect(requirementsPlan(installed: "1.52.2", command: ["/uv", "pip", "install"]).commandDisplay == "/uv pip install")
}

@Test func pinUpdatedIsItsOwnResultNotVerified() throws {
    let json = #"""
    {"schema_version": 1, "attempts": [{"id": 12,
     "item_key": "requirements/litellm@1.84.0|~/Projects/podcastfy|requirements.txt",
     "name": "litellm", "kind": "requirements", "command": [], "before_version": null,
     "target_version": "1.84.0", "after_version": null, "status": "pin_updated", "exit_code": null,
     "output": "No command runs.", "error": null, "manual_steps": [], "confirmed_major": false,
     "confirmed_scripts": false, "plan_id": "p", "started_at": "2026-10-30T10:00:00Z",
     "finished_at": "2026-10-30T10:00:01Z",
     "result_rows": [{"label": "requirements.txt", "value": "litellm==1.84.0", "ok": true},
                     {"label": "Installed (.venv)", "value": "litellm not installed"}]}]}
    """#
    struct Log: Decodable { var attempts: [UpdateAttempt] }
    let attempt = try #require(try EngineJSON.decode(Log.self, from: Data(json.utf8)).attempts.first)
    #expect(attempt.status == .pinUpdated && attempt.status.text == "Pin updated")
    #expect(attempt.commandDisplay == "No command runs. Watchtower edits requirements.txt only.")
    let style = UpdateResultStyle(attempt)
    #expect(style.text == "requirements.txt now pins litellm 1.84.0." && style.tone == .green)
    #expect(style.detail == "Watchtower read requirements.txt again. Nothing was installed.")
}
