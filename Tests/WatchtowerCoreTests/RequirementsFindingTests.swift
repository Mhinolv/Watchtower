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
