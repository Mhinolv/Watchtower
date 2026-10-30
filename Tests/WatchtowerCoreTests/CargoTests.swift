import Foundation
import Testing
@testable import WatchtowerCore

// MARK: - Cargo (#15)

private let smallvec = FindingRecord(
    id: "SEC-0009", ecosystem: "crates.io", package: "smallvec", title: "t", severity: .high,
    advisoryIds: ["RUSTSEC-2021-0003", "GHSA-43w2-9j62-hq99"], fixedIn: "1.6.1",
    firstSeen: Date(timeIntervalSince1970: 0), lastSeen: Date(timeIntervalSince1970: 0))
private let cargoPath = FindingPath(project: "tool", projectPath: "~/Projects/tool", lockfile: "Cargo.lock",
                                    version: "1.6.0")

@Test func cargoItemKeyComesFromTheFindingAndOnlyForCargoLockfiles() {
    #expect(CargoUpdate.key(finding: smallvec, path: cargoPath) == "cargo/smallvec@1.6.1|~/Projects/tool|Cargo.lock")
    #expect(UpdateKeys.forFinding(smallvec, cargoPath) == "cargo/smallvec@1.6.1|~/Projects/tool|Cargo.lock")
    let nested = FindingPath(project: "app", projectPath: "~/Projects/app", lockfile: "capture/Cargo.lock", version: "1")
    #expect(CargoUpdate.key(finding: smallvec, path: nested) == "cargo/smallvec@1.6.1|~/Projects/app|capture/Cargo.lock")
    let uv = FindingPath(project: "tool", projectPath: "~/Real/tool", lockfile: "uv.lock", version: "1")
    #expect(CargoUpdate.key(finding: smallvec, path: uv) == nil)
    var noFix = smallvec
    noFix.fixedIn = nil
    #expect(CargoUpdate.key(finding: noFix, path: cargoPath) == nil)
    #expect(UpdateKeys.blockReason(noFix, cargoPath) == "No fixed version is known.")
    var resolved = smallvec
    resolved.status = .resolved
    #expect(CargoUpdate.key(finding: resolved, path: cargoPath) == nil)
}

@Test func cargoUpdateIsOffWithTheReasonFromTheEngine() {
    var blocked = cargoPath
    blocked.updateBlock = "Cargo workspaces are not supported yet."
    #expect(UpdateKeys.blockReason(smallvec, blocked) == "Cargo workspaces are not supported yet.")
    #expect(UpdateKeys.blockReason(smallvec, cargoPath) == nil)
    let gemfile = FindingPath(project: "r", projectPath: "~/Projects/r", lockfile: "Gemfile.lock", version: "1")
    #expect(UpdateKeys.blockReason(smallvec, gemfile)
            == "Watchtower updates projects with package-lock.json, uv.lock, Cargo.lock or requirements.txt only.")
}

@Test func lockfileUpdatedIsItsOwnResultNotVerified() throws {
    let json = #"""
    {"schema_version": 1, "attempts": [{"id": 11, "item_key": "cargo/serde@1.0.210|~/Projects/tool|Cargo.lock",
     "name": "serde", "kind": "cargo", "command": ["/cargo", "update"], "before_version": "1.0.190",
     "target_version": "1.0.210", "after_version": "1.0.210", "status": "lockfile_updated", "exit_code": 0,
     "output": "", "error": null, "manual_steps": [], "confirmed_major": false, "confirmed_scripts": false,
     "plan_id": "p", "started_at": "2026-10-29T10:00:00Z", "finished_at": "2026-10-29T10:00:05Z",
     "result_rows": [{"label": "Lockfile", "value": "serde 1.0.210", "ok": true},
                     {"label": "Installed", "value": "not checked. Cargo builds crates on next use."}]}]}
    """#
    struct Log: Decodable { var attempts: [UpdateAttempt] }
    let attempt = try #require(try EngineJSON.decode(Log.self, from: Data(json.utf8)).attempts.first)
    #expect(attempt.status == .lockfileUpdated && attempt.status.text == "Lockfile updated")
    #expect(attempt.resultRows?.map(\.ok) == [true, nil])
    let style = UpdateResultStyle(attempt)
    #expect(style.text == "Lockfile updated." && style.tone == .green)
    #expect(style.detail == "Watchtower read Cargo.lock again. Cargo builds the crate on next use.")
    #expect(style.text != UpdateStatus.verified.text)
}

@Test func decodesTheDependenciesTableOfACargoProject() throws {
    let json = #"""
    {"schema_version": 1, "projects": [
      {"name": "tool", "path": "/Users/me/Projects/tool", "root": "~/Projects", "manifests": ["Cargo.lock", "Cargo.toml"],
       "state": "active", "dependency_note": null, "dependencies": [
        {"package": "itoa", "declared": "=1.0.9", "locked": "1.0.9", "evidence": "exact_pin", "ecosystem": "crates.io",
         "table": null, "manifest": "Cargo.toml"},
        {"package": "memchr", "declared": "2.6", "locked": "2.8.0", "evidence": "range", "ecosystem": "crates.io",
         "table": "dev-dependencies", "manifest": "Cargo.toml"}]},
      {"name": "ws", "path": "/Users/me/Projects/ws", "root": "~/Projects", "manifests": ["Cargo.toml"],
       "state": "active", "dependencies": null, "dependency_note": "Cargo workspaces are not supported yet."},
      {"name": "web", "path": "/Users/me/Projects/web", "root": "~/Projects", "manifests": ["package.json"],
       "state": "active"}],
     "root_errors": [], "skipped": []}
    """#
    let list = try EngineJSON.decode(ProjectList.self, from: Data(json.utf8))
    let tool = try #require(list.projects.first)
    #expect(tool.dependencies?.map(\.evidenceText) == ["Exact pin", "Range"])
    #expect(tool.dependencies?.map(\.packageText) == ["itoa", "memchr (dev)"])
    #expect(list.projects[1].dependencies == nil)
    #expect(list.projects[1].dependencyNote == "Cargo workspaces are not supported yet.")
    #expect(list.projects[2].dependencies == nil && list.projects[2].dependencyNote == nil)
}
