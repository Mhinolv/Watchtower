import Foundation
import Testing
@testable import WatchtowerCore

// #81: the Projects Dependencies table. The fixtures are real output of the engine (real PyPI and crates.io answers).

private let utc = TimeText(timeZone: TimeZone(identifier: "UTC")!)

private func fixture(_ name: String) throws -> DependencyList {
    let url = try #require(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures"))
    return try EngineJSON.decode(DependencyList.self, from: Data(contentsOf: url))
}

private func row(_ status: ItemState, installed: String? = "1.0", latest: String? = "2.0", key: String? = nil,
                 refusal: String? = nil, error: String? = nil) -> DependencyRow {
    DependencyRow(package: "p", declared: "==1.0", evidence: "exact_pin", installed: installed, installedLabel: ".venv",
                  latest: latest, latestError: error, status: status, updateKey: key, updateRefusal: refusal)
}

@Test func theRealRequirementsOutputDecodes() throws {
    let list = try fixture("dependencies-requirements")
    #expect(list.supported && list.project == "~/Real/script")
    let section = try #require(list.sections.first)
    #expect(section.manifest == "requirements.txt" && section.kind == "requirements" && section.refusal == nil)
    let requests = try #require(section.rows.first { $0.package == "requests" })
    #expect(requests.declared == "==2.31.0" && requests.evidenceText == "Exact pin")
    #expect(requests.installed == "2.32.3" && requests.installedLabel == ".venv")  // The file still says 2.31.0: the environment decides.
    #expect(requests.status == .updateAvailable)
    #expect(requests.updateKey?.hasPrefix("requirements/requests@") == true && requests.updateKey?.hasSuffix("|~/Real/script|requirements.txt") == true)
    #expect(section.latestSource.registry == "PyPI" && section.latestSource.retrievedAt != nil && section.latestSource.error == nil)
    let yaml = try #require(section.rows.first { $0.package == "PyYAML" })
    #expect(yaml.evidenceText == "Unpinned" && yaml.declaredText == "—")
}

@Test func theRealCargoOutputDecodesWithLockedAndTheDevTable() throws {
    let section = try #require(try fixture("dependencies-cargo").sections.first)
    #expect(section.manifest == "Cargo.toml" && section.kind == "cargo" && section.latestSource.registry == "crates.io")
    let itoa = try #require(section.rows.first { $0.package == "itoa" })
    #expect(itoa.evidenceText == "Exact pin" && itoa.installedLabel == "locked" && itoa.updateKey == nil)
    #expect(itoa.updateRefusal?.hasPrefix("Cargo.toml requires itoa \"=1.0.9\". That does not allow") == true)
    let memchr = try #require(section.rows.first { $0.package == "memchr" })
    #expect(memchr.packageText == "memchr (dev)" && memchr.status == .upToDate)
    let serde = try #require(section.rows.first { $0.package == "serde" })
    #expect(serde.updateKey?.hasPrefix("cargo/serde@") == true && serde.updateKey?.hasSuffix("|~/Projects/crabby|Cargo.lock") == true)
}

@Test func theEvidenceTextKeepsPinsAndRangesApart() {
    let texts = ["exact_pin", "range", "unpinned", "git", "path"].map {
        DependencyRow(package: "p", declared: "", evidence: $0, installed: nil, installedLabel: ".venv", latest: nil, status: .unknown).evidenceText
    }
    #expect(texts == ["Exact pin", "Range", "Unpinned", "Git", "Path"])
}

@Test func theUpdateButtonOpensThePlanOrStaysOffWithAReason() {
    #expect(row(.updateAvailable, key: "requirements/p@2.0|~/x|requirements.txt").update == .plan("requirements/p@2.0|~/x|requirements.txt"))
    #expect(row(.updateAvailable, refusal: "Cargo workspaces are not supported yet.").update == .off("Cargo workspaces are not supported yet."))
    #expect(row(.upToDate, latest: "1.0").update == .off("Already the latest version."))
    #expect(row(.unknown, installed: nil, latest: nil, error: "PyPI did not respond.").update == .off("PyPI did not respond."))
    #expect(row(.unknown, installed: nil, latest: nil).update == .off("The latest version is not known."))
    #expect(row(.vulnerable, latest: "1.0").update == .off("Already the latest version."))
    #expect(row(.vulnerable, key: "k").update == .plan("k"))
}

@Test func theLatestHelpNamesTheRegistryTheTimeAndAFailure() {
    let at = Date(timeIntervalSince1970: 1_793_345_280)  // 2026-10-30 07:28 UTC
    #expect(DependencyLatestSource(registry: "PyPI", retrievedAt: at).helpText(time: utc) == "PyPI, retrieved Oct 30, 07:28")
    #expect(DependencyLatestSource(registry: "PyPI", retrievedAt: at.addingTimeInterval(-86_400), error: "PyPI did not respond.")
        .helpText(time: utc) == "PyPI did not respond. Data from Oct 29.")
    #expect(DependencyLatestSource(registry: "crates.io", error: "crates.io did not respond.").helpText(time: utc)
        == "crates.io did not respond.")
}

@Test func theStatesHaveTheirExactCopy() {
    let empty = DependencySection(manifest: "requirements.txt", kind: "requirements", rows: [],
                                  latestSource: DependencyLatestSource(registry: "PyPI"))
    #expect(empty.emptyText == "No direct dependencies in requirements.txt.")
    let nested = DependencySection(manifest: "capture/Cargo.toml", kind: "cargo", rows: [], latestSource: DependencyLatestSource(registry: "crates.io"))
    #expect(nested.header == "capture/Cargo.toml" && nested.emptyText == "No direct dependencies in Cargo.toml.")
    #expect(DependencyList.unsupportedText == "Watchtower lists dependencies for requirements.txt and Cargo.toml only.")
}

@Test func voiceOverReadsPackageInstalledLatestAndStatus() {
    #expect(row(.updateAvailable).accessibilityText == "p, declared ==1.0, installed 1.0, latest 2.0, Update available")
    #expect(row(.unknown, installed: nil, latest: nil).accessibilityText == "p, declared ==1.0, installed not known, latest not known, Unknown")
}

private struct FakeDependencies: DependencyClient {
    var list: DependencyList
    var fail: EngineError?
    let calls = Calls()

    actor Calls {
        var paths: [String] = []
        func add(_ path: String) { paths.append(path) }
    }

    func dependencies(projectPath: String) async throws -> DependencyList {
        await calls.add(projectPath)
        if let fail { throw fail }
        return list
    }
}

private let project = ProjectRecord(name: "script", path: "/Users/me/Real/script", root: "~/Real", manifests: ["requirements.txt"], state: "active")

@MainActor
@Test func theModelReadsAProjectOnceAndKeepsItUntilReload() async throws {
    let list = try fixture("dependencies-requirements")
    let client = FakeDependencies(list: list)
    let model = DependencyModel(client: client)
    #expect(model.load(for: project.path) == nil)
    await model.load(project)
    #expect(model.load(for: project.path) == .loaded(list))
    await model.load(project)  // Already read: no second request.
    #expect(await client.calls.paths == [project.path])
    await model.load(project, force: true)
    #expect(await client.calls.paths.count == 2)
}

@MainActor
@Test func aFailedReadShowsTheEngineMessage() async {
    let client = FakeDependencies(list: DependencyList(project: "~", supported: false, sections: []),
                                  fail: .reported(message: "That folder is not a project in the project roots.", detail: nil))
    let model = DependencyModel(client: client)
    await model.load(project)
    #expect(model.load(for: project.path) == .failed(.reported(message: "That folder is not a project in the project roots.", detail: nil)))
}

private struct NoEngine: EngineClient {
    func state() async throws -> EngineState { throw CancellationError() }
    func refresh(progress: @escaping @Sendable (RefreshProgress) -> Void) async throws -> EngineState { throw CancellationError() }
    func projects() async throws -> ProjectList { ProjectList(schemaVersion: 1, projects: [], rootErrors: [], skipped: []) }
    func setProject(path: String, active: Bool) async throws -> ProjectRecord { throw CancellationError() }
    func deferFinding(id: String, days: Int) async throws -> FindingRecord { throw CancellationError() }
    func moveFindingToBacklog(id: String) async throws -> FindingRecord { throw CancellationError() }
    func reopenFinding(id: String) async throws -> FindingRecord { throw CancellationError() }
}

@MainActor
@Test func aClickOnVulnerableOpensTheFinding() {
    let model = DashboardModel(engine: NoEngine(), state: nil, projects: [project])
    model.selection = .projects
    model.itemFilter = .error
    model.openFinding("SEC-0012")
    #expect(model.selection == .findings && model.selectedItemKey == "SEC-0012" && model.itemFilter == .all)
    #expect(model.findingFilter == .open)
}
