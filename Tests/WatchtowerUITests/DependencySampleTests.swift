import Foundation
import Testing
@testable import WatchtowerCore
@testable import WatchtowerUI

// #94: the `dependencies-stopped` snapshot must show the rows not checked yet and `Check the rest`.
// The view reads the project when it appears. That read must not replace the partial list.

@MainActor
@Test func aReloadOfTheStoppedSampleKeepsTheRowsNotCheckedYet() async throws {
    let project = SampleData.dependencyProjects[0]
    let model = SampleData.dependencyModel(.dependenciesStopped)
    await model.load(project)  // What `DependenciesView.task` does.
    guard case .loaded(let list)? = model.load(for: project.path) else { Issue.record("not loaded"); return }
    #expect(list.pending == 2 && model.isChecking(project.path) == false)  // `Check the rest` shows, not the spinner.
    let pending = list.sections[0].rows.filter(\.latestPending)
    #expect(pending.count == 2 && pending.allSatisfy { $0.latestText == "Not checked yet" })
}

@MainActor
@Test func theCargoSampleHasAPathRowAndATooLargeRow() {
    let rows = SampleData.dependencyList(.dependenciesCargo).sections[0].rows
    let path = rows.first { $0.evidence == "path" }
    let big = rows.first { $0.latestTooLarge }
    #expect(path?.latestText == "No registry" && path?.update == .off("Git and path dependencies are not supported."))
    #expect(big?.latestText == "Too large" && big?.latestReason?.hasSuffix("larger than 8 MB. Watchtower did not read it.") == true)
}
