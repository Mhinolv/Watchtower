import Testing
@testable import WatchtowerCore

@Test func versionIsSet() {
    #expect(!Watchtower.version.isEmpty)
}
