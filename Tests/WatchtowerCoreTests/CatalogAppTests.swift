import Foundation
import Testing
@testable import WatchtowerCore

// #55: apps matched to the public Homebrew cask catalog. The update stays manual.

private func app(origin: String? = "Homebrew catalog", attributes: [String: String]? = nil,
                 state: ItemState = .updateAvailable) -> ItemRecord {
    ItemRecord(id: "com.t3tools.t3code", source: "apps", name: "T3 Code", state: state, kind: "app",
               installedVersion: "0.1.3", latestVersion: "0.1.5", origin: origin,
               sourceAt: Date(timeIntervalSince1970: 1_793_275_200),
               attributes: attributes ?? ["cask": "t3-code", "matchedBy": "Bundle ID",
                                          "latestFrom": "Homebrew catalog, cask t3-code",
                                          "homepage": "https://t3.codes/"])
}

@Test func catalogAppsAreRecognisedByOrigin() {
    #expect(app().isCatalogApp)
    #expect(!app(origin: "Homebrew cask").isCatalogApp)
    #expect(!app(origin: "Manual").isCatalogApp)
}

@Test func vendorPageNeedsAWebAddress() {
    #expect(app().vendorPageURL?.host == "t3.codes")
    #expect(app(attributes: ["homepage": "file:///etc/passwd"]).vendorPageURL == nil)
    #expect(app(attributes: ["homepage": "javascript:alert(1)"]).vendorPageURL == nil)
    #expect(app(attributes: ["cask": "t3-code"]).vendorPageURL == nil)
}

@Test func evidenceRowsComeFromTheAttributes() {
    let item = app()
    #expect(item.matchedBy == "Bundle ID")
    #expect(item.latestFromText?.hasPrefix("Homebrew catalog, cask t3-code. Retrieved ") == true)
    #expect(app(attributes: ["cask": "x"]).latestFromText == nil)
}

@Test func catalogAppsNeverOfferAnUpdate() {
    // The Update button is hidden for them. The policy also refuses to plan one.
    #expect(UpdatePolicy.blockReason(app()) == "Watchtower can update Homebrew formulae and casks only.")
}
