import SwiftUI
import WatchtowerCore

@main
struct WatchtowerApp: App {
    var body: some Scene {
        WindowGroup("Watchtower") {
            Text("Watchtower \(Watchtower.version)")
                .frame(minWidth: 640, minHeight: 400)
        }
    }
}
