// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "Watchtower",
    platforms: [.macOS(.v15)],
    products: [
        .executable(name: "Watchtower", targets: ["WatchtowerApp"]),
        .executable(name: "WatchtowerSnapshots", targets: ["WatchtowerSnapshots"]),
        .library(name: "WatchtowerCore", targets: ["WatchtowerCore"]),
    ],
    targets: [
        .target(name: "WatchtowerCore"),
        // Resources: menu bar template icons and the app icon PNG, copied from design/logo/.
        .target(name: "WatchtowerUI", dependencies: ["WatchtowerCore"], resources: [.process("Resources")]),
        // scripts/bundle.sh puts Info.plist and the compiled Assets.xcassets (AccentColor) in Watchtower.app.
        .executableTarget(name: "WatchtowerApp", dependencies: ["WatchtowerCore", "WatchtowerUI"],
                          exclude: ["Assets.xcassets", "Info.plist"]),
        // Offscreen PNG renders of the UI for review. Run with scripts/snapshot.sh.
        .executableTarget(name: "WatchtowerSnapshots", dependencies: ["WatchtowerCore", "WatchtowerUI"]),
        .testTarget(
            name: "WatchtowerCoreTests",
            dependencies: ["WatchtowerCore"],
            resources: [.copy("Fixtures")]
        ),
        .testTarget(name: "WatchtowerUITests", dependencies: ["WatchtowerCore", "WatchtowerUI"]),
    ]
)
