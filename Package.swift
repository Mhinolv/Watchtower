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
        .target(name: "WatchtowerUI", dependencies: ["WatchtowerCore"]),
        .executableTarget(name: "WatchtowerApp", dependencies: ["WatchtowerCore", "WatchtowerUI"]),
        // Offscreen PNG renders of the UI for review. Run with scripts/snapshot.sh.
        .executableTarget(name: "WatchtowerSnapshots", dependencies: ["WatchtowerCore", "WatchtowerUI"]),
        .testTarget(
            name: "WatchtowerCoreTests",
            dependencies: ["WatchtowerCore"],
            resources: [.copy("Fixtures")]
        ),
    ]
)
