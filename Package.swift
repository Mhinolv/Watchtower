// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "Watchtower",
    platforms: [.macOS(.v15)],
    products: [
        .executable(name: "Watchtower", targets: ["WatchtowerApp"]),
        .library(name: "WatchtowerCore", targets: ["WatchtowerCore"]),
    ],
    targets: [
        .target(name: "WatchtowerCore"),
        .executableTarget(name: "WatchtowerApp", dependencies: ["WatchtowerCore"]),
        .testTarget(
            name: "WatchtowerCoreTests",
            dependencies: ["WatchtowerCore"],
            resources: [.copy("Fixtures")]
        ),
    ]
)
