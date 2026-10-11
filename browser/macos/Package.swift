// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NomadBrowser",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "NomadBrowser", targets: ["NomadBrowser"])
    ],
    targets: [
        .executableTarget(
            name: "NomadBrowser",
            resources: [.process("Resources")]
        ),
        .testTarget(
            name: "NomadBrowserTests",
            dependencies: ["NomadBrowser"]
        )
    ]
)
