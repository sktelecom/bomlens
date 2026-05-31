// swift-tools-version:5.9
// Minimal SPM example for sbom-tools (pure-Swift deps — resolvable on Linux,
// no iOS-platform/UIKit dependency).
import PackageDescription

let package = Package(
    name: "SwiftExample",
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0"),
        .package(url: "https://github.com/apple/swift-log", from: "1.5.0"),
    ],
    targets: [
        .executableTarget(
            name: "SwiftExample",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
            ]
        )
    ]
)
