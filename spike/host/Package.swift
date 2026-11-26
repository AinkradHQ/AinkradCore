// swift-tools-version: 5.9
import Foundation
import PackageDescription

// Throwaway spike host. Links the Rust staticlib (Skia included) from ../engine/target/release.
let engine = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../engine/target/release").standardized.path

let package = Package(
    name: "DesignHost",
    platforms: [.macOS(.v14)],
    targets: [
        .target(name: "CDesign"),
        .executableTarget(
            name: "DesignHost",
            dependencies: ["CDesign"],
            linkerSettings: [
                .unsafeFlags(["-L", engine, "-ldesign_spike", "-lc++"]),
                .linkedFramework("Metal"), .linkedFramework("QuartzCore"), .linkedFramework("AppKit"),
                .linkedFramework("CoreText"), .linkedFramework("CoreGraphics"), .linkedFramework("CoreFoundation"),
                .linkedFramework("ApplicationServices"),
            ]
        ),
    ]
)
