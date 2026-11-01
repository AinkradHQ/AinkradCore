// swift-tools-version: 6.0
// The generated Swift client (E1-05.2): `generated/` is written by `make clients`; `Support/` and the rest are by hand.
import PackageDescription

let package = Package(
    name: "AinkradClient",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [.library(name: "AinkradClient", targets: ["AinkradClient"])],
    dependencies: [
        .package(url: "https://github.com/apple/swift-openapi-runtime", exact: "1.13.3"),
    ],
    targets: [
        .target(
            name: "AinkradClient",
            dependencies: [.product(name: "OpenAPIRuntime", package: "swift-openapi-runtime")],
            path: ".",
            sources: ["generated", "Support"]
        ),
        .testTarget(
            name: "AinkradClientTests",
            dependencies: ["AinkradClient"],
            resources: [.copy("Fixtures")]
        ),
    ]
)
