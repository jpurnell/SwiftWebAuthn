// swift-tools-version: 6.2
// legibility:description: A relying-party implementation of WebAuthn — verifying passkey registration and authentication ceremonies, written against the W3C specification.
//
// 6.2 rather than the toolchain that happens to be installed: consumers of this deploy to a
// host running Swift 6.3.3, and a manifest newer than the target's compiler fails at deploy
// time rather than here.

import PackageDescription

let package = Package(
    name: "SwiftWebAuthn",
    platforms: [
        .macOS(.v14),
    ],
    products: [
        .library(
            name: "SwiftWebAuthn",
            targets: ["SwiftWebAuthn"]
        ),
    ],
    dependencies: [
        // ES256 and Ed25519 verification, and SHA-256 over client data and the RP ID.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.4.3"),
    ],
    targets: [
        .target(
            name: "SwiftWebAuthn",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("ApproachableConcurrency"),
            ]
        ),
        .testTarget(
            name: "SwiftWebAuthnTests",
            dependencies: ["SwiftWebAuthn"],
            swiftSettings: [
                .enableUpcomingFeature("ApproachableConcurrency"),
            ]
        ),
    ]
)
