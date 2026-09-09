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
        // The adapter, kept a separate product on purpose (ADR-002): a deployment that never
        // uses passkeys imports SwiftIdentity alone and links none of this.
        .library(
            name: "SwiftWebAuthnIdentity",
            targets: ["SwiftWebAuthnIdentity"]
        ),
    ],
    dependencies: [
        // ES256 and Ed25519 verification, and SHA-256 over client data and the RP ID.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.4.3"),
        // Consumed only by the adapter product, so a deployment that never uses passkeys
        // never resolves it. Pinned to a version rather than a branch: a branch dependency
        // gives a consumer no way to say which version it was built against, which the
        // dependency auditor says out loud.
        .package(url: "git@github.com:jpurnell/SwiftIdentity.git", from: "0.1.0"),
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
        // A development tool, deliberately **not** vended as a product: nobody can depend on
        // it. It mints challenges and writes files, which is exactly what a library must never
        // do on a consumer's behalf. `swift run webauthn-capture` inside this repo.
        .executableTarget(
            name: "webauthn-capture",
            dependencies: ["SwiftWebAuthn"],
            swiftSettings: [
                .enableUpcomingFeature("ApproachableConcurrency"),
            ]
        ),
        .target(
            name: "SwiftWebAuthnIdentity",
            dependencies: [
                "SwiftWebAuthn",
                .product(name: "SwiftIdentity", package: "SwiftIdentity"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("ApproachableConcurrency"),
            ]
        ),
        .testTarget(
            name: "SwiftWebAuthnTests",
            dependencies: ["SwiftWebAuthn"],
            // Ceremonies captured from a real Apple platform authenticator. Copied rather than
            // processed: these are exact bytes, and a resource pipeline that normalised anything
            // would change what the signatures cover.
            resources: [.copy("CapturedCeremonies")],
            swiftSettings: [
                .enableUpcomingFeature("ApproachableConcurrency"),
            ]
        ),
        .testTarget(
            name: "SwiftWebAuthnIdentityTests",
            dependencies: [
                "SwiftWebAuthnIdentity",
                .product(name: "SwiftIdentityConformance", package: "SwiftIdentity"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("ApproachableConcurrency"),
            ]
        ),
    ]
)
