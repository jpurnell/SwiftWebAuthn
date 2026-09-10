#if canImport(os)
import os
#endif
import CaptureHTTP
import Foundation
import SwiftWebAuthn

/// What the browser posts back after a ceremony.
struct CeremonyResult: Decodable {
    let credentialID: String
    let clientDataJSON: String
    let attestationObject: String?
    let authenticatorData: String?
    let signature: String?
    let userHandle: String?
}

/// What gets written to disk, and what the test suite reads back.
///
/// The shape matches `RealCeremonyTests.Captured` exactly. It carries the challenge, origin and
/// relying party alongside the ceremony because a recorded ceremony is unverifiable without
/// them — and a fixture nobody can re-verify is a blob, not evidence.
struct CapturedCeremony: Encodable {
    let credentialID: String
    let clientDataJSON: String
    var attestationObject: String?
    var authenticatorData: String?
    var signature: String?
    var userHandle: String?
    let challenge: String
    let origin: String
    let relyingPartyID: String
}

/// The ceremony state one capture run accumulates.
actor Session {
    private var registrationChallenge: Challenge?
    private var authenticationChallenge: Challenge?
    private var registered: RegisteredCredential?

    /// The entropy source, handed in rather than reached for.
    private var generator: KernelRandom

    /// Starts a capture session against a chosen source of randomness.
    init(generator: KernelRandom) {
        self.generator = generator
    }

    func issueRegistrationChallenge() -> Challenge {
        let challenge = Challenge.random(using: &generator)
        registrationChallenge = challenge
        return challenge
    }

    func issueAuthenticationChallenge() -> Challenge {
        let challenge = Challenge.random(using: &generator)
        authenticationChallenge = challenge
        return challenge
    }

    func expectedRegistrationChallenge() throws -> Challenge {
        guard let registrationChallenge else { throw CaptureError.malformedRequest }
        return registrationChallenge
    }

    func expectedAuthenticationChallenge() throws -> Challenge {
        guard let authenticationChallenge else { throw CaptureError.malformedRequest }
        return authenticationChallenge
    }

    func store(_ credential: RegisteredCredential) { registered = credential }

    func credential() throws -> RegisteredCredential {
        guard let registered else { throw CaptureError.noRegistrationYet }
        return registered
    }
}

/// Captures a real ceremony from a real authenticator, and verifies it on the way past.
///
/// ## Why this exists
///
/// Every other test in this package builds its own inputs, so they agree with it by
/// construction. Only a ceremony from real hardware can disagree — which is how the signature
/// counter rule in §10.3 stopped being a reading of the specification and became a measurement.
///
/// ## Why it is a Swift tool rather than a script
///
/// It generates its options through ``RelyingParty/registrationOptions(for:challenge:excluding:userVerification:)``
/// and verifies the result through the same code a deployment would. A script with hand-written
/// JSON would capture a ceremony this package had never actually asked for, and could agree with
/// the browser while disagreeing with the library.
///
/// ## It is a target with no product
///
/// Nobody can depend on this. It mints challenges and writes files, which is exactly what a
/// library must never do on a consumer's behalf.
@main
struct Capture {

    static let port: UInt16 = 8099
    static let relyingPartyID = "localhost"


    static func main() async throws {
        let arguments = CommandLine.arguments
        let output = URL(
            fileURLWithPath: value(of: "--output", in: arguments) ?? FileManager.default.currentDirectoryPath
        )
        let origin = "http://\(relyingPartyID):\(port)"

        let party = RelyingParty(
            id: relyingPartyID, name: "SwiftWebAuthn capture", origins: [origin]
        )
        // Opened here and nowhere else. If the kernel's random device is unavailable this tool
        // refuses to start, rather than issuing challenges from something weaker without saying so.
        let session = Session(generator: try KernelRandom())

        let server = try HTTPServer(port: port) { request in
            await handle(request, party: party, session: session, origin: origin, output: output)
        }
        try server.start()

        write("""
            SwiftWebAuthn capture

              open   \(origin)
              writes \(output.path)

            Register, then authenticate. Each step asks for Touch ID, and each is verified here
            before it is written. Ctrl-C when done.

            Nothing secret is captured: an attestation object carries a public key, and the
            private half never leaves the Secure Enclave.

            """)

        // The listener serves on its own queue; this keeps the process alive until interrupted.
        // Guarded on cancellation rather than `true`, so the loop has a way out that is not the
        // process dying.
        while !Task.isCancelled {
            try await Task.sleep(for: .seconds(3600))
        }
    }

    #if canImport(os)
    static let logger = Logger(subsystem: "org.roseclub.swiftwebauthn", category: "capture")
    #endif

    // MARK: - Routing

    static func handle(
        _ request: Request, party: RelyingParty, session: Session, origin: String, output: URL
    ) async -> Response {
        do {
            switch (request.method, request.path) {
            case ("GET", "/"):
                return .html(page)

            case ("GET", "/register/options"):
                let challenge = await session.issueRegistrationChallenge()
                return try .json(party.registrationOptions(
                    for: UserEntity(
                        id: Array("capture-user".utf8), name: "capture", displayName: "Capture"
                    ),
                    challenge: challenge,
                    // The point of this tool is the built-in sensor. Without it a browser may
                    // offer to hand the ceremony to a phone, which captures a ceremony from
                    // hardware that is not the one being characterised.
                    attachment: .platform
                ))

            case ("GET", "/auth/options"):
                let credential = try await session.credential()
                let challenge = await session.issueAuthenticationChallenge()
                return try .json(party.authenticationOptions(
                    challenge: challenge, allowing: [credential.id]
                ))

            case ("POST", "/register/result"):
                return try await completeRegistration(
                    request, party: party, session: session, origin: origin, output: output
                )

            case ("POST", "/auth/result"):
                return try await completeAuthentication(
                    request, party: party, session: session, origin: origin, output: output
                )

            default:
                return .html("<h1>not here</h1>")
            }
        } catch {
            // Both, deliberately. The console line is this tool's interface — the operator is
            // watching it — and the log line is the record that survives the terminal being
            // closed. `.public`: a capture failure names a clause, never key material.
            #if canImport(os)
            logger.error("capture failed: \(String(describing: error), privacy: .public)")
            #endif
            write("  ✗ \(error)")
            return .html("<pre>\(error)</pre>")
        }
    }

    static func completeRegistration(
        _ request: Request, party: RelyingParty, session: Session, origin: String, output: URL
    ) async throws -> Response {
        let result = try JSONDecoder().decode(CeremonyResult.self, from: request.body)
        guard let attestation = result.attestationObject else { throw CaptureError.malformedRequest }
        let challenge = try await session.expectedRegistrationChallenge()

        // Verified before it is written. A fixture that does not verify is a bug report, and it
        // should be recognised as one here rather than committed as evidence.
        let credential = try party.verifyRegistration(
            RegistrationResponse(
                clientDataJSON: try Base64URL.decode(result.clientDataJSON),
                attestationObject: try Base64URL.decode(attestation)
            ),
            expecting: challenge
        )
        await session.store(credential)

        write("""
              ✓ registered
                  aaguid     \(credential.aaguid.map(hex).joined())
                  algorithm  \(credential.publicKey.algorithm)
                  backed up  \(credential.isBackedUp) (eligible: \(credential.isBackupEligible))
                  counter    \(credential.signCount)
            """)

        return try save(
            CapturedCeremony(
                credentialID: result.credentialID,
                clientDataJSON: result.clientDataJSON,
                attestationObject: attestation,
                challenge: Base64URL.encode(challenge.bytes),
                origin: origin,
                relyingPartyID: relyingPartyID
            ),
            as: "captured-registration.json", in: output
        )
    }

    static func completeAuthentication(
        _ request: Request, party: RelyingParty, session: Session, origin: String, output: URL
    ) async throws -> Response {
        let result = try JSONDecoder().decode(CeremonyResult.self, from: request.body)
        guard let authenticatorData = result.authenticatorData, let signature = result.signature else {
            throw CaptureError.malformedRequest
        }
        let challenge = try await session.expectedAuthenticationChallenge()
        let credential = try await session.credential()

        let verified = try party.verifyAuthentication(
            AuthenticationResponse(
                credentialID: try Base64URL.decode(result.credentialID),
                clientDataJSON: try Base64URL.decode(result.clientDataJSON),
                authenticatorData: try Base64URL.decode(authenticatorData),
                signature: try Base64URL.decode(signature),
                userHandle: try result.userHandle.map(Base64URL.decode)
            ),
            expecting: challenge,
            against: credential
        )

        write("""
              ✓ authenticated
                  verified   \(verified.userVerified)
                  backed up  \(verified.isBackedUp)
                  counter    \(credential.signCount) → \(verified.newSignCount)\
            \(verified.newSignCount == credential.signCount ? "  (unchanged — a synced passkey does not increment)" : "")
            """)

        return try save(
            CapturedCeremony(
                credentialID: result.credentialID,
                clientDataJSON: result.clientDataJSON,
                authenticatorData: authenticatorData,
                signature: signature,
                userHandle: result.userHandle,
                challenge: Base64URL.encode(challenge.bytes),
                origin: origin,
                relyingPartyID: relyingPartyID
            ),
            as: "captured-authentication.json", in: output
        )
    }

    // MARK: - Output

    static func save(_ ceremony: CapturedCeremony, as name: String, in directory: URL) throws -> Response {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let destination = directory.appendingPathComponent(name)
        try encoder.encode(ceremony).write(to: destination)
        write("    wrote \(destination.path)")
        return try .json(["saved": name])
    }

    static func value(of flag: String, in arguments: [String]) -> String? {
        guard let index = arguments.firstIndex(of: flag), index + 1 < arguments.count else {
            return nil
        }
        return arguments[index + 1]
    }

    /// Writes to standard output.
    ///
    /// `FileHandle` rather than `print`: this is a command-line tool whose entire output is its
    /// interface, and the logging rules exist to stop libraries printing — which this is not.
    static func write(_ text: String) {
        FileHandle.standardOutput.write(Data((text + "\n").utf8))
    }

    static func hex(_ byte: UInt8) -> String {
        let digits = "0123456789abcdef"
        let high = digits[digits.index(digits.startIndex, offsetBy: Int(byte >> 4))]
        let low = digits[digits.index(digits.startIndex, offsetBy: Int(byte & 0x0F))]
        return String([high, low])
    }
}
