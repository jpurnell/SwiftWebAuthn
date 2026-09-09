import Foundation
import Testing
@testable import SwiftWebAuthn

/// Verification against ceremonies a **real authenticator** produced.
///
/// Every other test in this package builds its own inputs, which means they agree with this
/// package by construction: if the CBOR subset, the flag layout or the signed-bytes order were
/// all wrong in the same direction, they would still pass. These do not have that problem —
/// nothing here was produced by any code in this repository.
///
/// Captured 2026-09-08 from Apple's platform authenticator (Touch ID, passkey synced to iCloud
/// Keychain) via Safari against `http://localhost:8099`. See `CapturedCeremonies/README.md`.
@Suite("A real ceremony, from a real authenticator")
struct RealCeremonyTests {

    /// Apple's iCloud Keychain passkey.
    static let appleKeychainAAGUID = "fbfc3007154e4ecc8c0b6e020557d7bd"

    struct Captured: Decodable {
        let credentialID: String
        let clientDataJSON: String
        let attestationObject: String?
        let authenticatorData: String?
        let signature: String?
        let userHandle: String?
        let challenge: String
        let origin: String
        let relyingPartyID: String
    }

    static func load(_ name: String) throws -> Captured {
        let url = try #require(
            Bundle.module.url(forResource: "CapturedCeremonies/\(name)", withExtension: "json"),
            "captured ceremony '\(name)' is missing from the test bundle"
        )
        return try JSONDecoder().decode(Captured.self, from: try Data(contentsOf: url))
    }

    static func party(_ captured: Captured) -> RelyingParty {
        RelyingParty(
            id: captured.relyingPartyID, name: "SwiftWebAuthn capture",
            origins: [captured.origin]
        )
    }

    // MARK: - Registration

    @Test("the registration this Mac produced verifies")
    func realRegistrationVerifies() throws {
        let captured = try Self.load("captured-registration")
        let party = Self.party(captured)

        let credential = try party.verifyRegistration(
            RegistrationResponse(
                clientDataJSON: try Base64URL.decode(captured.clientDataJSON),
                attestationObject: try Base64URL.decode(try #require(captured.attestationObject))
            ),
            expecting: Challenge(try Base64URL.decode(captured.challenge))
        )

        #expect(credential.id == (try Base64URL.decode(captured.credentialID)))
        #expect(credential.attestationFormat == "none")
        #expect(credential.publicKey.algorithm == .es256)
        #expect(credential.aaguid.map { String(ICSHexByte.of($0)) }.joined() == Self.appleKeychainAAGUID)
    }

    @Test("it reports a backed-up credential whose counter is zero")
    func realRegistrationIsBackedUpWithNoCounter() throws {
        let captured = try Self.load("captured-registration")
        let credential = try Self.party(captured).verifyRegistration(
            RegistrationResponse(
                clientDataJSON: try Base64URL.decode(captured.clientDataJSON),
                attestationObject: try Base64URL.decode(try #require(captured.attestationObject))
            ),
            expecting: Challenge(try Base64URL.decode(captured.challenge))
        )

        // The measurement §10.3 was waiting for. This is an ordinary Apple passkey, and it is
        // both backed up and counterless.
        #expect(credential.isBackupEligible)
        #expect(credential.isBackedUp)
        #expect(credential.signCount == 0)
    }

    // MARK: - Authentication

    @Test("the assertion this Mac produced verifies against the key it registered")
    func realAuthenticationVerifies() throws {
        let registration = try Self.load("captured-registration")
        let assertion = try Self.load("captured-authentication")
        let party = Self.party(assertion)

        let stored = try party.verifyRegistration(
            RegistrationResponse(
                clientDataJSON: try Base64URL.decode(registration.clientDataJSON),
                attestationObject: try Base64URL.decode(try #require(registration.attestationObject))
            ),
            expecting: Challenge(try Base64URL.decode(registration.challenge))
        )

        let verified = try party.verifyAuthentication(
            AuthenticationResponse(
                credentialID: try Base64URL.decode(assertion.credentialID),
                clientDataJSON: try Base64URL.decode(assertion.clientDataJSON),
                authenticatorData: try Base64URL.decode(try #require(assertion.authenticatorData)),
                signature: try Base64URL.decode(try #require(assertion.signature)),
                userHandle: try assertion.userHandle.map(Base64URL.decode)
            ),
            expecting: Challenge(try Base64URL.decode(assertion.challenge)),
            against: stored
        )

        #expect(verified.credentialID == stored.id)
        #expect(verified.userVerified)
        #expect(verified.isBackedUp)
    }

    @Test("the counter stayed at zero across both ceremonies, and was not treated as an attack")
    func aStaticCounterOnRealHardwareIsAccepted() throws {
        let registration = try Self.load("captured-registration")
        let assertion = try Self.load("captured-authentication")
        let party = Self.party(assertion)

        let stored = try party.verifyRegistration(
            RegistrationResponse(
                clientDataJSON: try Base64URL.decode(registration.clientDataJSON),
                attestationObject: try Base64URL.decode(try #require(registration.attestationObject))
            ),
            expecting: Challenge(try Base64URL.decode(registration.challenge))
        )
        #expect(stored.signCount == 0)

        let verified = try party.verifyAuthentication(
            AuthenticationResponse(
                credentialID: try Base64URL.decode(assertion.credentialID),
                clientDataJSON: try Base64URL.decode(assertion.clientDataJSON),
                authenticatorData: try Base64URL.decode(try #require(assertion.authenticatorData)),
                signature: try Base64URL.decode(try #require(assertion.signature)),
                userHandle: nil
            ),
            expecting: Challenge(try Base64URL.decode(assertion.challenge)),
            against: stored
        )

        // Zero, then zero again. Treating a static counter as evidence of cloning would refuse
        // the ordinary case on Apple hardware at its first login — which is exactly why
        // `checkCounter` gates regression on the backup flags.
        #expect(verified.newSignCount == 0)
    }

    // MARK: - The clauses, against real bytes

    @Test("a real assertion is still refused when the challenge is not the one issued")
    func realAssertionWithAForeignChallengeIsRefused() throws {
        let registration = try Self.load("captured-registration")
        let assertion = try Self.load("captured-authentication")
        let party = Self.party(assertion)

        let stored = try party.verifyRegistration(
            RegistrationResponse(
                clientDataJSON: try Base64URL.decode(registration.clientDataJSON),
                attestationObject: try Base64URL.decode(try #require(registration.attestationObject))
            ),
            expecting: Challenge(try Base64URL.decode(registration.challenge))
        )

        #expect(throws: RelyingParty.Failure.challengeMismatch) {
            try party.verifyAuthentication(
                AuthenticationResponse(
                    credentialID: try Base64URL.decode(assertion.credentialID),
                    clientDataJSON: try Base64URL.decode(assertion.clientDataJSON),
                    authenticatorData: try Base64URL.decode(try #require(assertion.authenticatorData)),
                    signature: try Base64URL.decode(try #require(assertion.signature)),
                    userHandle: nil
                ),
                expecting: Challenge([UInt8](repeating: 0x00, count: 32)),
                against: stored
            )
        }
    }

    @Test("a real registration is refused by a relying party it was not scoped to")
    func realRegistrationIsRefusedByAnotherParty() throws {
        let captured = try Self.load("captured-registration")
        let impostor = RelyingParty(
            id: "example.com", name: "Not the capture", origins: [captured.origin]
        )

        #expect(throws: RelyingParty.Failure.relyingPartyMismatch) {
            try impostor.verifyRegistration(
                RegistrationResponse(
                    clientDataJSON: try Base64URL.decode(captured.clientDataJSON),
                    attestationObject: try Base64URL.decode(try #require(captured.attestationObject))
                ),
                expecting: Challenge(try Base64URL.decode(captured.challenge))
            )
        }
    }
}

/// Hexadecimal for a single byte, for comparing an AAGUID against a published one.
enum ICSHexByte {
    /// Two lowercase hexadecimal characters.
    static func of(_ value: UInt8) -> String {
        let digits = "0123456789abcdef"
        let high = digits[digits.index(digits.startIndex, offsetBy: Int(value >> 4))]
        let low = digits[digits.index(digits.startIndex, offsetBy: Int(value & 0x0F))]
        return String([high, low])
    }
}
