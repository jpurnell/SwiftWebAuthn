import Crypto
import Foundation
import Testing
@testable import SwiftWebAuthn

/// Registration, verified step by step against §7.1.
///
/// > A ceremony succeeds only if the challenge is one we issued, the origin and RP ID hash are
/// > ours, the user was present, the algorithm is one we chose to support, and any attestation
/// > we were given verifies.
///
/// Every clause below is one test, and the negative cases outnumber the positive ones.
@Suite("Registration — every clause of the verification")
struct RegistrationCeremonyTests {

    static let party = RelyingParty(
        id: "example.com", name: "Example", origins: ["https://example.com"]
    )

    static func response(_ registration: Fixtures.Registration) -> RegistrationResponse {
        RegistrationResponse(
            clientDataJSON: registration.clientDataJSON,
            attestationObject: registration.attestationObject
        )
    }

    // MARK: - What must succeed

    @Test("a ceremony with no attestation, which is what a platform authenticator sends")
    func noneAttestationIsAccepted() throws {
        let registration = try Fixtures.registration()
        let credential = try Self.party.verifyRegistration(
            Self.response(registration), expecting: Challenge(registration.challenge)
        )

        #expect(credential.id == registration.credentialID)
        #expect(credential.publicKey.algorithm == .es256)
        #expect(credential.publicKey.keyData == registration.x963)
        #expect(credential.signCount == 0)
        #expect(credential.attestationFormat == "none")
    }

    @Test("self attestation, where the signature is checked against the key being registered")
    func selfAttestationIsVerified() throws {
        let registration = try Fixtures.registration(selfAttested: true)
        let credential = try Self.party.verifyRegistration(
            Self.response(registration), expecting: Challenge(registration.challenge)
        )

        #expect(credential.attestationFormat == "packed")
        #expect(credential.publicKey.keyData == registration.x963)
    }

    @Test("the backup flags are carried through, because the counter's meaning depends on them")
    func backupFlagsAreRecorded() throws {
        let registration = try Fixtures.registration(
            flags: Fixtures.Flag.userPresent | Fixtures.Flag.userVerified
                | Fixtures.Flag.attestedCredentialData
                | Fixtures.Flag.backupEligible | Fixtures.Flag.backedUp
        )
        let credential = try Self.party.verifyRegistration(
            Self.response(registration), expecting: Challenge(registration.challenge)
        )

        #expect(credential.isBackupEligible)
        #expect(credential.isBackedUp)
    }

    // MARK: - What must fail, one clause at a time

    @Test("a challenge we did not issue")
    func aForeignChallengeIsRefused() throws {
        let registration = try Fixtures.registration()
        #expect(throws: RelyingParty.Failure.challengeMismatch) {
            try Self.party.verifyRegistration(
                Self.response(registration),
                expecting: Challenge([UInt8](repeating: 0x11, count: 32))
            )
        }
    }

    @Test("an origin that is not ours — the clause that stops a look-alike site registering keys")
    func anUntrustedOriginIsRefused() throws {
        let registration = try Fixtures.registration(origin: "https://example.com.evil.test")
        #expect(throws: RelyingParty.Failure.untrustedOrigin("https://example.com.evil.test")) {
            try Self.party.verifyRegistration(
                Self.response(registration), expecting: Challenge(registration.challenge)
            )
        }
    }

    @Test("authenticator data scoped to a different relying party")
    func aForeignRelyingPartyIsRefused() throws {
        let registration = try Fixtures.registration(relyingPartyID: "other.example")
        #expect(throws: RelyingParty.Failure.relyingPartyMismatch) {
            try Self.party.verifyRegistration(
                Self.response(registration), expecting: Challenge(registration.challenge)
            )
        }
    }

    @Test("the authentication ceremony's client data, replayed into registration")
    func theWrongCeremonyTypeIsRefused() throws {
        let registration = try Fixtures.registration(type: "webauthn.get")
        #expect(throws: RelyingParty.Failure.wrongCeremonyType(expected: "webauthn.create", actual: "webauthn.get")) {
            try Self.party.verifyRegistration(
                Self.response(registration), expecting: Challenge(registration.challenge)
            )
        }
    }

    @Test("nobody was present")
    func absentUserPresenceIsRefused() throws {
        let registration = try Fixtures.registration(
            flags: Fixtures.Flag.attestedCredentialData
        )
        #expect(throws: RelyingParty.Failure.userNotPresent) {
            try Self.party.verifyRegistration(
                Self.response(registration), expecting: Challenge(registration.challenge)
            )
        }
    }

    @Test("present but not verified, when verification was required")
    func absentUserVerificationIsRefusedWhenRequired() throws {
        let registration = try Fixtures.registration(
            flags: Fixtures.Flag.userPresent | Fixtures.Flag.attestedCredentialData
        )
        #expect(throws: RelyingParty.Failure.userNotVerified) {
            try Self.party.verifyRegistration(
                Self.response(registration),
                expecting: Challenge(registration.challenge),
                requiringUserVerification: true
            )
        }
        // …and accepted when it was not required, so the flag is read rather than assumed.
        #expect(throws: Never.self) {
            try Self.party.verifyRegistration(
                Self.response(registration),
                expecting: Challenge(registration.challenge),
                requiringUserVerification: false
            )
        }
    }

    @Test("no credential, on the one ceremony whose entire purpose is to deliver one")
    func missingAttestedCredentialIsRefused() throws {
        let registration = try Fixtures.registration(
            flags: Fixtures.Flag.userPresent | Fixtures.Flag.userVerified
        )
        #expect(throws: RelyingParty.Failure.missingAttestedCredential) {
            try Self.party.verifyRegistration(
                Self.response(registration), expecting: Challenge(registration.challenge)
            )
        }
    }

    @Test("a self-attestation signature over different bytes")
    func aCorruptSignatureIsRefused() throws {
        let registration = try Fixtures.registration(selfAttested: true, corruptSignature: true)
        #expect(throws: RelyingParty.Failure.attestationSignatureInvalid) {
            try Self.party.verifyRegistration(
                Self.response(registration), expecting: Challenge(registration.challenge)
            )
        }
    }

    @Test("an attestation format that cannot be verified is refused, never trusted unchecked")
    func unverifiableAttestationFormatsAreRefused() throws {
        for format in ["tpm", "android-key", "apple", "fido-u2f"] {
            let registration = try Fixtures.registration(selfAttested: true, format: format)
            #expect(throws: RelyingParty.Failure.unsupportedAttestationFormat(format)) {
                try Self.party.verifyRegistration(
                    Self.response(registration), expecting: Challenge(registration.challenge)
                )
            }
        }
    }

    @Test("a `none` attestation carrying a statement it should not have")
    func noneWithAStatementIsRefused() throws {
        let registration = try Fixtures.registration(selfAttested: true, format: "none")
        #expect(throws: RelyingParty.Failure.malformedAttestation) {
            try Self.party.verifyRegistration(
                Self.response(registration), expecting: Challenge(registration.challenge)
            )
        }
    }
}
