import Crypto
import Foundation
import Testing
@testable import SwiftWebAuthn

/// Authentication, verified step by step against §7.2.
///
/// The clauses it shares with registration are the same clauses and are tested again here,
/// because "registration checks the origin" is not a statement about this function.
@Suite("Authentication — every clause, and the counter")
struct AuthenticationCeremonyTests {

    static let party = RelyingParty(
        id: "example.com", name: "Example", origins: ["https://example.com"]
    )

    static func response(_ assertion: Fixtures.Assertion) -> AuthenticationResponse {
        AuthenticationResponse(
            credentialID: assertion.credentialID,
            clientDataJSON: assertion.clientDataJSON,
            authenticatorData: assertion.authenticatorData,
            signature: assertion.signature,
            userHandle: nil
        )
    }

    static func verify(
        _ assertion: Fixtures.Assertion,
        requiringUserVerification: Bool = true,
        counterPolicy: SignatureCounterPolicy = .refuseWhenStalled
    ) throws -> VerifiedAuthentication {
        try party.verifyAuthentication(
            response(assertion),
            expecting: Challenge(assertion.challenge),
            against: assertion.credential,
            requiringUserVerification: requiringUserVerification,
            counterPolicy: counterPolicy
        )
    }

    // MARK: - What must succeed

    @Test("a signature made by the registered key, over the challenge we issued")
    func aValidAssertionIsAccepted() throws {
        let assertion = try Fixtures.assertion()
        let verified = try Self.verify(assertion)

        #expect(verified.credentialID == assertion.credentialID)
        #expect(verified.newSignCount == 5)
        #expect(verified.userVerified)
    }

    @Test("the new backup state is returned, because it can change after registration")
    func backupStateIsReturned() throws {
        let assertion = try Fixtures.assertion(
            flags: Fixtures.Flag.userPresent | Fixtures.Flag.userVerified
                | Fixtures.Flag.backupEligible | Fixtures.Flag.backedUp,
            storedIsBackedUp: false
        )
        // Registered on one device, since synced. The consumer has to persist the new value or
        // its counter rule will be working from a stale answer.
        #expect(try Self.verify(assertion).isBackedUp)
    }

    // MARK: - The counter, which is the whole of §10.3

    @Test("a counter that advanced")
    func anAdvancingCounterIsAccepted() throws {
        let verified = try Self.verify(try Fixtures.assertion(signCount: 9, storedSignCount: 8))
        #expect(verified.newSignCount == 9)
    }

    @Test("a counter that went backwards on a credential that is not backed up — a cloned key")
    func aRegressedCounterIsRefusedWhenNotBackedUp() throws {
        let assertion = try Fixtures.assertion(
            signCount: 3, storedSignCount: 8, storedIsBackedUp: false
        )
        #expect(throws: RelyingParty.Failure.signatureCounterRegressed(stored: 8, received: 3)) {
            try Self.verify(assertion)
        }
    }

    @Test("a counter that did not move at all, on a credential that is not backed up")
    func aStaticCounterIsRefusedWhenNotBackedUp() throws {
        let assertion = try Fixtures.assertion(
            signCount: 8, storedSignCount: 8, storedIsBackedUp: false
        )
        #expect(throws: RelyingParty.Failure.signatureCounterRegressed(stored: 8, received: 8)) {
            try Self.verify(assertion)
        }
    }

    @Test("a stalled counter on a backed-up credential is refused by default, and that is a change")
    func aStalledCounterOnABackedUpCredentialIsRefusedByDefault() throws {
        let assertion = try Fixtures.assertion(
            flags: Fixtures.Flag.userPresent | Fixtures.Flag.userVerified
                | Fixtures.Flag.backupEligible | Fixtures.Flag.backedUp,
            signCount: 0, storedSignCount: 8, storedIsBackedUp: true
        )

        // This package used to accept it, on the reading that a synced passkey may never
        // increment. That reading is right about the *Apple* case — where both counters are zero
        // and the branch below is never reached — and has no evidence behind it for a credential
        // that reports a non-zero counter and then goes backwards. An authenticator that keeps a
        // counter at all is one whose regression might still mean something.
        #expect(throws: RelyingParty.Failure.signatureCounterRegressed(stored: 8, received: 0)) {
            try Self.verify(assertion)
        }
    }

    @Test("a deployment that has met such an authenticator can say so")
    func theBackupFlagCanStillBeTrustedOnRequest() throws {
        let assertion = try Fixtures.assertion(
            flags: Fixtures.Flag.userPresent | Fixtures.Flag.userVerified
                | Fixtures.Flag.backupEligible | Fixtures.Flag.backedUp,
            signCount: 0, storedSignCount: 8, storedIsBackedUp: true
        )
        let verified = try Self.verify(assertion, counterPolicy: .allowWhenBackedUp)
        #expect(verified.newSignCount == 0)
        #expect(verified.counterStalled)
    }

    @Test("or decline to decide, and read the signal off the result")
    func theSignalCanBeSurfacedInsteadOfEnforced() throws {
        let assertion = try Fixtures.assertion(
            signCount: 3, storedSignCount: 8, storedIsBackedUp: false
        )
        let verified = try Self.verify(assertion, counterPolicy: .report)

        // §7.2 says a relying party SHOULD apply its own risk policy. This is that, literally:
        // the ceremony verified, the counter went backwards, and what to do about it is the
        // consumer's call rather than this package's.
        #expect(verified.counterStalled)
        #expect(verified.newSignCount == 3)
    }

    @Test("a counter that is not stalled says so, under every policy")
    func anAdvancingCounterIsNeverStalled() throws {
        let assertion = try Fixtures.assertion(signCount: 9, storedSignCount: 8)
        #expect(try !Self.verify(assertion).counterStalled)
        #expect(try !Self.verify(assertion, counterPolicy: .report).counterStalled)
    }

    @Test("two zeroes are an authenticator with no counter, not a stall")
    func twoZeroesAreNotAStall() throws {
        let assertion = try Fixtures.assertion(signCount: 0, storedSignCount: 0)
        // The Apple case. Both counters zero means the authenticator keeps none, so there is
        // nothing to have stalled — and every policy must accept it.
        #expect(try !Self.verify(assertion).counterStalled)
        #expect(try !Self.verify(assertion, counterPolicy: .allowWhenBackedUp).counterStalled)
    }

    @Test("both counters zero, which is an authenticator that does not implement one")
    func twoZeroesAreAccepted() throws {
        #expect(try Self.verify(try Fixtures.assertion(signCount: 0, storedSignCount: 0)).newSignCount == 0)
    }

    // MARK: - What must fail

    @Test("a signature by a key nobody registered")
    func anotherKeysSignatureIsRefused() throws {
        let assertion = try Fixtures.assertion(signWithAnotherKey: true)
        #expect(throws: RelyingParty.Failure.assertionSignatureInvalid) {
            try Self.verify(assertion)
        }
    }

    @Test("a signature over different bytes")
    func aCorruptSignatureIsRefused() throws {
        let assertion = try Fixtures.assertion(corruptSignature: true)
        #expect(throws: RelyingParty.Failure.assertionSignatureInvalid) {
            try Self.verify(assertion)
        }
    }

    @Test("an assertion answering with a credential other than the one being checked")
    func aMismatchedCredentialIsRefused() throws {
        let assertion = try Fixtures.assertion()
        let response = AuthenticationResponse(
            credentialID: [0xFF, 0xFE],
            clientDataJSON: assertion.clientDataJSON,
            authenticatorData: assertion.authenticatorData,
            signature: assertion.signature,
            userHandle: nil
        )
        #expect(throws: RelyingParty.Failure.credentialMismatch) {
            try Self.party.verifyAuthentication(
                response, expecting: Challenge(assertion.challenge), against: assertion.credential
            )
        }
    }

    @Test("registration's client data, replayed into authentication")
    func theWrongCeremonyTypeIsRefused() throws {
        let assertion = try Fixtures.assertion(type: "webauthn.create")
        #expect(throws: RelyingParty.Failure.wrongCeremonyType(expected: "webauthn.get", actual: "webauthn.create")) {
            try Self.verify(assertion)
        }
    }

    @Test("a challenge we did not issue")
    func aForeignChallengeIsRefused() throws {
        let assertion = try Fixtures.assertion()
        #expect(throws: RelyingParty.Failure.challengeMismatch) {
            try Self.party.verifyAuthentication(
                Self.response(assertion),
                expecting: Challenge([UInt8](repeating: 0x22, count: 32)),
                against: assertion.credential
            )
        }
    }

    @Test("an origin that is not ours")
    func anUntrustedOriginIsRefused() throws {
        let assertion = try Fixtures.assertion(origin: "https://example.com.evil.test")
        #expect(throws: RelyingParty.Failure.untrustedOrigin("https://example.com.evil.test")) {
            try Self.verify(assertion)
        }
    }

    @Test("authenticator data scoped to a different relying party")
    func aForeignRelyingPartyIsRefused() throws {
        let assertion = try Fixtures.assertion(relyingPartyID: "other.example")
        #expect(throws: RelyingParty.Failure.relyingPartyMismatch) {
            try Self.verify(assertion)
        }
    }

    @Test("nobody was present")
    func absentUserPresenceIsRefused() throws {
        let assertion = try Fixtures.assertion(flags: 0)
        #expect(throws: RelyingParty.Failure.userNotPresent) {
            try Self.verify(assertion)
        }
    }

    @Test("present but not verified, when verification was required")
    func absentUserVerificationIsRefusedWhenRequired() throws {
        let assertion = try Fixtures.assertion(flags: Fixtures.Flag.userPresent)
        #expect(throws: RelyingParty.Failure.userNotVerified) {
            try Self.verify(assertion)
        }
        #expect(throws: Never.self) {
            try Self.verify(assertion, requiringUserVerification: false)
        }
    }
}
