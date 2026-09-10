import Crypto
import Foundation
import Testing
@testable import SwiftWebAuthn

/// The fixed-layout structure an authenticator signs over.
///
/// It is the one part of a ceremony that is not CBOR: a hash, a flags byte, a big-endian
/// counter, and then optionally a credential whose public key *is* CBOR and carries no length.
/// That last detail is why the decoder has to report how far it read.
@Suite("Authenticator data — the fixed layout, and where it stops")
struct AuthenticatorDataTests {

    @Test("the minimum: hash, flags, counter, and nothing else")
    func minimalStructure() throws {
        let bytes = Fixtures.authenticatorData(flags: Fixtures.Flag.userPresent, signCount: 7)
        let data = try AuthenticatorData(bytes)

        #expect(data.relyingPartyIDHash == Array(SHA256.hash(data: Data("example.com".utf8))))
        #expect(data.signCount == 7)
        #expect(data.flags.userPresent)
        #expect(!data.flags.userVerified)
        #expect(data.attestedCredential == nil)
    }

    @Test("every flag this package reads, set independently")
    func flagsAreReadIndependently() throws {
        let all = Fixtures.Flag.userPresent | Fixtures.Flag.userVerified
            | Fixtures.Flag.backupEligible | Fixtures.Flag.backedUp
        let data = try AuthenticatorData(Fixtures.authenticatorData(flags: all))

        #expect(data.flags.userPresent)
        #expect(data.flags.userVerified)
        #expect(data.flags.backupEligible)
        #expect(data.flags.isBackedUp)
        #expect(!data.flags.hasAttestedCredentialData)

        let none = try AuthenticatorData(Fixtures.authenticatorData(flags: 0))
        #expect(!none.flags.userPresent)
        #expect(!none.flags.backupEligible)
        #expect(!none.flags.isBackedUp)
    }

    @Test("the counter is big-endian — a byte order read backwards is a counter that never regresses")
    func signCountIsBigEndian() throws {
        let data = try AuthenticatorData(Fixtures.authenticatorData(flags: 0, signCount: 0x01020304))
        #expect(data.signCount == 0x01020304)
    }

    @Test("attested credential data, with a public key that has no length prefix")
    func attestedCredentialIsParsed() throws {
        let key = Fixtures.es256COSEKey()
        let aaguid = [UInt8](repeating: 0xAB, count: 16)
        let credentialID = [UInt8](repeating: 0xCD, count: 20)

        let data = try AuthenticatorData(Fixtures.authenticatorData(
            flags: Fixtures.Flag.userPresent | Fixtures.Flag.attestedCredentialData,
            aaguid: aaguid, credentialID: credentialID, publicKey: key.cbor
        ))

        let credential = try #require(data.attestedCredential)
        #expect(credential.aaguid == aaguid)
        #expect(credential.credentialID == credentialID)
        #expect(credential.publicKey.algorithm == .es256)
        #expect(credential.publicKey.keyData == key.x963)
    }

    // MARK: - Refusals

    @Test("shorter than the fixed header")
    func truncatedHeaderIsRefused() {
        #expect(throws: AuthenticatorData.Failure.truncated(expected: 37, actual: 36)) {
            try AuthenticatorData([UInt8](repeating: 0, count: 36))
        }
    }

    @Test("the attested-credential flag set with no attested credential data behind it")
    func flagWithoutDataIsRefused() {
        #expect(throws: AuthenticatorData.Failure.truncated(expected: 55, actual: 37)) {
            try AuthenticatorData(Fixtures.authenticatorData(
                flags: Fixtures.Flag.attestedCredentialData
            ))
        }
    }

    @Test("a declared credential-id length longer than the bytes that follow")
    func overlongCredentialIDLengthIsRefused() {
        let key = Fixtures.es256COSEKey()
        #expect(throws: AuthenticatorData.Failure.credentialIDLengthExceedsData(declared: 4096)) {
            try AuthenticatorData(Fixtures.authenticatorData(
                flags: Fixtures.Flag.attestedCredentialData,
                credentialID: [UInt8](repeating: 0xCD, count: 20),
                publicKey: key.cbor,
                credentialIDLengthOverride: 4096
            ))
        }
    }

    @Test("a credential id past the 1023-byte ceiling the specification sets")
    func oversizeCredentialIDIsRefused() {
        let key = Fixtures.es256COSEKey()
        #expect(throws: AuthenticatorData.Failure.credentialIDTooLong(1024)) {
            try AuthenticatorData(Fixtures.authenticatorData(
                flags: Fixtures.Flag.attestedCredentialData,
                credentialID: [UInt8](repeating: 0xCD, count: 1024),
                publicKey: key.cbor
            ))
        }
    }

    @Test("bytes left over after the public key, when no extensions were declared")
    func trailingBytesAreRefused() {
        let key = Fixtures.es256COSEKey()
        #expect(throws: AuthenticatorData.Failure.trailingBytes(count: 3)) {
            try AuthenticatorData(Fixtures.authenticatorData(
                flags: Fixtures.Flag.attestedCredentialData,
                credentialID: [UInt8](repeating: 0xCD, count: 20),
                publicKey: key.cbor,
                trailing: [0x01, 0x02, 0x03]
            ))
        }
    }

    @Test("bytes after the fixed header when nothing was declared to follow")
    func trailingBytesWithoutFlagsAreRefused() {
        #expect(throws: AuthenticatorData.Failure.trailingBytes(count: 2)) {
            try AuthenticatorData(Fixtures.authenticatorData(flags: 0, trailing: [0xAA, 0xBB]))
        }
    }
}

@Suite("CBOR — reading one item out of a longer buffer")
struct CBORPrefixTests {

    @Test("decodePrefix reports how far it read, which is what an unprefixed key needs")
    func prefixReportsItsLength() throws {
        let key = Fixtures.es256COSEKey()
        let buffer = key.cbor + [0xDE, 0xAD, 0xBE, 0xEF]

        let (value, consumed) = try CBOR.decodePrefix(buffer)
        #expect(consumed == key.cbor.count)
        guard case .map = value else {
            Issue.record("expected a COSE key map")
            return
        }
    }

    @Test("decode still refuses trailing bytes — only decodePrefix tolerates them")
    func strictDecodeIsUnchanged() {
        let key = Fixtures.es256COSEKey()
        #expect(throws: CBOR.Failure.trailingBytes(at: key.cbor.count)) {
            try CBOR.decode(key.cbor + [0x00])
        }
    }
}

/// Extension output, which this package carries but does not interpret.
///
/// It sits at the very end of authenticator data, and nothing follows it. That fact is what
/// makes parsing it unnecessary — and parsing something you never read can only ever refuse a
/// ceremony that would otherwise have worked.
@Suite("Authenticator data — extension output is carried, not parsed")
struct AuthenticatorDataExtensionTests {

    /// `{"credProps": {"rk": true}}`, canonically encoded, as a browser sends it.
    static let credProps: [UInt8] = [0xA1]
        + [0x69] + Array("credProps".utf8)
        + [0xA1] + [0x62] + Array("rk".utf8) + [0xF5]

    @Test("canonical extension output is carried through verbatim")
    func canonicalExtensionsAreCarried() throws {
        let data = try AuthenticatorData(Fixtures.authenticatorData(
            flags: Fixtures.Flag.userPresent | Fixtures.Flag.extensionData,
            trailing: Self.credProps
        ))
        #expect(data.flags.hasExtensionData)
        #expect(data.extensionOutput == Self.credProps)
    }

    @Test("so is output this package cannot parse, because it never needed to")
    func unparseableExtensionsAreStillCarried() throws {
        // A non-canonical text length: 9 written in a following byte where it fits inline.
        let nonCanonical: [UInt8] = [0xA1]
            + [0x78, 0x09] + Array("credProps".utf8)
            + [0xA1] + [0x62] + Array("rk".utf8) + [0xF5]

        // Refusing this used to cost a *login*, every time, to protect against nothing: the
        // bytes are inside the region the authenticator signed, so an attacker cannot have put
        // them there, and no step here reads them.
        let data = try AuthenticatorData(Fixtures.authenticatorData(
            flags: Fixtures.Flag.userPresent | Fixtures.Flag.extensionData,
            trailing: nonCanonical
        ))
        #expect(data.extensionOutput == nonCanonical)
    }

    @Test("an attested credential and extension output together")
    func bothAttestedDataAndExtensions() throws {
        let key = Fixtures.es256COSEKey()
        let credentialID = [UInt8](repeating: 0xCD, count: 20)
        let data = try AuthenticatorData(Fixtures.authenticatorData(
            flags: Fixtures.Flag.userPresent | Fixtures.Flag.attestedCredentialData
                | Fixtures.Flag.extensionData,
            aaguid: [UInt8](repeating: 0xAB, count: 16),
            credentialID: credentialID,
            publicKey: key.cbor,
            trailing: Self.credProps
        ))

        // The credential still has to be found exactly, because the public key before it *is*
        // length-delimited only by being parsed.
        let credential = try #require(data.attestedCredential)
        #expect(credential.credentialID == credentialID)
        #expect(credential.publicKey.keyData == key.x963)
        #expect(data.extensionOutput == Self.credProps)
    }

    @Test("without the flag there is no extension output, and leftovers are still refused")
    func absentFlagStillRefusesLeftovers() {
        #expect(throws: AuthenticatorData.Failure.trailingBytes(count: 4)) {
            try AuthenticatorData(Fixtures.authenticatorData(
                flags: Fixtures.Flag.userPresent, trailing: [0xDE, 0xAD, 0xBE, 0xEF]
            ))
        }
    }

    @Test("the flag set with nothing behind it")
    func flagWithNoOutputIsRefused() {
        #expect(throws: AuthenticatorData.Failure.truncated(expected: 38, actual: 37)) {
            try AuthenticatorData(Fixtures.authenticatorData(
                flags: Fixtures.Flag.userPresent | Fixtures.Flag.extensionData
            ))
        }
    }
}
