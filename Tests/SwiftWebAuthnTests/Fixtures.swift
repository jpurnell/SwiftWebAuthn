import Crypto
import Foundation
@testable import SwiftWebAuthn

/// Byte builders shared by the suites.
///
/// Everything here assembles **real** material: a genuine P-256 or Ed25519 key taken apart and
/// reassembled in the wire format under test. Hand-invented blobs of the right length parse
/// perfectly and prove nothing, which is the failure mode these fixtures exist to avoid.
enum Fixtures {

    // MARK: - CBOR

    /// A definite-length byte string header, in the shortest form the decoder accepts.
    static func byteString(_ bytes: [UInt8]) -> [UInt8] {
        if bytes.count < 24 { return [0x40 | UInt8(bytes.count)] + bytes }
        if bytes.count <= 255 { return [0x58, UInt8(bytes.count)] + bytes }
        return [0x59, UInt8(bytes.count >> 8), UInt8(bytes.count & 0xFF)] + bytes
    }

    // MARK: - COSE keys

    /// An EC2 COSE key: `{1: 2, 3: alg, -1: crv, -2: x, -3: y}`.
    static func ec2Key(algorithm: [UInt8], curve: [UInt8], x: [UInt8], y: [UInt8]) -> [UInt8] {
        [0xA5]
            + [0x01, 0x02]
            + [0x03] + algorithm
            + [0x20] + curve
            + [0x21] + byteString(x)
            + [0x22] + byteString(y)
    }

    /// An OKP COSE key: `{1: 1, 3: alg, -1: crv, -2: x}`.
    static func okpKey(algorithm: [UInt8], curve: [UInt8], x: [UInt8]) -> [UInt8] {
        [0xA4]
            + [0x01, 0x01]
            + [0x03] + algorithm
            + [0x20] + curve
            + [0x21] + byteString(x)
    }

    /// A real P-256 key, and the pieces COSE carries separately.
    static func p256() -> (privateKey: P256.Signing.PrivateKey, x: [UInt8], y: [UInt8], x963: [UInt8]) {
        let priv = P256.Signing.PrivateKey()
        let x963 = Array(priv.publicKey.x963Representation)   // 0x04 ‖ x ‖ y
        return (priv, Array(x963[1..<33]), Array(x963[33..<65]), x963)
    }

    /// A real P-256 key already encoded as an ES256 COSE key.
    static func es256COSEKey() -> (privateKey: P256.Signing.PrivateKey, cbor: [UInt8], x963: [UInt8]) {
        let key = p256()
        return (key.privateKey, ec2Key(algorithm: [0x26], curve: [0x01], x: key.x, y: key.y), key.x963)
    }

    // MARK: - Authenticator data

    /// Flag bits, named so a test reads as the property it is asserting.
    enum Flag {
        static let userPresent: UInt8 = 0x01
        static let userVerified: UInt8 = 0x04
        static let backupEligible: UInt8 = 0x08
        static let backedUp: UInt8 = 0x10
        static let attestedCredentialData: UInt8 = 0x40
        static let extensionData: UInt8 = 0x80
    }

    /// Assembles authenticator data: RP ID hash, flags, counter, and optional attested data.
    static func authenticatorData(
        relyingPartyID: String = "example.com",
        flags: UInt8,
        signCount: UInt32 = 0,
        aaguid: [UInt8]? = nil,
        credentialID: [UInt8]? = nil,
        publicKey: [UInt8]? = nil,
        credentialIDLengthOverride: UInt16? = nil,
        trailing: [UInt8] = []
    ) -> [UInt8] {
        var bytes = Array(SHA256.hash(data: Data(relyingPartyID.utf8)))
        bytes.append(flags)
        bytes += [
            UInt8((signCount >> 24) & 0xFF), UInt8((signCount >> 16) & 0xFF),
            UInt8((signCount >> 8) & 0xFF), UInt8(signCount & 0xFF),
        ]
        if let credentialID {
            bytes += aaguid ?? [UInt8](repeating: 0, count: 16)
            let declared = credentialIDLengthOverride ?? UInt16(credentialID.count)
            bytes += [UInt8(declared >> 8), UInt8(declared & 0xFF)]
            bytes += credentialID
            bytes += publicKey ?? []
        }
        return bytes + trailing
    }

    // MARK: - CBOR encoding, enough to build an attestation object

    /// A text string header plus its bytes.
    static func textString(_ text: String) -> [UInt8] {
        let bytes = Array(text.utf8)
        precondition(bytes.count < 24, "only the width these fixtures use")
        return [0x60 | UInt8(bytes.count)] + bytes
    }

    /// A small negative integer, as COSE algorithm labels are.
    static func negative(_ value: Int) -> [UInt8] {
        precondition(value < 0 && value >= -24, "only the width these fixtures use")
        return [0x20 | UInt8(-1 - value)]
    }

    /// A map of already-encoded key/value pairs.
    static func map(_ pairs: [([UInt8], [UInt8])]) -> [UInt8] {
        precondition(pairs.count < 24, "only the width these fixtures use")
        return [0xA0 | UInt8(pairs.count)] + pairs.flatMap { $0.0 + $0.1 }
    }

    /// An attestation object: `{"fmt": …, "attStmt": …, "authData": …}`.
    static func attestationObject(
        format: String, statement: [UInt8], authenticatorData: [UInt8]
    ) -> [UInt8] {
        map([
            (textString("fmt"), textString(format)),
            (textString("attStmt"), statement),
            (textString("authData"), byteString(authenticatorData)),
        ])
    }

    // MARK: - A complete registration

    /// Everything a relying party is handed at the end of a registration ceremony.
    struct Registration {
        let clientDataJSON: [UInt8]
        let attestationObject: [UInt8]
        let authenticatorData: [UInt8]
        let credentialID: [UInt8]
        let x963: [UInt8]
        let challenge: [UInt8]
    }

    /// Builds a registration, signing it for real when `selfAttested` is set.
    ///
    /// The signature is produced by the same private key whose public half is registered, over
    /// exactly `authenticatorData ‖ SHA256(clientDataJSON)` — so a test that passes has verified
    /// arithmetic rather than a shape.
    static func registration(
        relyingPartyID: String = "example.com",
        origin: String = "https://example.com",
        challenge: [UInt8] = [UInt8](repeating: 0x5A, count: 32),
        type: String = "webauthn.create",
        flags: UInt8 = Flag.userPresent | Flag.userVerified | Flag.attestedCredentialData,
        signCount: UInt32 = 0,
        selfAttested: Bool = false,
        format: String? = nil,
        corruptSignature: Bool = false
    ) throws -> Registration {
        let key = es256COSEKey()
        let credentialID = [UInt8](repeating: 0xC1, count: 32)

        // The credential is present only when the flag says it is. An authenticator that set
        // one without the other would be producing trailing bytes, and the parser refuses those
        // — so a fixture that did it would be testing the wrong refusal.
        let carriesCredential = flags & Flag.attestedCredentialData != 0
        let authData = authenticatorData(
            relyingPartyID: relyingPartyID, flags: flags, signCount: signCount,
            aaguid: carriesCredential ? [UInt8](repeating: 0, count: 16) : nil,
            credentialID: carriesCredential ? credentialID : nil,
            publicKey: carriesCredential ? key.cbor : nil
        )

        let clientDataJSON = Array("""
            {"type":"\(type)","challenge":"\(Base64URL.encode(challenge))","origin":"\(origin)","crossOrigin":false}
            """.utf8)

        let statement: [UInt8]
        if selfAttested {
            let hash = Array(SHA256.hash(data: Data(clientDataJSON)))
            var signature = Array(try key.privateKey.signature(for: Data(authData + hash)).derRepresentation)
            if corruptSignature { signature[signature.count - 1] ^= 0xFF }
            statement = map([
                (textString("alg"), negative(-7)),
                (textString("sig"), byteString(signature)),
            ])
        } else {
            statement = map([])
        }

        return Registration(
            clientDataJSON: clientDataJSON,
            attestationObject: attestationObject(
                format: format ?? (selfAttested ? "packed" : "none"),
                statement: statement,
                authenticatorData: authData
            ),
            authenticatorData: authData,
            credentialID: credentialID,
            x963: key.x963,
            challenge: challenge
        )
    }
}
