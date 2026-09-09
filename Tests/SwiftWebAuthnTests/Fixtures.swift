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
}
