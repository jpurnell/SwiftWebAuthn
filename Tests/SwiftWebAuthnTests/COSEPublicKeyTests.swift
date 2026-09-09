import Foundation
import Crypto
import Testing
@testable import SwiftWebAuthn

/// Parsing the key an authenticator registers, from the COSE_Key structure it arrives in.
///
/// The vectors are **generated rather than hand-written**: a real P-256 key, taken apart into
/// its coordinates and reassembled as CBOR. A hand-invented pair of 32-byte blobs would parse
/// perfectly and not be a point on the curve, and the test would pass while proving nothing.
@Suite("COSE — the keys accepted, and the algorithms refused")
struct COSEPublicKeyTests {

    // MARK: - The keys it must read

    @Test("an ES256 key, reassembled from a real P-256 point")
    func es256IsParsed() throws {
        let point = Fixtures.p256()
        let key = try COSEPublicKey(Fixtures.ec2Key(algorithm: [0x26], curve: [0x01], x: point.x, y: point.y))

        #expect(key.algorithm == .es256)
        // Stored in the form the verifier needs, so nothing reassembles coordinates later.
        #expect(key.keyData == point.x963)
    }

    @Test("an EdDSA key")
    func eddsaIsParsed() throws {
        let raw = Array(Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        let key = try COSEPublicKey(Fixtures.okpKey(algorithm: [0x27], curve: [0x06], x: raw))

        #expect(key.algorithm == .eddsa)
        #expect(key.keyData == raw)
    }

    @Test("a parsed key survives a round trip, because a consumer has to store it")
    func parsedKeyIsCodable() throws {
        let point = Fixtures.p256()
        let key = try COSEPublicKey(Fixtures.ec2Key(algorithm: [0x26], curve: [0x01], x: point.x, y: point.y))

        let encoded = try JSONEncoder().encode(key)
        #expect(try JSONDecoder().decode(COSEPublicKey.self, from: encoded) == key)
    }

    // MARK: - What it must refuse, and by name

    @Test("RS256 — refused loudly, which is the decision recorded in §10.2")
    func rs256IsRefusedByName() {
        // {1: 3, 3: -257} — an RSA key, the algorithm Windows Hello has historically wanted.
        let bytes: [UInt8] = [0xA2, 0x01, 0x03, 0x03, 0x39, 0x01, 0x00]
        #expect(throws: COSEPublicKey.Failure.unsupportedAlgorithm(-257)) {
            try COSEPublicKey(bytes)
        }
    }

    @Test("a key type this package does not verify")
    func unsupportedKeyTypeIsRefused() {
        // {1: 4, 3: -7} — a symmetric key, which is not a public key at all.
        let bytes: [UInt8] = [0xA2, 0x01, 0x04, 0x03, 0x26]
        #expect(throws: COSEPublicKey.Failure.unsupportedKeyType(4)) {
            try COSEPublicKey(bytes)
        }
    }

    @Test("an algorithm that does not belong to the curve it was sent with")
    func algorithmAndCurveMustAgree() {
        let point = Fixtures.p256()
        // ES256 declared over Ed25519's curve identifier.
        #expect(throws: COSEPublicKey.Failure.algorithmCurveMismatch(algorithm: -7, curve: 6)) {
            try COSEPublicKey(Fixtures.ec2Key(algorithm: [0x26], curve: [0x06], x: point.x, y: point.y))
        }
    }

    @Test("a coordinate of the wrong length")
    func wrongCoordinateLengthIsRefused() {
        let point = Fixtures.p256()
        let truncated = Array(point.x[0..<31]) + [0x00] // still 32 to build, then cut the y
        _ = truncated
        #expect(throws: COSEPublicKey.Failure.malformedCoordinate(label: -3, expected: 32, actual: 31)) {
            try COSEPublicKey([0xA5]
                + [0x01, 0x02] + [0x03, 0x26] + [0x20, 0x01]
                + [0x21] + Fixtures.byteString(point.x)
                + [0x22, 0x58, 0x1F] + Array(point.y[0..<31]))
        }
    }

    @Test("32 bytes that are not a point on the curve")
    func aCoordinatePairOffTheCurveIsRefused() {
        // Correctly shaped and structurally perfect; not a solution of the curve equation.
        // Only swift-crypto can tell the difference, which is why the key is constructed here
        // rather than merely measured.
        let notAPoint = [UInt8](repeating: 0xAA, count: 32)
        #expect(throws: COSEPublicKey.Failure.invalidPublicKey) {
            try COSEPublicKey(Fixtures.ec2Key(algorithm: [0x26], curve: [0x01], x: notAPoint, y: notAPoint))
        }
    }

    @Test("a missing required field, named so it can be found")
    func missingFieldsAreRefused() {
        // {1: 2, 3: -7, -1: 1} — an EC2 key with no coordinates at all.
        let bytes: [UInt8] = [0xA3, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01]
        #expect(throws: COSEPublicKey.Failure.missingField(label: -2)) {
            try COSEPublicKey(bytes)
        }
    }

    @Test("something that is not a map")
    func aNonMapIsRefused() {
        #expect(throws: COSEPublicKey.Failure.notAMap) {
            try COSEPublicKey([0x01])
        }
    }
}
