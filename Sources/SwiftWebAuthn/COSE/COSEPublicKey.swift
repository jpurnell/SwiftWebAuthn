import Crypto

/// The public key an authenticator registers, parsed from its COSE_Key structure.
///
/// Stored as the bytes a verifier needs rather than as a live key object, because a consumer has
/// to persist this between the registration ceremony and every authentication that follows. The
/// key is rebuilt for each verification, which costs a little and means nothing here holds
/// crypto state across a database round trip.
///
/// ## Algorithms, and the one that is refused by name
///
/// ES256 and EdDSA. **RS256 is refused loudly** — the decision recorded in §10.2 of the design
/// proposal — because an unsupported algorithm must be a named error rather than a silent
/// failure to verify. The failure mode being avoided is a ceremony that appears to succeed
/// because nothing checked it.
public struct COSEPublicKey: Sendable, Equatable, Codable {

    /// A signature algorithm this package can verify.
    ///
    /// The raw values are the COSE algorithm identifiers, so the wire format and this enum
    /// cannot drift apart.
    public enum Algorithm: Int, Sendable, Equatable, Codable {
        /// ECDSA over P-256 with SHA-256.
        case es256 = -7
        /// EdDSA over Ed25519.
        case eddsa = -8
    }

    /// Why a key was refused.
    public enum Failure: Error, Equatable {
        /// The payload was not a COSE_Key map.
        case notAMap
        /// A required label was absent, named by its COSE label.
        case missingField(label: Int64)
        /// A label held the wrong CBOR type.
        case malformedField(label: Int64)
        /// A key type this package does not verify.
        case unsupportedKeyType(Int64)
        /// An algorithm this package does not verify — RS256 arrives here.
        case unsupportedAlgorithm(Int64)
        /// A curve that does not belong to the declared algorithm.
        case algorithmCurveMismatch(algorithm: Int64, curve: Int64)
        /// A coordinate of the wrong length for its curve.
        case malformedCoordinate(label: Int64, expected: Int, actual: Int)
        /// Correctly shaped bytes that are not a valid public key — an EC point off the curve.
        case invalidPublicKey
    }

    /// The algorithm this key signs with.
    public let algorithm: Algorithm

    /// The key material, in the form its verifier takes.
    ///
    /// Uncompressed X9.63 (`0x04 ‖ x ‖ y`) for ES256; the raw 32 bytes for EdDSA. Kept in the
    /// verifier's own form so nothing reassembles coordinates at verification time.
    public let keyData: [UInt8]

    /// Parses a COSE_Key.
    ///
    /// - Parameter bytes: The CBOR-encoded COSE_Key structure.
    /// - Throws: ``COSEPublicKey/Failure``, or ``CBOR/Failure`` if the CBOR itself is refused.
    public init(_ bytes: [UInt8]) throws {
        try self.init(CBOR.decode(bytes))
    }

    /// Parses an already-decoded COSE_Key.
    ///
    /// The entry point used when the key was found inside a larger structure, so authenticator
    /// data does not decode the same bytes twice to learn where they ended.
    ///
    /// - Parameter value: The decoded COSE_Key map.
    /// - Throws: ``COSEPublicKey/Failure``.
    public init(_ value: CBOR) throws {
        guard case .map(let fields) = value else { throw Failure.notAMap }

        // The algorithm is read before the key type, deliberately. An RSA key carries both an
        // unsupported type and an unsupported algorithm, and "RS256 is not verified here" is the
        // more useful of the two answers.
        let algorithmLabel = try Self.integer(fields, label: 3)
        guard let algorithm = Algorithm(rawValue: Int(algorithmLabel)) else {
            throw Failure.unsupportedAlgorithm(algorithmLabel)
        }

        let keyType = try Self.integer(fields, label: 1)
        guard keyType == 1 || keyType == 2 else { throw Failure.unsupportedKeyType(keyType) }

        let curve = try Self.integer(fields, label: -1)

        switch algorithm {
        case .es256:
            // EC2 over P-256, and nothing else may claim ES256.
            guard keyType == 2 else { throw Failure.unsupportedKeyType(keyType) }
            guard curve == 1 else {
                throw Failure.algorithmCurveMismatch(algorithm: algorithmLabel, curve: curve)
            }
            let x = try Self.coordinate(fields, label: -2, expected: 32)
            let y = try Self.coordinate(fields, label: -3, expected: 32)
            let x963 = [0x04] + x + y
            // Constructed rather than merely measured: only the curve arithmetic can tell a
            // correctly shaped pair of blobs from a point that actually lies on P-256.
            //
            // The caught error is translated rather than discarded: swift-crypto reports "the
            // data is not a valid key" and this package's caller needs the label it was found
            // under, which the surrounding frame knows and the crypto library does not.
            do {
                _ = try P256.Signing.PublicKey(x963Representation: x963)
            } catch {
                throw Failure.invalidPublicKey
            }
            self.keyData = x963

        case .eddsa:
            guard keyType == 1 else { throw Failure.unsupportedKeyType(keyType) }
            guard curve == 6 else {
                throw Failure.algorithmCurveMismatch(algorithm: algorithmLabel, curve: curve)
            }
            let x = try Self.coordinate(fields, label: -2, expected: 32)
            do {
                _ = try Curve25519.Signing.PublicKey(rawRepresentation: x)
            } catch {
                throw Failure.invalidPublicKey
            }
            self.keyData = x
        }

        self.algorithm = algorithm
    }

    /// Reads an integer label, distinguishing "absent" from "present and the wrong type".
    private static func integer(_ fields: [CBOR.Key: CBOR], label: Int64) throws -> Int64 {
        guard let value = fields[.int(label)] else { throw Failure.missingField(label: label) }
        switch value {
        case .unsigned(let raw):
            guard raw <= UInt64(Int64.max) else { throw Failure.malformedField(label: label) }
            return Int64(raw)
        case .negative(let raw):
            return raw
        default:
            throw Failure.malformedField(label: label)
        }
    }

    /// Reads a coordinate, checking its length against the curve rather than trusting it.
    private static func coordinate(
        _ fields: [CBOR.Key: CBOR], label: Int64, expected: Int
    ) throws -> [UInt8] {
        guard let value = fields[.int(label)] else { throw Failure.missingField(label: label) }
        guard case .bytes(let raw) = value else { throw Failure.malformedField(label: label) }
        guard raw.count == expected else {
            throw Failure.malformedCoordinate(label: label, expected: expected, actual: raw.count)
        }
        return raw
    }
}
