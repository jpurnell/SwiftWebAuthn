/// The three-field structure a registration ceremony returns.
///
/// `fmt` names how the authenticator attested to the key it made, `attStmt` is that attestation,
/// and `authData` is the structure it signed. The raw authenticator data is kept as well as the
/// parsed form, because an attestation signature is computed over the **bytes**, and re-encoding
/// the parsed structure would produce different ones.
public struct AttestationObject: Sendable {

    /// Why an attestation object was refused.
    public enum Failure: Error, Equatable {
        /// The payload was not a map.
        case notAMap
        /// A required field was absent.
        case missingField(String)
        /// A field held the wrong CBOR type.
        case malformedField(String)
    }

    /// The attestation statement format — `none`, `packed`, and others this package refuses.
    public let format: String
    /// The attestation statement, as its format defines it.
    public let statement: [CBOR.Key: CBOR]
    /// The parsed authenticator data.
    public let authenticatorData: AuthenticatorData
    /// The authenticator data exactly as it arrived, which is what a signature covers.
    public let rawAuthenticatorData: [UInt8]

    /// Parses an attestation object.
    ///
    /// - Parameter bytes: The CBOR-encoded structure.
    /// - Throws: ``AttestationObject/Failure``, ``AuthenticatorData/Failure`` or ``CBOR/Failure``.
    public init(_ bytes: [UInt8]) throws {
        guard case .map(let fields) = try CBOR.decode(bytes) else { throw Failure.notAMap }

        guard let rawFormat = fields[.text("fmt")] else { throw Failure.missingField("fmt") }
        guard case .text(let format) = rawFormat else { throw Failure.malformedField("fmt") }

        guard let rawStatement = fields[.text("attStmt")] else {
            throw Failure.missingField("attStmt")
        }
        guard case .map(let statement) = rawStatement else {
            throw Failure.malformedField("attStmt")
        }

        guard let rawData = fields[.text("authData")] else {
            throw Failure.missingField("authData")
        }
        guard case .bytes(let authData) = rawData else {
            throw Failure.malformedField("authData")
        }

        self.format = format
        self.statement = statement
        self.rawAuthenticatorData = authData
        self.authenticatorData = try AuthenticatorData(authData)
    }
}
