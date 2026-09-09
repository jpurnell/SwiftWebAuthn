import Foundation

/// What the browser says the ceremony was: which kind, against which challenge, from which
/// origin.
///
/// ## The raw bytes are kept, and that is the point
///
/// The authenticator signs over a hash of **exactly the bytes the browser produced**. Parsing
/// this structure and re-serialising it would produce different bytes — key order, whitespace,
/// escaping — and the signature would be computed over something that never travelled. So the
/// original is carried alongside the parsed fields and is what gets hashed.
public struct CollectedClientData: Sendable, Equatable {

    /// Why client data was refused.
    public enum Failure: Error, Equatable {
        /// Not JSON, or missing a field this structure requires.
        case invalidJSON
        /// The challenge was not URL-safe base64.
        case malformedChallenge
    }

    /// The ceremony the browser believes it performed — `webauthn.create` or `webauthn.get`.
    ///
    /// Kept as text rather than an enum: an unexpected value must be comparable and reportable,
    /// and a decoder that refused to parse it would report "malformed JSON" for what is really
    /// the wrong ceremony.
    public let type: String
    /// The challenge, decoded.
    public let challenge: [UInt8]
    /// The origin the ceremony ran at, exactly as the browser reported it.
    public let origin: String
    /// Whether the ceremony ran in a cross-origin frame. Absent means `false`.
    public let crossOrigin: Bool
    /// The bytes as they arrived, which are what a signature covers.
    public let raw: [UInt8]

    /// The fields as JSON carries them.
    private struct Payload: Decodable {
        let type: String
        let challenge: String
        let origin: String
        let crossOrigin: Bool?
    }

    /// Parses `clientDataJSON`.
    ///
    /// - Parameter bytes: The JSON exactly as the browser sent it.
    /// - Throws: ``CollectedClientData/Failure``.
    public init(_ bytes: [UInt8]) throws {
        let payload: Payload
        do {
            payload = try JSONDecoder().decode(Payload.self, from: Data(bytes))
        } catch {
            // Translated rather than discarded: a missing field and malformed syntax are the
            // same answer to the caller — this is not client data — and the underlying
            // description names Swift types the caller never sees.
            throw Failure.invalidJSON
        }

        do {
            self.challenge = try Base64URL.decode(payload.challenge)
        } catch {
            throw Failure.malformedChallenge
        }

        self.type = payload.type
        self.origin = payload.origin
        self.crossOrigin = payload.crossOrigin ?? false
        self.raw = bytes
    }
}
