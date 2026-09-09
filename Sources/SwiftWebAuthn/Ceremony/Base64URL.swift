import Foundation

/// Base64 with the URL-safe alphabet and no padding — the encoding every WebAuthn field arrives
/// in.
///
/// Written out rather than reached for through `Data(base64Encoded:)` with substitutions,
/// because the two differ in exactly the ways that matter here: the alphabet's last two
/// characters, and whether padding is present. A decoder that quietly accepted the standard
/// alphabet would accept a challenge nobody issued in that form.
public enum Base64URL {

    /// Why a string could not be decoded.
    public enum Failure: Error, Equatable {
        /// A character outside the URL-safe alphabet — `+` and `/` included, deliberately.
        case invalidCharacters
    }

    /// Encodes bytes, without padding.
    ///
    /// - Parameter bytes: The bytes to encode.
    /// - Returns: The URL-safe encoding, with no `=`.
    public static func encode(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decodes a URL-safe, unpadded string.
    ///
    /// - Parameter text: The encoded text.
    /// - Returns: The decoded bytes.
    /// - Throws: ``Base64URL/Failure/invalidCharacters`` for anything outside the alphabet.
    public static func decode(_ text: String) throws -> [UInt8] {
        // Checked before translating, so `+` and `/` are refused rather than silently accepted
        // as if they were `-` and `_`.
        let alphabet = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        guard text.allSatisfy(alphabet.contains) else { throw Failure.invalidCharacters }

        var standard = text.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        standard += String(repeating: "=", count: (4 - standard.count % 4) % 4)

        guard let data = Data(base64Encoded: standard) else { throw Failure.invalidCharacters }
        return Array(data)
    }
}
