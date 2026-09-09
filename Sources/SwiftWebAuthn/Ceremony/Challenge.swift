/// A nonce issued for one ceremony.
///
/// ## This package does not remember it
///
/// A challenge must be **single-use**, and where that state lives — memory, a cache, a database
/// — is a deployment decision. So this generates and compares; it never stores.
///
/// The consequence is stated rather than buried: a consumer that does not enforce single use has
/// a replay vulnerability, and nothing here can detect it. Hiding the requirement inside a
/// library would make that invisible, which is why §10.4 left it outside.
public struct Challenge: Sendable, Equatable {

    /// The challenge bytes.
    public let bytes: [UInt8]

    /// Wraps bytes that were issued elsewhere.
    ///
    /// - Parameter bytes: The challenge as it was sent to the authenticator.
    public init(_ bytes: [UInt8]) { self.bytes = bytes }

    /// Generates a challenge from a generator you supply.
    ///
    /// There is deliberately no overload that picks a generator for you. This package already
    /// declines to own where a challenge is *stored*, on the grounds that hiding a security
    /// decision inside a library makes it invisible; silently choosing the randomness source
    /// would be the same move, and a predictable challenge is a replayable ceremony.
    ///
    /// So the source is one visible line at the call site, and it is auditable:
    ///
    /// ```swift
    /// var generator = SystemRandomNumberGenerator()
    /// let challenge = Challenge.random(using: &generator)
    /// ```
    ///
    /// `SystemRandomNumberGenerator` is the platform's own — `arc4random_buf` on Darwin,
    /// `getrandom` on Linux — and is the right choice in production. A seeded generator belongs
    /// only in tests, where it is what makes the exact bytes assertable.
    ///
    /// - Parameters:
    ///   - byteCount: How many bytes.
    ///   - generator: The source of randomness.
    /// - Returns: A fresh challenge.
    public static func random<Generator: RandomNumberGenerator>(
        byteCount: Int = 32, using generator: inout Generator
    ) -> Challenge {
        Challenge((0..<byteCount).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }
}
