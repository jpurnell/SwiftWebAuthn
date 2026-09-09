import SwiftIdentity
import SwiftWebAuthn

/// A registered passkey and the subject it belongs to.
public struct PasskeyRegistration: Sendable {
    /// What was stored at registration.
    public let credential: RegisteredCredential
    /// Who it proves.
    public let subject: Subject

    /// Pairs a credential with its subject.
    public init(credential: RegisteredCredential, subject: Subject) {
        self.credential = credential
        self.subject = subject
    }
}

/// Where registered passkeys live, which is not here.
///
/// Both packages decline to own storage, and for the same reason: a deployment's database is a
/// deployment's decision. This protocol is the seam, and it has exactly two operations because
/// a third would start describing a schema.
///
/// ## Recording is not optional
///
/// ``record(_:)`` is how the signature counter and the backup state reach durable storage. A
/// directory that ignores it leaves ``PasskeyCredentialStore`` comparing every assertion against
/// the counter captured at registration — so the regression check silently stops detecting
/// anything, while continuing to look like it works.
public protocol PasskeyDirectory: Sendable {
    /// Looks up a registered passkey.
    ///
    /// - Parameter credentialID: The identifier the assertion answered with.
    /// - Returns: The registration, or nil if nothing was enrolled under that identifier.
    func registration(for credentialID: [UInt8]) async -> PasskeyRegistration?

    /// Persists what a successful verification produced.
    ///
    /// Called **only** after an assertion verifies and its subject is active. The counter and
    /// the backup state both change over time, and both must survive the request.
    ///
    /// - Parameter verification: The outcome to store against the credential.
    func record(_ verification: VerifiedAuthentication) async
}
