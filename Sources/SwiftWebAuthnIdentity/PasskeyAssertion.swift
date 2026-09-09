import SwiftIdentity
import SwiftWebAuthn

/// A completed WebAuthn assertion, presented as a ``SwiftIdentity/Credential``.
///
/// ## Why this type is here and not in either package
///
/// `SwiftIdentity` made ``SwiftIdentity/Credential`` a protocol rather than a closed enum
/// precisely so a kind it had never heard of could be declared elsewhere. This is that kind, and
/// this module is the whole payoff of that decision: `SwiftIdentity` gains no knowledge of
/// WebAuthn and no dependency on it, so a service whose clients cannot run a ceremony — a shared
/// speaker, a calendar client subscribing to a feed — links none of this.
///
/// Recorded as ADR-002.
///
/// ## It carries the challenge
///
/// Verification needs the challenge that was issued, and neither package stores one. So the
/// caller pairs them here, having taken the challenge back out of wherever it put it.
/// **Single use remains the caller's to enforce**, and nothing in this module can check it.
public struct PasskeyAssertion: Credential {

    /// The stable name for this kind of proof.
    ///
    /// Appears in audit records, and is what keeps a store from accepting some other kind's
    /// value as a passkey.
    public static let kind = "passkey"

    /// What the browser returned.
    public let response: AuthenticationResponse
    /// The challenge that was issued for this ceremony.
    public let challenge: Challenge

    /// Pairs a response with the challenge it was meant to answer.
    public init(response: AuthenticationResponse, challenge: Challenge) {
        self.response = response
        self.challenge = challenge
    }
}
