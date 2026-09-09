#if canImport(os)
import os
#endif
import SwiftIdentity
import SwiftWebAuthn

/// Resolves a WebAuthn assertion to a ``SwiftIdentity/Subject``.
///
/// The adapter itself: a ``SwiftIdentity/CredentialStore`` that verifies a ceremony instead of
/// comparing a digest. A consumer composes it beside whatever other store it has — one protocol,
/// several implementations, which is what `SwiftIdentity`'s §14.2 chose composition for.
///
/// ## The order of the checks is the design
///
/// **Possession first, status second.** The signature is verified before the subject's status is
/// consulted, so `revoked` and `honeypot` are only ever reported for someone who actually holds
/// the private key. Reversing them would let anyone who guesses a credential identifier fill an
/// audit log with refusals that read like a leak and are not one — and a tripwire that fires on
/// guesses is a tripwire nobody keeps reading.
///
/// Nothing is recorded unless the assertion verifies **and** the subject is active.
public struct PasskeyCredentialStore: CredentialStore {

    /// Told why a ceremony was refused, without that reason reaching the caller.
    ///
    /// The refusal a caller sees is always `unknown` — telling them which clause failed tells an
    /// attacker which part of a forgery was closest. But the operator needs exactly that detail
    /// to tell a stale challenge from a wrong origin from a counter that went backwards, so it
    /// goes here instead of being dropped.
    public typealias FailureObserver = @Sendable (any Error) -> Void

    #if canImport(os)
    private static let logger = Logger(
        subsystem: "org.roseclub.swiftwebauthn", category: "PasskeyCredentialStore"
    )
    #endif

    private let relyingParty: RelyingParty
    private let directory: any PasskeyDirectory
    private let requiringUserVerification: Bool
    private let counterPolicy: SignatureCounterPolicy
    private let onFailure: FailureObserver?

    /// Builds a store over a directory.
    ///
    /// - Parameters:
    ///   - relyingParty: The party whose ceremonies this accepts.
    ///   - directory: Where registered passkeys live.
    ///   - requiringUserVerification: Whether the person must have been identified rather than
    ///     merely present. `true` by default, matching both ceremonies' own default and what
    ///     ``SwiftWebAuthn/RelyingParty/authenticationOptions(challenge:allowing:userVerification:)``
    ///     asks the browser for.
    ///   - counterPolicy: What a stalled signature counter means here. Defaults to
    ///     ``SwiftWebAuthn/SignatureCounterPolicy/refuseWhenStalled``, the careful answer.
    ///   - onFailure: Handed the reason a ceremony was refused. Wire it to whatever this
    ///     deployment logs with — this package takes no logging dependency, because a library
    ///     that picks a logging backend picks it for everyone.
    public init(
        relyingParty: RelyingParty,
        directory: any PasskeyDirectory,
        requiringUserVerification: Bool = true,
        counterPolicy: SignatureCounterPolicy = .refuseWhenStalled,
        onFailure: FailureObserver? = nil
    ) {
        self.relyingParty = relyingParty
        self.directory = directory
        self.requiringUserVerification = requiringUserVerification
        self.counterPolicy = counterPolicy
        self.onFailure = onFailure
    }

    /// Resolves an assertion, reporting the reason to the service and nothing to the caller.
    ///
    /// - Parameter credential: The proof presented. Anything that is not a ``PasskeyAssertion``
    ///   is refused as unknown, which is the fail-closed answer for a kind this store was never
    ///   taught.
    /// - Returns: The subject, or the reason it was refused.
    public func resolve(_ credential: any Credential) async -> Resolution {
        guard let assertion = credential as? PasskeyAssertion else { return .refused(.unknown) }

        guard let registration = await directory.registration(
            for: assertion.response.credentialID
        ) else {
            return .refused(.unknown)
        }

        let verified: VerifiedAuthentication
        do {
            verified = try relyingParty.verifyAuthentication(
                assertion.response,
                expecting: assertion.challenge,
                against: registration.credential,
                requiringUserVerification: requiringUserVerification,
                counterPolicy: counterPolicy
            )
        } catch {
            // Every ceremony failure collapses to `unknown` for the caller. The specific clause
            // that failed is exactly what an attacker would use to find out which part of a
            // forgery was closest — and exactly what an operator needs. So it goes to the
            // observer and no further, rather than being discarded to keep the two apart.
            // Logged as well as handed to the observer: the observer is optional and a
            // deployment that supplies none must still leave a trace, or a service under attack
            // looks identical to a quiet one.
            //
            // `.public` deliberately. A refusal reason is a clause name and, at worst, an
            // origin — never a key, a signature or a challenge. Redacting it would cost the
            // operator the only thing that distinguishes a stale challenge from a forgery.
            #if canImport(os)
            Self.logger.warning("passkey assertion refused: \(String(describing: error), privacy: .public)")
            #endif
            onFailure?(error)
            return .refused(.unknown)
        }

        switch registration.subject.status {
        case .revoked:
            return .refused(.revoked)
        case .honeypot:
            // Reached only by someone who proved possession, which is what makes it worth
            // reading: this is a leaked key being used, not an identifier being guessed.
            return .refused(.honeypot)
        case .active:
            break
        }

        await directory.record(verified)
        return .verified(registration.subject)
    }
}
