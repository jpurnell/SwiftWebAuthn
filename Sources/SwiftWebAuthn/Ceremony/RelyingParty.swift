import Crypto
import Foundation

/// What a browser hands back at the end of a registration ceremony.
public struct RegistrationResponse: Sendable {
    /// The client data, exactly as the browser produced it.
    public let clientDataJSON: [UInt8]
    /// The attestation object.
    public let attestationObject: [UInt8]

    /// Wraps a ceremony's two byte strings.
    public init(clientDataJSON: [UInt8], attestationObject: [UInt8]) {
        self.clientDataJSON = clientDataJSON
        self.attestationObject = attestationObject
    }
}

/// A credential that passed registration, and everything a consumer must keep about it.
///
/// Never a secret — only a public key. Storing this is what makes later authentications
/// verifiable, and the counter and backup flags travel with it because their meaning is
/// entangled: see ``isBackedUp``.
public struct RegisteredCredential: Sendable, Equatable, Codable {
    /// The credential's identifier, echoed on every later assertion.
    public let id: [UInt8]
    /// The public key to verify those assertions against.
    public let publicKey: COSEPublicKey
    /// The signature counter at registration.
    public let signCount: UInt32
    /// Whether the credential may be synced to other devices.
    public let isBackupEligible: Bool
    /// Whether it currently is.
    ///
    /// **A backed-up credential may never increment its signature counter**, so counter
    /// regression is only evidence of cloning when this is `false`. Stored rather than derived
    /// because the consumer needs it at every later verification.
    public let isBackedUp: Bool
    /// Which model of authenticator made it. All zeroes for anonymous attestation.
    public let aaguid: [UInt8]
    /// The attestation format that was seen, recorded even when it was `none`.
    ///
    /// Kept so a deployment can find out later what its authenticators actually sent, which is
    /// the evidence any future decision about attestation would need.
    public let attestationFormat: String

    /// Rebuilds a stored credential.
    ///
    /// Public because a consumer persists this at registration and has to reconstruct it at
    /// every authentication afterwards — the type would be unusable if only this package could
    /// make one.
    public init(
        id: [UInt8],
        publicKey: COSEPublicKey,
        signCount: UInt32,
        isBackupEligible: Bool,
        isBackedUp: Bool,
        aaguid: [UInt8],
        attestationFormat: String
    ) {
        self.id = id
        self.publicKey = publicKey
        self.signCount = signCount
        self.isBackupEligible = isBackupEligible
        self.isBackedUp = isBackedUp
        self.aaguid = aaguid
        self.attestationFormat = attestationFormat
    }
}

/// What a browser hands back at the end of an authentication ceremony.
public struct AuthenticationResponse: Sendable {
    /// Which credential answered.
    public let credentialID: [UInt8]
    /// The client data, exactly as the browser produced it.
    public let clientDataJSON: [UInt8]
    /// The authenticator data that was signed.
    public let authenticatorData: [UInt8]
    /// The signature over that data and the client data hash.
    public let signature: [UInt8]
    /// The user handle, present when the credential is discoverable.
    public let userHandle: [UInt8]?

    /// Wraps a ceremony's parts.
    public init(
        credentialID: [UInt8],
        clientDataJSON: [UInt8],
        authenticatorData: [UInt8],
        signature: [UInt8],
        userHandle: [UInt8]?
    ) {
        self.credentialID = credentialID
        self.clientDataJSON = clientDataJSON
        self.authenticatorData = authenticatorData
        self.signature = signature
        self.userHandle = userHandle
    }
}

/// The outcome of a verified authentication, and the state the consumer must write back.
public struct VerifiedAuthentication: Sendable, Equatable {
    /// The credential that answered.
    public let credentialID: [UInt8]
    /// The counter to store. **Persist this**, or the next verification compares against a stale
    /// value and the regression check stops meaning anything.
    public let newSignCount: UInt32
    /// Whether the person was identified rather than merely present.
    public let userVerified: Bool
    /// Whether the credential is now backed up.
    ///
    /// Returned because it **changes after registration** — a credential enrolled on one device
    /// becomes backed up the moment it syncs. Persist it: the counter rule reads it.
    public let isBackedUp: Bool
}

/// The server side of WebAuthn: one relying party, and the ceremonies it will verify.
///
/// ## What it does not do
///
/// It does not remember challenges (``Challenge``), does not mint sessions, and does not decide
/// what a verified user may then do. Those are the consumer's, and each one kept out of here is
/// a decision a deployment gets to make.
public struct RelyingParty: Sendable {

    /// Why a ceremony was refused.
    ///
    /// Every case is one clause of §7.1. A ceremony succeeds only when none of them applies.
    public enum Failure: Error, Equatable {
        /// The client data described a different ceremony.
        case wrongCeremonyType(expected: String, actual: String)
        /// The challenge was not the one issued.
        case challengeMismatch
        /// The ceremony ran at an origin this relying party does not accept.
        ///
        /// The clause that stops a look-alike domain registering keys against this account.
        case untrustedOrigin(String)
        /// The authenticator data was scoped to a different relying party.
        case relyingPartyMismatch
        /// Nobody was physically present.
        case userNotPresent
        /// Present, but not identified, where identification was required.
        case userNotVerified
        /// No credential, on the one ceremony whose purpose is to deliver one.
        case missingAttestedCredential
        /// An attestation statement that its format does not permit.
        case malformedAttestation
        /// The attestation signature did not verify, or could not be read.
        case attestationSignatureInvalid
        /// An attestation format this package cannot verify.
        ///
        /// Refused rather than accepted unchecked — the failure mode being an attestation that
        /// is trusted because it was not understood.
        case unsupportedAttestationFormat(String)
        /// The assertion answered with a credential other than the one being checked.
        case credentialMismatch
        /// The assertion signature did not verify, or could not be read.
        case assertionSignatureInvalid
        /// The signature counter did not advance on a credential that should increment it.
        ///
        /// Evidence of a cloned authenticator — but only for a credential that is **not** backed
        /// up. See ``verifyAuthentication(_:expecting:against:requiringUserVerification:)``.
        case signatureCounterRegressed(stored: UInt32, received: UInt32)
    }

    /// The relying party identifier — a domain the ceremony is scoped to.
    public let id: String
    /// A human-readable name, shown by the authenticator.
    public let name: String
    /// The origins a ceremony may run at.
    public let origins: Set<String>

    /// Describes one relying party.
    ///
    /// - Parameters:
    ///   - id: The relying party identifier, a registrable domain.
    ///   - name: The name shown to the person.
    ///   - origins: Every origin permitted to run a ceremony. Compared exactly; a suffix match
    ///     would accept `example.com.evil.test`.
    public init(id: String, name: String, origins: Set<String>) {
        self.id = id
        self.name = name
        self.origins = origins
    }

    /// How long a browser should wait for a ceremony, in milliseconds.
    ///
    /// Sixty seconds. Long enough to find a phone, short enough that an abandoned prompt does
    /// not keep a challenge alive indefinitely.
    public static let defaultTimeout = 60_000

    /// Builds the options for a registration ceremony.
    ///
    /// - Parameters:
    ///   - user: The person the credential is for.
    ///   - challenge: The challenge to be signed. **Remember it**; verification compares against
    ///     it and cannot know whether it has been used before.
    ///   - excluding: Credential identifiers this person already has, so an authenticator that
    ///     already holds one declines rather than silently enrolling a second.
    ///   - userVerification: How thoroughly the person must be identified. `required` by
    ///     default, matching ``verifyRegistration(_:expecting:requiringUserVerification:)``.
    /// - Returns: The options, encodable to the JSON form the browser expects.
    public func registrationOptions(
        for user: UserEntity,
        challenge: Challenge,
        excluding: [[UInt8]] = [],
        userVerification: UserVerificationRequirement = .required
    ) -> PublicKeyCredentialCreationOptions {
        PublicKeyCredentialCreationOptions(
            relyingParty: (id: id, name: name),
            user: user,
            challenge: challenge.bytes,
            // Derived from what the verifier accepts rather than listed again here. Offering an
            // algorithm this package refuses produces a ceremony that fails *after* the person
            // has touched the sensor; offering fewer narrows what can enrol, silently.
            algorithms: COSEPublicKey.Algorithm.allCases,
            excludeCredentials: excluding.map(CredentialDescriptor.init),
            userVerification: userVerification,
            timeout: Self.defaultTimeout
        )
    }

    /// Builds the options for an authentication ceremony.
    ///
    /// - Parameters:
    ///   - challenge: The challenge to be signed.
    ///   - allowing: The credentials permitted to answer. Empty invites any discoverable
    ///     credential, which is what a login page with no username field wants.
    ///   - userVerification: How thoroughly the person must be identified.
    /// - Returns: The options, encodable to the JSON form the browser expects.
    public func authenticationOptions(
        challenge: Challenge,
        allowing: [[UInt8]],
        userVerification: UserVerificationRequirement = .required
    ) -> PublicKeyCredentialRequestOptions {
        PublicKeyCredentialRequestOptions(
            challenge: challenge.bytes,
            relyingPartyID: id,
            allowCredentials: allowing.map(CredentialDescriptor.init),
            userVerification: userVerification,
            timeout: Self.defaultTimeout
        )
    }

    /// Verifies a registration ceremony and returns the credential to store.
    ///
    /// - Parameters:
    ///   - response: What the browser returned.
    ///   - challenge: The challenge that was issued. **Single use is the caller's to enforce**;
    ///     this compares, and cannot know whether the value has been seen before.
    ///   - requiringUserVerification: Whether the person must have been identified rather than
    ///     merely present. Defaults to `true`, which is the safe default and what a platform
    ///     authenticator does anyway.
    /// - Returns: The credential, to be persisted.
    /// - Throws: ``RelyingParty/Failure``, or the parsing failure underneath it.
    public func verifyRegistration(
        _ response: RegistrationResponse,
        expecting challenge: Challenge,
        requiringUserVerification: Bool = true
    ) throws -> RegisteredCredential {
        let clientData = try CollectedClientData(response.clientDataJSON)

        guard clientData.type == "webauthn.create" else {
            throw Failure.wrongCeremonyType(expected: "webauthn.create", actual: clientData.type)
        }
        guard clientData.challenge == challenge.bytes else { throw Failure.challengeMismatch }
        // Exact membership, never a suffix test: `example.com.evil.test` ends with nothing
        // useful, and a prefix or suffix comparison here is the classic way this check is
        // written wrong.
        guard origins.contains(clientData.origin) else {
            throw Failure.untrustedOrigin(clientData.origin)
        }

        let attestation = try AttestationObject(response.attestationObject)
        let authenticatorData = attestation.authenticatorData

        guard authenticatorData.relyingPartyIDHash == Array(SHA256.hash(data: Data(id.utf8))) else {
            throw Failure.relyingPartyMismatch
        }
        guard authenticatorData.flags.userPresent else { throw Failure.userNotPresent }
        guard !requiringUserVerification || authenticatorData.flags.userVerified else {
            throw Failure.userNotVerified
        }
        guard let credential = authenticatorData.attestedCredential else {
            throw Failure.missingAttestedCredential
        }

        try verifyAttestation(
            attestation,
            credential: credential,
            clientDataHash: Array(SHA256.hash(data: Data(response.clientDataJSON)))
        )

        return RegisteredCredential(
            id: credential.credentialID,
            publicKey: credential.publicKey,
            signCount: authenticatorData.signCount,
            isBackupEligible: authenticatorData.flags.backupEligible,
            isBackedUp: authenticatorData.flags.isBackedUp,
            aaguid: credential.aaguid,
            attestationFormat: attestation.format
        )
    }

    /// Verifies an authentication ceremony.
    ///
    /// - Parameters:
    ///   - response: What the browser returned.
    ///   - challenge: The challenge that was issued. **Single use is the caller's to enforce.**
    ///   - credential: The stored credential this assertion claims to be from.
    ///   - requiringUserVerification: Whether the person must have been identified rather than
    ///     merely present. Defaults to `true`.
    /// - Returns: The outcome, carrying the counter and backup state to persist.
    /// - Throws: ``RelyingParty/Failure``, or the parsing failure underneath it.
    public func verifyAuthentication(
        _ response: AuthenticationResponse,
        expecting challenge: Challenge,
        against credential: RegisteredCredential,
        requiringUserVerification: Bool = true
    ) throws -> VerifiedAuthentication {
        // Checked first: everything below verifies against `credential`, and doing that work for
        // an assertion from a different credential would be answering a question nobody asked.
        guard response.credentialID == credential.id else { throw Failure.credentialMismatch }

        let clientData = try CollectedClientData(response.clientDataJSON)

        guard clientData.type == "webauthn.get" else {
            throw Failure.wrongCeremonyType(expected: "webauthn.get", actual: clientData.type)
        }
        guard clientData.challenge == challenge.bytes else { throw Failure.challengeMismatch }
        guard origins.contains(clientData.origin) else {
            throw Failure.untrustedOrigin(clientData.origin)
        }

        let authenticatorData = try AuthenticatorData(response.authenticatorData)

        guard authenticatorData.relyingPartyIDHash == Array(SHA256.hash(data: Data(id.utf8))) else {
            throw Failure.relyingPartyMismatch
        }
        guard authenticatorData.flags.userPresent else { throw Failure.userNotPresent }
        guard !requiringUserVerification || authenticatorData.flags.userVerified else {
            throw Failure.userNotVerified
        }

        // The signature covers the authenticator data as it arrived, concatenated with the hash
        // of the client data as it arrived. Both are the raw bytes for that reason.
        do {
            try verify(
                signature: response.signature,
                over: response.authenticatorData
                    + Array(SHA256.hash(data: Data(response.clientDataJSON))),
                with: credential.publicKey
            )
        } catch {
            // Re-labelled: the shared helper reports an attestation failure, and this is an
            // assertion. The distinction matters to whoever reads the log.
            throw Failure.assertionSignatureInvalid
        }

        try checkCounter(
            received: authenticatorData.signCount,
            against: credential,
            isBackedUp: authenticatorData.flags.isBackedUp
        )

        return VerifiedAuthentication(
            credentialID: credential.id,
            newSignCount: authenticatorData.signCount,
            userVerified: authenticatorData.flags.userVerified,
            isBackedUp: authenticatorData.flags.isBackedUp
        )
    }

    /// The signature-counter rule, which is §10.3 and is the softest thing in this package.
    ///
    /// A counter that fails to advance is the specification's evidence of a cloned
    /// authenticator. It is only evidence for a credential that **increments one at all**, and
    /// two cases do not:
    ///
    /// - An authenticator that never implements a counter reports zero forever.
    /// - **A passkey synced through a keychain may never increment it**, because the counter is
    ///   per-device state and the credential is not.
    ///
    /// So regression is an error only when the credential is not backed up. Refusing otherwise
    /// would lock out every synced passkey, which is the common case rather than the attack.
    ///
    /// - Important: This rule is read from the specification and has **not** been checked
    ///   against a real device. It is the first thing to verify once real-device fixtures exist.
    private func checkCounter(
        received: UInt32, against credential: RegisteredCredential, isBackedUp: Bool
    ) throws {
        // Zero on both sides is an authenticator that does not keep one. There is nothing to
        // compare, and treating it as regression would refuse every such device.
        if received == 0 && credential.signCount == 0 { return }
        if received > credential.signCount { return }
        if isBackedUp || credential.isBackedUp { return }
        throw Failure.signatureCounterRegressed(stored: credential.signCount, received: received)
    }

    /// Checks the attestation statement, as far as this package will believe one.
    ///
    /// `none` and self attestation only. Anything else is refused by name rather than accepted
    /// unchecked, because an attestation trusted because it was not understood is worse than no
    /// attestation at all — §7 of the design proposal.
    private func verifyAttestation(
        _ attestation: AttestationObject,
        credential: AuthenticatorData.AttestedCredential,
        clientDataHash: [UInt8]
    ) throws {
        switch attestation.format {
        case "none":
            // The format asserts nothing, so a statement alongside it is a contradiction rather
            // than extra information.
            guard attestation.statement.isEmpty else { throw Failure.malformedAttestation }

        case "packed" where attestation.statement[.text("x5c")] == nil:
            // Self attestation: signed by the very key being registered, which proves the
            // authenticator holds the private half and nothing about what kind of device it is.
            guard case .negative(let algorithm)? = attestation.statement[.text("alg")],
                  case .bytes(let signature)? = attestation.statement[.text("sig")] else {
                throw Failure.malformedAttestation
            }
            guard Int(algorithm) == credential.publicKey.algorithm.rawValue else {
                throw Failure.malformedAttestation
            }
            try verify(
                signature: signature,
                over: attestation.rawAuthenticatorData + clientDataHash,
                with: credential.publicKey
            )

        default:
            // "packed" carrying an x5c arrives here too: a certificate chain this package does
            // not validate, and validating it partly would be worse than declining.
            throw Failure.unsupportedAttestationFormat(attestation.format)
        }
    }

    /// Verifies a signature against a registered key.
    ///
    /// A signature that cannot be *parsed* and one that does not verify are the same answer —
    /// this did not prove what it claimed — and distinguishing them in the error would tell an
    /// attacker which half of their guess was closer.
    private func verify(signature: [UInt8], over data: [UInt8], with key: COSEPublicKey) throws {
        switch key.algorithm {
        case .es256:
            do {
                let publicKey = try P256.Signing.PublicKey(x963Representation: key.keyData)
                let parsed = try P256.Signing.ECDSASignature(derRepresentation: Data(signature))
                guard publicKey.isValidSignature(parsed, for: Data(data)) else {
                    throw Failure.attestationSignatureInvalid
                }
            } catch {
                throw Failure.attestationSignatureInvalid
            }
        case .eddsa:
            do {
                let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: key.keyData)
                guard publicKey.isValidSignature(Data(signature), for: Data(data)) else {
                    throw Failure.attestationSignatureInvalid
                }
            } catch {
                throw Failure.attestationSignatureInvalid
            }
        }
    }
}
