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
