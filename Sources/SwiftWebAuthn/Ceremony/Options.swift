/// A person, as the authenticator will show them.
///
/// The `id` is an opaque handle, not an email address and not a database row that means
/// anything on its own: it is returned inside an assertion, and anything recognisable in it is
/// recognisable to whoever obtains the device.
public struct UserEntity: Sendable, Equatable {
    /// The opaque user handle.
    public let id: [UInt8]
    /// The account name, shown in the authenticator's picker.
    public let name: String
    /// The name shown to the person.
    public let displayName: String

    /// Describes one person.
    public init(id: [UInt8], name: String, displayName: String) {
        self.id = id
        self.name = name
        self.displayName = displayName
    }
}

/// How thoroughly the person must be identified.
public enum UserVerificationRequirement: String, Sendable, Codable {
    /// A ceremony without verification is refused.
    case required
    /// Verification if the authenticator offers it.
    case preferred
    /// Presence is enough.
    case discouraged
}

/// Which kind of authenticator a ceremony will accept.
///
/// Left unset, any will do — and that is the right default, because a relying party that does
/// not care must not accidentally exclude a security key or someone's phone.
public enum AuthenticatorAttachment: String, Sendable, Codable {
    /// Built into the device running the browser: Touch ID, Face ID, Windows Hello.
    case platform
    /// Something detachable — a security key, or another device over the hybrid transport.
    case crossPlatform = "cross-platform"
}

/// One credential named to the browser, to allow or to exclude.
public struct CredentialDescriptor: Sendable, Equatable, Encodable {
    /// The credential identifier.
    public let id: [UInt8]

    /// Names one credential.
    public init(_ id: [UInt8]) { self.id = id }

    private enum CodingKeys: String, CodingKey { case id, type }

    /// Encodes to the JSON form, with the identifier as base64url.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(Base64URL.encode(id), forKey: .id)
        try container.encode("public-key", forKey: .type)
    }
}

/// What the browser is asked to create.
///
/// Encoded in the JSON form the WebAuthn API expects, with every byte string as base64url.
public struct PublicKeyCredentialCreationOptions: Sendable, Equatable, Encodable {
    /// The relying party's identifier and name.
    public let relyingParty: (id: String, name: String)
    /// The person the credential is for.
    public let user: UserEntity
    /// The challenge to sign.
    public let challenge: [UInt8]
    /// The algorithms offered, which are exactly the algorithms this package verifies.
    public let algorithms: [COSEPublicKey.Algorithm]
    /// Credentials this person already has, so a device does not enrol twice.
    public let excludeCredentials: [CredentialDescriptor]
    /// How thoroughly the person must be identified.
    public let userVerification: UserVerificationRequirement
    /// Which kind of authenticator will be accepted, or nil for any.
    public let attachment: AuthenticatorAttachment?
    /// How long the browser should wait, in milliseconds.
    public let timeout: Int

    /// Two option sets are equal when every field is; the tuple is compared by hand.
    public static func == (
        lhs: PublicKeyCredentialCreationOptions, rhs: PublicKeyCredentialCreationOptions
    ) -> Bool {
        lhs.relyingParty == rhs.relyingParty && lhs.user == rhs.user
            && lhs.challenge == rhs.challenge && lhs.algorithms == rhs.algorithms
            && lhs.excludeCredentials == rhs.excludeCredentials
            && lhs.userVerification == rhs.userVerification && lhs.attachment == rhs.attachment
            && lhs.timeout == rhs.timeout
    }

    private enum CodingKeys: String, CodingKey {
        case rp, user, challenge, pubKeyCredParams, excludeCredentials
        case authenticatorSelection, attestation, timeout
    }
    private enum PartyKeys: String, CodingKey { case id, name }
    private enum UserKeys: String, CodingKey { case id, name, displayName }
    private enum ParameterKeys: String, CodingKey { case alg, type }
    private enum SelectionKeys: String, CodingKey {
        case userVerification, residentKey, authenticatorAttachment
    }

    /// Encodes to the WebAuthn JSON form.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        var party = container.nestedContainer(keyedBy: PartyKeys.self, forKey: .rp)
        try party.encode(relyingParty.id, forKey: .id)
        try party.encode(relyingParty.name, forKey: .name)

        var subject = container.nestedContainer(keyedBy: UserKeys.self, forKey: .user)
        try subject.encode(Base64URL.encode(user.id), forKey: .id)
        try subject.encode(user.name, forKey: .name)
        try subject.encode(user.displayName, forKey: .displayName)

        try container.encode(Base64URL.encode(challenge), forKey: .challenge)

        var parameters = container.nestedUnkeyedContainer(forKey: .pubKeyCredParams)
        for algorithm in algorithms {
            var entry = parameters.nestedContainer(keyedBy: ParameterKeys.self)
            try entry.encode(algorithm.rawValue, forKey: .alg)
            try entry.encode("public-key", forKey: .type)
        }

        try container.encode(excludeCredentials, forKey: .excludeCredentials)

        var selection = container.nestedContainer(
            keyedBy: SelectionKeys.self, forKey: .authenticatorSelection
        )
        try selection.encode(userVerification, forKey: .userVerification)
        try selection.encode("preferred", forKey: .residentKey)
        // Omitted entirely when unset. Encoding null would be a different statement from saying
        // nothing, and some browsers treat the key's presence as a constraint.
        try selection.encodeIfPresent(attachment, forKey: .authenticatorAttachment)

        // Not requested, because none of it would be verified. Asking for attestation this
        // package refuses would be theatre, and would prompt some authenticators to show the
        // person a consent screen for a disclosure that is then discarded.
        try container.encode("none", forKey: .attestation)
        try container.encode(timeout, forKey: .timeout)
    }
}

/// What the browser is asked to assert.
public struct PublicKeyCredentialRequestOptions: Sendable, Equatable, Encodable {
    /// The challenge to sign.
    public let challenge: [UInt8]
    /// The relying party the credential must be scoped to.
    public let relyingPartyID: String
    /// The credentials that may answer. Empty invites any discoverable credential.
    public let allowCredentials: [CredentialDescriptor]
    /// How thoroughly the person must be identified.
    public let userVerification: UserVerificationRequirement
    /// How long the browser should wait, in milliseconds.
    public let timeout: Int

    private enum CodingKeys: String, CodingKey {
        case challenge, rpId, allowCredentials, userVerification, timeout
    }

    /// Encodes to the WebAuthn JSON form.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(Base64URL.encode(challenge), forKey: .challenge)
        try container.encode(relyingPartyID, forKey: .rpId)
        try container.encode(allowCredentials, forKey: .allowCredentials)
        try container.encode(userVerification, forKey: .userVerification)
        try container.encode(timeout, forKey: .timeout)
    }
}
