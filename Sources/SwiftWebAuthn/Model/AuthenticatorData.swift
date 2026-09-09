/// The structure an authenticator signs over, in the fixed layout the specification defines.
///
/// Everything else in a ceremony is CBOR; this is not. It is a hash, a byte of flags, a
/// big-endian counter, and then — when the flags say so — a credential whose public key is CBOR
/// and **carries no length**. Finding where that key ends means decoding it, which is why
/// ``CBOR/decodePrefix(_:)`` exists.
public struct AuthenticatorData: Sendable, Equatable {

    /// What the authenticator asserts about the ceremony it just performed.
    public struct Flags: Sendable, Equatable {
        /// Someone was physically present — a touch, not a remote call.
        public let userPresent: Bool
        /// That person was identified, by biometric or PIN, rather than merely present.
        public let userVerified: Bool
        /// The credential may be backed up — synced to another device.
        ///
        /// Read together with ``isBackedUp``, because the pair is what makes the signature
        /// counter trustworthy or not.
        public let backupEligible: Bool
        /// The credential is currently backed up.
        ///
        /// **A backed-up credential may never increment its signature counter.** Treating a
        /// static counter as an attack would refuse every legitimate synced passkey, which is
        /// why counter regression is only an error when this is `false`. Recorded as §10.3, and
        /// derived from the specification rather than from a real ceremony — it wants checking
        /// against a real device before anything leans on it.
        public let isBackedUp: Bool
        /// Attested credential data follows the fixed header.
        public let hasAttestedCredentialData: Bool
        /// Extension output follows everything else.
        public let hasExtensionData: Bool
    }

    /// The credential an authenticator just created.
    public struct AttestedCredential: Sendable, Equatable {
        /// Which model of authenticator made it. Zero for anonymous attestation, which is what
        /// Apple's platform authenticator sends.
        public let aaguid: [UInt8]
        /// The credential's identifier, echoed back on every later authentication.
        public let credentialID: [UInt8]
        /// The public key to verify future assertions against.
        public let publicKey: COSEPublicKey
    }

    /// Why authenticator data was refused.
    public enum Failure: Error, Equatable {
        /// Fewer bytes than the layout requires at that point.
        case truncated(expected: Int, actual: Int)
        /// A declared credential-id length longer than the data that followed it.
        case credentialIDLengthExceedsData(declared: Int)
        /// A credential id past the ceiling the specification sets.
        case credentialIDTooLong(Int)
        /// Bytes left over that nothing declared.
        case trailingBytes(count: Int)
    }

    /// The fixed header: 32 bytes of hash, one of flags, four of counter.
    public static let minimumLength = 37

    /// The longest credential id the specification permits.
    public static let maximumCredentialIDLength = 1023

    /// SHA-256 of the relying party identifier this ceremony was scoped to.
    public let relyingPartyIDHash: [UInt8]
    /// What the authenticator asserted.
    public let flags: Flags
    /// The authenticator's signature counter.
    public let signCount: UInt32
    /// The credential created, present only on registration.
    public let attestedCredential: AttestedCredential?

    /// Parses authenticator data.
    ///
    /// - Parameter bytes: The complete structure. Anything left unaccounted for is a failure —
    ///   trailing bytes here would be data an attacker added that no step examined.
    /// - Throws: ``AuthenticatorData/Failure``, ``COSEPublicKey/Failure`` or ``CBOR/Failure``.
    public init(_ bytes: [UInt8]) throws {
        guard bytes.count >= Self.minimumLength else {
            throw Failure.truncated(expected: Self.minimumLength, actual: bytes.count)
        }

        self.relyingPartyIDHash = Array(bytes[0..<32])
        let raw = bytes[32]
        self.flags = Flags(
            userPresent: raw & 0x01 != 0,
            userVerified: raw & 0x04 != 0,
            backupEligible: raw & 0x08 != 0,
            isBackedUp: raw & 0x10 != 0,
            hasAttestedCredentialData: raw & 0x40 != 0,
            hasExtensionData: raw & 0x80 != 0
        )
        // Big-endian, as every multi-byte field in this structure is. Read the other way round
        // a counter would never appear to regress, and regression is the whole reason it exists.
        self.signCount = (UInt32(bytes[33]) << 24) | (UInt32(bytes[34]) << 16)
            | (UInt32(bytes[35]) << 8) | UInt32(bytes[36])

        var cursor = Self.minimumLength

        if flags.hasAttestedCredentialData {
            let headerEnd = cursor + 18   // 16 bytes of AAGUID, 2 of length
            guard bytes.count >= headerEnd else {
                throw Failure.truncated(expected: headerEnd, actual: bytes.count)
            }
            let aaguid = Array(bytes[cursor..<(cursor + 16)])
            let declared = Int(bytes[cursor + 16]) << 8 | Int(bytes[cursor + 17])
            cursor = headerEnd

            // Availability before the ceiling: a length that overruns the buffer is a different
            // fault from one that is merely too large, and reporting the ceiling for a declared
            // 4096 would describe the wrong problem.
            guard declared <= bytes.count - cursor else {
                throw Failure.credentialIDLengthExceedsData(declared: declared)
            }
            guard declared <= Self.maximumCredentialIDLength else {
                throw Failure.credentialIDTooLong(declared)
            }

            let credentialID = Array(bytes[cursor..<(cursor + declared)])
            cursor += declared

            let (value, consumed) = try CBOR.decodePrefix(Array(bytes[cursor...]))
            cursor += consumed
            self.attestedCredential = AttestedCredential(
                aaguid: aaguid, credentialID: credentialID, publicKey: try COSEPublicKey(value)
            )
        } else {
            self.attestedCredential = nil
        }

        if flags.hasExtensionData {
            let (_, consumed) = try CBOR.decodePrefix(Array(bytes[cursor...]))
            cursor += consumed
        }

        guard cursor == bytes.count else {
            throw Failure.trailingBytes(count: bytes.count - cursor)
        }
    }
}
