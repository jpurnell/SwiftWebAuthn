import Crypto
import Foundation
import SwiftIdentity
import SwiftIdentityConformance
import SwiftWebAuthn
import SwiftWebAuthnIdentity
import Testing

/// The seam between the two packages, exercised through public API only.
///
/// Nothing here reaches inside either package — which is the point. If this file needs
/// `@testable`, the adapter is not usable by anyone else either.
@Suite("Passkeys as a SwiftIdentity credential")
struct PasskeyCredentialStoreTests {

    static let party = RelyingParty(
        id: "example.com", name: "Example", origins: ["https://example.com"]
    )

    /// A directory held in memory, recording what it was told to persist.
    actor Directory: PasskeyDirectory {
        private var registrations: [[UInt8]: PasskeyRegistration] = [:]
        private(set) var recorded: [VerifiedAuthentication] = []

        init(_ registrations: [PasskeyRegistration]) {
            for registration in registrations {
                self.registrations[registration.credential.id] = registration
            }
        }

        func registration(for credentialID: [UInt8]) async -> PasskeyRegistration? {
            registrations[credentialID]
        }

        func record(_ verification: VerifiedAuthentication) async {
            recorded.append(verification)
        }
    }

    /// A registered passkey and an assertion from it, both built through public API.
    struct Enrolled {
        let registration: PasskeyRegistration
        let assertion: PasskeyAssertion
    }

    /// Enrols a subject and produces one assertion it can present.
    static func enrol(
        subject id: String,
        status: Subject.Status = .active,
        challenge: [UInt8] = [UInt8](repeating: 0x33, count: 32),
        signCount: UInt32 = 4,
        storedSignCount: UInt32 = 3,
        signWithAnotherKey: Bool = false
    ) throws -> Enrolled {
        let privateKey = P256.Signing.PrivateKey()
        let x963 = Array(privateKey.publicKey.x963Representation)
        let credentialID = Array("credential-\(id)".utf8)

        // A COSE key, assembled the way an authenticator would send one.
        let cose: [UInt8] = [0xA5]
            + [0x01, 0x02] + [0x03, 0x26] + [0x20, 0x01]
            + [0x21, 0x58, 0x20] + Array(x963[1..<33])
            + [0x22, 0x58, 0x20] + Array(x963[33..<65])

        var authData = Array(SHA256.hash(data: Data("example.com".utf8)))
        authData.append(0x01 | 0x04)                       // present, verified
        authData += [
            UInt8((signCount >> 24) & 0xFF), UInt8((signCount >> 16) & 0xFF),
            UInt8((signCount >> 8) & 0xFF), UInt8(signCount & 0xFF),
        ]

        let clientDataJSON = Array("""
            {"type":"webauthn.get","challenge":"\(Base64URL.encode(challenge))","origin":"https://example.com","crossOrigin":false}
            """.utf8)
        let hash = Array(SHA256.hash(data: Data(clientDataJSON)))
        let signer = signWithAnotherKey ? P256.Signing.PrivateKey() : privateKey
        let signature = Array(try signer.signature(for: Data(authData + hash)).derRepresentation)

        return Enrolled(
            registration: PasskeyRegistration(
                credential: RegisteredCredential(
                    id: credentialID,
                    publicKey: try COSEPublicKey(cose),
                    signCount: storedSignCount,
                    isBackupEligible: false,
                    isBackedUp: false,
                    aaguid: [UInt8](repeating: 0, count: 16),
                    attestationFormat: "none"
                ),
                subject: Subject(id: id, kind: .person, status: status, attributes: ["tier": "full"])
            ),
            assertion: PasskeyAssertion(
                response: AuthenticationResponse(
                    credentialID: credentialID,
                    clientDataJSON: clientDataJSON,
                    authenticatorData: authData,
                    signature: signature,
                    userHandle: nil
                ),
                challenge: Challenge(challenge)
            )
        )
    }

    static func store(_ enrolled: [Enrolled], directory: Directory? = nil) -> (PasskeyCredentialStore, Directory) {
        let directory = directory ?? Directory(enrolled.map(\.registration))
        return (PasskeyCredentialStore(relyingParty: party, directory: directory), directory)
    }

    // MARK: - The seam

    @Test("a passkey assertion resolves to the subject that registered it")
    func aValidAssertionResolvesToItsSubject() async throws {
        let ada = try Self.enrol(subject: "ada")
        let (store, directory) = Self.store([ada])

        let subject = try #require(await store.subject(for: ada.assertion))
        #expect(subject.id == "ada")
        #expect(subject.attributes["tier"] == "full")

        // The counter must reach the consumer's storage, or the regression check compares
        // against a stale value forever.
        #expect(await directory.recorded.count == 1)
        #expect(await directory.recorded.first?.newSignCount == 4)
    }

    @Test("a credential kind this store was never taught proves nothing")
    func aForeignCredentialKindIsRefused() async throws {
        let ada = try Self.enrol(subject: "ada")
        let (store, _) = Self.store([ada])
        #expect(await store.resolve(BearerKey("anything")) == .refused(.unknown))
    }

    @Test("an assertion signed by a key nobody registered")
    func anotherKeysAssertionIsRefused() async throws {
        let forged = try Self.enrol(subject: "ada", signWithAnotherKey: true)
        let (store, directory) = Self.store([forged])

        #expect(await store.resolve(forged.assertion) == .refused(.unknown))
        // And nothing was written back on a failure.
        #expect(await directory.recorded.isEmpty)
    }

    @Test("a revoked subject, refused after the signature has been checked and not before")
    func aRevokedSubjectIsRefused() async throws {
        let retired = try Self.enrol(subject: "retired-agent", status: .revoked)
        let (store, directory) = Self.store([retired])

        #expect(await store.resolve(retired.assertion) == .refused(.revoked))
        // Status is examined only once possession is proved, so `revoked` in an audit log means
        // somebody actually holds the key — not that somebody guessed an identifier.
        #expect(await directory.recorded.isEmpty)
    }

    @Test("a honeypot subject reports itself, which is the whole point of the status")
    func aHoneypotSubjectIsReported() async throws {
        let leaked = try Self.enrol(subject: "leaked-share-link", status: .honeypot)
        let (store, _) = Self.store([leaked])
        #expect(await store.resolve(leaked.assertion) == .refused(.honeypot))
    }

    @Test("a credential identifier nobody enrolled")
    func anUnknownCredentialIsRefused() async throws {
        let ada = try Self.enrol(subject: "ada")
        let stranger = try Self.enrol(subject: "stranger")
        let (store, _) = Self.store([ada])
        #expect(await store.resolve(stranger.assertion) == .refused(.unknown))
    }

    // MARK: - The bar the other package sets

    @Test("it passes SwiftIdentity's conformance suite")
    func itPassesTheConformanceSuite() async throws {
        let ada = try Self.enrol(subject: "ada")
        let retired = try Self.enrol(subject: "retired-agent", status: .revoked)
        let leaked = try Self.enrol(subject: "leaked-share-link", status: .honeypot)
        let stranger = try Self.enrol(subject: "stranger")

        let (store, _) = Self.store([ada, retired, leaked])

        let report = await ConformanceSuite(
            store: store,
            fixtures: .init(
                // A passkey has no lifetime of its own and no external issuer, and throttling
                // defends a guessable secret — a signature is not one. Declared rather than
                // failed: an unclaimed capability is an honest statement, not a gap.
                capabilities: [.revocation, .honeypot],
                active: .init(id: "ada", credential: ada.assertion, attributes: ["tier": "full"]),
                refusals: .init(
                    revoked: retired.assertion,
                    honeypot: leaked.assertion,
                    expired: stranger.assertion,
                    unknown: stranger.assertion
                ),
                // The active subject's credential identifier, offered as a bearer key. A store
                // that matched on value without regard to kind would treat an identifier — which
                // travels in the clear on every ceremony — as a proof.
                //
                // The suite could not derive this: it has never heard of a passkey, which is
                // exactly the case `Credential` was made a protocol to allow. It reported a gap
                // until this fixture existed.
                activeAsAnotherKind: BearerKey(
                    String(decoding: ada.assertion.response.credentialID, as: UTF8.self)
                )
            )
        ).run()

        #expect(report.isConformant, "\(report.summary)")
        #expect(report.gaps.isEmpty, "\(report.summary)")
    }
}

/// The refusal reason must reach the operator and stop there.
@Suite("Passkeys — what the operator is told")
struct PasskeyFailureObserverTests {

    @Test("the operator learns which clause failed; the caller learns only that it did")
    func theReasonReachesTheObserverAndNoFurther() async throws {
        let ada = try PasskeyCredentialStoreTests.enrol(subject: "ada", signWithAnotherKey: true)
        let directory = PasskeyCredentialStoreTests.Directory([ada.registration])

        let observed = Observed()
        let store = PasskeyCredentialStore(
            relyingParty: PasskeyCredentialStoreTests.party,
            directory: directory,
            onFailure: { error in observed.record(error) }
        )

        #expect(await store.resolve(ada.assertion) == .refused(.unknown))

        let reasons = observed.reasons
        #expect(reasons.count == 1)
        #expect(reasons.first as? RelyingParty.Failure == .assertionSignatureInvalid)
    }

    /// A collector, locked because the observer is `@Sendable`.
    // Justification: every access to `storage` is serialised by `lock`, so the mutable state is never reached concurrently.
    final class Observed: @unchecked Sendable {
        private let lock = NSLock()
        private var storage: [any Error] = []

        func record(_ error: any Error) {
            lock.lock()
            defer { lock.unlock() }
            storage.append(error)
        }

        var reasons: [any Error] {
            lock.lock()
            defer { lock.unlock() }
            return storage
        }
    }
}
