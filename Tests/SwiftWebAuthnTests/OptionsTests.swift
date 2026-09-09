import Foundation
import Testing
@testable import SwiftWebAuthn

/// The two option structures a relying party sends to the browser.
///
/// They are pure data, but they are where a package can quietly disagree with itself: offering
/// an algorithm the verifier will not accept produces a ceremony that fails after the person has
/// already touched the sensor. The last test here exists to make that impossible.
@Suite("Options — what the browser is asked to do")
struct OptionsTests {

    static let party = RelyingParty(
        id: "example.com", name: "Example", origins: ["https://example.com"]
    )

    static func encoded(_ value: some Encodable) throws -> [String: Any] {
        let data = try JSONEncoder().encode(value)
        let object = try JSONSerialization.jsonObject(with: data)
        return try #require(object as? [String: Any])
    }

    // MARK: - Registration

    @Test("creation options carry the party, the user, and the challenge as base64url")
    func creationOptionsAreEncoded() throws {
        let user = UserEntity(id: [0x01, 0x02, 0x03], name: "ada", displayName: "Ada")
        let options = Self.party.registrationOptions(for: user, challenge: Challenge([0xAA, 0xBB]))
        let json = try Self.encoded(options)

        #expect(json["challenge"] as? String == Base64URL.encode([0xAA, 0xBB]))

        let party = try #require(json["rp"] as? [String: Any])
        #expect(party["id"] as? String == "example.com")
        #expect(party["name"] as? String == "Example")

        let subject = try #require(json["user"] as? [String: Any])
        #expect(subject["id"] as? String == Base64URL.encode([0x01, 0x02, 0x03]))
        #expect(subject["name"] as? String == "ada")
        #expect(subject["displayName"] as? String == "Ada")
    }

    @Test("attestation is not requested, because none of it would be verified")
    func attestationIsNotRequested() throws {
        let options = Self.party.registrationOptions(
            for: UserEntity(id: [1], name: "ada", displayName: "Ada"),
            challenge: Challenge([0xAA])
        )
        #expect(try Self.encoded(options)["attestation"] as? String == "none")
    }

    @Test("credentials already registered are excluded, so a device does not enrol twice")
    func excludedCredentialsAreEncoded() throws {
        let options = Self.party.registrationOptions(
            for: UserEntity(id: [1], name: "ada", displayName: "Ada"),
            challenge: Challenge([0xAA]),
            excluding: [[0xC1, 0xC2], [0xD1]]
        )
        let excluded = try #require(try Self.encoded(options)["excludeCredentials"] as? [[String: Any]])

        #expect(excluded.count == 2)
        #expect(excluded[0]["id"] as? String == Base64URL.encode([0xC1, 0xC2]))
        #expect(excluded[0]["type"] as? String == "public-key")
    }

    // MARK: - Authentication

    @Test("request options carry the relying party id and the credentials allowed")
    func requestOptionsAreEncoded() throws {
        let options = Self.party.authenticationOptions(
            challenge: Challenge([0x01, 0x02]), allowing: [[0xC1]]
        )
        let json = try Self.encoded(options)

        #expect(json["challenge"] as? String == Base64URL.encode([0x01, 0x02]))
        #expect(json["rpId"] as? String == "example.com")

        let allowed = try #require(json["allowCredentials"] as? [[String: Any]])
        #expect(allowed.count == 1)
        #expect(allowed[0]["id"] as? String == Base64URL.encode([0xC1]))
    }

    @Test("user verification is requested by default, matching what verification requires")
    func userVerificationIsRequestedByDefault() throws {
        let request = try Self.encoded(
            Self.party.authenticationOptions(challenge: Challenge([0x01]), allowing: [])
        )
        #expect(request["userVerification"] as? String == "required")

        let creation = try Self.encoded(Self.party.registrationOptions(
            for: UserEntity(id: [1], name: "ada", displayName: "Ada"), challenge: Challenge([0x01])
        ))
        let selection = try #require(creation["authenticatorSelection"] as? [String: Any])
        #expect(selection["userVerification"] as? String == "required")
    }

    // MARK: - The two halves must agree

    @Test("the algorithms offered are exactly the algorithms this package verifies")
    func offeredAlgorithmsMatchVerifiedAlgorithms() throws {
        let options = Self.party.registrationOptions(
            for: UserEntity(id: [1], name: "ada", displayName: "Ada"), challenge: Challenge([0xAA])
        )
        let parameters = try #require(try Self.encoded(options)["pubKeyCredParams"] as? [[String: Any]])

        let offered = Set(parameters.compactMap { $0["alg"] as? Int })
        let verified = Set(COSEPublicKey.Algorithm.allCases.map(\.rawValue))

        // Not a list written twice. Offering an algorithm the verifier refuses produces a
        // ceremony that fails *after* the person has already touched the sensor, and offering
        // fewer than we verify silently narrows what can enrol.
        #expect(offered == verified)
        #expect(parameters.allSatisfy { $0["type"] as? String == "public-key" })
    }
}
