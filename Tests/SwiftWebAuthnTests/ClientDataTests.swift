import Foundation
import Testing
@testable import SwiftWebAuthn

@Suite("Base64URL — the encoding every WebAuthn field arrives in")
struct Base64URLTests {

    @Test("round trips, including the lengths that need padding")
    func roundTrips() throws {
        for length in 0...32 {
            let bytes = (0..<length).map { UInt8($0 &* 7 &+ 1) }
            let text = Base64URL.encode(bytes)
            #expect(try Base64URL.decode(text) == bytes, "length \(length)")
        }
    }

    @Test("it emits no padding, because WebAuthn's encoding does not")
    func encodesWithoutPadding() {
        #expect(!Base64URL.encode([0x01]).contains("="))
        #expect(!Base64URL.encode([0x01, 0x02]).contains("="))
    }

    @Test("the URL alphabet, not the standard one")
    func usesTheURLAlphabet() {
        // 0xFB 0xFF encodes to "+/" in standard base64 and "-_" here.
        let encoded = Base64URL.encode([0xFB, 0xFF])
        #expect(encoded == "-_8")
        #expect(!encoded.contains("+"))
        #expect(!encoded.contains("/"))
    }

    @Test("input outside the alphabet is refused rather than silently dropped")
    func refusesForeignCharacters() {
        #expect(throws: Base64URL.Failure.invalidCharacters) { try Base64URL.decode("ab+d") }
        #expect(throws: Base64URL.Failure.invalidCharacters) { try Base64URL.decode("ab/d") }
        #expect(throws: Base64URL.Failure.invalidCharacters) { try Base64URL.decode("ab d") }
    }
}

@Suite("Collected client data — what the browser says the ceremony was")
struct CollectedClientDataTests {

    static func json(
        type: String = "webauthn.create",
        challenge: String = Base64URL.encode([1, 2, 3, 4]),
        origin: String = "https://example.com",
        crossOrigin: Bool? = false
    ) -> [UInt8] {
        var fields = [
            "\"type\":\"\(type)\"",
            "\"challenge\":\"\(challenge)\"",
            "\"origin\":\"\(origin)\"",
        ]
        if let crossOrigin { fields.append("\"crossOrigin\":\(crossOrigin)") }
        return Array("{\(fields.joined(separator: ","))}".utf8)
    }

    @Test("the three fields that matter, and the raw bytes kept alongside them")
    func parsesTheFields() throws {
        let bytes = Self.json()
        let data = try CollectedClientData(bytes)

        #expect(data.type == "webauthn.create")
        #expect(data.challenge == [1, 2, 3, 4])
        #expect(data.origin == "https://example.com")
        #expect(!data.crossOrigin)
        // The hash is computed over exactly what arrived. Re-serialising would change the bytes
        // a signature was made over, so the original is kept rather than reconstructed.
        #expect(data.raw == bytes)
    }

    @Test("crossOrigin is optional, and its absence means false")
    func crossOriginDefaultsToFalse() throws {
        #expect(try !CollectedClientData(Self.json(crossOrigin: nil)).crossOrigin)
    }

    @Test("a challenge that is not base64url")
    func malformedChallengeIsRefused() {
        #expect(throws: CollectedClientData.Failure.malformedChallenge) {
            try CollectedClientData(Self.json(challenge: "not valid!"))
        }
    }

    @Test("something that is not JSON at all")
    func nonJSONIsRefused() {
        #expect(throws: CollectedClientData.Failure.invalidJSON) {
            try CollectedClientData(Array("{".utf8))
        }
    }

    @Test("JSON that is missing a required field")
    func missingFieldIsRefused() {
        let bytes = Array("{\"type\":\"webauthn.create\"}".utf8)
        #expect(throws: CollectedClientData.Failure.invalidJSON) {
            try CollectedClientData(bytes)
        }
    }
}

@Suite("Challenge")
struct ChallengeTests {

    /// A seeded generator, so the assertions below are about the code and not about luck.
    ///
    /// SplitMix64 — small, well-known, and emphatically not for production use, which is why it
    /// lives in the tests and `Challenge.random()` reaches for the system's generator instead.
    struct SeededGenerator: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9E3779B97F4A7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
            z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
            return z ^ (z >> 31)
        }
    }

    @Test("the length asked for")
    func lengthIsRespected() {
        var generator = SeededGenerator(state: 1)
        #expect(Challenge.random(using: &generator).bytes.count == 32)
        #expect(Challenge.random(byteCount: 16, using: &generator).bytes.count == 16)
    }

    @Test("a seeded generator produces the same challenge twice, so the draw is the generator's")
    func generationIsDrivenEntirelyByTheGenerator() {
        var first = SeededGenerator(state: 42)
        var second = SeededGenerator(state: 42)
        #expect(Challenge.random(using: &first) == Challenge.random(using: &second))

        // And a different seed gives a different challenge, which is the failure that actually
        // happens: a generator wired up to return a constant.
        var third = SeededGenerator(state: 43)
        #expect(Challenge.random(using: &first) != Challenge.random(using: &third))
    }

    @Test("successive draws from one generator differ")
    func successiveDrawsDiffer() {
        var generator = SeededGenerator(state: 7)
        let drawn = Set((0..<8).map { _ in Challenge.random(using: &generator).bytes })
        #expect(drawn.count == 8)
    }
}
