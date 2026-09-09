import Testing
@testable import SwiftWebAuthn

/// The decoder's job is to read the shape an attestation object and a COSE key use, and to
/// refuse everything else.
///
/// The negative tests outnumber the positive ones, which is the point: this parses bytes an
/// attacker supplies, and every shape it accepts is a shape someone can send.
@Suite("CBOR — the subset, and the refusals")
struct CBORDecoderTests {

    // MARK: - The shapes it must read

    @Test("unsigned integers, at every width the encoding allows")
    func unsignedAtEveryWidth() throws {
        #expect(try CBOR.decode([0x00]) == .unsigned(0))
        #expect(try CBOR.decode([0x17]) == .unsigned(23))          // the largest immediate value
        #expect(try CBOR.decode([0x18, 0x18]) == .unsigned(24))    // one following byte
        #expect(try CBOR.decode([0x19, 0x01, 0x00]) == .unsigned(256))
        #expect(try CBOR.decode([0x1A, 0x00, 0x01, 0x00, 0x00]) == .unsigned(65536))
        #expect(try CBOR.decode([0x1B, 0, 0, 0, 1, 0, 0, 0, 0]) == .unsigned(4_294_967_296))
    }

    @Test("negative integers — COSE labels the key parser needs are all negative")
    func negativeIntegers() throws {
        #expect(try CBOR.decode([0x20]) == .negative(-1))   // crv
        #expect(try CBOR.decode([0x21]) == .negative(-2))   // x
        #expect(try CBOR.decode([0x22]) == .negative(-3))   // y
        #expect(try CBOR.decode([0x38, 0x63]) == .negative(-100))
    }

    @Test("byte strings and text strings")
    func strings() throws {
        #expect(try CBOR.decode([0x40]) == .bytes([]))
        #expect(try CBOR.decode([0x43, 0x01, 0x02, 0x03]) == .bytes([1, 2, 3]))
        #expect(try CBOR.decode([0x60]) == .text(""))
        #expect(try CBOR.decode([0x64, 0x6E, 0x6F, 0x6E, 0x65]) == .text("none"))
    }

    @Test("arrays, because refusing them would turn an unsupported format into a parse failure")
    func arrays() throws {
        #expect(try CBOR.decode([0x80]) == .array([]))
        #expect(try CBOR.decode([0x83, 0x01, 0x02, 0x03]) == .array([.unsigned(1), .unsigned(2), .unsigned(3)]))
    }

    @Test("maps keyed by text, which is the attestation object's shape")
    func mapWithTextKeys() throws {
        // {"fmt": "none"}
        let bytes: [UInt8] = [0xA1, 0x63, 0x66, 0x6D, 0x74, 0x64, 0x6E, 0x6F, 0x6E, 0x65]
        #expect(try CBOR.decode(bytes) == .map([.text("fmt"): .text("none")]))
    }

    @Test("maps keyed by integer, which is a COSE key's shape")
    func mapWithIntegerKeys() throws {
        // {1: 2, -1: 1}
        let bytes: [UInt8] = [0xA2, 0x01, 0x02, 0x20, 0x01]
        #expect(try CBOR.decode(bytes) == .map([.int(1): .unsigned(2), .int(-1): .unsigned(1)]))
    }

    @Test("the whole attestation object shape, nested")
    func attestationObjectShape() throws {
        // {"fmt": "none", "attStmt": {}, "authData": h'AABB'}
        let bytes: [UInt8] = [
            0xA3,
            0x63, 0x66, 0x6D, 0x74, 0x64, 0x6E, 0x6F, 0x6E, 0x65,
            0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6D, 0x74, 0xA0,
            0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, 0x42, 0xAA, 0xBB,
        ]
        #expect(try CBOR.decode(bytes) == .map([
            .text("fmt"): .text("none"),
            .text("attStmt"): .map([:]),
            .text("authData"): .bytes([0xAA, 0xBB]),
        ]))
    }

    @Test("true, false and null — the only simple values that are allowed through")
    func theThreeSimpleValues() throws {
        #expect(try CBOR.decode([0xF4]) == .boolean(false))
        #expect(try CBOR.decode([0xF5]) == .boolean(true))
        #expect(try CBOR.decode([0xF6]) == .null)
    }

    // MARK: - What it must refuse, and for the stated reason

    @Test("indefinite-length items, for every major type that offers them")
    func indefiniteLengthIsRefused() {
        for opening in [UInt8(0x5F), 0x7F, 0x9F, 0xBF] {
            #expect(throws: CBOR.Failure.indefiniteLength(at: 0)) {
                try CBOR.decode([opening, 0xFF])
            }
        }
    }

    @Test("tags — nothing in this subset is tagged, and a tag can re-type what follows")
    func tagsAreRefused() {
        #expect(throws: CBOR.Failure.unsupportedMajorType(6, at: 0)) {
            try CBOR.decode([0xC0, 0x00])
        }
    }

    @Test("floats, and any simple value that is not true, false or null")
    func floatsAndOtherSimpleValuesAreRefused() {
        #expect(throws: CBOR.Failure.unsupportedSimpleValue(at: 0)) {
            try CBOR.decode([0xFA, 0x00, 0x00, 0x00, 0x00])   // float32
        }
        #expect(throws: CBOR.Failure.unsupportedSimpleValue(at: 0)) {
            try CBOR.decode([0xF7])                            // undefined
        }
    }

    @Test("a non-shortest-form integer — two encodings of one value is a signature-bypass surface")
    func nonCanonicalIntegersAreRefused() {
        // 23 encoded in a following byte, when it fits in the initial byte.
        #expect(throws: CBOR.Failure.nonCanonicalInteger(at: 0)) {
            try CBOR.decode([0x18, 0x17])
        }
        // 255 encoded in two bytes, when it fits in one.
        #expect(throws: CBOR.Failure.nonCanonicalInteger(at: 0)) {
            try CBOR.decode([0x19, 0x00, 0xFF])
        }
    }

    @Test("a declared length longer than the data, without trying to allocate it")
    func absurdLengthIsRefusedNotAllocated() {
        // Declares 2^64-1 bytes and supplies none. Must be refused by comparing against what is
        // actually there, never by attempting the reservation.
        #expect(throws: CBOR.Failure.truncated(at: 9)) {
            try CBOR.decode([0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        }
    }

    @Test("truncated input, at the header and in the middle of a payload")
    func truncatedInputIsRefused() {
        #expect(throws: CBOR.Failure.truncated(at: 0)) { try CBOR.decode([]) }
        #expect(throws: CBOR.Failure.truncated(at: 1)) { try CBOR.decode([0x18]) }
        #expect(throws: CBOR.Failure.truncated(at: 1)) { try CBOR.decode([0x43, 0x01]) }
    }

    @Test("trailing bytes after a complete item — the payload is one item, not a stream")
    func trailingBytesAreRefused() {
        #expect(throws: CBOR.Failure.trailingBytes(at: 1)) {
            try CBOR.decode([0x00, 0x00])
        }
    }

    @Test("a duplicate map key, because whichever value won would be arbitrary")
    func duplicateMapKeysAreRefused() {
        // {1: 1, 1: 2}
        #expect(throws: CBOR.Failure.duplicateKey(at: 3)) {
            try CBOR.decode([0xA2, 0x01, 0x01, 0x01, 0x02])
        }
    }

    @Test("a map key that is neither integer nor text")
    func unsupportedKeyTypesAreRefused() {
        // {h'01': 1}
        #expect(throws: CBOR.Failure.unsupportedKeyType(at: 1)) {
            try CBOR.decode([0xA1, 0x41, 0x01, 0x01])
        }
    }

    @Test("nesting deeper than the shape allows, so a small input cannot exhaust the stack")
    func excessiveNestingIsRefused() {
        // 32 nested single-element arrays, one past the limit.
        let bytes = [UInt8](repeating: 0x81, count: 32) + [0x00]
        #expect(throws: CBOR.Failure.nestingTooDeep(at: 31)) {
            try CBOR.decode(bytes)
        }
    }

    @Test("text that is not valid UTF-8")
    func invalidUTF8IsRefused() {
        #expect(throws: CBOR.Failure.invalidText(at: 1)) {
            try CBOR.decode([0x62, 0xFF, 0xFE])
        }
    }
}
