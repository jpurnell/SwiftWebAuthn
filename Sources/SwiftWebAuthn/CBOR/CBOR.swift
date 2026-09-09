/// The subset of CBOR that an attestation object and a COSE key are made of.
///
/// ## Why a decoder rather than a dependency
///
/// The shapes this package reads are small and closed: a map of three known keys holding a text
/// string, a nested map, and a byte string; and a key map whose labels are small integers. A
/// general CBOR library is a dependency and an attack surface disproportionate to that.
///
/// So this reads that subset and **refuses everything else** — tags, floating point, indefinite
/// lengths, non-canonical integers, duplicate map keys, and anything left over at the end.
/// Refusing is the correct posture for bytes an attacker supplies, and every shape accepted here
/// is a shape someone can send.
///
/// ## The abandonment condition
///
/// Recorded before any of this existed, in ADR-001: **if this subset starts growing in order to
/// make real authenticators work, take a maintained dependency instead.** That is a check
/// against a stated bar rather than a defence of effort already spent.
public indirect enum CBOR: Sendable, Equatable {

    /// A non-negative integer.
    case unsigned(UInt64)
    /// A negative integer. COSE labels the key parser needs are all negative.
    case negative(Int64)
    /// A byte string.
    case bytes([UInt8])
    /// A UTF-8 text string.
    case text(String)
    /// An ordered sequence.
    case array([CBOR])
    /// A map, keyed by integer or text.
    case map([Key: CBOR])
    /// `true` or `false`.
    case boolean(Bool)
    /// `null`.
    case null

    /// A map key.
    ///
    /// Integer or text and nothing else: an attestation object keys by text and a COSE key keys
    /// by integer, and admitting other key types would widen the shape for no reader.
    public enum Key: Sendable, Hashable {
        /// An integer key, as COSE uses.
        case int(Int64)
        /// A text key, as the attestation object uses.
        case text(String)
    }

    /// Why a payload was refused.
    ///
    /// Each case carries the byte offset it was found at, because "the CBOR is malformed" sends
    /// someone reading a hex dump by eye.
    public enum Failure: Error, Equatable {
        /// The payload ended in the middle of an item.
        case truncated(at: Int)
        /// A complete item was decoded and bytes remained. The payload is one item, not a stream.
        case trailingBytes(at: Int)
        /// An indefinite-length item. Canonical CBOR does not produce them.
        case indefiniteLength(at: Int)
        /// A major type this subset does not read — tags, principally.
        case unsupportedMajorType(UInt8, at: Int)
        /// A simple value other than `true`, `false` or `null`, which includes all floating point.
        case unsupportedSimpleValue(at: Int)
        /// An integer encoded in more bytes than it needs.
        case nonCanonicalInteger(at: Int)
        /// The same map key twice.
        case duplicateKey(at: Int)
        /// A map key that is neither integer nor text.
        case unsupportedKeyType(at: Int)
        /// Nesting beyond ``CBOR/maximumNesting``.
        case nestingTooDeep(at: Int)
        /// A text string that is not valid UTF-8.
        case invalidText(at: Int)
        /// A negative integer too large to represent.
        case integerOutOfRange(at: Int)
    }

    /// How deeply items may nest.
    ///
    /// A real attestation object nests three deep. The limit is generous by comparison and
    /// exists only so that a few bytes of input cannot exhaust the stack: 31 opening bytes is a
    /// 31-byte payload.
    public static let maximumNesting = 31

    /// Decodes exactly one item from `bytes`.
    ///
    /// - Parameter bytes: The complete payload. Anything left over is a failure, not a second item.
    /// - Returns: The decoded item.
    /// - Throws: ``CBOR/Failure``.
    public static func decode(_ bytes: [UInt8]) throws -> CBOR {
        var reader = Reader(bytes: bytes)
        let value = try reader.item(depth: 0)
        guard reader.cursor == bytes.count else {
            throw Failure.trailingBytes(at: reader.cursor)
        }
        return value
    }
}

/// The cursor, kept out of ``CBOR`` so the public surface stays the shape and its failures.
private struct Reader {
    let bytes: [UInt8]
    var cursor = 0

    /// Bytes not yet consumed. Compared against a declared length so an absurd one is refused
    /// by arithmetic rather than by attempting the allocation it asks for.
    var remaining: Int { bytes.count - cursor }

    mutating func byte() throws -> UInt8 {
        guard cursor < bytes.count else { throw CBOR.Failure.truncated(at: cursor) }
        defer { cursor += 1 }
        return bytes[cursor]
    }

    /// Reads one item, and everything nested inside it.
    mutating func item(depth: Int) throws -> CBOR {
        let start = cursor
        let initial = try byte()
        let major = initial >> 5
        let additional = initial & 0x1F

        switch major {
        case 0:
            return .unsigned(try argument(additional, headerAt: start))
        case 1:
            let magnitude = try argument(additional, headerAt: start)
            guard magnitude <= UInt64(Int64.max) else {
                throw CBOR.Failure.integerOutOfRange(at: start)
            }
            return .negative(-1 - Int64(magnitude))
        case 2:
            return .bytes(try payload(additional, headerAt: start))
        case 3:
            let raw = try payload(additional, headerAt: start)
            let payloadStart = cursor - raw.count
            // Decoded, then re-encoded and compared. `String(decoding:)` substitutes a
            // replacement character for invalid input rather than failing, which would silently
            // change bytes a signature was computed over; the round trip is what detects that.
            // `String(validating:as:)` says this directly but is macOS 15, and this package
            // deploys to 14.
            let text = String(decoding: raw, as: UTF8.self)
            guard Array(text.utf8) == raw else {
                throw CBOR.Failure.invalidText(at: payloadStart)
            }
            return .text(text)
        case 4:
            let count = try container(additional, headerAt: start, depth: depth)
            var items: [CBOR] = []
            items.reserveCapacity(count)
            for _ in 0..<count { items.append(try item(depth: depth + 1)) }
            return .array(items)
        case 5:
            let count = try container(additional, headerAt: start, depth: depth)
            var pairs: [CBOR.Key: CBOR] = [:]
            pairs.reserveCapacity(count)
            for _ in 0..<count {
                let keyStart = cursor
                let key: CBOR.Key
                switch try item(depth: depth + 1) {
                case .unsigned(let value):
                    guard value <= UInt64(Int64.max) else {
                        throw CBOR.Failure.integerOutOfRange(at: keyStart)
                    }
                    key = .int(Int64(value))
                case .negative(let value): key = .int(value)
                case .text(let value): key = .text(value)
                default: throw CBOR.Failure.unsupportedKeyType(at: keyStart)
                }
                guard pairs[key] == nil else { throw CBOR.Failure.duplicateKey(at: keyStart) }
                pairs[key] = try item(depth: depth + 1)
            }
            return .map(pairs)
        case 7:
            switch additional {
            case 20: return .boolean(false)
            case 21: return .boolean(true)
            case 22: return .null
            default: throw CBOR.Failure.unsupportedSimpleValue(at: start)
            }
        default:
            // 6 is tags. A tag re-types what follows it, and nothing in this subset is tagged.
            throw CBOR.Failure.unsupportedMajorType(major, at: start)
        }
    }

    /// Reads an item's argument, enforcing the shortest encoding that could carry it.
    ///
    /// Two encodings of one value would mean two byte sequences with the same meaning, which is
    /// a difference an attacker chooses and a verifier does not see.
    mutating func argument(_ additional: UInt8, headerAt start: Int) throws -> UInt64 {
        switch additional {
        case 0...23:
            return UInt64(additional)
        case 24...27:
            let width = 1 << Int(additional - 24)
            guard remaining >= width else { throw CBOR.Failure.truncated(at: cursor) }
            var value: UInt64 = 0
            for _ in 0..<width { value = (value << 8) | UInt64(try byte()) }
            let smallest: UInt64 = additional == 24 ? 24 : (1 << (UInt64(width / 2) * 8))
            guard value >= smallest else { throw CBOR.Failure.nonCanonicalInteger(at: start) }
            return value
        case 31:
            throw CBOR.Failure.indefiniteLength(at: start)
        default:
            // 28, 29, 30 are reserved and have no meaning to assign.
            throw CBOR.Failure.unsupportedSimpleValue(at: start)
        }
    }

    /// Reads a byte- or text-string payload, refusing a length longer than the data.
    mutating func payload(_ additional: UInt8, headerAt start: Int) throws -> [UInt8] {
        let length = try argument(additional, headerAt: start)
        guard length <= UInt64(remaining) else { throw CBOR.Failure.truncated(at: cursor) }
        let count = Int(length)
        defer { cursor += count }
        return Array(bytes[cursor..<(cursor + count)])
    }

    /// Reads a container's element count, refusing one that cannot fit and nesting that is too deep.
    mutating func container(_ additional: UInt8, headerAt start: Int, depth: Int) throws -> Int {
        guard depth < CBOR.maximumNesting else { throw CBOR.Failure.nestingTooDeep(at: start) }
        let count = try argument(additional, headerAt: start)
        // One element needs at least one byte, so a count beyond what remains cannot be honoured.
        // Checked before reserving, so a declared count of 2^64-1 costs arithmetic and not memory.
        guard count <= UInt64(remaining) else { throw CBOR.Failure.truncated(at: cursor) }
        return Int(count)
    }
}
