#if canImport(os)
import os
#endif
import Foundation

/// Challenge bytes, drawn straight from the kernel's entropy pool.
///
/// ## Why not `SystemRandomNumberGenerator`
///
/// `SwiftWebAuthn` deliberately refuses to choose a randomness source, so the choice lands here,
/// on the caller. Making it explicitly — naming the device, opening it once, reading from it —
/// says where the bytes come from in a way that a type name does not. `/dev/urandom` is the
/// kernel CSPRNG on both platforms this tool runs on, and it is the same pool the standard
/// library's generator draws from.
///
/// It also happens to satisfy a rule worth agreeing with: a stochastic function should take its
/// generator rather than reach for one. Every function here does; this type is the one place the
/// source is decided, and it is a type rather than a hidden call.
///
/// ## Not seedable, deliberately
///
/// A seeded mode would make captures reproducible, and a predictable challenge is a replayable
/// ceremony. A tool whose entire purpose is producing trustworthy evidence should not offer a
/// mode that produces untrustworthy evidence.
struct KernelRandom: RandomNumberGenerator {

    private let source: FileHandle

    /// Opens the kernel's random device.
    ///
    /// - Throws: If the device cannot be opened, in which case this tool must not run: silently
    ///   falling back to something weaker would make every captured ceremony worthless without
    ///   saying so.
    init() throws {
        source = try FileHandle(forReadingFrom: URL(fileURLWithPath: "/dev/urandom"))
    }

    /// Eight bytes from the pool, assembled without touching a pointer.
    mutating func next() -> UInt64 {
        let bytes: Data
        do {
            guard let read = try source.read(upToCount: 8), read.count == 8 else {
                // The kernel's random device returning short is not a condition to paper over.
                preconditionFailure("/dev/urandom returned fewer than 8 bytes")
            }
            bytes = read
        } catch {
            #if canImport(os)
            Logger(subsystem: "org.roseclub.swiftwebauthn", category: "capture")
                .fault("/dev/urandom could not be read: \(String(describing: error), privacy: .public)")
            #endif
            preconditionFailure("/dev/urandom could not be read: \(error)")
        }

        // Shifted rather than reinterpreted: a raw load would need a pointer, and byte order
        // does not matter for a value that is uniformly random either way.
        return bytes.reduce(into: UInt64(0)) { accumulated, byte in
            accumulated = (accumulated << 8) | UInt64(byte)
        }
    }
}
