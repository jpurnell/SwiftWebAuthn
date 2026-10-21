# SwiftWebAuthn

**Verifying passkey ceremonies, from the specification rather than from a port.**

The server's half of WebAuthn: registration, where an authenticator produces a key pair and
attests to it, and authentication, where it signs a challenge with a key it already holds.

## Why this exists rather than a dependency

A maintained Swift implementation exists. This is written anyway, from the W3C specification,
with that implementation's public test suite kept as an **external bar to clear** — no code and
no tests copied.

What is being verified is a signature that decides who someone is. Reading the specification
closely enough to implement it is how anyone earns the right to say the verification is correct,
and a deployment adopting passkeys as its default is exactly where that matters.

No cryptographic primitive is written here. `swift-crypto` does the mathematics; this parses,
checks the specification's steps in order, and refuses everything it does not understand.

## Status

**0.2.1: implemented and in use**, pre-1.0. Registration and authentication ceremonies are
verified step by step from the W3C specification: CBOR and COSE parsing, ES256 and Ed25519,
origin and RP ID checks, and signature-counter clone detection that reads the backup flags.
`SwiftWebAuthnIdentity` makes a passkey one more SwiftIdentity credential, resolved by a store
that passes SwiftIdentity's conformance suite.

Verified against `swift-server/webauthn-swift` as an **external bar**: the same bytes are judged by
both implementations. Two disagreements were found and are recorded as policy, not correctness.
The proposal kept a written-down bar at which this package should be abandoned in favour of the
maintained one; it has not been reached.

## Requirements

Swift 6.2+, macOS 14+.

## License

MIT — see [LICENSE](LICENSE).
