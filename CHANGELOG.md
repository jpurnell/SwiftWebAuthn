# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **The registration ceremony, verified clause by clause against §7.1.** Every step is a named
  error and a named test: a foreign challenge, an untrusted origin, another relying party's
  hash, the wrong ceremony type, absent user presence, absent verification where it was
  required, no attested credential, an invalid attestation signature, and every attestation
  format this package will not pretend to check.

  Origins are matched **exactly**. A prefix or suffix comparison is the usual way this clause is
  written wrong, and `example.com.evil.test` is in the tests because of it.

- **A CBOR decoder for the subset an attestation object and a COSE key are made of**, refusing
  everything else — non-canonical integers, duplicate map keys, tags, floats, indefinite
  lengths, trailing bytes, and nesting past 31. Each refusal is a difference an attacker could
  choose and a verifier would not see. Every failure carries the byte offset it was found at.

- **COSE public key parsing** for ES256 and EdDSA. The key is **constructed, not measured**:
  two 32-byte blobs of the right length are a structurally perfect EC2 key and need not be a
  point on P-256, and only the curve arithmetic can tell the difference. **RS256 is refused by
  name**, so an unsupported algorithm never reads as a ceremony that succeeded.

- **`AuthenticatorData`** — the one structure in a ceremony that is not CBOR. Includes the
  backup-eligible and backed-up flags, because a synced passkey may never increment its
  signature counter and counter regression is therefore only meaningful when a credential is not
  backed up.

- **`CollectedClientData` and `Base64URL`.** The raw `clientDataJSON` is kept alongside the
  parsed fields, because a signature covers the bytes the browser produced and re-serialising
  would change them. The base64url alphabet is checked before translation, so `+` and `/` are
  refused rather than silently accepted as `-` and `_`.

- **`Challenge`**, generated from a generator the caller supplies. There is deliberately no
  overload that picks one: this package already declines to own where a challenge is stored, and
  silently choosing the randomness source would hide the same kind of decision.

- **The authentication ceremony (§7.2)**, with the same clauses tested again rather than assumed
  from registration, and the signature counter gated on the backup flags: regression is an error
  only for a credential that is **not** backed up, because a passkey synced through a keychain
  may never increment one and refusing that would lock out the common case rather than the
  attack.

- **Both option sets**, with the offered algorithms derived from what the verifier accepts rather
  than listed a second time. Offering an algorithm this package refuses produces a ceremony that
  fails after the person has already touched the sensor.

- **`SwiftWebAuthnIdentity`** — the adapter product (ADR-002). `PasskeyAssertion` is a
  `SwiftIdentity.Credential`, and `PasskeyCredentialStore` resolves one to a `Subject` by
  verifying the ceremony. `SwiftIdentity` gains no knowledge of WebAuthn and no dependency on
  it, so a service whose clients cannot run a ceremony links none of this.

  **It passes SwiftIdentity's conformance suite** — 7 requirements met, 0 failed, 0 inconclusive,
  4 honestly declined. Possession is checked before status, so `revoked` and `honeypot` are
  reported only for someone who actually holds the private key rather than for anyone who guesses
  an identifier.

### Decided

- **Proposal approved 2026-09-08**, with all four open questions answered in §10.
- **ADR-001** — written from the specification, with `brokenhandsio/swift-webauthn` kept as an
  external bar, recorded together with the counterargument and with the condition under which
  this package should be abandoned in its favour.
- **ADR-002** — passkeys reach `SwiftIdentity` through an adapter product rather than a
  dependency, so a consumer whose clients cannot run a ceremony links none of this.

### Not yet done, and not claimed

The authentication ceremony, the options types both ceremonies need, the `SwiftWebAuthnIdentity`
adapter, fixtures captured from real devices, and the external bar. **Until that suite is run,
this implementation has been checked by one party.**

- Package scaffolded from development-guidelines v2.3.0 — the first project to use the release
  that stopped the scaffolder writing four defects into every new repository.
- `project/plans/proposals/RelyingPartyImplementation.md` — the design: two ceremonies, a CBOR
  subset that fails closed, attestation believed only as far as it can be verified, and an
  existing implementation kept as an external bar rather than a starting point.

The proposal came before the code, and the code came before this entry claimed anything.
