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

- **Ceremonies captured from a real Apple platform authenticator**, and verified end to end.
  AAGUID `fbfc3007-154e-4ecc-8c0b-6e020557d7bd`, backup flags set, **signature counter 0 at
  registration and 0 again at authentication** — which settles §10.3 as a measurement rather
  than a reading of the specification, and confirms that refusing a static counter would have
  locked out the ordinary case on Apple hardware.

  These are the only tests here whose inputs this package did not produce.

- **`webauthn-capture`** — a development tool for capturing ceremonies from real authenticators,
  as an executable target with **no product**, so nothing can depend on it. It generates its
  options through `RelyingParty` and verifies each ceremony before writing it, so a fixture that
  does not verify is caught at capture time rather than committed as evidence.

- **`AuthenticatorAttachment`**, so a relying party can insist on the built-in sensor rather than
  being offered a phone. Unset by default, because a party that does not care must not
  accidentally exclude a security key. Found by using the options for real: the capture tool
  needed it and the library had no way to say it.

### Decided

- **Proposal approved 2026-09-08**, with all four open questions answered in §10.
- **ADR-001** — written from the specification, with `brokenhandsio/swift-webauthn` kept as an
  external bar, recorded together with the counterargument and with the condition under which
  this package should be abandoned in its favour.
- **ADR-002** — passkeys reach `SwiftIdentity` through an adapter product rather than a
  dependency, so a consumer whose clients cannot run a ceremony links none of this.

- **The external bar was run** (2026-09-09), discharging ADR-001's outstanding claim: 34
  ceremonies, the identical bytes handed to this implementation and to
  `brokenhandsio/swift-webauthn`. **28 agreements, 6 disagreements**, every one understood and
  written up in `project/external-bar/`. Two further oracles were then added —
  `@simplewebauthn/server` 14.0.1 and `py_webauthn` 3.0.0 — judging the identical corpus:
  **24 of 29 cases unanimous across four implementations in three languages**, including every
  security-critical case and all ten signature-counter cases.

  The five splits are all CBOR strictness. On **trailing bytes we are alone, 0 of 3** — the
  strictness stays, because it costs no interop and refuses bytes nothing examines, but the
  earlier claim that this was a defect in the other implementation is withdrawn. On non-canonical
  lengths and indefinite-length maps the field splits evenly, with SimpleWebAuthn strict too.

### Changed

- **`SignatureCounterPolicy`, and a default that reverses a guess.** This package used to accept
  a stalled signature counter whenever the credential reported itself backed up, citing the
  real-device capture as evidence. The external bar showed the capture does not reach that
  branch — an Apple passkey reports zero throughout, so the both-zero carve-out fires first and
  a second implementation with no backup rule accepts the same ceremonies.

  The rule had no evidence, and it weakened cloning detection precisely where the signal might
  still mean something: an authenticator reporting a non-zero counter is one that keeps a
  counter. §7.2 says a relying party SHOULD apply its own risk policy, so this package stopped
  deciding — `refuseWhenStalled` (the new default), `allowWhenBackedUp` (the old behaviour, for
  a deployment that has met such an authenticator), or `report`.

  `VerifiedAuthentication.counterStalled` carries the signal under every policy, so it is never
  lost.

- Removed the scaffold's `public enum SwiftWebAuthn {}`, which shadowed the module name and made
  `SwiftWebAuthn.RelyingParty` fail to resolve for any consumer that needed to disambiguate.
  Found by the external bar, which had to import both packages and could not name ours.

### Still not claimed

Two implementations can share a misreading, and a differential test cannot see a step both of
them skipped. Only the zero signature-counter path has met real hardware.

- Package scaffolded from development-guidelines v2.3.0 — the first project to use the release
  that stopped the scaffolder writing four defects into every new repository.
- `project/plans/proposals/RelyingPartyImplementation.md` — the design: two ceremonies, a CBOR
  subset that fails closed, attestation believed only as far as it can be verified, and an
  existing implementation kept as an external bar rather than a starting point.

The proposal came before the code, and the code came before this entry claimed anything.
