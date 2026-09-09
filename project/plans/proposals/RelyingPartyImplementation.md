# Design Proposal — a WebAuthn relying party, written from the specification

**Status:** **Approved 2026-09-08**, with all four open questions answered — see §10.
**Date:** 2026-09-02
**Consumer:** `SwiftIdentity` — passkeys as a credential kind (`SubjectsAndCredentials.md` §4c)
**Approach decided 2026-09-02:** clean-room, with `brokenhandsio/swift-webauthn` as an external
bar rather than a starting point

---

## 1. Objective

Verify the two WebAuthn ceremonies on the server: **registration**, where an authenticator
produces a key pair and attests to it, and **authentication**, where it signs a challenge with a
key it already holds. Nothing else.

## 2. Motivation

**Passkeys should be the default here, not an alternative.** The target deployment is
Apple-only: every device carries a platform authenticator, iCloud Keychain syncs credentials
between them, and the prompt is a fingerprint rather than a password nobody remembers. `SwiftIdentity` §4c observed
that passkeys would retire the one credential kind that is guessable — which is an argument for
building them early rather than eventually.

**Why not depend on the existing package.** A maintained Swift implementation exists, and taking
it would be the cheaper decision. What is being verified here is a signature that decides who
someone is; reading the specification closely enough to implement it is how anyone earns the
right to say the verification is correct. Their public test suite stays valuable as an
**independent check we must also pass** — a second opinion written by people who solved this
already, which is worth more as an adversary than as a foundation.

Clean-room also settles the licence question before it is asked: no code copied, no tests
copied.

## 3. Scope

**In:** relying-party verification of registration and authentication; challenge issuance and
single-use enforcement; RP ID and origin validation; CBOR decoding of the attestation object;
COSE public key parsing; ES256 and Ed25519 signature verification; signature-counter regression
detection; user-presence and user-verification flags.

**Out, deliberately:** acting as an authenticator; the browser-side JavaScript; enterprise
attestation and certificate-chain validation beyond `none`/self attestation (see §7); RS256
until something needs it; anything resembling a session, which belongs to the consumer.

## 4. Proposed architecture

```
Sources/SwiftWebAuthn/
├── Ceremony/       registration and authentication, the two public entry points
├── Model/          options, credentials, authenticator data, flags
├── Attestation/    the attestation object, its statement formats, and what we accept
├── COSE/           public key parsing, and the algorithms we verify
└── CBOR/           a decoder for the subset an attestation object uses
```

**A CBOR decoder of our own is the one build-versus-buy call inside a clean-room build.** The
attestation object is a small, closed shape: a map of three known keys, a byte string, and a
nested map. A general CBOR library is a dependency and an attack surface disproportionate to
that. A decoder that handles the subset and **refuses everything else** is smaller, auditable,
and fails closed — which is the correct posture for parsing bytes an attacker supplies.

### The verification, stated once

> A ceremony succeeds only if the challenge is one we issued and have not seen used, the origin
> and RP ID hash are ours, the user-presence flag is set, the algorithm is one we chose to
> support, the signature verifies against the stored public key, and the signature counter has
> not gone backwards.

Every clause is a test.

## 5. API surface

```swift
public struct RelyingParty: Sendable {
    public init(id: String, name: String, origins: Set<String>)

    public func registrationOptions(for user: UserEntity, challenge: Challenge) -> PublicKeyCredentialCreationOptions
    public func verifyRegistration(_ response: RegistrationResponse, expecting challenge: Challenge) throws -> RegisteredCredential

    public func authenticationOptions(challenge: Challenge, allowing: [CredentialID]) -> PublicKeyCredentialRequestOptions
    public func verifyAuthentication(_ response: AuthenticationResponse, expecting challenge: Challenge, against credential: RegisteredCredential) throws -> VerifiedAuthentication
}

/// What a consumer stores per credential: never a secret, only a public key.
public struct RegisteredCredential: Sendable, Codable, Equatable {
    public let id: CredentialID
    public let publicKey: COSEPublicKey
    public let signCount: UInt32
    public let isBackedUp: Bool
}

/// The result, including the new counter the consumer must persist.
public struct VerifiedAuthentication: Sendable {
    public let credentialID: CredentialID
    public let newSignCount: UInt32
    public let userVerified: Bool
}
```

**Challenge storage is the consumer's**, deliberately: a challenge must be single-use, and where
that state lives — memory, Redis, a database — is a deployment decision. This package generates
and compares; it does not remember. Stated because getting this wrong is a replay vulnerability,
and hiding it inside a library would make it invisible.

## 6. Test strategy

**Sources of truth, in order of authority:**

1. **The W3C Web Authentication specification**, §7.1 and §7.2, which enumerate the verification
   steps. Each numbered step becomes a named test, so a reader can check coverage against the
   document rather than against our judgement.
2. **Real ceremonies from the deployment's own devices** — Touch ID on a Mac, Face ID on a
   phone — captured as fixtures. The most valuable vectors available, because they are what the
   deployment will actually see.
3. **FIDO Alliance conformance vectors**, where published and usable.
4. **`brokenhandsio/swift-webauthn`'s public suite**, run against this implementation as an
   external check once the API is stable. Not copied, and not a dependency of our tests — a
   second opinion, run deliberately.

**Negative tests are the point, and outnumber the positive ones.** A wrong origin, a replayed
challenge, a challenge never issued, a flipped user-presence bit, an unsupported algorithm, a
signature over different bytes, a counter that went backwards, a truncated attestation object,
CBOR with trailing garbage, a nested map deeper than the shape allows. Each must fail, and each
must fail for the stated reason rather than by accident.

**Reference truth for the crypto:** `swift-crypto`'s own P-256 and Ed25519 vectors — this package
verifies signatures, it does not implement primitives.

## 7. Attestation, and how much of it to believe

Attestation answers "what kind of authenticator made this key". Verifying it fully means
validating certificate chains against the FIDO Metadata Service and keeping that metadata fresh.

**Where nothing needs to distinguish authenticator makes, `none` is the right answer**, and
Apple's platform authenticator uses anonymous attestation regardless. So v1 accepts `none` and self attestation, records the
attestation format it saw, and **refuses formats it cannot verify rather than accepting them
unchecked** — the failure mode being an attestation that is trusted because it was not
understood.

Full `packed`/`tpm`/`apple-appattest` verification is a later phase, and only if something needs
to distinguish authenticator makes.

## 8. Architecture decision review

- [x] New repository; no prior ADRs.
- [x] **ADR-001** recorded on approval: *implemented from the specification, with an existing
  implementation kept as an external conformance bar.* Category: architecture.
- [x] **ADR-002** recorded on approval: *passkeys reach `SwiftIdentity` through an adapter
  product, not a dependency* — the answer to §10.1. Category: architecture.

## 9. Adversarial review

**Strongest case for a different approach.** Depend on `brokenhandsio/swift-webauthn`. It is
maintained, it is used, its bugs have been found by people who are not us, and cryptographic
verification code is the canonical example of what not to write yourself. A reviewer would say
that a small deployment adopting passkeys is *more* reason to use the reviewed implementation,
not less.

That is a serious argument and it is not fully answerable. What tips it: this package verifies
rather than implements — no primitive is written here, `swift-crypto` does the mathematics — and
the parts that are ours are parsing and step-checking, where the specification is explicit and
testable step by step. The risk is real and is mitigated by the external bar in §6.4, which is
the whole reason that bar exists.

**Where this is most likely wrong.** The CBOR decoder. Hand-written parsers of
attacker-controlled bytes are where memory and logic bugs live, and "a small subset" has a way of
growing until it is a general parser written by someone who did not intend to write one. If it
starts accepting shapes to make a real authenticator work, that is the signal to take a
dependency instead.

**What an experienced critic would say.** "You are hand-rolling authentication *and* a binary
parser, in the same package, for a handful of users." The honest reply is that the alternative was
considered, the bar for replacing this with the maintained package is written down in §6.4, and
if the CBOR subset grows the decision gets revisited rather than defended.

## 10. Open questions — all answered 2026-09-08

1. ~~**Does `SwiftIdentity` depend on this, or an adapter between them?**~~ **An adapter, and it
   lives here.** A second library product in this package, `SwiftWebAuthnIdentity`, depends on
   both and declares `PasskeyAssertion: Credential`. `SwiftIdentity` gains no knowledge of
   WebAuthn and no new dependency.

   The alternative that was rejected is worth naming: had `SwiftIdentity` depended on this
   package, a calendar feed would link CBOR and attestation parsing in order to verify a
   capability token. A separate third repository was also rejected — cleanest separation, but a
   third repo, gate and handoff for one type and one function. Recorded as **ADR-002**.

   This is the concrete payoff of §4b(5) in the consumer's proposal, which made `Credential` a
   protocol rather than an enum. If this seam turns out awkward, that decision was wrong, and
   this is where it shows.

2. ~~**RS256?**~~ **No, and refuse it loudly.** Omitted until a device actually requires it.
   An unsupported algorithm is a named error, never a silent failure to verify — the failure
   mode being a ceremony that appears to succeed because nothing checked it.

3. ~~**What is stored when a credential is backed up to iCloud Keychain?**~~ **Both flags are
   recorded, and the counter is only trusted when the credential is not backed up.**

   A synced passkey may never increment its signature counter, so treating a non-incrementing
   counter as an attack would refuse every legitimate iCloud-synced credential — the failure
   mode being a defence that locks out the common case. So: `isBackupEligible` and `isBackedUp`
   are both stored, counter regression is an error only when the credential is not backed up,
   and when it is backed up a static counter is recorded and accepted.

   **This is the one answer here derived from the specification rather than from evidence.** It
   must be checked against a real ceremony from a real device before anything relies on it, and
   §6.2 already calls for those fixtures. Until then it is the best available reading, not a
   verified fact.

4. ~~**Where do challenges live?**~~ **Not here, deliberately.** This package generates a
   challenge and compares one; it never remembers. Single-use enforcement is a deployment
   decision, and a library that hid it would make a replay vulnerability invisible.

   The consequence is stated rather than buried: a consumer that does not enforce single use has
   a replay vulnerability and this package cannot detect it. `SwiftIdentity` needs an answer
   before a web UI does, and that answer belongs in `SwiftIdentity`.

## 11. Documentation strategy

**Narrative article required.** The two ceremonies need explaining to anyone integrating this,
and the verification steps need to be traceable to the specification section they come from —
that traceability is what makes the clean-room claim checkable rather than asserted.
