# SwiftWebAuthn Master Plan

> **ACTION REQUIRED:** Replace all `[PLACEHOLDER]` sections below with your
> project's actual content. This file is the source of truth for project vision,
> architecture, and goals. Do not start implementation until it is filled in.

**Purpose:** Source of truth for project vision, architecture, and goals.

---

## Project Overview

### Mission

Verify WebAuthn's two ceremonies on the server, written from the W3C specification, so that
passkeys can be the default way a person proves who they are rather than an alternative to a
password.

### Target Users
- **`SwiftIdentity`**, as the credential kind that retires the passphrase — the only kind a
  person could plausibly guess.
- **Any Swift service authenticating people on Apple devices**, where a platform authenticator
  and iCloud Keychain make passkeys the path of least resistance rather than the ambitious one.

### Key Differentiators
- **Written from the specification**, with a maintained implementation kept as an external bar
  rather than a starting point. No code copied, no tests copied, no licence question.
- **No primitive is implemented here.** `swift-crypto` does the mathematics; this parses and
  checks the specification's steps in order.
- **A CBOR decoder for the subset an attestation object uses, which refuses everything else.**
  Failing closed on attacker-supplied bytes is the point.
- **A written bar for its own abandonment.** The proposal states the condition under which this
  package should be replaced by the maintained one.

---

## Architecture

### Technology Stack
- **Language:** Swift 6.2 tools version, targeting macOS 14
- **Build System:** Swift Package Manager
- **Testing:** Swift Testing framework
- **Concurrency:** Swift 6 strict concurrency throughout
- **`swift-crypto`** — every primitive. P-256 and Ed25519 verification, SHA-256. Nothing
  cryptographic is implemented in this package.
- **`swift-docc-plugin`** — the documentation catalogue the gate requires.

No CBOR dependency, deliberately: see Key Differentiators.

### Module Structure

```
Sources/SwiftWebAuthn/
├── CBOR/        the subset an attestation object uses, and its refusals
├── COSE/        public key parsing, and the algorithms verified
├── Model/       authenticator data — the one structure that is not CBOR
└── Ceremony/    registration, client data, challenges, base64url
```

Planned and not yet present: `Attestation/` as a directory of its own, once more than `none`
and self attestation are understood; and a second library product, `SwiftWebAuthnIdentity`,
carrying the `SwiftIdentity` adapter (ADR-002).

### Key Types

| Type | Purpose |
|------|---------|
| `CBOR` | The decoded subset, and `Failure` — mostly a list of what is refused |
| `COSEPublicKey` | A registered public key, stored in the form its verifier takes |
| `AuthenticatorData` | The fixed-layout structure an authenticator signs over |
| `AttestationObject` | `fmt`, `attStmt`, `authData`, plus the raw bytes a signature covers |
| `CollectedClientData` | What the browser says the ceremony was, and the bytes it said it in |
| `Challenge` | A nonce this package generates and compares but never stores |
| `RelyingParty` | The verifier: one party, and the ceremonies it will accept |
| `RegisteredCredential` | What a consumer persists — never a secret, only a public key |
| `Base64URL` | The encoding every WebAuthn field arrives in |

### Data Flow

```
Registration
  clientDataJSON ─┬─► CollectedClientData ─► type, challenge, origin checked
                  └─► SHA-256 ──────────────┐
  attestationObject ─► AttestationObject ─► AuthenticatorData ─► COSEPublicKey
                          │                      │                    │
                          └── attStmt ───────────┴── signature ───────┘
                                                          │
                                                    RegisteredCredential
```

The raw bytes travel alongside the parsed forms throughout, because signatures are computed over
bytes and re-encoding a parsed structure produces different ones.

---

## Core Architectural Decisions

1. **Written from the specification**, with `brokenhandsio/swift-webauthn` kept as an external
   bar rather than a starting point. Recorded with its counterargument intact as **ADR-001**,
   including the condition under which this package should be abandoned for that one.
2. **Passkeys reach `SwiftIdentity` through an adapter product**, `SwiftWebAuthnIdentity`, not
   through a dependency — so a consumer whose clients cannot run a ceremony links none of this.
   **ADR-002**, and the answer to the proposal's §10.1.
3. **A CBOR decoder for the subset, refusing everything else.** Non-canonical integers,
   duplicate keys, tags, floats, indefinite lengths and trailing bytes are all refused, each
   because it is a difference an attacker can choose and a verifier would not see.
4. **Attestation is believed only as far as it can be verified.** `none` and self attestation;
   every other format refused by name. An attestation trusted because it was not understood is
   worse than none.
5. **Challenge storage and the randomness source are both the consumer's.** This package
   generates and compares; it never remembers, and it does not silently choose a generator. A
   security decision hidden inside a library is invisible.
6. **RS256 is refused loudly** rather than omitted quietly, so an unsupported algorithm can
   never read as a ceremony that succeeded.

---

## Current Status

### What's Working
- [x] SwiftWebAuthn
- [x] Proposal approved 2026-09-08, all four open questions answered
- [x] ADR-001 and ADR-002 recorded
- [x] **CBOR subset decoder** — 22 tests, the refusals outnumbering the shapes
- [x] **COSE public key parsing** — ES256 and EdDSA, keys constructed rather than measured,
      RS256 refused by name
- [x] **Authenticator data** — fixed layout, flags, big-endian counter, attested credential
      whose public key carries no length
- [x] **Base64URL and collected client data**, keeping the bytes a signature was made over
- [x] **`Challenge`**, generated from an injected generator
- [x] **The registration ceremony**, every clause of §7.1 a named error and a named test,
      including a self-attestation signature verified for real
- [x] **The authentication ceremony** (§7.2), and the signature counter gated on the backup flags
- [x] **Both option sets**, with the offered algorithms derived from what the verifier accepts
- [x] SwiftWebAuthnIdentity — the adapter product, which **passes SwiftIdentity's conformance
      suite**: 7 met, 0 failed, 0 inconclusive, 4 honestly declined
- [x] webauthn-capture — a development tool that captures **and verifies** a ceremony from real
      hardware. A target with no product, so nothing can depend on it

### What's Next
- [x] **Ceremonies captured from real devices**, which §6.2 calls the most valuable vectors
      available — and which are the only tests here not produced by this package's own code
- [ ] **The external bar** — `brokenhandsio/swift-webauthn`'s public suite, run against this
      implementation once the API is stable. Until it is run, this package has been checked by
      one party

---

## Quality Standards

### Code Quality
- All code follows `coding_rules.md`
- TDD: failing tests before implementation
- Documentation for all public APIs
- No warnings in build output
- Quality gate: 0 errors, 0 warnings before every commit

### Documentation Quality
- DocC comments for all public functions
- Usage examples in documentation
- Articles for complex topics

---

## Collaboration Principles

### AI as Sparring Partner, Not Oracle

AI proposes; the human interrogates. High AI confidence triggers harder questions, not faster acceptance.

- **Interrogate confident outputs.** When the AI states something with certainty, ask for the counterargument before accepting.
- **Demand counterarguments.** Before locking in an approach, require an explicit case for the strongest alternative.
- **Sit with discomfort.** Resist the pull to take the first plausible answer.

This principle is operationalized in the **Adversarial Review** step of `design_proposal.md`.

---

## Roadmap

### Phase 1: Registration — **complete**
- [x] CBOR subset, COSE keys, authenticator data, client data, challenges
- [x] `verifyRegistration`, with `none` and self attestation

### Phase 2: Authentication — **complete**
- [x] `verifyAuthentication` (§7.2)
- [x] Signature-counter regression, gated on the backup flags
- [x] Options types for both ceremonies

### Phase 3: Integration and evidence
- [x] `SwiftWebAuthnIdentity` adapter product, passing SwiftIdentity's conformance suite
- [x] **Real-device fixtures** — captured 2026-09-08 from Apple's platform authenticator, and
      they settle §10.3: BE and BS set, counter 0 across both ceremonies
- [ ] **The external bar run deliberately** — until it is, this package has been checked by one
      party

### Future
- Full `packed` / `tpm` / `apple-appattest` attestation, **only** if something needs to
  distinguish authenticator makes. Requires the FIDO Metadata Service and keeping it fresh.
- RS256, only if a device requires it.

---

**Last Updated:** 2026-09-08 — real ceremonies captured from an Apple platform authenticator,
settling the §10.3 counter rule as a measurement rather than a reading; Phase 2 (authentication,
options) and the adapter product added;
proposal approved and §10 answered; ADR-001 and ADR-002 recorded;
Phase 1 (registration) implemented and reconciled here. Scaffold placeholders in Technology
Stack, Module Structure, Key Types, Data Flow, Core Architectural Decisions, Current Status and
Roadmap were replaced with what is actually true, having survived from the 2026-09-02 scaffold.
