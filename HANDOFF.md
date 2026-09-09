# HANDOFF

**Active feature:** none in flight. Phases 1–3 of the roadmap are done: both ceremonies, both
option sets, and the `SwiftIdentity` adapter. What remains is **evidence**, not code.

**Last updated:** 2026-09-08
**Branch:** `main`, clean, pushed to `github.com/jpurnell/SwiftWebAuthn` (**private**). No tags.
**State:** **97 tests** across two test targets, `quality-gate --no-cache` **0 errors, 0
warnings, 45 of 45 checkers**, documentation coverage 100%.
**Depends on:** `SwiftIdentity` **0.1.0** (private), consumed only by the adapter product.

## What this package is

The **server's half** of WebAuthn, written from the W3C specification: verifying both ceremonies
and vending the options that start them. It is not an authenticator and does not touch the
browser side.

Its consumer is `SwiftIdentity`, where passkeys replace the *passphrase* — never the capability
token, because a shared speaker and a calendar client cannot run a ceremony at all.

## How to recover

Run **`/recover SwiftWebAuthn`**.

1. **This file.**
2. **`project/master_plan.md`** — Current Status and Roadmap, reconciled 2026-09-08.
3. **`project/plans/proposals/RelyingPartyImplementation.md`** — **approved 2026-09-08**, with
   §10's four questions answered. §4 architecture, §6 test strategy, §7 attestation, §9
   adversarial review.
4. **`project/decisions/ARCHITECTURE_DECISIONS.md`** — ADR-001 and ADR-002. **Grep `^id: ADR`**,
   not for headings: this log is YAML inside fences.

```sh
git log --oneline -8 && git status -sb
swift test 2>&1 | tail -2        # 67 tests as of 2026-09-08
quality-gate --no-cache          # never trust a cached green
```

## Done

| | |
|---|---|
| `CBOR` | The subset, and its refusals. Offsets on every failure |
| `COSEPublicKey` | ES256 and EdDSA; RS256 refused by name; keys **constructed**, not measured |
| `AuthenticatorData` | Fixed layout, flags, big-endian counter, unprefixed embedded key |
| `Base64URL`, `CollectedClientData` | Raw bytes kept, because signatures cover bytes |
| `Challenge` | Generated from an **injected** generator |
| `RelyingParty.verifyRegistration` | Every clause of §7.1, `none` and self attestation |
| `RelyingParty.verifyAuthentication` | Every clause of §7.2, and the counter rule |
| Both option sets | Algorithms **derived** from what the verifier accepts, never restated |
| `SwiftWebAuthnIdentity` | The adapter (ADR-002). Passes SwiftIdentity's conformance suite |

## The exact next step

**Capture a real ceremony from a real device and turn it into a fixture.** Touch ID on a Mac,
Face ID on a phone. Everything below depends on it, and no more code will make it true.

It settles the §10.3 counter rule (weakness 1), gives §6.2 the vectors it calls the most
valuable available, and is the prerequisite for running the external bar meaningfully.

The code is otherwise done. **Resist adding more of it** — the next real increment is evidence.

## Where this is weakest, in order

1. **The backup-flag rule is a reading, not a measurement.** §10.3 decided that counter
   regression is an error *only* when a credential is not backed up, because a passkey synced
   through iCloud Keychain may never increment its counter. That comes from the specification.
   **It has never been checked against a real device**, and it is now shipped code —
   `checkCounter` in `RelyingParty`, marked `- Important:` at the site. If the reading is wrong,
   this package either locks out synced passkeys or fails to notice a cloned authenticator, and
   there is currently no test that could tell you which.

2. **The external bar has not been run.** ADR-001 rests on it:
   `brokenhandsio/swift-webauthn`'s public suite, run against this implementation once the API
   is stable, deliberately and not as a test dependency. **Until it is run, this package has
   been checked by one party** — which is exactly the risk the adversarial review named.

3. **The CBOR decoder is the most likely thing here to be wrong**, and the proposal says so.
   Watch its size: **if the subset starts growing to make a real authenticator work, take the
   maintained dependency instead.** That bar was written before any code existed so it would be
   a check rather than a defence of effort already spent. Honour it.

## Conventions worth knowing before editing

- **Raw bytes travel with parsed forms.** Every signature covers bytes, and re-encoding a parsed
  structure produces different ones. `AttestationObject.rawAuthenticatorData` and
  `CollectedClientData.raw` exist for this and must not be reconstructed.
- **`CBOR.decode` refuses trailing bytes; `CBOR.decodePrefix` is the single exception**, and
  exists only because a credential's public key sits inside authenticator data with no length.
- **Fixtures build real material** — genuine P-256 and Ed25519 keys taken apart and reassembled
  in the wire format under test. A hand-invented blob of the right length parses perfectly and
  proves nothing. Signatures in tests are produced by actually signing.
- **A parse failure and a verification failure raise the same error** where an attacker could
  otherwise learn which half of a guess was closer.

## Open

- **`.quality-gate.yml` names the judgement corpus** and says why in the file: deleting the block
  would not fail the consistency checker, it would make it *skip*. Path is relative. Revisit if
  this package is ever made public.
- **No tag.** Nothing is released. The ceremonies exist now, so the bar has moved: **do not tag
  until a real ceremony has been verified end to end**, because a version number is a claim that
  this works against a device and nothing here has met one.
