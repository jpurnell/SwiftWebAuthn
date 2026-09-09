# HANDOFF

**Active feature:** none. **Nothing is implemented.** The package is a scaffold plus a design
proposal that is **awaiting approval**, with four open questions unanswered.

**Last updated:** 2026-09-08
**Branch:** `main`, clean, pushed to `github.com/jpurnell/SwiftWebAuthn` (**private**). No tags.
**State:** 1 placeholder test, `quality-gate --no-cache` **0 errors, 0 warnings, 45 of 45
checkers**, documentation coverage 100% — of one public API, which is `public enum SwiftWebAuthn {}`.

**Do not mistake a green gate for progress here.** Everything passes because there is nothing to
fail. The gate figure is in this file only so a later reader knows the scaffold was sound, not
because any WebAuthn behaviour has been verified.

## What this package is meant to be

The **server's half** of WebAuthn: verifying the registration ceremony (an authenticator makes a
key pair and attests to it) and the authentication ceremony (it signs a challenge with a key it
already holds). Nothing else — it is not an authenticator, and it does not touch the browser
side.

Its declared consumer is **`SwiftIdentity`**, where passkeys are Phase 3 and would replace the
*passphrase* — never the capability token, because a shared speaker and a calendar client cannot
run a WebAuthn ceremony. That constraint is permanent and is why `SwiftIdentity` exists in the
shape it does.

## How to recover

Run **`/recover SwiftWebAuthn`**.

1. **This file.**
2. **`project/plans/proposals/RelyingPartyImplementation.md`** — the whole design. §4 is the
   architecture, §6 the test strategy, §7 how much attestation to believe, §9 the adversarial
   review, **§10 the four open questions that block approval**.
3. **`project/master_plan.md`** — roadmap.

```sh
git log --oneline -5 && git status -sb
swift test 2>&1 | tail -2        # 1 placeholder test
quality-gate --no-cache
```

## The four questions that block starting

From §10, none of them answered:

1. **Does `SwiftIdentity` depend on this, or is there an adapter between them?** The proposal
   recommends an **adapter**, so a deployment that never uses passkeys does not link a WebAuthn
   implementation. This is the one that decides package topology, and it should be settled before
   any code exists.
2. **RS256?** Windows Hello has historically needed it. Recommendation: omit, and refuse the
   algorithm loudly rather than silently.
3. **What does a backed-up credential do to the sign counter?** Passkeys synced through iCloud
   Keychain may not increment it at all, which makes counter-regression detection weaker than §4
   implies. This needs an answer from a real ceremony, not from the specification.
4. **Where do challenges live?** §5 leaves single-use enforcement to the consumer deliberately.
   `SwiftIdentity` needs an answer before a web UI does.

## Decisions already taken, so they are not relitigated

- **Clean-room from the W3C specification**, with `brokenhandsio/swift-webauthn` as an **external
  bar** rather than a starting point — its public suite is to be run against this implementation
  once the API is stable. No code copied, no tests copied.
- **No cryptographic primitive is written here.** `swift-crypto` does the mathematics; this
  package parses bytes and checks the specification's steps in order.
- **A CBOR decoder for the subset an attestation object uses**, refusing everything else. The
  proposal names this as the most likely place for the design to be wrong.
- **Attestation is believed only as far as it can be verified** — `none` and self attestation
  accepted, format recorded, anything unverifiable refused rather than trusted.

## The abandonment condition, written before any code exists

**If the CBOR subset starts growing to make real authenticators work, take the dependency
instead.** That was recorded deliberately at scaffold time so the decision is a check against a
stated bar rather than a defence of sunk effort. Honour it.

## Open

- **`.quality-gate.yml` names the judgement corpus** and says why in the file: deleting the block
  would not fail the consistency checker, it would make it *skip*. Path is relative. Revisit if
  this package is ever made public.
- **No ADR yet.** One is due on approval: *implemented from the specification, with an existing
  implementation kept as an external conformance bar.*
