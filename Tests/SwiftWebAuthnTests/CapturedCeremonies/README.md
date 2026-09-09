# Captured ceremonies

Real WebAuthn ceremonies, captured 2026-09-08 from this project's development Mac using the
**Apple platform authenticator** (Touch ID, passkey synced to iCloud Keychain), through Safari
against `http://localhost:8099`.

`§6.2` of the design proposal calls these the most valuable vectors available, because they are
what the deployment will actually see. Everything else in the test suite is synthesised by this
package and therefore agrees with this package by construction.

## Nothing here is secret

An attestation object carries a **public** key; the private half never left the Secure Enclave.
The credential identifier is random, the user handle is the literal string `capture-user`, and
the relying party is `localhost`. There is nothing to leak and nothing to rotate.

## What they established

The authenticator reports **AAGUID `fbfc3007-154e-4ecc-8c0b-6e020557d7bd`** — Apple's iCloud
Keychain passkey — and:

| | Registration | Authentication |
|---|---|---|
| Backup eligible (BE) | set | set |
| Backed up (BS) | set | set |
| Signature counter | 0 | 0 |

**The counter does not move**, and both counters are therefore zero at every step.

**Be careful what this proves.** It proves the *both-zero* case: an authenticator that keeps no
counter must not be treated as having stalled, or the ordinary Apple credential is refused at its
first login. That is a real and load-bearing measurement.

It does **not** prove the rule this package originally built on top of it — that a stalled
counter is acceptable whenever a credential is backed up. These ceremonies never reach that
branch, because both counters are zero and the both-zero carve-out fires first. The external bar
(`project/external-bar/`) demonstrated exactly that by replaying these files through a second
implementation, which accepts them too despite having no backup rule at all.

The backup rule has since been withdrawn as a default. See ``SignatureCounterPolicy``.

## Regenerating

```sh
swift run webauthn-capture --output Tests/SwiftWebAuthnTests/CapturedCeremonies
```

Then open <http://localhost:8099> and run both steps. The tool is `Sources/webauthn-capture` — an
executable target with **no product**, so nothing can depend on it.

It generates its options through `RelyingParty.registrationOptions` and **verifies each ceremony
before writing it**, which is the reason it is Swift rather than a script: a hand-written options
blob could capture a ceremony this package never actually asked for, and could agree with the
browser while disagreeing with the library. A fixture that does not verify is a bug report, and
it should be recognised as one at capture time rather than committed as evidence.

The bytes are recorded exactly as the browser produced them. Every signature covers those bytes,
so re-encoding them would change what is being verified.

## What is still missing

**An authenticator whose counter actually increments** — a hardware security key, or Windows
Hello. Every counter path in `checkCounter` is unit-tested, but only the zero path has met real
hardware. Pass `attachment: .crossPlatform` to steer a ceremony at a roaming authenticator if one
is to hand.
