# The external bar

ADR-001 rests on a claim: that this implementation, written from the specification rather than
from anyone else's code, would be run against **`brokenhandsio/swift-webauthn`'s** public work as
an independent check — "deliberately, and not as a dependency of these tests".

This is that check, and its result.

## What it does

Not a port of their tests. Each case builds **one ceremony** and hands the *identical bytes* to
both implementations, then compares accept against accept. A disagreement is a finding in one of
them, and which one is a question the specification answers rather than a vote.

The key material is theirs too — the P-256 pair published in their test suite — so the vectors
are not ours either.

## Why it is not part of this package

Their library is not a dependency of this one and must not become one: the whole point of
ADR-001 is that the two implementations are independent. The harness therefore lives here as
source rather than as a target, kept out of `Sources/` so nothing builds or links it.

`main.swift.txt` and `Package.swift.txt` carry the `.txt` suffix for the same reason — so no
tool mistakes them for part of this package.

## Running it

```sh
git clone --depth 1 https://github.com/brokenhandsio/swift-webauthn.git
mkdir -p external-bar/Sources/external-bar
cp <this directory>/Package.swift.txt   external-bar/Package.swift
cp <this directory>/main.swift.txt      external-bar/Sources/external-bar/main.swift
# point the first `.package(path:)` at this checkout of SwiftWebAuthn
cd external-bar && swift run external-bar
```

## Result, 2026-09-09

Against `brokenhandsio/swift-webauthn` at `2b6b4d4`, Apache-2.0.

```
14 agreements, 2 disagreements
```

Eleven registration cases and five authentication cases. Both implementations accept the valid
ceremony, and both reject: a challenge nobody issued, a look-alike origin, another relying
party's hash, the wrong ceremony type, absent user presence, absent verification when required,
a credential-id length beyond the data, a duplicate CBOR map key, an unverifiable attestation
format, a tampered signature, a signature from an unregistered key, and a counter that went
backwards on a credential that is not backed up.

### Disagreement 1 — trailing bytes after the attestation object

**We reject; they accept.**

Their decoder stops at the end of the first CBOR item and does not object to what follows, so
bytes can be appended to an attestation object and no verification step will look at them. Ours
refuses a payload with anything left over, on the grounds that unexamined attacker-supplied
bytes have no business travelling with a credential.

We believe ours is right, and this is the finding worth reporting upstream.

### Disagreement 2 — a backed-up credential whose counter did not advance

**We accept; they reject** with `potentialReplayAttack`.

**This is a policy difference and both are specification-conformant.** §7.2 says that a counter
which fails to advance "is a signal that the authenticator may be cloned" and that the relying
party **SHOULD apply its own risk policy** — it does not mandate refusal.

Their policy: skip the check when both counters are zero, otherwise demand an increase. Ours:
skip when both are zero *or* when the credential reports itself backed up.

Both handle the ordinary Apple passkey identically — it reports zero from registration onward,
so both take the both-zero path. **They do not refuse iCloud-synced passkeys**, and it would be
wrong to say they do. The two policies diverge only for a credential that once had a non-zero
counter and later reports a lower one while backed up.

Ours is the better-informed policy, because it reads the backup flags rather than inferring from
the counter alone — and the measurement in `Tests/SwiftWebAuthnTests/CapturedCeremonies/` is why
we trust that reading. But it is a policy, not a correctness win, and the record should say so.

## What this does and does not establish

It establishes that on sixteen ceremonies, two independently written verifiers reach the same
verdict fourteen times, and that both exceptions are understood.

It does **not** establish that either implementation is correct. Two implementations can share a
misreading, and a differential test cannot see a step both of them skipped.
