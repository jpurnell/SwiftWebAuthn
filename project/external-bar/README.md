# The external bar

ADR-001 rests on a claim: that this implementation, written from the specification rather than
from anyone else's code, would be run against **`brokenhandsio/swift-webauthn`'s** public work as
an independent check — "deliberately, and not as a dependency of these tests".

This is that check, its result, and the two things it changed here.

## What it does

Not a port of their tests. Each case builds **one ceremony** and hands the *identical bytes* to
both implementations, then compares accept against accept. A disagreement is a finding in one of
them, and which one is a question the specification answers rather than a vote.

The key material is theirs too — the P-256 pair published in their test suite — so the vectors
are not ours either. The last two cases replay the **real captured Apple ceremonies** through
both.

## Why it is not part of this package

Their library is not a dependency of this one and must not become one: the whole point of
ADR-001 is that the two implementations are independent. The harness therefore lives here as
source rather than as a target, kept out of `Sources/` so nothing builds or links it, and the
files carry a `.txt` suffix so no tool mistakes them for part of this package.

## Running it

```sh
git clone --depth 1 https://github.com/brokenhandsio/swift-webauthn.git
mkdir -p external-bar/Sources/external-bar
cp <this directory>/Package.swift.txt   external-bar/Package.swift
cp <this directory>/main.swift.txt      external-bar/Sources/external-bar/main.swift
# point the first `.package(path:)` at this checkout, and `capturedDirectory` at its fixtures
cd external-bar && swift run external-bar
```

## Result

Against `brokenhandsio/swift-webauthn` at `2b6b4d4`, Apache-2.0.

| | First run, 2026-09-09 | After the change below |
|---|---|---|
| Agreements | 24 | **28** |
| Disagreements | 10 | **6** |

The six that remain are all one thing: **their CBOR decoder is lax and ours is strict.**

## The counter policy: we were wrong, and the bar is how we found out

The first run disagreed on a backed-up credential whose counter did not advance — we accepted,
they refused. The write-up said our real-device capture settled it.

**It did not.** Replaying the captured Apple ceremonies through both implementations shows *both
accept them*, because an Apple passkey reports zero from registration onward and both
implementations skip the check when both counters are zero. The capture exercises that carve-out
and never reaches the disputed branch. It is an Apple-shaped oracle, and the disputed case is not
Apple-shaped.

So the rule "a stalled counter is fine when the credential is backed up" had **no evidence behind
it at all**, and it weakened cloning detection in exactly the case where the signal might still
mean something: an authenticator reporting a non-zero counter is one that *keeps* a counter.

§7.2 says a stalled counter is "a signal that the authenticator may be cloned" and that the
relying party **SHOULD apply its own risk policy**. It does not say to refuse, and it does not
say to accept. So this package stopped deciding:

- ``SignatureCounterPolicy/refuseWhenStalled`` — the default now, and what they do.
- ``SignatureCounterPolicy/allowWhenBackedUp`` — the old behaviour, for a deployment that has
  actually met an authenticator which both syncs and counts.
- ``SignatureCounterPolicy/report`` — never refuse; read `counterStalled` off the result.

`VerifiedAuthentication.counterStalled` is reported under every policy, so the signal is never
lost. Ten counter cases now agree with them, ten out of ten.

## What remains: their CBOR is lax

All six surviving disagreements are registration payloads that we refuse and they accept:

| Payload | Ours | Theirs |
|---|---|---|
| One trailing zero byte | reject | accept |
| A second complete CBOR item appended | reject | accept |
| 1024 bytes of padding appended | reject | accept |
| A non-canonical string length | reject | accept |
| An indefinite-length map | reject | accept |
| Trailing bytes after the attestation object | reject | accept |

An unknown *fourth key inside* the map is accepted by both, which is correct — that is forward
compatibility, not malleability.

WebAuthn requires the attestation object in **CTAP2 canonical CBOR encoding form**, which is
definite-length and shortest-form by definition. Every row above violates it. The sharpest is the
second: a complete second CBOR item can ride along inside an attestation object, and two parsers
looking at the same payload can legitimately disagree about what it contains. That is the parser
-differential class, and it is worth reporting upstream.

## What this establishes, and what it does not

It establishes that on thirty-four ceremonies two independently written verifiers now reach the
same verdict twenty-eight times, that every remaining difference is understood, and that one of
our rules was a guess we have since withdrawn.

It does **not** establish that either implementation is correct. Two implementations can share a
misreading, and a differential test cannot see a step both of them skipped.
