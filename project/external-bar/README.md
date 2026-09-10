# The external bar

ADR-001 rests on a claim: that this implementation, written from the specification rather than
from anyone else's code, would be checked against independent work — "deliberately, and not as a
dependency of these tests".

This is that check. It now runs against **three** other implementations, in three languages, and
it has corrected this package twice.

## How it works

One corpus, four verdicts. The Swift harness builds 29 ceremonies, judges them with this package
and with `brokenhandsio/swift-webauthn`, and writes `corpus.json` — every payload as base64url,
plus the stored counter and backup state each case assumes. Two scripts then read that same file
and judge the identical bytes.

A disagreement is a finding in *someone*, and which one is a question the specification answers
rather than a vote. But a 0/3 minority is worth noticing before insisting.

| Implementation | Language | Version |
|---|---|---|
| **SwiftWebAuthn** | Swift | this package |
| `brokenhandsio/swift-webauthn` | Swift | `2b6b4d4`, Apache-2.0 |
| `@simplewebauthn/server` | TypeScript | 14.0.1 |
| `py_webauthn` (Duo) | Python | 3.0.0 |

The key material is `brokenhandsio`'s published P-256 test pair, so even the vectors are not ours.

**Every run starts with a positive control.** Each implementation must accept the valid
registration and the valid assertion, or its column means nothing — an implementation that
refuses everything agrees with every negative case for free. Both Node and Python harnesses
initially scored 0 accepts because of bugs in the harness, not findings; the control is what
caught it.

## Result, 2026-09-09

**25 of 32 unanimous across all four.** Every security-critical case is unanimous: the challenge,
the origin, the relying party hash, the ceremony type, user presence, user verification, the
signature, an unverifiable attestation format, a duplicate CBOR map key, and all ten
signature-counter cases.

The seven splits are all one topic — how strict a CBOR decoder should be, and the section below
argues that the right answer is not the same in both ceremonies:

| Payload | Ours | brokenhands | SimpleWebAuthn | py_webauthn | With us |
|---|---|---|---|---|---|
| One trailing zero byte | reject | accept | accept | accept | **0/3** |
| A second complete CBOR item appended | reject | accept | accept | accept | **0/3** |
| 1024 bytes of padding appended | reject | accept | accept | accept | **0/3** |
| A non-canonical string length | reject | accept | reject | accept | 1/3 |
| An indefinite-length map | reject | accept | reject | accept | 1/3 |
| An unknown fourth key *inside* the map | accept | accept | accept | accept | unanimous |
| An assertion with non-canonical extension output | accept | accept | reject | reject | 1/3 |
| An assertion with bytes after the extensions | accept | accept | reject | reject | 1/3 |

That last row is the control for this section: a map with an extra key is forward compatibility,
not malleability, and all four accept it.

## Is the strictness a posture, correctness, or aggression?

Not one answer — three, and they differ by **what is signed** and **how often the failure
repeats**. That turns out to be the whole of it.

### Tier 1 · Trailing bytes on the attestation object — *posture* (0/3 with us)

For `none` attestation **nothing in the attestation object is signed**. The object is
trusted-on-first-use and TLS is the only thing protecting it, so an attacker who can append
bytes can equally replace the entire public key — a strictly stronger attack that trailing bytes
add nothing to.

So refusing them protects against no attack the alternative doesn't already permit. What it
does buy is hygiene: nothing unexamined is stored alongside a credential, and no second component
reading the payload can disagree with us about what it contains.

**Loosening here would be low-risk.** We stay strict because it costs nothing — the failure is
one-time, at enrolment, and visible — but this is posture rather than protection, and it should
not be described as their defect.

### Tier 2 · Non-canonical lengths and indefinite-length maps — *correctness* (1/3 with us)

CTAP2 canonical CBOR encoding form is definite-length and shortest-form by definition, so a
conforming authenticator never emits either of these. Accepting them means accepting encodings no
conforming device produces.

There is a second, self-interested reason: indefinite-length decoding is extra state machine in
**our** parser, and ADR-001 names that parser as the most likely thing here to be wrong. Refusing
a shape means never having to be right about it.

**This is the best-justified strictness of the three**, and here we are not alone.

### Tier 3 · Extension output — *this was aggression, and it is fixed*

Extension output is the last field in authenticator data, and this package **reads no
extension**. It was decoded for exactly one reason: to find where it ended. That end is the end
of the buffer.

Meanwhile, on an assertion the extension bytes sit **inside the region the authenticator
signed**. An attacker cannot put them there without breaking the signature. So refusing a
ceremony because those bytes would not decode protected against nothing — and it cost a
**login**, every single time, for as long as the authenticator kept sending them.

Extension output is now carried verbatim as `AuthenticatorData.extensionOutput` and never parsed.
A consumer that actually uses an extension can decode the bytes itself, and gets them exactly as
they arrived — which is more faithful than parse-and-re-encode, the approach py_webauthn takes,
where a non-canonical input is stored back in canonical form and is no longer the bytes that were
signed.

### The rule that falls out

**Strictness is cheap where the data is unauthenticated and the failure is one-time. It is
expensive where a signature already excludes the attacker and the failure repeats.** Registration
is the first; login is the second. A uniform posture gets one of them wrong, and ours got the
second one wrong until this was measured.

## What the extra oracles changed

### The signature counter — we were wrong, and this is how we found out

The first run of the bar disagreed with `brokenhands` on a backed-up credential whose counter did
not advance: we accepted, they refused, and the write-up cited our real-device capture as
evidence. Replaying the captured Apple ceremonies through both showed **both accept them** — an
Apple passkey reports zero throughout, so both take the both-zero carve-out and neither reaches
the disputed branch. It was an Apple-shaped oracle, and the disputed case is not Apple-shaped.

The rule became ``SignatureCounterPolicy``, defaulting to refusal. **All four implementations now
agree on all ten counter cases.**

### Trailing bytes — we are alone, and the earlier write-up overstated it

The previous version of this file said the trailing-bytes laxity was "the finding worth reporting
upstream" and "theirs to fix". With three independent implementations all accepting it, that was
overconfident and is withdrawn.

We still reject, and the reason stands on its own: an attestation object carrying bytes that no
verification step examines is attacker-controlled data riding along inside a credential, and two
parsers reading one payload can disagree about what it contains. But **being stricter than the
field is not the same as the field being wrong**, and this file should not have implied it was.

There is no interop cost — no browser appends bytes — so the strictness stays.

### Canonical CBOR — a genuine 2–2 split

Non-canonical string lengths and indefinite-length maps are refused by us and by SimpleWebAuthn,
accepted by the other two. CTAP2 canonical CBOR encoding form is definite-length and shortest-form
by definition, so we think the strict reading is right, and here we are not alone.

## Running it

```sh
git clone --depth 1 https://github.com/brokenhandsio/swift-webauthn.git
mkdir -p external-bar/Sources/external-bar
cp <this directory>/Package.swift.txt external-bar/Package.swift
cp <this directory>/main.swift.txt    external-bar/Sources/external-bar/main.swift
# point the first `.package(path:)` at this checkout
(cd external-bar && swift run external-bar)          # writes corpus.json

mkdir -p oracles/node && cd oracles/node
npm init -y && npm install @simplewebauthn/server
cp <this directory>/verify-simplewebauthn.mjs.txt verify.mjs
node verify.mjs ../../external-bar/corpus.json && cd ../..

mkdir -p oracles/python && cd oracles/python
python3 -m venv .venv && ./.venv/bin/pip install webauthn
cp <this directory>/verify-py_webauthn.py.txt verify.py
./.venv/bin/python verify.py ../../external-bar/corpus.json && cd ../..

cp <this directory>/compare.py.txt compare.py && python3 compare.py
```

## Why none of this is a dependency

The other three must not become dependencies of this package: the whole point of ADR-001 is that
the implementations are independent, and a shared dependency is a shared misreading waiting to
happen. The harnesses live here as source, outside `Sources/`, suffixed `.txt` so no tool
mistakes them for part of this package.

## What this establishes, and what it does not

Twenty-four unanimous verdicts across four independently written verifiers in three languages is
meaningful evidence, and it is a great deal more than one implementation agreeing with itself.

It still does **not** establish correctness. All four read the same specification, and a
differential test cannot see a step that every implementation skipped. What it does establish is
where this package is unusual — and on the two occasions it found us unusual, once we were wrong
and once we were merely alone.
