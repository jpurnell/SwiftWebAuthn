# Architecture Decisions Log

**Purpose:** Machine-readable log of architectural decisions. Each entry is a YAML block.

Format matches the rest of the portfolio so entries can be queried the same way. **Grep for
`^id: ADR`**, not for Markdown headings — this log is YAML inside fences, and checking for
headings is how an entry elsewhere was briefly filed as a duplicate.

---

## Entry Template

```yaml
id: ADR-NNN
date: YYYY-MM-DD
status: proposed  # proposed | accepted | superseded | amended | deprecated
category: [category]  # concurrency | storage | api | testing | performance | architecture | security
title: [Brief title]
context: |
  [The specific problem, constraints, and why a decision is needed.]
decision: |
  [The chosen approach or convention.]
rationale: |
  - [Reason]
consequences: |
  [Positive and negative impacts.]
alternatives_rejected:
  - "[Alternative]: [Why rejected]"
affected_files:
  - [file path]
supersedes: null
amends: null
superseded_by: null
```

---

## Decisions

```yaml
id: ADR-001
date: 2026-09-08
status: accepted
category: architecture
title: Implemented from the specification, with an existing implementation as an external bar
context: |
  This package verifies a signature that decides who someone is. A maintained Swift
  implementation already exists — brokenhandsio/swift-webauthn — and depending on it would be
  the cheaper decision by every ordinary measure: it is used, and its bugs have been found by
  people who are not us.

  Cryptographic verification code is also the canonical example of what not to write yourself,
  so this decision needs to be recorded with its counterargument intact rather than asserted.
decision: |
  Implement the relying party clean-room from the W3C Web Authentication specification, §7.1
  and §7.2. No code copied and no tests copied.

  brokenhandsio/swift-webauthn's public test suite is kept as an **external bar**: run against
  this implementation once the API is stable, deliberately, and not as a dependency of these
  tests.

  No cryptographic primitive is written here. swift-crypto does the mathematics; this package
  parses bytes and checks the specification's steps in order.
rationale: |
  - What is ours is parsing and step-checking, where the specification is explicit and each
    numbered step becomes a named test. That is checkable in a way "we trust the library" is not.
  - Reading the specification closely enough to implement it is how anyone earns the right to
    say the verification is correct.
  - Clean-room settles the licence question before it is asked.
  - A second opinion written by people who solved this already is worth more as an adversary
    than as a foundation.
consequences: |
  Positive: every verification step is traceable to the specification section it came from,
  which is what makes the clean-room claim checkable rather than asserted.

  Negative, and real: this is hand-written verification of attacker-supplied bytes. The risk is
  not eliminated by care, it is mitigated by the external bar — which only helps once it is
  actually run.

  The bar was run on 2026-09-09 against brokenhandsio/swift-webauthn at 2b6b4d4: sixteen
  ceremonies, the same bytes to both verifiers, 14 agreements and 2 disagreements. One is a
  laxity on their side (trailing bytes after the attestation object are ignored); the other is a
  signature-counter policy where both behaviours are conformant, because §7.2 says a relying
  party SHOULD apply its own risk policy rather than mandating refusal. Written up in
  project/external-bar/README.md.

  What that does NOT establish: that either implementation is correct. Two implementations can
  share a misreading, and a differential test cannot see a step both of them skipped.

  An abandonment condition is recorded rather than left to judgement: if the CBOR subset starts
  growing to make real authenticators work, take the dependency instead. Written before any code
  existed so the decision is a check against a stated bar rather than a defence of sunk effort.
alternatives_rejected:
  - "Depend on brokenhandsio/swift-webauthn: the stronger argument on maintenance and review, and not fully answerable. Kept as the external bar and as the named fallback."
  - "Depend on a general CBOR library: a dependency and an attack surface disproportionate to a closed shape of three known keys."
affected_files:
  - project/plans/proposals/RelyingPartyImplementation.md
supersedes: null
amends: null
superseded_by: null
```

```yaml
id: ADR-002
date: 2026-09-08
status: accepted
category: architecture
title: Passkeys reach SwiftIdentity through an adapter product, not a dependency
context: |
  A passkey assertion has to become a SwiftIdentity `Credential` somewhere. `Credential` is an
  open protocol precisely so that type can be declared outside SwiftIdentity — §4b(5) of its
  proposal made it a protocol rather than an enum for exactly this case.

  The obvious wiring is for SwiftIdentity to depend on this package. That would make every
  consumer of SwiftIdentity link a WebAuthn implementation, including the ones whose clients
  cannot run a ceremony at all: a shared speaker cannot, and a calendar client subscribing to an
  .ics feed cannot. Those clients are the reason SwiftIdentity has the shape it does.
decision: |
  A second library product in **this** package — `SwiftWebAuthnIdentity` — depends on both
  `SwiftWebAuthn` and `SwiftIdentity`, and declares `PasskeyAssertion: Credential`.

  SwiftIdentity gains no knowledge of WebAuthn and no new dependency. A deployment that never
  uses passkeys imports `SwiftIdentity` alone and links none of this.
rationale: |
  - The dependency arrow points one way, so the lower-level package stays unaware of the higher-level one.
  - No third repository, third quality gate, or third handoff for one type and one function.
  - It is the concrete payoff of making `Credential` a protocol; if this seam is awkward, that decision was wrong and we find out here.
consequences: |
  Positive: the packages can be released independently, and SwiftIdentity's dependency list stays
  short enough that a service needing only API keys links nothing it cannot justify.

  Negative: this package now depends on SwiftIdentity, so a change to the `Credential` protocol
  is a change here. That is the correct direction for the coupling, but it is coupling.
alternatives_rejected:
  - "SwiftIdentity depends on SwiftWebAuthn: contradicts §4b(2) — resolution stays the only required protocol — and makes a calendar feed link CBOR and attestation parsing to verify a capability token."
  - "A separate SwiftIdentityWebAuthn repository: cleanest separation, but a third repo, gate and handoff to keep current for one type and one function."
affected_files:
  - Package.swift
  - project/plans/proposals/RelyingPartyImplementation.md
supersedes: null
amends: null
superseded_by: null
```
