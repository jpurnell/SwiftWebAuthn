# ``SwiftWebAuthn``

Verifying passkey ceremonies, from the specification rather than from a port.

## Overview

WebAuthn has two ceremonies and this package implements the server's half of both: **registration**,
where an authenticator produces a new key pair and attests to it, and **authentication**, where it
signs a challenge with a key it already holds.

Everything else — generating keys, prompting for Touch ID, deciding whether a fingerprint matched —
happens on the authenticator, where this package has no reach and wants none.

## Why this exists rather than a dependency

A maintained Swift implementation exists. This is written anyway, from the W3C specification, with
that implementation's public test suite kept as an **external bar to clear** rather than as a
starting point. No code and no tests are copied, which also settles any licence question before it
is asked.

The reason is that the thing being verified is a signature that decides who someone is. Reading the
specification closely enough to implement it is how a reviewer earns the right to say the
verification is correct — and a deployment adopting passkeys as its default is exactly the case
where that matters.

## Topics

### Status

Nothing is implemented. The design is under review in
`project/plans/proposals/RelyingPartyImplementation.md`.
