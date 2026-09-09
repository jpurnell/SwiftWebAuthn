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

**The counter does not move.** That is the measurement `RelyingParty.checkCounter` was written
against and, until this capture, had only read from the specification: regression is evidence of
a cloned authenticator *only* for a credential that is not backed up. Had a static counter been
treated as an attack, this credential — the ordinary case on Apple hardware — would have been
refused at its first login.

## Regenerating

The harness is not committed; it is twenty lines of `http.server` plus a page calling
`navigator.credentials`. Any equivalent will do. What matters is that the bytes are recorded
exactly as the browser produced them, since every signature covers those bytes and re-encoding
them changes what is being verified.
