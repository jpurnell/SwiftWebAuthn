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
- **Language:** Swift 6.0+
- **Build System:** Swift Package Manager
- **Testing:** Swift Testing framework
- **Concurrency:** Swift 6 strict concurrency throughout
- [Add frameworks: SwiftUI, SwiftData, Vapor, etc.]
- [Add dependencies: BusinessMath, etc.]

### Module Structure

```
Sources/[ProjectName]/
├── [Describe your source layout here]
└── ...
```

### Key Types

| Type | Purpose |
|------|---------|
| `[TypeName]` | [What it does] |

### Data Flow

```
[Describe the primary data pipeline from input to output]
```

---

## Core Architectural Decisions

1. [Decision 1 — what you chose and why.]
2. [Decision 2]
3. [Add more as needed]

---

## Current Status

### What's Working
- [ ] [List completed milestones]

### What's Next
- [ ] [List upcoming work items]

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

### Phase 1: [Name]
- [ ] [Milestone]

### Phase 2: [Name]
- [ ] [Milestone]

### Future
- [Ideas not yet committed to]

---

**Last Updated:** 2026-09-02 (created; scaffolded from development-guidelines v2.3.0)
