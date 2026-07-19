---
title: "Spec series — build order and status ledger"
---
# Spec series — build order and status ledger

Every implementation session picks **one milestone of one spec**, in build
order, and follows `000-development-process.md`. This file is the single
status ledger: when a milestone lands green, update its row here in the same
PR.

A spec is implementable when every spec it builds on is **Implemented** (or
the specific milestones it needs are done). "Builds on" below mirrors each
spec's own header, which is authoritative.

## Index

| # | Spec | Builds on | Module(s) | Status |
|---|------|-----------|-----------|--------|
| 000 | [development-process](000-development-process.md) | — | all | Spec ready |
| 001 | [architecture-and-trust-model](001-architecture-and-trust-model.md) | 000 (M2–M3) | all | Spec ready |
| 002 | [repo-module-and-config-contract](002-repo-module-and-config-contract.md) | 000 (M2) | all | Spec ready |
| 003 | [wire-contract](003-wire-contract.md) | 000–002 | contract | Spec ready |
| 004 | [sdk-core](004-sdk-core.md) | 000–002 | sdk | Spec ready |
| 005 | [event-store](005-event-store.md) | 000–003 | server | Spec ready |
| 006 | [pki-and-identity](006-pki-and-identity.md) | 003, 005 | server | Spec ready |
| 007 | [authentication](007-authentication.md) | 003, 005 | server | Spec ready |
| 008 | [authorization](008-authorization.md) | 005, 007 | server | Spec ready |
| 009 | [crud-kernel-search-and-domains](009-crud-kernel-search-and-domains.md) | 005, 007, 008 | server | Spec ready |
| 010 | [artifact-store](010-artifact-store.md) | 003, 005 | server | Spec ready |
| 011 | [audit-and-retention](011-audit-and-retention.md) | 005, 008, 010 | server | Spec ready |
| 012 | [gateway](012-gateway.md) | 003, 006 | server | Spec ready |
| 013 | [agent-core](013-agent-core.md) | 003, 004, 006, 010 | agent | Spec ready |
| 014 | [action-catalog](014-action-catalog.md) | 003, 004, 009, 010, 013 | contract, sdk, server, agent | Spec ready |
| 015 | [secret-surfaces](015-secret-surfaces.md) | 006, 009, 011, 013 | server, agent | Spec ready |
| 016 | [operations-and-ha](016-operations-and-ha.md) | 005, 012 | server | Spec ready |
| 017 | [testing-and-release](017-testing-and-release.md) | 000–016 | all | Spec ready |

Status values: `Spec ready` → `In progress (M<n> done)` → `Implemented`.

## Milestone ledger

Append one line per completed milestone:

```
SPEC-NNN M<k> — <one-line summary> — <commit/PR>
```

(none yet)

## Rules

- Specs are operator-approved. A material deviation needs operator sign-off
  before code; mechanical gaps are fixed in the spec in the same PR.
- Specs reference each other as `(REQ-ID, SPEC-NNN)`. Nothing in this repo
  references any external repository, issue tracker, or document.
- Every spec has: numbered requirements, acceptance criteria, a rejection-path
  table, a TDD test plan, and self-discovering guards. If you find one
  without, that is a spec bug — fix it before implementing.
