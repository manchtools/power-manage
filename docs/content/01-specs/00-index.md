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
| 000 | [development-process](000-development-process.md) | — | all | Implemented |
| 001 | [architecture-and-trust-model](001-architecture-and-trust-model.md) | 000 (M2–M3) | all | Implemented |
| 002 | [repo-module-and-config-contract](002-repo-module-and-config-contract.md) | 000 (M2) | all | Implemented |
| 003 | [wire-contract](003-wire-contract.md) | 000–002 | contract | Implemented |
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

SPEC-000 M1 — self-discovering verify gate (module walk + floor, -race, self-test) — PR #1
SPEC-000 M2 — guard harness sdk/guardtest (Discover + matches-zero, liveness pattern, G-000-3) — PR #2
SPEC-000 M3 — derived invariant registry + coverage join G-000-1 + CI-lane guard G-000-2 (AC-5) — PR #3
SPEC-000 M4 — portable AST-guard library (clock, ctx, imports, sentinel, enum-default) with fixture self-tests (AC-7) — PR #4
SPEC-001 M1 — storage-dependency + gateway-purity guards, B1–B11 machine-readable registry (AC-1, AC-3) — PR #6
SPEC-001 M2 — boundary-registry harness G-001-2: listener discovery, registration API, exact-set join (AC-2) — PR #7
SPEC-001 M3 — ledger wiring: TM-1..TM-5 derived rows, TM registration grammar, coverage-join demand (AC-4, AC-5) — PR #8
SPEC-002 M1 — repo skeleton + license-layout guard G-002-3: go.work discovery, identity classifier, README mapping probe (AC-1) — PR #9
SPEC-002 M2 — archtests G-002-1 (INV-19 directional imports, Guards-registered) + G-002-2 (SDK-0 proto purity) with liveness fixtures (AC-2, AC-3) — PR #10
SPEC-002 M3 — sdk/config loader (strict INI subset, derived PM_* set, named boot failures) + G-002-4 env hygiene, G-002-5 round-trip/adoption, G-002-7 secret indirection (AC-4, AC-5, AC-7) — PR #11
SPEC-002 M4 — config.Doc struct-derived reference (mandatory doc tag, golden staleness diff) + G-002-6 read-site scan and per-binary docs-test demand (AC-6) — PR #12
SPEC-002 M5 — CI conventions lane G-002-8 (commit lint, vYYYY.MM.PP tags, attribution; fixture-tested script) + contract TS manifest MIT (AC-8, AC-9) — PR #13
SPEC-003 M1 — contract scaffold: six services, protovalidate ULID rule, descriptor-walk harness (G-1, G-2a, exact-set surface), G-6 protojson ban, gen-sync verify stage — PR #14
SPEC-003 M2 — ActionParams registry: 21-member oneof + stub params, one Action shape, G-3 authority walk, G-4 explicit presence, enum-bounds pair — PR #15
SPEC-003 M3 — SignedCommand envelope: golden-pinned domain framing, contract/sign sign/verify helpers, freshness windows, Ed25519 refusal, G-5 domain isolation — PR #16
SPEC-003 M4 — DeviceSigned results, SealedBlob + seal infos, SPIFFE identity constants, SyncManifest + monotonicity, no-removal-verbs guard — PR #17
SPEC-003 M5 — stream protocols (Agent/Internal frames, artifact fetch, terminal token unary), scim/export deleted, [WIRE-20a] closed result set, G-5→14, G-7 deny-list, G-8 near-copy — PR #19

## Rules

- Specs are operator-approved. A material deviation needs operator sign-off
  before code; mechanical gaps are fixed in the spec in the same PR.
- Specs reference each other as `(REQ-ID, SPEC-NNN)`. Nothing in this repo
  references any external repository, issue tracker, or document.
- Every spec has: numbered requirements, acceptance criteria, a rejection-path
  table, a TDD test plan, and self-discovering guards. If you find one
  without, that is a spec bug — fix it before implementing.
