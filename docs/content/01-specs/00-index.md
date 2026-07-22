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
| 004 | [sdk-core](004-sdk-core.md) | 000–002 | sdk | Implemented |
| 005 | [event-store](005-event-store.md) | 000–003 | server | Implemented |
| 006 | [pki-and-identity](006-pki-and-identity.md) | 003, 005 | contract, server, agent | In progress (M5 done) |
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
`Implemented` means the spec's own milestones and module-owned checks are green;
it does not claim that downstream components or end-to-end product paths exist.

## Deferred cross-spec obligations

These obligations are visible exceptions, not silent green coverage:

- SPEC-001's boundary-registry and gateway-purity guards remain dormant until
  server listener and gateway packages exist. Their skips are surfaced by the
  verification gate and their violation fixtures remain active.
- SPEC-003 G-5 currently proves the contract domain registry, round trips, and
  pairwise isolation. Its cross-repository sign-site + fail-closed verify-site
  floor activates when SPEC-005/007/013 add those consumers.

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
SPEC-004 M1 — sdk-core guards: G-3 randomness (both math/rand generations), G-4 regex chokepoint (decl-keyed allowlist + orphan check), G-5 hash-import ban, G-6 AAD surface (dormant), G-7 mutation chokepoint, G-9 clock seam; G-1/G-2/G-8 mapped to the SPEC-002 estate — PR #20
SPEC-004 M2 — Runner: sdk/exec on stdlib os/exec (Setpgid group, SIGTERM→grace→SIGKILL, D-state fallback), allowlist-baseline child env (curated PATH, forced C locale, hijack blocklist), argv-only + SeparatePositionals, escalation sudo/doas/direct, exectest.FakeRunner; sdk/narrow range-checked To; sdk/redos Vet/Compile/MustVet with parent-state propagation; sdk package floor 1→6 — PR #21
SPEC-004 M3 — filesystem: sdk/fsafe fd-anchored no-follow primitives, streaming atomic replace (RENAME_NOREPLACE, raw renameat2/unlinkat wrappers, no x/sys), protected-prefix predicates (symmetric create/delete, symlink-resolving), Manager direct + escalated tiers (single-root-shell write, stdin content, C-locale ENOENT mapping); sdk/fetch HTTPS-only SSRF-guarded pinned download (AG-13a hops/pin/size); floor 6→8; G-5 file-keyed fetch exemption with M5 sunset (AC-9..13) — PR #22
SPEC-004 M4 — validators: sdk/validate intent grammars (package/rpm/repo/flatpak-remote names, GPG key ref, repo base URL with $releasever accept, username, systemd unit, ULID-charset path ID), structured-file value validators (sshd_config/sudoers/authorized_keys/NM-keyfile record-separator reject, GECOS `:`, group-list `:,`, deb822 URI, Suites/Components cross-field, ToolErrorNamesFile rollback trigger), system refs (LUKS /dev path, reverse-DNS flatpak app ID, /etc/shells-membership login shell fail-closed via seam); floor 8→9 (AC-14, AC-15) — PR #23

SPEC-004 M5 — crypto: sdk/crypto stdlib-only seal/open — AES-256-GCM AEAD (SealWithAAD/OpenWithAAD, mandatory non-empty key/AAD/plaintext rejected symmetrically at seal AND open, nonce‖ct‖tag layout, ErrMalformedCiphertext floor, fail-closed on tamper/wrong-key/wrong-AAD), X25519+HKDF-SHA256+AES-256-GCM sealed transport (SealToPublicKey/OpenWithPrivateKey, framePreimage length-prefix/domain salt over both public keys, mandatory info domain separation, fresh ephemeral per seal), constantTimeEqual (subtle), randReader RNG seam with NewPrivateKey keygen honoring crypto/rand read errors (GenerateKey ignores its reader in Go 1.26); armed G-3 (crypto/rand call-site floor), G-5 M5 per-construction framing, G-6 AAD-surface auto-arm; floor 9→10 (AC-16, AC-17) — PR #24

SPEC-004 M6 — package managers + rollback: typed absent/query-failure split, strict non-nil/error-returning parsers, reverse compensation with joined failures, real apt/dnf/pacman/zypper/flatpak container lanes (non-English apt), exact lane-parity guard; floor 10→12 (AC-18..20) — PR #31

SPEC-004 M7 — policy-file engine: one fsafe composition, closed three-row surface table, surface-path/symlink guards, candidate validation, atomic swap with cancellation-independent restore, marker-delimited updates, real sshd/visudo container lane (AC-21, AC-22) — PR #32

SPEC-005 M1 — events schema, auto-versioned append with exact conflict retry, capability-limited in-transaction projector registry, atomic rollback, read-after-write, real Postgres contention tests (AC-1..4) — PR #33

SPEC-005 M2 — expected-version CAS without retry, atomic ordered batch append, and real Postgres consume/rollback tests (AC-8..9; AC-10 activates with the first state-changing RPC) — PR #35

SPEC-005 M3 — repeatable-read projection rebuild through the production projector registry, exact target parity, and FK-closure refusal (AC-6, SPEC-005), (AC-7, SPEC-005) — PR #36

SPEC-005 M4 — same-transaction durable work queue, bounded retry/backoff, SKIP LOCKED workers, and rebuild-safe work preservation (AC-12, SPEC-005) — PR #37

SPEC-006 M1 — certificate identity profile, TLS 1.3 class enforcement, and self-asserted identity guard (AC-6, GUARD-006-3) — PR #39

SPEC-005 M5 — exact storage classification and static guards, golden event corpus, version-guarded inventory snapshots, bounded operational output, and CLI-only recovery wiring (AC-5, SPEC-005), (AC-11, SPEC-005), (AC-13, SPEC-005), (AC-14, SPEC-005), (AC-15, SPEC-005) — PR #38

SPEC-006 M2 — control-only agent CA, gateway CA, and command-key custody; approved-key boot gates; DER-derived result verification; agent/control signing chokepoints; fail-closed control dependencies; cross-module signature-domain parity (AC-11, SPEC-006), (AC-14, SPEC-006), (AC-15, SPEC-006), (GUARD-006-2, SPEC-006), (GUARD-006-6, SPEC-006) — PR #40

SPEC-006 M3 — hash-only registration-token minting, constant-time admission, bounded-use expected-version CAS, durable disable, five-per-minute source limiting, and rebuildable Postgres projection (AC-2, SPEC-006), (AC-3, SPEC-006) — PR #41

SPEC-006 M4 — TLS 1.3 PkiService enrollment, CSR SAN refusal, token-authorized agent certificate issuance, rebuildable device projection, local-key custody, root-safe no-clobber credentials, and the mode-0666 bounded local enrollment relay/CLI (AC-1, SPEC-006), (AC-2, SPEC-006), (AC-16, SPEC-006), (GUARD-006-1, SPEC-006) — PR #42

SPEC-006 M5 — fingerprint- and possession-bound agent renewal, per-device transaction locking, exact supersession state, atomic sealing-key rotation, and the 80%-lifetime hourly-retry loop (AC-4, SPEC-006), (AC-5, SPEC-006), (GUARD-006-4, SPEC-006) — PR #43

## Rules

- Specs are operator-approved. A material deviation needs operator sign-off
  before code; mechanical gaps are fixed in the spec in the same PR.
- Specs reference each other as `(REQ-ID, SPEC-NNN)`. Nothing in this repo
  references any external repository, issue tracker, or document.
- Every spec has: numbered requirements, acceptance criteria, a rejection-path
  table, a TDD test plan, and self-discovering guards. If you find one
  without, that is a spec bug — fix it before implementing.
