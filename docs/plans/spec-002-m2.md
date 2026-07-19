# Plan — SPEC-002 M2: Archtests

Implements SPEC-002 §9 M2 (AC-2, AC-3; guards G-002-1, G-002-2). Delta only.

## Mechanical spec gap (fixed in the spec in this PR)

AC-2 and the G-002-1 floor cell say "zero packages in any module fails" /
"≥1 package each" — but contract, server, and agent contain zero Go
packages until SPEC-003/005/013 land code, so that floor cannot hold at M2
("ends green"). Same shape as SPEC-001's AC-1/AC-3, resolved the same
sanctioned way: per-module package floors are ratchet data in the test
(`modulePackageFloors`: sdk ≥ 1 today, others 0), rising with each spec
that lands code — a code-bearing module can never silently drop to zero.
Workspace-wide package discovery keeps the matches-zero floor (≥1).

## Design

Both guards discover from ground truth: module dirs from `go.work`
(`workspaceModules`, M1), module identities from each `go.mod`'s `module`
line, packages and imports from the file walk (`walkGoFiles` — testdata and
hidden dirs excluded; test files INCLUDED: a test importing a forbidden
module links the same code). Import→module resolution matches declared
module paths (exact or path-prefix), so aliased/blank/dot imports cannot
evade — the import path is what's matched, not a name.

- **G-002-1 directional imports [INV-19]**: `importAllowlist` is the
  normative §3.3 table (fail closed: an unmapped go.work module is a
  violation). Cross-module import outside the allowlist → violation.
  Registered `Guards: INV-19.` — the SPEC-000 coverage join demands exactly
  this guard when SPEC-002 flips Implemented.
- **G-002-2 proto purity [SDK-0]**: every sdk package import checked
  against `protoImportPrefixes` (protobuf, genproto, connectrpc, buf.build
  gen, and the in-repo contract module) — a test-owned threat model, one
  known import per family.

## Delta — all in `sdk/guardtest`

- `imports.go`: `modulePaths(root, mods)`, `importAllowlist`,
  `modulePackageFloors`, `directionalImportViolations(root, mods)`
  (violations + per-module package counts), `protoImportPrefixes`,
  `protoPurityViolations(root)`.
- `imports_test.go`:
  - `TestGuard_DirectionalImports` (G-002-1, `Guards: INV-19.`): Discover
    modules floor 4 + workspace package floor 1 + per-module ratchet floors
    + zero violations.
  - `TestGuard_DirectionalImports_Liveness`: fixture workspace plants
    sdk→contract and agent→server (the licensing breach), server→contract
    stays clean; exact-set.
  - `TestGuard_ProtoPurity` (G-002-2): Discover sdk packages floor 1 +
    zero violations.
  - `TestGuard_ProtoPurity_Liveness`: fixture sdk package imports
    protobuf, connect, and the generated contract; clean file untouched;
    exact-set.
  - `TestProtoImportPrefixes_ThreatModel`: one classified import per
    family + innocents (grpc-adjacent but sanctioned paths stay clean).
- Fixtures `testdata/arch/imports/ws/` (four-module workspace with two
  planted violations) and `testdata/arch/imports/purity/` (bad + clean
  files).
- Spec: AC-2 + §7 G-002-1 floor cell reworded to the ratchet form.
- Ledger: SPEC-002 → In progress (M2 done); M2 milestone line (PR #10).

## Scenario matrix (red = stub scans return nothing)

| # | Test | Expectation |
|---|------|-------------|
| 1 | G-002-1 on this repo | 4 modules, ≥1 package, zero violations — red while stub (floors) |
| 2 | ws fixture | sdk→contract + agent→server flagged exact-set, server clean — red while stub |
| 3 | G-002-2 on this repo | ≥1 sdk package, zero violations — red while stub (floor) |
| 4 | purity fixture | protobuf/connect/contract imports flagged exact-set — red while stub |
| 5 | prefix threat model | each family classified, innocents clean — red while stub |

## Out of scope

Config loader + G-002-4/5/7 (M3); docs generation (M4); CI conventions (M5).
