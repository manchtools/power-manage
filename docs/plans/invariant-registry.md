# Plan — SPEC-000 M3: Invariant registry

Implements SPEC-000 §9 M3 (AC-5; guards G-000-1, G-000-2). Delta only.

## Design: the registry is DERIVED, never hand-maintained

[META-2] forbids hand-maintained lists, so the machine-readable registry is
parsed from ground truth at guard time, in `sdk/guardtest`:

- **Invariant → owning specs**: parsed from SPEC-000 §3.4 — each
  `**[INV-n]**` catalog entry's text carries its `SPEC-NNN` refs — unioned
  with any other spec file whose text cites that `INV-n`. Exact-set floor:
  the parse must yield precisely INV-1..INV-19.
- **Spec → implementation status**: parsed from the ledger table in
  `00-index.md` (floor: 18 spec rows).
- **Invariant → registered guards**: `Guards: INV-n[, INV-m]` lines in
  `TestGuard_*` doc comments, extracted by the existing AST inventory walk
  (now parsing comments). Registration is thereby co-located with the guard
  (PROC-3.4).
- INV-17 is web-repo-enforced (SPEC-000 §3.4/§10): one identity-keyed
  exemption constant with a comment — the sanctioned allowlist form.

## Delta

- `sdk/guardtest/coverage_test.go` — `invariant{ID, OwningSpecs, InRepo}`,
  the §3.4/cross-ref parser, the ledger-status parser, and the join. All
  test-local: G-000-1 is the sole consumer, so the shipped sdk surface gains
  nothing.
- **G-000-1** `TestGuard_InvariantCoverage` (same file):
  Discover(registry, floor 19) + exact-set INV-1..19 both directions; join:
  every in-repo invariant with an Implemented owning spec must have ≥1
  registered guard. Pure-function join with a planted
  implemented-spec-without-guard input as its liveness proof (§6.3: the
  neutralizing edit is removing a guard registration).
- `sdk/guardtest/cilane_test.go` — **G-000-2** `TestGuard_CILaneCompleteness`:
  discovers test-bearing packages (floor ≥1) across module dirs; each must
  belong to a depth-1 module (`*/go.mod` — exactly what verify.sh's walk
  covers) and ≥1 workflow under `.github/workflows/` must run
  `scripts/verify.sh` on `pull_request`. Liveness fixture: a nested module
  (depth 2) bearing a test file, invisible to the verify.sh walk, must be
  flagged specifically, next to a conforming depth-1 module that must not be.
- `sdk/guardtest/conformance_test.go` — inventory walk extended: parse
  comments, return per-guard invariant annotations.
- Fixtures: `testdata/cilane/goodmod/` (depth-1, conforming) and
  `testdata/cilane/tools/helper/` (depth-2, planted violation);
  `testdata/liveness/good_guard_test.go` gains a `Guards: INV-19.` line for
  the annotation-extraction test.

## Scenario matrix (red = stub parsers/join/scan return nothing)

| # | Test | Expectation |
|---|------|-------------|
| 1 | Invariants() on this repo | exactly INV-1..19, floor-protected — red while parser is a stub |
| 2 | each derived invariant has its owners cited in real spec files | red while parser is a stub |
| 3 | SpecStatuses() on this repo | 18 rows, SPEC-000 shows In progress — red while stub |
| 4 | coverage join: planted Implemented owner, no registered guard | flagged — red while join is a stub |
| 5 | coverage join: same invariant WITH a registered guard | clean (checker not always-red) |
| 6 | annotation extraction: fixture guard carrying `Guards: INV-19.` | extracted — red while stub |
| 7 | G-000-2 liveness: nested-module test fixture | flagged specifically, depth-1 neighbor clean — red while scan stub |
| 8 | G-000-1 + G-000-2 on the real repo | green (no Implemented spec yet; all packages covered) |

## Known catalog gaps (resolved during review)

INV-3, INV-5, and INV-11 carried no `SPEC-NNN` ref in their §3.4 entries and
no other spec cited them — empty derived owner sets, so the completeness
join could never demand a guard for them (INV-11 was found by the reviewer
pass). Resolution:

- A per-invariant owner floor now makes the hole loud: every in-repo
  invariant needs ≥1 derived owner or an identity-keyed `ownerlessPending`
  entry recording the open question.
- INV-5 → SPEC-003 (WIRE-14) and INV-11 → SPEC-008 (AUTHZ-2) refs added to
  the catalog as mechanical gap fixes — both requirements exist verbatim in
  those specs; the omission was the citation only. Pinned by owner
  spot-checks.
- INV-3 is specified verbatim in both SPEC-003 and SPEC-006; the ref choice
  is an operator decision, recorded in `ownerlessPending` until made.

## Out of scope

Portable AST guards (M4); behavioral INV enforcement (owning specs).
