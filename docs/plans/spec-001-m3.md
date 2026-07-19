# Plan — SPEC-001 M3: Ledger wiring

Implements SPEC-001 §9 M3 (AC-4, AC-5). Delta only.

## Design: TM rows join the derived registry

The SPEC-000 invariant registry (SPEC-000 AC-5, `docs/plans/invariant-registry.md`)
gains SPEC-001's trust-model invariants TM-1..TM-5 as derived rows, parsed the
same way the INV catalog is: each `**[TM-n]**` entry in SPEC-001 §3.2 carries
its `SPEC-NNN` refs, unioned with any other spec file citing that `TM-n` —
SPEC-001 itself excluded as the defining spec (mirroring SPEC-000's exclusion
for INV rows). Derived owners today, verified by hand:

- TM-1 → SPEC-005 (entry), SPEC-003 (cross-ref)
- TM-2 → SPEC-012 (entry), SPEC-003 + SPEC-010 (cross-refs)
- TM-3 → SPEC-016 (entry), SPEC-005 (cross-ref) — **the AC-5 obligation**:
  the singleton-work guard is demanded when either flips Implemented
- TM-4 → SPEC-003 + SPEC-013 (cross-refs)
- TM-5 → SPEC-003 + SPEC-013 (cross-refs) — **the AC-4 obligation**: the
  fail-closed behavioral tests are demanded when either flips Implemented

The existing G-000-1 coverage join (`coverageViolations`) is ID-agnostic; TM
rows feed through it unchanged. Guards register with the same co-located
doc-comment line, whose grammar extends from `Guards: INV-n` to
`Guards: (INV|TM)-n`. Ends green: no owning spec above is Implemented, and
SPEC-001's own flip to Implemented demands nothing (it cites no INV ID and is
excluded from TM ownership).

## Delta

- `sdk/guardtest/coverage_test.go` — `invariantRegistry` parameterized into a
  shared `derivedRegistry(root, sourceFile, secStart, secEnd, entryRe, excludeBase)`
  with thin `invariantRegistry`/`trustModelRegistry` wrappers;
  `TestGuard_InvariantCoverage` gains a second Discover (TM rows, floor 5),
  exact-set TM-1..TM-5 both directions, the per-row owner floor, the
  owners-in-ledger check, and TM rows appended into the coverage join.
  Spot-check test `TestTrustModelRegistry_DerivedOwners` pins the hand-verified
  owners above (incl. the SPEC-001 exclusion).
- `sdk/guardtest/conformance_test.go` — `guardsLineRe` accepts TM IDs.
- `sdk/guardtest/testdata/liveness/good_guard_test.go` — a second conforming
  fixture guard carrying `Guards: TM-3.`; `TestGuardInventory_ExtractsRegistrations`
  asserts its extraction.
- Carried nits from PR #7's clean re-review (both `sdk/guardtest`):
  `testdata/arch/listeners/plain.go` gains a `net.FilePacketConn` fixture +
  want-list row (own red-proof for the token); `ListenerRegistrations` doc
  comment documents the receiver-qualified `"<rel-file>:(T).name"` key form.
- `docs/content/01-specs/00-index.md` — SPEC-001 → Implemented; M3 milestone
  line.

## Scenario matrix (red = stub parser / old regex)

| # | Test | Expectation |
|---|------|-------------|
| 1 | trustModelRegistry on this repo | exactly TM-1..TM-5, floor 5 — red while stub |
| 2 | TM-1/TM-3/TM-5 derived owners match the hand-verified sets; SPEC-001 not an owner | red while stub |
| 3 | `Guards: TM-3.` fixture line | extracted — red under the INV-only regex |
| 4 | INV exact-set, spot-checks, ledger floor | unchanged, stay green |
| 5 | coverage join over INV ∪ TM rows on the real repo | green (no TM owner Implemented) |
| 6 | FilePacketConn fixture line | flagged in liveness want-list — red-proven by token neutralization |

## Out of scope

The AC-4 behavioral tests and the AC-5 singleton-work guard themselves — they
land with their owning specs (SPEC-003/013, SPEC-005/016); M3 wires only the
demand. Registering SPEC-001's own guards against TM rows (genuine coverage
claims like G-001-3 → TM-2) is left to the owning specs' sessions.
