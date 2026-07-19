# Plan — SPEC-000 M2: Guard harness

Implements SPEC-000 §9 M2 (AC-3, AC-4; guard G-000-3). Delta only.

## Placement

`sdk/guardtest` (new package, stdlib-only). Derived from the spec series, not
chosen ad hoc: CFG-1 (SPEC-002) names `sdk` the home of shared proto-free
mechanism — the only module every permitted consumer may import under INV-19 —
and SPEC-003 M1 gives `contract` its own descriptor-walk library with the
matches-zero pattern, so the no-imports module is deliberately not a consumer
of this harness.

## Delta

- `sdk/guardtest/guardtest.go` — the harness:
  - `Discover[T](t testing.TB, desc string, floor int, discover func() ([]T, error)) []T`
    — runs discovery; a returned error, or fewer than `floor` subjects, FAILS
    the test (matches-zero, PROC-3.2). Failure text tells the tripping session
    what to do.
  - `RequireViolation(t testing.TB, name string, scan func(root string) ([]string, error), fixtureRoot string)`
    — the liveness-fixture pattern (PROC-3.3): scanning a fixture containing a
    deliberate violation must report it, proving the guard can still go red.
  - `RepoRoot(t testing.TB) string` — walks up to the `go.work` root.
- `sdk/guardtest/conformance_test.go` — G-000-3 `TestGuard_GuardAPIConformance`:
  AST walk discovers every `TestGuard_*` function under the repo root
  (via `Discover`, floor 1 — itself), fails any guard that does not call the
  harness; liveness fixture `testdata/liveness/` holds a non-conforming
  `TestGuard_*` file the scan must flag.
- `sdk/guardtest/guardtest_test.go` — the §6.1 harness tests.

## Scenario matrix (red = stub bodies pass discovery through unchecked / scan
returns nothing; the violation fixture is each guard's standing red proof §6.4)

| # | Test | Expectation |
|---|------|-------------|
| 1 | Discover, empty discovery | test FAILS naming the floor (matches-zero) |
| 2 | Discover, below-floor discovery | test FAILS naming got vs. floor |
| 3 | Discover, discovery error | test FAILS wrapping the error |
| 4 | Discover, floor met | subjects returned, no failure |
| 5 | RequireViolation, scan finds planted violation | passes |
| 6 | RequireViolation, scan reports clean on the fixture | test FAILS (guard can no longer go red) |
| 7 | G-000-3 liveness: non-conforming `TestGuard_*` fixture | flagged by the conformance scan |
| 8 | G-000-3 real walk: every repo `TestGuard_*` conforms | green on this repo |

Failure recording uses a `testing.TB`-embedding recorder so helper failures
are observable without aborting the harness test.

## Known limitation (recorded)

G-000-3's conformance check is syntactic: harness calls are resolved through
the file's imports to the real `sdk/guardtest` path (aliases, dot-imports),
but without `go/types`. A dot-import shadowed by a local declaration would
still pass; a guard delegating its harness call to a helper function is
flagged (false positive — the fail-closed direction). Move to type-checked
resolution with the M4 AST-guard library if either ever bites.

## Out of scope

Invariant registry + G-000-1/2 (M3), AST guard library (M4), module discovery
helpers beyond `RepoRoot` (land with SPEC-002 M2's archtests, which need them).
