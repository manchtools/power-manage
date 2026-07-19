# Plan — SPEC-000 M1: Verification gate

Implements SPEC-000 §9 M1 (AC-1; AC-2 minus the lane guard, whose CI wiring
already exists in `.github/workflows/ci.yml`). Delta only; the spec is
authoritative.

## Delta

- `scripts/verify.sh` — replace the hand-maintained `MODULES=(contract sdk
  server agent)` list with a self-discovering module walk (`find` for
  `*/go.mod`, depth 2), matches-zero protected with the G-000-4 floor
  (< 4 modules discovered = FAIL). Add `-race` to the test stage (AC-1).
  Missing required tooling (staticcheck; buf once protos exist) becomes a
  FAIL, not a SKIP — a gate that silently skips a required check is fail-open
  (INV-3). Add a `scripts: self-test` stage running `scripts/verify_test.sh`;
  the explicit named bypass `PM_VERIFY_SKIP_SELFTEST=1` prevents recursion
  when the self-test invokes verify.sh against fixtures.
- `scripts/verify_test.sh` — new; the SPEC-000 §6.2 verify.sh tests, run
  against generated fixture repos in a temp dir (never against this repo).

## Scenario matrix (all confirmed RED against the scaffold script first)

| # | Fixture | Expectation | Red-reason vs. scaffold |
|---|---------|-------------|-------------------------|
| 1 | 4 passing modules | exit 0 AND every module's test stage appears in the log | scaffold's hardcoded names never match fixture modules — stages absent |
| 2 | 4 modules, one failing test | nonzero exit, output names the failure | scaffold discovers nothing in the fixture → exits 0 |
| 3 | fixture of #1 plus a 5th module with a failing test, script untouched | nonzero exit | scaffold's list can't pick up a new module → exits 0 |
| 4 | 3 modules | nonzero exit naming the discovery floor | scaffold has no matches-zero floor → exits 0 |

Guard-suite and generated-artifact freshness stages of AC-1 have no subjects
yet: guards are Go tests inside modules (picked up by the test stage as they
land, M2+), and freshness lands with the first generated artifacts (SPEC-003).
The buf lint/breaking stage stays conditional on protos existing.

## Out of scope

G-000-1..3 (M2/M3), AST guards (M4), CI lane guard (TEST-3, M3).
