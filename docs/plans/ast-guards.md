# Plan — SPEC-000 M4: Portable AST guards

Implements SPEC-000 §9 M4 (AC-7). Delta only.

## Design: four generic scans cover the six checks

The library ships as exported functions in `sdk/guardtest` (`astban.go`) —
the only module every consumer may import (INV-19). Scans are parse-level
(`go/ast`, no type checking, no new dependencies), resolve names through
each file's actual imports (aliases and dot-imports; a same-named symbol
from an unrelated package is not flagged), walk non-test `.go` files
skipping `testdata`/hidden dirs (except a fixture root itself), and take
trailing slash-relative path-prefix allowlists. Violations are
`relpath:line: message`.

| AC-7 check | Call |
|---|---|
| clock seam (`time.Now`, incl. `SetDeadline` args — any `time.Now` site is flagged, so a seam-less deadline is caught at its `time.Now`) | `BannedCalls(root, "time", "Now")` |
| `context.Background()` ban (owning spec allows main/lifecycle paths) | `BannedCalls(root, "context", "Background")` |
| `math/rand` ban (jitter allowlist by caller; pass `math/rand/v2` too) | `BannedImports(root, "math/rand")` |
| protojson-only (import-level ceiling; per-value proto enforcement is the owning spec's behavioral guard) | `BannedImports(root, "encoding/json")` |
| sentinel-comparison ban [INV-13] (`errors.Is(x, S)` and `==`/`!=` against caller-named sentinels) | `SentinelComparisons(root, map[importPath][]name)` |
| enum-switch erroring default (a switch with a case resolving into a caller-named generated-enum import-path prefix must have a `default` containing `return` or `panic`) | `EnumSwitchesWithoutErroringDefault(root, prefixes)` |

Per SPEC-000 §10, repo-wide application (and `Guards: INV-n` registration)
lands with each owning spec; M4 ships the library and its standing red
proofs only. The import-resolution helper is shared with the G-000-3
conformance scan (extracted from `conformance_test.go`).

## Delta

- `sdk/guardtest/astban.go` — the four scans + shared walk/import helpers.
- `sdk/guardtest/astban_test.go` — self-tests per §6.4: violation fixture
  detected (via `RequireViolation`) AND clean fixture passes, plus
  alias/decoy resolution and allowlist rows.
- `sdk/guardtest/conformance_test.go` — `harnessRefs` replaced by the
  extracted helper.
- Fixtures `sdk/guardtest/testdata/astban/{clock,ctxbg,mathrand,protojson,sentinel,enumdefault}/`
  — each with planted violations (incl. an aliased import) and a clean
  file; clock and mathrand also carry decoy/allowlist cases.
- Ledger: SPEC-000 → `Implemented` (M4 is the last milestone) + milestone
  line. `TestSpecStatuses_ReadsLedger`'s "In progress" pin updated to
  `Implemented` — the test pins exact current ledger state by design; the
  ground truth legitimately changed with this milestone.

## Scenario matrix (red = scans are stubs returning nil)

| # | Test | Expectation |
|---|------|-------------|
| 1 | clock fixture: `time.Now()` + `SetDeadline(time.Now()...)` + aliased `tm "time"` | all flagged — red while stub |
| 2 | clock decoy: package aliased AS `time` from another path calling `.Now()` | NOT flagged (green by construction; guards against name-only matching) |
| 3 | ctxbg fixture: `context.Background()` | flagged — red while stub |
| 4 | mathrand fixture: `math/rand` import; `jitter/` subdir allowlisted | bad flagged, jitter allowed — red while stub |
| 5 | protojson fixture: `encoding/json` import | flagged — red while stub |
| 6 | sentinel fixture: `errors.Is(err, sql.ErrNoRows)`, `err == sql.ErrNoRows`, aliased `dbsql` | all flagged — red while stub |
| 7 | enumdefault fixture: enum switch w/o default; w/ non-erroring default | both flagged — red while stub |
| 8 | every check's clean file | zero violations |
| 9 | G-000-3 + M2/M3 suite | unchanged green (helper extraction is behavior-neutral) |

## Out of scope

Repo-wide application of the scans (owning specs); type-checked resolution
(recorded ceiling from M2 stands); proto-descriptor enum exhaustiveness
(WIRE-4, SPEC-003).
