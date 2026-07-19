# Plan — SPEC-001 M2: boundary registry harness (G-001-2)

Milestone: SPEC-001 §9 M2 — the listener-discovery scan, the registration
API for later specs, and the join against `Boundaries` (M1). Delta only.

## Files

- `sdk/guardtest/listeners.go`:
  - `ListenerRegistrations` — map of listen/serve call-site key
    (`"<repo-rel-file>:<enclosing-func>"`) → boundary ID (`"B4"`). The
    registration API: owning specs add entries as their listeners land.
  - `ListenerSites(root)` — AST walk over non-test files of the depth-1
    modules (walkGoFiles): package-func matches resolved through
    importAliases + unwrapExpr (net.Listen*, net.FileListener, tls.Listen,
    tls.NewListener, http.ListenAndServe*, http.Serve*), plus method-name
    matches for the serve family (`ListenAndServe`, `ListenAndServeTLS`,
    `Serve`, `ServeTLS`, `Listen` on a non-package receiver — ListenConfig
    and custom servers; recorded ceiling: method matching is name-only).
  - `boundaryJoinViolations(sites, regs, boundaries)` — pure join:
    unregistered site / orphan registration / unknown boundary ID, exact
    set in both directions.
- `sdk/guardtest/listeners_test.go` — guard + liveness (below).
- `sdk/guardtest/testdata/arch/listeners/` fixture: plain net.Listen,
  aliased import, dot-import, paren-wrapped callee, unix-socket listen,
  method ListenAndServe, ListenConfig .Listen, call inside a closure, and
  a decoy package aliased as "net" (must NOT flag).

## Tests

| Test | Proves |
|---|---|
| `TestGuard_BoundaryRegistry` | G-001-2: zero discovered sites → reported dormant skip (spec: floor = current listener count, 0 today; ratchets as owning specs land); otherwise Discover floor 1 + join |
| `TestGuard_BoundaryRegistry_Liveness` | fixture: every evasion family flags at its exact line; the registered site does not; an orphan registration and an unknown boundary ID are violations; the decoy stays clean |
| `TestBoundaryJoin_Exhaustive` | pure-function proof of the three violation classes and the clean case |

Red-first: stubs (`ListenerSites`/`boundaryJoinViolations` return nil),
observe assertion-level red, then implement.

## Registration semantics

A site key covers all listen calls inside that function (ceiling: two
different-boundary listens in one function cannot be expressed — split the
function; recorded in the doc comment). Registrations must reference an
existing `Boundaries` ID — B-row parity with the spec is already guarded
by `TestGuard_BoundaryRegistryParity` (M1).

## Out of scope

Floor ratcheting to 7 (owning specs); real listeners; M3 ledger wiring.
