# SPEC-004 M1 — Skeleton + guards G-1..G-9

Milestone: SPEC-004 §9 M1. Mechanical milestone (guard wiring over the
existing SPEC-000 M4 astban primitives); tests written from the matrix
below. Delta only; the spec is authoritative.

## Scope

Guards G-1..G-9 of SPEC-004 §7, each proven red via scoped fixtures then
green. The module layout half of M1 is already satisfied (SPEC-002 M1);
no new sdk packages land here — capability packages arrive M2+.

## Recorded mechanical choices

1. **Three guards are the existing estate, reused as-is.** G-1 proto
   purity = `TestGuard_ProtoPurity` (G-002-2; `connectrpc.com` already in
   `protoImportPrefixes`). G-2 env hygiene = `TestGuard_EnvHygiene`
   (G-002-4; bans `os.Environ` repo-wide; its allowlist comment already
   reserves the M2 Runner child-env builder). G-8 directional imports =
   `TestGuard_DirectionalImports` (G-002-1, INV-19-registered). No new
   code for these; the plan records the mapping so G-4..G-9 numbering
   stays greppable against SPEC-004 §7.
2. **New guards live in `sdk/guardtest/sdkcore.go` + `sdkcore_test.go`**
   (same flat package as every other guard; sdk package floor stays 1).
   Scans compose the astban primitives; no new scan engine.
3. **G-3 randomness**: `BannedImports(sdkRoot, "math/rand")` +
   `BannedImports(sdkRoot, "math/rand/v2")`. Jitter allowlist is EMPTY at
   M1 — the jitter package does not exist; its path is added (with
   rationale) in the milestone that creates it. The spec's "≥1 crypto
   call site" liveness floor arms at M5 when `sdk/crypto` lands; until
   then the population floor is the scanned-file count (≥1, satisfied by
   the existing sdk packages). Scope-ceiling comment on the guard.
4. **G-4 regex chokepoint**: discover `regexp.Compile`/`MustCompile`
   call sites across sdk (floor ≥1 — two exist today); every site must be
   under the ReDoS-guard package path (`sdk/redos`, lands M2) or in the
   decl-keyed allowlist (receiver-qualified for methods — a PR #20 review
   finding closed the same-name collision). Allowlist at M1: exactly
   `secrets.go` vars `secretNameRe`, `secretPathSuffixRe` — compile-time
   literal patterns owned by the guard suite, never operator input; each
   entry carries that rationale inline.
5. **G-5 preimage framing, M1 form**: import-level ban —
   `crypto/sha256`, `crypto/sha512`, `crypto/hmac` are banned in sdk
   outside the future `sdk/crypto` package path. Per-construction
   lp/domain-helper enforcement INSIDE `sdk/crypto` is the M5 extension
   (asserted there per hash/MAC construction); the M1 ban guarantees no
   hash/MAC surface can grow outside the package the M5 guard will walk.
   Scope-ceiling comment records the two halves.
6. **G-6 no nil-AAD API, AST form**: the spec's mechanism column says
   "reflection walk", which requires importing `sdk/crypto` — a package
   that must not exist until M5 — and cannot be exercised against
   violation fixtures (a test cannot link a deliberately-wrong API).
   Implemented instead as an AST walk over exported functions in the
   `sdk/crypto` path whose name contains `Seal` or `Open`: each must
   carry a parameter named `aad`. Same population, same demand,
   fixture-testable; fail-closed direction (a differently-named AAD
   parameter is flagged, never silently passed). The walk covers
   functions, methods, and interface method declarations (the last added
   red-first for a PR #20 review finding). Dormant
   (`t.Skipf`) until `sdk/crypto` exists — the GatewayPurity pattern —
   with fixture liveness meanwhile.
7. **G-7 mutation chokepoint**: `BannedCalls` over sdk for the path-based
   mutation set — `os.` {`Chmod`, `Chown`, `Lchown`, `Rename`, `Remove`,
   `RemoveAll`, `Truncate`, `WriteFile`, `Symlink`, `Link`, `Mkdir`,
   `MkdirAll`, `Create`, `CreateTemp`, `MkdirTemp`, `Chtimes` (the last
   three added red-first for a PR #20 review finding)} — allowed only
   under the future fd-anchored
   helpers path (`sdk/fsafe`, lands M3; allow-prefix recorded now, empty
   population until then). Recorded ceiling: `os.OpenFile` stays legal
   everywhere — it is the fd-anchored primitive itself; a non-helper
   `OpenFile` with `O_CREATE|O_TRUNC` clobber flags is caught at M3 when
   the helpers land and review anchors on the allow-prefix, not here.
8. **G-9 clock seam**: `BannedCalls(sdkRoot, "time", "Now")`. No separate
   `SetDeadline` scan: a seamless `SetDeadline` is caught at its
   `time.Now(...)` argument (the astban clock fixture already plants
   exactly that case); a deadline computed from the injected clock is
   legal. Zero sites today — green with the file-count floor.
9. **Registrations now, halves recorded.** `Guards: INV-8.` on the
   randomness guard (ULID-not-UUID and crypto/rand-error halves arm at
   M5 with `sdk/crypto`); `Guards: INV-16.` on the clock-seam guard
   (C-locale Runner half arms at M2; the protojson half is SPEC-003's
   G-6). G-000-1 demands these only when SPEC-004 flips Implemented
   (M7); registering at M1 with scope ceilings preempts that red the
   same way SPEC-003 M5 did.
10. **Fixtures**: G-3/G-9 liveness rows reuse the proven
    `testdata/astban/{mathrand,clock}` roots. New roots
    `testdata/sdkcore/{regexploose,hashout,aad,mutation}` plant: a bare
    `MustCompile` outside the chokepoint (+ aliased-import variant); a
    `sha256.Sum256` outside the crypto path; seal/open functions
    missing `aad` beside a clean one and an unexported decoy; an
    `os.Chmod` + aliased `os.Rename` beside an `os.OpenFile` decoy.

## Files

- `sdk/guardtest/sdkcore.go` — new: `randomnessViolations`,
  `regexChokepointViolations` (+ decl-keyed allowlist),
  `hashImportViolations`, `aadAPIViolations`,
  `mutationChokepointViolations` (+ banned-call set), `clockViolations`.
- `sdk/guardtest/sdkcore_test.go` — new: `TestGuard_Randomness` (+
  `_Liveness`), `TestGuard_RegexChokepoint` (+ `_Liveness`),
  `TestGuard_PreimageFraming` (+ `_Liveness`), `TestGuard_SealAADSurface`
  (dormant + `_Liveness`), `TestGuard_MutationChokepoint` (+
  `_Liveness`), `TestGuard_ClockSeam` (+ `_Liveness`).
- `sdk/guardtest/testdata/sdkcore/...` — fixture roots (choice 10).
- `docs/content/01-specs/00-index.md` — SPEC-004 → In progress (M1
  done); milestone line.

## Test authorship

Mechanical milestone: rows from the matrix above, written red-first —
each `_Liveness` row proven by `RequireViolation` against its fixture;
each armed guard red-checked by a scoped neutralizing edit (drop one
banned name / blank one allowlist rationale key), observed failing for
the right reason, restored.
