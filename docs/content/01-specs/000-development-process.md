---
title: "SPEC-000 — Development Process"
---
# SPEC-000 — Development Process

Status: READY FOR IMPLEMENTATION
Builds on: nothing
Enables: SPEC-001..SPEC-017 (every other spec is implemented under this process)
Module(s): all (`contract/`, `sdk/`, `server/`, `agent/`) + root tooling (`scripts/`, CI)

## 1. Scope

Defines HOW every other spec in this repository is implemented: the feature
pipeline (DISCUSS → SPEC → TEST(red) → IMPLEMENT → VERIFY → DOCUMENT), the TDD
mandate, the guard doctrine, the complete cross-cutting invariant catalog
[INV-1..INV-19] as the normative guard list, and the session/verification
discipline anchored on `scripts/verify.sh`. Product behavior lives in
SPEC-001..017; this spec owns process and guards.

## 2. Context capsule

Power Manage is a Linux device-management system built from scratch: an
event-sourced control server (single writer to Postgres), a stateless gateway
relay, a root agent with offline autonomy, an SDK (OS capability library), and a
wire-contract module. Priorities: security first, simplicity second, features
third; between two equally secure designs, the one with less code and fewer
concepts wins.

The predecessor system accreted through rapid iteration: duplicated proto
shapes, two coexisting eras of gateway trust, five hand-rolled signing schemes,
fail-open branches patched one at a time, and validation drift between sibling
components. This project's job is to make those recurring bug classes
**structurally impossible**, not individually patched. That is why every
invariant below ships with a build-failing guard, never a code-review habit.

## 3. Requirements

### 3.1 Meta-rules

- **[META-1]** Spec → failing test → implementation, per feature. No code
  without numbered acceptance criteria; no acceptance criterion without a test
  that failed first.
- **[META-2]** Every invariant in §3.4 ships with a **self-discovering** fitness
  test (AST scan, registry walk, proto-descriptor walk) carrying a matches-zero
  guard and, where applicable, a liveness probe. Hand-maintained lists of
  files/handlers/fields are forbidden — they go stale and fail open.
  Lesson: a hand-built audit-redaction type map drifted from the real emitters
  and became dead code — secrets flowed unredacted while its tests stayed green.
  Lesson: hand-wired CI lanes silently dropped test-bearing packages from CI.
- **[META-3]** V1 clean breaks. No compatibility shims, no deprecation aliases,
  no `reserved` proto markers (re-tag in place), no "coming later" fields or UI
  stubs. Invalid states are made unrepresentable rather than documented as
  ignored. Flexibility is a clean SEAM (an interface at a boundary, a probed
  capability, a table-driven registry) — never OPTIONALITY (config knobs,
  fallback backends, "just in case" paths): build the seam, implement exactly
  one thing behind it. Lesson: reserved enum values with no implementation
  behind them shipped in the old contract and became standing validation traps;
  an enum value exists only WITH its implementation.
- **[META-4]** No AI attribution anywhere: commits, PRs, comments, docs.

### 3.2 The pipeline

- **[PROC-1]** Every feature follows DISCUSS → SPEC → TEST(red) → IMPLEMENT →
  VERIFY → DOCUMENT [TEST-1]:

| Stage | Obligation |
|---|---|
| DISCUSS | Clarify until the design is unambiguous. Questions that a spec cannot answer go to the operator before any code exists. |
| SPEC | Write/extend a spec in `docs/content/01-specs/` using the template of this file (§1–§10): numbered requirements, acceptance criteria AC-1..N, a rejection-paths table, a test plan, guards, milestones. |
| TEST (red) | Derive tests from the acceptance criteria. Confirm they FAIL, red for the RIGHT reason — verified by a scoped neutralizing edit, never a revert. |
| IMPLEMENT | Minimal code to green. Commit incrementally. |
| VERIFY | Run `scripts/verify.sh` (§3.6). All gates green before the change is done. |
| DOCUMENT | Update docs; anchor every behavioral claim about code (docref); record significant decisions as ADRs; record knob rationale (INV-18, SPEC-002). |

- **[PROC-2]** Rules marked "recorded decision" anywhere in SPEC-001..017 are
  settled operator decisions. Do not re-litigate them, do not "improve" them, do
  not re-propose rejected alternatives. Changing one requires an explicit
  operator decision recorded as an ADR.

### 3.3 Guard doctrine

- **[PROC-3]** A guard is a build-failing fitness test with ALL of these
  properties:
  1. **Self-discovering**: it enumerates its subjects (handlers, tables, enums,
     fields, packages, RPCs) from a registry, descriptor, AST, or directory
     walk — never from a hand-maintained list [META-2].
  2. **Matches-zero protected**: a discovery step that returns zero subjects
     FAILS the guard. An empty result means the discovery broke, not that the
     codebase is clean.
  3. **Liveness-probed** where applicable: a fixture containing a deliberate
     violation must be detected, proving the guard can still go red.
  4. **Co-shipped**: the guard lands in the same change as the first
     implementation of its invariant — never as a follow-up.
  5. Deny-lists inside guards are tested against a **test-owned threat model**,
     never by iterating the implementation's own set. Lesson: a protected-path
     test iterated the implementation's own deny-set and could never catch a
     missing entry.

### 3.4 Invariant catalog [INV-1..INV-19] — the normative guard list

Each entry is rule + enforcement guard. All guards obey [PROC-3]. This is the
list an implementer builds guards for FIRST.

**Fail-closed (the #1 historical bug class)**

- **[INV-1]** Every deserialization/DB/crypto error in a request, dispatch, or
  persisted-security-state path returns an error — never proceeds with
  nil/empty/default. Guard: error-return lint + targeted behavioral tests per
  boundary. Lesson: cached-state decode failures that defaulted to permissive
  turned corrupt files into policy bypasses.
- **[INV-2]** Every enum switch has an erroring `default`; an exhaustiveness
  guard walks the proto descriptor (WIRE-4, SPEC-003).
- **[INV-3]** Disabled security gates do not exist silently: a nil
  verifier/resolver/sealer is a boot failure; sanctioned bypasses are explicit
  named configuration. Lesson: a "no resolver wired → skip the binding check"
  nil-check ran fail-open in production; the gate was off and nothing said so.
- **[INV-4]** Availability-critical loops self-heal: validation/config errors
  are fatal at boot; transient errors retry with backoff and periodic re-warn.
  Lesson: a relay treated a transient registration failure as one-shot and left
  terminal access dead for five days (GW-5, SPEC-012).

**Identity, signing, secrets**

- **[INV-5]** Signed bytes == executed bytes; single representation; sign at
  one seam; framed, length-prefixed, domain-separated preimages. Guards:
  signature-over-deterministic-proto tests, a no-unframed-hash-preimage scan,
  and domain round-trip + pairwise-isolation tests over self-discovered
  `*SignatureDomain` constants. Lesson: a second canonical-JSON representation
  of commands diverged from the signed proto bytes — the agent acted on bytes
  the signature never covered.
- **[INV-6]** Every control→agent surface is CA-signed with freshness
  (WIRE-14/15, SPEC-003); every device→control report is device-signed
  (WIRE-20, SPEC-003). Wiring-parity guard: every signature domain has a sign
  site AND a fail-closed verify site, across modules.
- **[INV-7]** No plaintext secret transits the relay, lands in events, or
  appears in logs/audit (sealed transport WIRE-23/24 SPEC-003; redaction
  schemas AUD-3, SPEC-011). No secrets in URL query params; tokens hashed at
  rest. Lesson: disk-encryption passphrases historically transited the relay in
  plaintext, both directions.
- **[INV-8]** One AEAD format (`enc:v1`, AAD-bound); encryption at rest is
  mandatory — no opt-out knob exists (recorded decision); constant-time
  compares for every secret/MAC; `crypto/rand` only; `math/rand` banned outside
  a jitter allowlist; ULID only, never UUID (SDK-13, SPEC-004).
- **[INV-9]** Certificate identity only (WIRE-18/19, SPEC-003); certificate
  authority state is DER-derived from the stored certificate, never trusted
  from projections; proof-of-possession on renewal; per-device advisory lock on
  lifecycle operations; version-pinned token consume (PKI-2..4, SPEC-006).
  Lesson: N racing enrollments against a bounded-use token minted more devices
  than permitted — an auto-retrying append is designed to defeat the optimistic
  lock.

**Authorization**

- **[INV-10]** validate → authenticate → authorize → work, everywhere, at the
  interceptor AND the handler (guarded per-RPC); every RPC classified
  (public / permission / alt-auth); every confinable permission
  handler-enforced under scoped grants (AUTHZ-3, SPEC-008); every self-scoped
  grant rejects cross-user access; uniform NotFound for cross-actor access,
  with one recorded exception: execution/log handlers return PermissionDenied
  for scoped callers — keep it, documented (AUTHZ-5, SPEC-008). Scope
  enforcement is proven behaviorally against the real backend, never by
  presence-based type-level checks. Lesson: list/dispatch handlers passed a
  type-level authorization check while their queries applied no scope filter.
- **[INV-11]** Every admin-removing handler takes the last-admin advisory lock
  (self-discovering coverage guard); the count includes enabled,
  group-inherited admins and is atomic with the mutation. The role-management
  permission is the SOLE grant gate — no grant-subset ceiling (recorded
  decision; do not re-add).

**Event store**

- **[INV-12]** Total table classification; replay is 1:1; rebuild computes the
  FK-cascade closure; projections are written only by projectors (guarded); no
  dynamic SQL (guarded); every mutation reaches `AppendEvent*` — guaranteed by
  composition of the previous two, not by a name heuristic; event payloads are
  golden-corpus pinned (ES-1..9, SPEC-005). Lesson: "event didn't persist but
  the RPC returned OK" is the double-spend class; a primary-mutation append
  failure fails the RPC.
- **[INV-13]** Not-found detection uses the store's recognizer
  (`store.IsNotFound`-style), never raw `errors.Is(err, Sentinel)` or
  `sql.ErrNoRows` comparisons. Guard: AST scan banning sentinel comparisons
  outside the recognizer package, matches-zero protected. Lesson: raw sentinel
  comparisons never matched driver-returned errors, so the graceful not-found
  branch was dead code under a green suite.

**Request boundary**

- **[INV-14]** Size caps on every handler surface, pagination-offset ceilings,
  DB statement timeouts + per-handler deadlines, parser recursion caps, output
  budgets with explicit truncation markers (LIM-1/2, SPEC-009); no
  `context.Background()` in request paths — detached work uses
  `WithoutCancel` + timeout, allowlisted by function; panic recovery on every
  background goroutine and dispatch loop.
- **[INV-15]** The rate-limit ladder covers every public procedure
  (descriptor-walk guard); anti-enumeration timing/content parity is tested
  (AUTH-4/5, SPEC-007).

**Time, locale, codecs**

- **[INV-16]** No unabstracted `time.Now()` — a clock seam everywhere,
  including `SetDeadline`; UTC instants everywhere, never string-compared
  times (lesson: schedule times stored as strings misordered across formats);
  C-locale Runner invariant (lesson: localized tool output broke parsers on
  non-English systems — SDK-3, SPEC-004); protojson only; stdlib
  `encoding/json` on a proto message is a build failure (guarded).

**Web (separate repo; listed for catalog completeness)**

- **[INV-17]** Every `.catch()` logs at ≥ debug (guarded scan); no
  `crypto.randomUUID()` (guarded); CORS is a fail-closed allowlist; auth model
  per AUTH-9 (SPEC-007): Bearer + refresh rotation with reuse detection +
  strict CSP/Trusted Types.

**Configuration**

- **[INV-18]** No env-config sprawl: each binary has ONE typed config struct as
  the single source of truth, loaded from one file; env overrides exist but
  their names are DERIVED mechanically from the struct (`PM_<SECTION>_<KEY>`) —
  no hand-registered env var anywhere. Unknown config key or unrecognized
  `PM_*` variable = boot failure (typos and stale knobs fail closed, never
  silently ignored). Reference config docs are GENERATED from the struct; a
  knob that exists but is never read cannot survive the generator. Secrets are
  never config VALUES — file-path indirection only. Adding a knob requires a
  recorded rationale; the default is convention over configuration ([META-3]:
  seams, not optionality). Mechanics: SPEC-002.

**Module boundaries & licensing**

- **[INV-19]** Directional in-repo import allowlist: `contract` imports no
  in-repo module; `sdk` imports no in-repo module; `agent` imports only
  {`contract`, `sdk`}; `server` imports only {`contract`, `sdk`}. Enforced by
  an archtest that DISCOVERS modules and packages from the repo layout (never a
  hand-maintained list), matches-zero protected. This guard is simultaneously
  the architecture boundary and the licensing boundary: an `agent`→`server`
  import would silently turn the GPL agent binary AGPL. The proto-purity
  archtest (SDK-0, SPEC-002) is a separate, narrower check.

### 3.5 TDD core rules

- **[TEST-1]** Pipeline per feature as in [PROC-1]: spec (numbered ACs,
  rejection-path table) → tests written from ACs, confirmed FAILING red for the
  right reason via a scoped neutralizing edit, never a revert → minimal
  implementation → verify gate → docs/ADR.
- **[TEST-2]** Handler tests use REAL Postgres (testcontainer, template-cloned
  per test) and REAL handlers — never mocks or stubs of either.
  Correct/absent/wrong coverage for every request field, where "wrong" violates
  the field's validate tag. A rejection-path test for every authorization gate:
  unauthenticated, wrong role, self-scope override attempt, scoped-grant
  denial, cross-actor → NotFound.
- **[TEST-3]** CI gates the FULL unit + arch suite under `-race`; a
  self-discovering CI-lane guard proves every test-bearing package runs in some
  workflow (matches-zero protected).
- **[TEST-5]** Tests must fail when the control is absent: no fixtures derived
  from the implementation's own artifacts, no uid-gated branches that never
  run, no assert-first-element-only. Documentation claims about controls are
  doc-anchored and behaviorally tested.
- **[TEST-8]** Every bug fix ships a regression test that fails on the buggy
  version. Findings from delegated audits are re-verified against the actual
  code before being acted on.

The remaining testing doctrine — container-based SDK system tests, non-English
locale lanes, the deployment E2E gate, release provenance — is SPEC-017.

### 3.6 Session and verification discipline

- **[PROC-4]** `scripts/verify.sh` is the canonical verification gate. It runs,
  across all modules: `go vet`, `staticcheck`, the full test suite under
  `-race`, the entire guard suite, doc-anchor checks, and generated-artifact
  freshness checks. Exit is nonzero on any failure. CI runs it on every PR;
  merge is blocked on red.
- **[PROC-5]** A session works ONE milestone at a time, from one spec's §9,
  and every milestone ends with a green `scripts/verify.sh` before the next
  begins; a session that has merged its milestone green may take the next one.
  A session never ends red: finish to green or restore the last green state.
  Milestones are sized so this is possible.
- **[PROC-6]** **Porting from the predecessor.** This system re-implements a
  working predecessor. When a predecessor checkout is available and its code
  already satisfies a milestone's requirements, porting that code and its
  tests is the PREFERRED implementation route — re-deriving proven mechanism
  from prose is waste, and the predecessor's test estates (tool-fidelity and
  container suites especially) are encoded ground truth that transfers
  regardless of implementation. Porting changes where the implementation text
  comes from, never the gate: acceptance criteria, guards, and red-first
  discipline apply unchanged, with ported tests proven red via scoped
  neutralizing edits [TEST-1]. Where ported code and this spec series
  disagree, the spec wins — fix the port, never relax the spec. Every spec
  remains implementable standalone; porting is an optimization, never a
  dependency.

## 4. Acceptance criteria

- **AC-1** `scripts/verify.sh` exists at the repo root, runs vet, staticcheck,
  the full `-race` suite, the guard suite, and freshness checks over every
  module, and exits nonzero when any check fails.
- **AC-2** CI executes `scripts/verify.sh` on every PR and blocks merge on
  failure; the CI-lane guard [TEST-3] discovers all test-bearing packages and
  fails when it discovers zero.
- **AC-3** The guard harness provides a discovery + matches-zero helper; a
  guard whose discovery returns an empty subject set fails the build.
- **AC-4** Every guard has a liveness self-test: a fixture containing a
  deliberate violation is detected.
- **AC-5** A machine-readable invariant registry lists INV-1..INV-19 with
  owning spec and registered guard(s); a completeness test fails when an
  invariant whose owning spec is implemented has no registered guard.
- **AC-6** The spec template (§1–§10 of this file) is checked in; every feature
  PR names the spec section and AC IDs it implements (auditable in review).
- **AC-7** A portable AST-guard library exists with fixture self-tests for:
  clock seam (no unabstracted `time.Now()`, including `SetDeadline`), protojson
  only, no `context.Background()` in request paths, sentinel-comparison ban
  [INV-13], `math/rand` ban, enum-switch erroring default.
- **AC-8** Every bug fix merged after this spec lands carries a regression test
  demonstrated red on the pre-fix code [TEST-8] (auditable in review).

## 5. Rejection paths

| Input / state | Required behavior |
|---|---|
| Code change with no governing spec section + AC | Not merged; write or extend the spec first [META-1] |
| New test first observed green (never seen red) | Rework: prove red via a scoped neutralizing edit, never a revert [TEST-1] |
| Guard implemented as a hand-maintained list | Not merged [META-2] |
| Guard discovery returns zero subjects | Build failure (matches-zero), never a silent pass [PROC-3] |
| Invariant implementation without its guard in the same change | Not merged [PROC-3] |
| Bug fix without a fails-on-buggy-version regression test | Not merged [TEST-8] |
| Attempt to re-litigate a recorded decision | Rejected in review; only an operator ADR changes it [PROC-2] |
| Attribution trailer or disclosure in any commit/PR/comment/doc | Not merged [META-4] |
| Session ending with a red verify gate | Not permitted: finish to green or restore last green [PROC-5] |
| Compatibility shim, deprecation alias, `reserved` proto marker, "coming later" field | Not merged [META-3] |
| Config knob without recorded rationale | Not merged (INV-18, SPEC-002) |
| Mocked Postgres or stubbed handler in a handler test | Not merged [TEST-2] |

## 6. Test plan (TDD)

Write FIRST, confirm red, then implement:

1. **Harness tests**: matches-zero helper fails on empty discovery; the
   liveness-fixture pattern detects a planted violation; both red before the
   helper exists.
2. **verify.sh tests**: an injected failing check propagates to a nonzero exit;
   a module added to the repo is picked up without editing the script
   (self-discovering module walk).
3. **Invariant-registry completeness test**: red when a registered-as-implemented
   invariant has no guard; the neutralizing edit is removing one guard
   registration.
4. **AST-guard library**: each guard's violation fixture is its standing red
   proof; the guard test asserts detection AND asserts a clean fixture passes.

Real-backend rule: tests in this spec are pure Go/tooling tests. Behavioral
invariant tests (scope enforcement, fail-closed paths) land with their owning
specs against real Postgres per [TEST-2].

## 7. Guards

| Guard | Discovery | Matches-zero floor |
|---|---|---|
| G-000-1 invariant-coverage ledger | Walks the machine-readable INV registry; joins against registered guards | Registry must contain exactly INV-1..INV-19 |
| G-000-2 CI-lane completeness [TEST-3] | Walks the repo for test-bearing packages; asserts each runs in some workflow | ≥1 test-bearing package |
| G-000-3 guard-API conformance | AST walk over the guard suite; every guard uses the discovery + matches-zero helper | ≥1 guard discovered |
| G-000-4 verify.sh module walk | Discovers modules from the repo layout; asserts each is covered by every gate stage | ≥4 modules |

## 8. Historical lessons

- A hand-built redaction type map drifted from real emitters and became dead
  code; secrets went unredacted under a green suite. Guards must be
  self-discovering and derive from the real emit path.
- Hand-wired CI lanes silently dropped test-bearing packages; the lane list is
  discovered, never maintained.
- Reserved/aspirational enum values shipped without implementations and became
  validation traps; the contract contains only implemented values.
- A nil-check "resolver not wired → skip check" ran fail-open in production; an
  unwired security dependency is a boot failure.
- Raw error-sentinel comparisons never matched driver-returned errors; the
  not-found branch was dead. Recognizer functions only.
- List/dispatch handlers passed presence-based type-level authorization checks
  while applying no scope filter; enforcement is proven behaviorally.
- Racing consumes of bounded-use tokens over-minted devices; one-time consumes
  use expected-version CAS, never auto-retrying appends.
- A second serialized representation diverged from the signed bytes; sign one
  representation at one seam and execute exactly the verified bytes.
- A deny-list test iterated the implementation's own set and could never catch
  a missing entry; deny-lists are tested against a test-owned threat model.
- A relay treated a transient registration failure as one-shot and caused a
  multi-day terminal outage; availability-critical loops self-heal with
  periodic re-warn.
- "Event didn't persist but the RPC returned OK" caused double-spend bugs; a
  primary-mutation append failure fails the RPC.

## 9. Milestones

Each milestone is one implementation session and ends with a green
`scripts/verify.sh`.

1. **M1 — Verification gate**: `scripts/verify.sh` with self-discovering module
   walk + CI wiring (AC-1, AC-2 minus the lane guard).
2. **M2 — Guard harness**: discovery helpers, matches-zero enforcement,
   liveness-fixture pattern, G-000-3 (AC-3, AC-4).
3. **M3 — Invariant registry**: machine-readable INV-1..19 registry, coverage
   ledger G-000-1, CI-lane guard G-000-2 (AC-5).
4. **M4 — Portable AST guards**: clock seam, protojson-only, context.Background
   ban, sentinel-comparison ban, math/rand ban, enum-default guard, each with
   violation fixtures (AC-7).

## 10. Out of scope

- The deployment E2E gate, container test lanes, locale lanes, and release
  provenance (SPEC-017).
- Per-boundary behavioral tests — they land with their owning specs.
- Repo layout, licensing, and config-loader mechanics (SPEC-002) — INV-18/19
  are cataloged here, implemented there.
- The web repository (separate repo, separate flow); INV-17 is listed for
  catalog completeness and enforced in that repo.
