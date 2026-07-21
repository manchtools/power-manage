---
title: "SPEC-005 — Event Store"
---
# SPEC-005 — Event Store

Status: See `00-index.md` (single status ledger)
Builds on: SPEC-000 (development-process), SPEC-001 (architecture-and-trust-model), SPEC-002 (repo-module-and-config-contract), SPEC-003 (wire-contract)
Enables: SPEC-006, SPEC-007, SPEC-008, SPEC-009, SPEC-010, SPEC-011, SPEC-012, SPEC-016
Module(s): server

## 1. Scope

The storage contract of the control server: the append-only `events` table and its
key design, in-transaction Go projectors, total table classification, the three
append APIs and their mandatory-use rules, replay and rebuild, Postgres work tables
as the only asynchronous mechanism, golden-corpus event-payload pinning, the
inventory snapshot tier, and the operational-telemetry tier.

## 2. Context capsule

Minimum prior knowledge, restated:

- Control is the sole Postgres writer; HA is active/standby, never active/active
  (TM-3, HA-1, SPEC-001). Postgres is the ONLY datastore — no queue product, no
  cache tier, no second search store. Anything durable is a Postgres table.
- Durable buffering lives at the edges (TM-1, SPEC-001): desired state in the
  event store, unshipped device results in the agent's local store. No middle tier
  may hold state a restart can lose.
- All singleton/background work in control acquires a Postgres advisory lock via
  one uniform helper (HA-1, SPEC-001), so a second control instance is
  safe-by-construction. No process-local timers that silently assume one instance.
- Proto payloads use deterministic serialization only; stdlib `encoding/json` on a
  proto message is a build failure (WIRE-10, SPEC-003). IDs are bare ULID strings
  (WIRE-5, SPEC-003).
- Failure recognition uses store recognizer helpers (`store.IsNotFound`-style),
  never raw `errors.Is(err, Sentinel)` or `sql.ErrNoRows` comparison [INV-13]:
  generated and driver queries return raw backend errors, so a direct sentinel
  comparison silently never matches and its branch is dead.
- The event store doubles as the audit log. Audit semantics, redaction, and
  retention policy are specified in SPEC-011; this spec provides the substrate.
- Guards are self-discovering with matches-zero protection (META-2, SPEC-000):
  hand-maintained lists of tables/types/handlers are forbidden — they go stale and
  fail open.
- **Defended actors:** external unauthenticated and low-privilege callers must
  not inject, overwrite, or observe state outside their authority; a compromised
  relay has no event-store write path.

## 3. Requirements

### 3.1 The `events` table (normative schema contract)

Every state change is an immutable row in `events`. Reads come exclusively from
projections; no request path reads state from `events` except audit/history reads
and replay/rebuild.

Minimum columns: `stream_type`, `stream_id` (ULID), `stream_version`,
`event_type`, versioned payload bytes, created-at timestamp. Constraint:

```
UNIQUE (stream_type, stream_id, stream_version)
```

The three-column key is load-bearing, not ceremony:

| Column | Load it bears |
|---|---|
| `stream_id` | Entity key: audit filtering, per-entity history, single-entity rebuild |
| `stream_version` | Makes one-time consumes race-free (ES-4) and per-stream replay order deterministic |
| `stream_type` | Namespaces streams; keys the projector registry and rebuild targets |

A global bigserial cannot serve either role: sequence order ≠ commit order under
concurrent transactions, and CAS needs a per-entity version to pin. A surrogate
key MAY exist for pagination but is never an ordering or replay authority. Do not
"simplify" these columns away.

### 3.2 Projection model (why in-transaction Go projectors)

Projectors are Go functions that run INSIDE the append transaction:

- Not PL/pgSQL triggers — untestable, wrong language.
- Not post-commit listeners — the root of the wiring-order, watermark-drift, and
  crash-window bug families.
- Event insert and projection update commit atomically or not at all. Eventual
  consistency between an event store and its read model is only forced when they
  live in different stores; here they don't, so it is not.

### 3.3 Requirements [ES-1..12]

- **[ES-1] Total table classification.** Every Postgres table is exactly one of:
  1. `events`;
  2. a **projection** with a registered rebuild target;
  3. a **work table** (ES-8/ES-11);
  4. an **operational-telemetry table** (ES-12);
  5. a **content-addressed artifact table** (ART-1, SPEC-010) — non-replay-derivable
     by design: events pin `(sha256, size)` references only; deletion is governed
     by artifact GC (ART-3, SPEC-010), never by replay;
  6. migration-tool bookkeeping (goose);
  plus the single sanctioned non-replay exception `user_encryption_keys` (per-user
  DEKs, excluded from replay so crypto-shred is real deletion — SPEC-011). A
  schema-walking guard makes an unclassified table unmergeable.

- **[ES-2] Replay is 1:1.** Rebuilding any projection from events into an empty
  schema reproduces it byte-for-byte. Therefore: no projection column is ever
  written in place outside a projector; every value a projector writes is
  derivable from event payloads; every stream type with a registered projector has
  a rebuild target.

- **[ES-3] Rebuild FK closure.** `RebuildAll(target)` computes the FK-cascade
  closure and auto-includes — or refuses to run against — every table it would
  otherwise silently wipe: a `users` rebuild must not destroy SSO links or API
  tokens. Rebuild is a CLI-only recovery tool; no RPC exists for it.

- **[ES-4] Append API discipline.** Exactly three append APIs exist:

  | API | Semantics | Mandatory for |
  |---|---|---|
  | `AppendEvent` | Auto-versioning; retries past unique-violation (23505) | Independent facts only |
  | `AppendEventWithVersion` | Expected-version CAS; a version conflict surfaces to the caller and is NEVER auto-retried | Every one-time / bounded-use consume: registration tokens, break-glass login URLs (AUTH-3, SPEC-007), certificate renewals (PKI-3, SPEC-006) |
  | `AppendEvents([]Event)` | One transaction, all-or-nothing | Every multi-event operation (user+roles, SCIM group+mapping, SSO auto-create); a compound fact MAY instead be one compound event (e.g. `UserCreatedWithRoles`) |

  An auto-retrying append is *designed* to defeat an optimistic lock; using
  `AppendEvent` for a bounded-use consume is therefore a correctness bug, not a
  style choice.

- **[ES-5]** A primary-mutation append failure fails the RPC. "Event didn't
  persist but we returned OK" is the double-spend class.

- **[ES-6]** Delete/downgrade projectors carry `projection_version` guards so
  out-of-order replay cannot wipe newer rows.

- **[ES-7] In-tx projection mechanics.** One table-driven registry maps event type
  → projector function; `AppendEvent*` invokes the registered projectors on the
  SAME transaction before commit. Appending an event type with no registered
  projector is a HARD ERROR in the same call — a boot-order or wiring-order gap is
  unrepresentable, not merely tested. A projector error aborts the transaction:
  event and projection can never diverge, so watermark/drift monitoring reduces to
  a doctor sanity check (OPS-1, SPEC-016), not an operational necessity.
  Replay/rebuild calls the exact same projector functions.

- **[ES-8] Async work is the exception, and it is a Postgres work table.**
  Expensive derived computation (dynamic-group evaluation) and future-dated work
  (scheduled one-shot dispatch, retention prune, stale-execution expiry, pending
  instant-command delivery with TTL — GW-4, SPEC-012) are NOT projections: the
  append transaction writes a work row (outbox pattern — atomic with the event),
  and an advisory-lock worker drains it via `SELECT … FOR UPDATE SKIP LOCKED`
  using `run_at` / `attempts` / `next_attempt_at` columns. Exhausted attempts stay
  queryable in SQL and surface in the doctor and the admin UI — dead-letter triage
  is a WHERE clause, not a session in some queue product's CLI. Server-side
  `run_at` exists ONLY for control-plane jobs and for minting one-shot fan-outs;
  device-targeted timing ("run this at 02:00") belongs to the agent scheduler via
  the signed manifest (SPEC-012, SPEC-013) — a server-side delayed dispatch cannot
  be correct for offline devices.

- **[ES-9]** Event payloads are versioned, with a golden-corpus test pinning every
  event type's serialized form. Built in from day one.

- **[ES-10]** Inventory is the one latest-snapshot-replaces surface (not
  event-sourced history) — an explicit, documented tiering decision, enforced by
  classifying its table as a projection of a dedicated snapshot event carrying
  only the latest state.

- **[ES-11]** Work tables are enumerated, bounded, and derived: each row's
  *intent* is derivable from an event (e.g. `DispatchScheduled`), while runtime
  columns (`attempts`, `next_attempt_at`) sit explicitly outside the replay
  guarantee, like `user_encryption_keys`. Workers run projector-grade discipline:
  `context.WithoutCancel` + timeout + `recover()`.

- **[ES-12] Operational-telemetry tier.** Execution output bodies and terminal
  recordings are operational data, NOT events. Lifecycle facts (created,
  completed, status, truncation) are events. Execution-output bodies live in
  bounded, prunable operational tables; terminal-recording bodies live in the
  artifact store as sealed ciphertext (ART-4, SPEC-010; sealing and access rules
  in AUD-8, SPEC-011), with the ES-12 retention window supplying the
  "past retention" input to artifact GC (ART-3, SPEC-010). Retention classes:
  compliance-linked output is evidence and retained per policy; everything else
  defaults to a short operator-configurable window. This deletes the
  output-bodies-in-events bloat class at the root.

## 4. Acceptance criteria

- **AC-1** The `events` table enforces `UNIQUE(stream_type, stream_id,
  stream_version)`; two concurrent appends to the same stream version conflict at
  the database, and exactly one commits.
- **AC-2** Appending an event whose type has no registered projector returns a
  hard error from the same call; neither the event nor any projection row
  persists.
- **AC-3** A projector returning an error aborts the entire transaction: no event
  row, no projection write, and the calling RPC fails.
- **AC-4** A successful append is immediately visible in its projection to the
  next statement in the same transaction and to all subsequent transactions
  (read-after-write; no reconcile loop exists).
- **AC-5** The classification guard walks the live schema, classifies every table
  into exactly one ES-1 class (or the named exception), fails on any unclassified
  table, and fails if it discovers zero tables (matches-zero).
- **AC-6** For every projection: replay of the full event history into an empty
  schema reproduces the projection byte-for-byte (row-set equality including
  column values).
- **AC-7** `RebuildAll` on a table with FK dependents either includes the full
  closure in the rebuild or refuses with an explicit error naming the dependent
  tables; it never silently cascades.
- **AC-8** N concurrent consumers of a bounded-use resource (e.g. a `max_uses=1`
  registration token) using `AppendEventWithVersion` yield exactly the permitted
  number of successes against real Postgres; the losers receive a version-conflict
  error, not a retry.
- **AC-9** `AppendEvents` is all-or-nothing: a failure on the k-th event (append
  or projection) rolls back events 1..k-1.
- **AC-10** A handler whose primary-mutation append fails returns an error to the
  caller; no code path returns success after a failed append. The behavioral
  test activates with the first state-changing RPC implementation; this storage
  milestone does not add a placeholder handler solely to create a test subject.
- **AC-11** Replaying a delete/downgrade event against a projection row with a
  newer `projection_version` leaves the newer row untouched.
- **AC-12** A work row is written in the same transaction as its motivating event:
  if the transaction aborts, neither exists. Workers drain with
  `FOR UPDATE SKIP LOCKED`; two workers never process the same row; `run_at` is
  honored; failures increment `attempts` and set `next_attempt_at`; exhausted rows
  remain queryable and appear in the doctor output.
- **AC-13** The golden corpus contains a pinned serialized form for every
  registered event type; adding an event type without a corpus entry fails the
  guard; changing a payload's serialized form fails the corpus test.
- **AC-14** Inventory ingestion replaces the latest snapshot via its dedicated
  snapshot event; the inventory table rebuilds from that event alone.
- **AC-15** No execution-output body or terminal-recording body appears in any
  event payload; output bodies live in operational tables with byte/chunk caps
  and a truncation marker in the execution record (LIM-2, SPEC-009); recording
  bodies live in the artifact store.

## 5. Rejection paths

| Input / state | Required behavior |
|---|---|
| Append of an event type with no registered projector | Hard error in the same call; transaction aborted; nothing persisted |
| Projector returns an error | Whole transaction aborts; calling RPC fails |
| `AppendEventWithVersion` with a stale expected version | Version-conflict error to the caller; NO automatic retry |
| Any single append/projection inside `AppendEvents` fails | Entire batch rolls back |
| Primary-mutation append fails | RPC fails; success is never returned (ES-5) |
| Out-of-order replay delivers an older delete/downgrade | `projection_version` guard leaves the newer row untouched (ES-6) |
| `RebuildAll(target)` would FK-cascade into non-target tables | Auto-include the closure or refuse with an explicit error; never silent cascade (ES-3) |
| Migration introduces an unclassified table | Classification guard fails; change is unmergeable (ES-1) |
| New event type without a golden-corpus entry | Corpus guard fails (ES-9) |
| Direct write to a projection outside a projector | Guard failure (ES-2); change is unmergeable |
| Work row exhausts `attempts` | Row stays queryable; doctor- and admin-UI-visible; never silently dropped (ES-8) |
| Execution-output body offered as an event payload | Guard failure (ES-12) |

## 6. Test plan (TDD)

All storage tests run against REAL Postgres via testcontainers — one shared
container per package test binary, template-cloned per test. The transactional
semantics ARE the subject under test; a mocked database proves nothing. Handler
paths exercised in these tests use real handlers, never stubs. Every test is
written first and confirmed RED for the right reason via a scoped neutralizing
edit (comment the guard, flip one branch), never a revert.

Write in this order:

1. **Schema + key tests**: unique-key conflict under concurrent same-stream
   appends (AC-1).
2. **Registry tests**: unregistered event type → hard error, nothing persisted
   (AC-2); projector error → full abort (AC-3); read-after-write (AC-4).
3. **Append API tests**: CAS race with N goroutines on a bounded-use consume
   (AC-8); `AppendEvents` atomicity (AC-9). Append-failure-fails-RPC (AC-10)
   activates with the first real state-changing handler.
4. **Replay tests**: 1:1 rebuild equality per projection (AC-6, SPEC-005);
   FK-closure refuse/include (AC-7, SPEC-005). The `projection_version` out-of-order guard
   (AC-11, SPEC-005) activates with the first production projection in (M5,
   SPEC-005); no test-only production projector is added solely to create an
   earlier subject.
5. **Work-table tests**: same-tx outbox atomicity, SKIP LOCKED exclusivity,
   `run_at`/`attempts`/`next_attempt_at` semantics, exhausted-row visibility
   (AC-12).
6. **Corpus + tier tests**: golden corpus (AC-13), inventory snapshot (AC-14),
   telemetry-tier exclusion (AC-15).

## 7. Guards

Self-discovering, matches-zero protected (META-2, SPEC-000):

| Guard | Discovery source | Fails when |
|---|---|---|
| Table classification | Live schema walk (`pg_catalog`) | Any table lacks exactly one ES-1 class; zero tables discovered |
| Rebuild-target completeness | Projector registry walk | A stream type has a projector but no rebuild target; zero projectors discovered |
| Projection write discipline | AST scan + query inventory (static SQL only; no dynamic SQL anywhere) | A projection table is written outside a projector function |
| Mutation reaches `AppendEvent*` | Composition of the two guards above — projections writable only by projectors + no dynamic SQL [INV-12] | (structural; no separate name-heuristic scan) |
| Sentinel-comparison ban | AST scan over the server module | `errors.Is` against store sentinels or `sql.ErrNoRows` outside the recognizer package [INV-13]; zero call sites scanned |
| Golden corpus completeness | Event-type registry walk | A registered event type has no pinned corpus entry; zero types discovered |
| Worker discipline | AST scan over work-table workers | A worker lacks `WithoutCancel` + timeout + `recover()` |
| Doctor checks | Registered check list, each with a unit test | Work-table depth or exhausted-attempts anomalies invisible; projection-drift sanity check absent (OPS-1, SPEC-016) |

## 8. Historical lessons

Inlined from the predecessor system's operating history; each motivates a
requirement above.

- **Lesson (ES-7):** A release candidate booted with an event type wired to no
  projector — post-commit listener wiring order made "event persisted, projection
  never updated" reachable. In-tx projection with unregistered-type-is-an-error
  makes the state unrepresentable.
- **Lesson (§3.2):** Post-commit listeners bred a whole bug family — wiring-order
  gaps, watermark drift between store and read model, and a crash window between
  commit and projection — each patched individually until the design was replaced.
- **Lesson (ES-1, ES-2):** Tables were added without replay/rebuild coverage, and
  projections were written in place outside projectors; both went unnoticed until
  rebuilds produced wrong data. Classification must be total and machine-enforced.
- **Lesson (ES-3):** A `users` projection rebuild truncated FK-dependent tables
  (SSO links, API tokens) that were not themselves rebuilt, silently destroying
  state that had no event-sourced origin.
- **Lesson (ES-4):** Racing enrollments over-consumed a bounded-use registration
  token because the append helper auto-retried past the version conflict that WAS
  the lock; the same class produced an orphan certificate under concurrent
  renewals. CAS consumes must never auto-retry.
- **Lesson (ES-4):** Multi-event operations (user + role grants) appended in
  separate transactions left half-created principals when the second append
  failed.
- **Lesson (ES-5):** A handler returned OK after its event append failed — the
  double-spend class: the client believed a state change that never persisted.
- **Lesson (ES-6):** Out-of-order replay of a delete projector wiped rows that a
  newer event had already rewritten.
- **Lesson (ES-8, TM-1):** An external queue datastore wedged in production (a
  post-fork futex deadlock) and cut the fleet off from the control plane;
  dead-letter triage required that product's own CLI. Work queues in Postgres are
  inspectable with plain SQL and share the database's durability and backup story.
- **Lesson (ES-9):** Event-payload format pinning was accepted as necessary in a
  prior audit but never built; payload drift was only caught by downstream
  breakage. The corpus exists from day one here.
- **Lesson (ES-12):** Execution output chunks stored as events bloated the event
  store unboundedly; retention could not prune them without violating
  append-only. Output bodies are operational-tier from the start.

## 9. Milestones

Each milestone is one implementation session ending green (full suite passing).

1. **M1 — Core append + in-tx projection**: `events` schema + migrations;
   `AppendEvent`; projector registry; hard error on unregistered type;
   projector-error abort; read-after-write. Tests: AC-1..4.
2. **M2 — Append discipline**: `AppendEventWithVersion` (CAS, no auto-retry),
   `AppendEvents` (all-or-nothing). Handler-level append-failure propagation
   activates with the first real state-changing RPC. Tests: AC-8..9; AC-10 at
   its activation floor.
3. **M3 — Replay + rebuild**: replay runner over the same projector functions;
   `RebuildAll` with FK-closure computation and exact projector/rebuild-target
   registry parity. Tests: (AC-6, SPEC-005), (AC-7, SPEC-005).
4. **M4 — Work tables**: outbox write in the append transaction; advisory-lock
   worker harness (`WithoutCancel` + timeout + `recover()`); SKIP LOCKED drain;
   attempts/backoff columns; doctor queries. Tests: (AC-12, SPEC-005).
5. **M5 — Guards + tiers**: classification guard, projection-write guard,
   sentinel ban, golden-corpus harness; inventory snapshot event + projection
   with its `projection_version` guard; operational-telemetry tables with caps;
   recovery CLI wiring for the first production rebuild target. Tests: (AC-5,
   SPEC-005), (AC-11, SPEC-005), (AC-13, SPEC-005), (AC-14, SPEC-005), and
   (AC-15, SPEC-005).

## 10. Out of scope

- Audit semantics, redaction, retention policy values, crypto-shred, and the
  append-only trigger's prune exception — SPEC-011.
- Artifact-store schema, chunked upload, GC — SPEC-010.
- Search columns and FTS maintenance rules — SPEC-009 (the in-tx hook they use is
  ES-7).
- Command delivery, pending-command TTL semantics, gateway streams — SPEC-012.
- Agent-side storage (SQLite, offline buffering) — SPEC-013.
- The doctor binary and check framework — SPEC-016.
