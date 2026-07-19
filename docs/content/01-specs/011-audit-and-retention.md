---
title: "SPEC-011 — Audit and Retention"
---
# SPEC-011 — Audit and Retention

Status: READY FOR IMPLEMENTATION
Builds on: SPEC-005 (event-store), SPEC-008 (authorization), SPEC-010 (artifact-store)
Enables: SPEC-012, SPEC-016, SPEC-017
Module(s): server (audit, redaction, retention, recording storage), contract (audit/export/recording RPC shapes)

## 1. Scope

The audit posture of the control plane: audit coverage of every state-changing
RPC, audit of secret-returning reads, the schema-driven redaction sweep, the
append-only guarantee and its single prune exception, retention classes,
crypto-shred erasure, audit export, the revert-on-unassign audit trail, and
terminal session recording [AUD-1..8] plus the retention aspects of the
operational-telemetry tier (ES-12, SPEC-005).

## 2. Context capsule

Minimum prior knowledge, restated:

- **Event store (SPEC-005):** every state change is an immutable event in the
  append-only `events` table; projectors run inside the append transaction;
  projections are writable ONLY by projectors; dynamic SQL is banned; every
  mutation therefore reaches `AppendEvent*` by construction. Execution-output
  bodies and terminal-recording bodies are operational-tier data, never events;
  lifecycle facts (created, completed, status, truncation) are events (ES-12).
  Retention prune and stale-execution expiry run as Postgres work tables under
  advisory locks (ES-8).
- **Authorization (SPEC-008):** scope lives on the grant; permissions are
  scope-confinable (global / device-group set / user-group set / self) except an
  enumerated global-only set that includes retention/audit administration.
  Cross-actor access returns NotFound uniformly. The control-plane administrator
  is TRUSTED (actor 3, SPEC-001): audit exists for attribution, not to protect
  the system from its own admin.
- **Artifact store (SPEC-010):** one content-addressed blob store, key = SHA-256,
  behind a two-method Get/Put interface; a blob is deletable only when
  unreferenced by every live action/recording/archive AND past its retention
  window; fetching a GC'd blob is a structured error (ART-1, ART-3). The store
  holds terminal recordings and encrypted audit archives as ciphertext (ART-4).
- **Crypto (SDK-13, SPEC-004):** one AEAD surface, `enc:v1` (AES-256-GCM) with
  MANDATORY non-empty AAD and domain-separation info strings; no nil-AAD API
  exists. Secrets are never present in events, logs, or audit payloads; tokens
  are hashed at rest (INV-7).
- **Config (INV-18, SPEC-002):** operator configuration is one typed struct per
  binary; retention windows and the recording opt-in are configuration keys with
  generated reference docs.

## 3. Requirements

### 3.1 Audit coverage

- **[AUD-1]** The event store IS the audit log. Every state-changing RPC reaches
  `AppendEvent*` — structurally guaranteed because projections are writable only
  by projectors and dynamic SQL is banned (composition of SPEC-005 guards, not a
  name-heuristic scan). There is no separate audit table to keep in sync.
- **[AUD-2]** Secret-returning READS emit their own audit events — local-password
  (LPS) views, disk-encryption (LUKS) key views, osquery reads, log reads —
  including denial events (`*ViewDenied`), with ZERO secret material in payloads.
  One event per call.
- **[AUD-3]** On-read redaction is schema-dispatched from the REAL emit path —
  never a hand-built type map that can drift from emitters. A self-discovering
  AST sweep over every event-payload struct fails the build if any
  secret-bearing field lacks a redaction schema. A narrow fallback redacts
  unrecognized decoded objects on a secret-key deny-set. The redaction schema is
  the canonical enumeration of secret-bearing fields (consumed by the action
  catalog's redactor: script, detection script, file content, unit content,
  custom repo config, GPG key, pre-shared keys, client keys — SPEC-014).

### 3.2 Append-only guarantee and erasure

- **[AUD-4]** An append-only DB trigger protects `events`, with a single guarded
  retention-prune exception. Prune emits tamper-evident `EventLogPruned` marker
  events; archives are **encrypted ciphertext event batches** — never
  projections. GDPR erasure = crypto-shred: per-user DEK envelope encryption over
  `pii:"true"`-tagged fields, with atomic shred + DEK delete
  (`user_encryption_keys` is the sanctioned non-replay table for exactly this
  reason — ES-1, SPEC-005). PII sealing fails CLOSED: if the sealer is absent,
  the write is refused, never stored in plaintext.
- **[AUD-5]** `AUDIT GAP` posture: an audit append failure never blocks
  login/logout/refresh, but logs loudly and is doctor-visible (OPS-1, SPEC-016).
  Availability of sign-in wins over audit completeness for exactly these three
  flows; everywhere else ES-5 applies (append failure fails the RPC).
- **[AUD-6]** Audit export is UNARY CHUNKED (recorded operator decision — do not
  re-litigate toward streaming): same permission and same redaction as the audit
  list path. No export path may bypass redaction.

### 3.3 Revert trail

- **[AUD-7]** Revert-on-unassign gets a first-class audit trail designed UP
  FRONT: a revert event carrying (device, action snapshot, reverted artifacts).
  The tables and event shapes exist before the first revert ships, so the trail
  is never an infeasible retrofit.

### 3.4 Terminal session recording

- **[AUD-8]** Terminal session recording captures input AND output:
  - Timestamped chunk streams, sealed with `enc:v1` AEAD,
    AAD = `session|device|user`, stored as sealed ciphertext in the artifact
    store (ART-4, SPEC-010) under the ES-12 operational-retention tier.
  - Per-session size cap with a truncation marker.
  - Session lifecycle events go to the event store — always, regardless of the
    recording setting.
  - Retrieval is a device-scopable permission (AUTHZ-3, SPEC-008), and EVERY
    read emits an audit event (AUD-2 pattern). Raw streams cannot be redacted,
    so sealed storage + access audit IS the control.
  - Recording is **OPT-IN, default OFF**, enabled by explicit operator
    configuration surfaced in docs and UI. Zero input/output capture happens
    unless enabled. There is NO input-only middle ground: the setting is
    all-or-nothing by design.
  - Rationale for the opt-in posture: recording administrative sessions can
    carry labor-law obligations (works councils / Betriebsrat in DACH
    jurisdictions); the product must not put operators into silent
    non-compliance by default.

### 3.5 Retention classes

Retention is operator-configurable through the single typed config (INV-18,
SPEC-002); the defaults and classes below are normative.

| ID | Data class | Retention rule |
|---|---|---|
| **[RET-1]** | Event log | Append-only; prunable ONLY via the AUD-4 guarded exception, leaving `EventLogPruned` markers; archives are encrypted ciphertext event batches in the artifact store (ART-4, SPEC-010) |
| **[RET-2]** | Execution-output bodies (operational tables, ES-12) | Compliance-linked output is EVIDENCE: retained per policy. All other output: short operator-configurable default — troubleshooting value decays in days, but is not zero |
| **[RET-3]** | Terminal recordings | Operational tier; the retention window supplies the "past retention" input to artifact GC (ART-3, SPEC-010); a blob still referenced by a live record is never collected |
| **[RET-4]** | Backups vs. crypto-shred | Backups containing crypto-shredded DEKs MUST age out under a documented backup-retention window, or GDPR erasure is not real |
| **[RET-5]** | Retention posture | Doctor-visible (OPS-1, SPEC-016): current windows, prune backlog, exhausted prune attempts |

## 4. Acceptance criteria

- **AC-1** Every state-changing ControlService RPC produces at least one event in
  `events`; a direct projection write outside a projector is impossible (guard
  failure), so the property holds by construction and is spot-checked
  behaviorally on a sample of mutating RPCs through real handlers.
- **AC-2** A permitted secret-returning read (LPS view, LUKS view, osquery, log
  read) emits exactly one audit event per call, containing requester, target,
  and outcome — and zero secret material.
- **AC-3** A DENIED secret-returning read emits a `*ViewDenied` audit event; the
  caller receives the uniform denial (NotFound posture per SPEC-008).
- **AC-4** The redaction AST sweep fails the build when a new payload struct
  gains a secret-bearing field without a redaction schema entry; it fails when it
  discovers zero payload structs (matches-zero).
- **AC-5** Reading audit events through list AND export yields redacted payloads
  from the same schema dispatch; an unrecognized decoded object passes the
  secret-key deny-set fallback (asserted against a test-owned key list, never by
  iterating the implementation's own set).
- **AC-6** UPDATE and DELETE on `events` are rejected by the DB trigger; the
  retention-prune path succeeds and leaves a tamper-evident `EventLogPruned`
  marker; the produced archive decrypts to the pruned event batch and is NOT a
  projection dump.
- **AC-7** Crypto-shred: after shredding user U, U's `pii:"true"` field values
  are unrecoverable from events, projections, and archives readable with live
  keys; the DEK row is gone; both effects are atomic (no observable intermediate
  state).
- **AC-8** With the PII sealer absent/unconfigured, a write carrying
  `pii:"true"` fields is refused with an error — never stored in plaintext.
- **AC-9** With audit append forced to fail, login, logout, and refresh still
  succeed; a loud log entry is emitted and the doctor reports the gap; every
  other mutating RPC fails under the same fault (ES-5).
- **AC-10** Audit export is unary chunked; a caller lacking the audit permission
  is denied identically to the list path; exported chunks reassemble to the same
  redacted content the list path serves.
- **AC-11** Unassigning an action that reverts device state produces a revert
  event carrying device, action snapshot, and reverted artifacts, queryable per
  device.
- **AC-12** With recording OFF (default), a full terminal session stores ZERO
  input/output bytes anywhere, while session lifecycle events are recorded. The
  OFF state requires no configuration.
- **AC-13** With recording ON, chunks stored in the artifact store are ciphertext
  under `enc:v1` with AAD `session|device|user`; opening with any altered AAD
  component fails; plaintext never appears in the artifact table, events, or
  logs.
- **AC-14** A session exceeding the per-session size cap stores a truncated
  recording with an explicit truncation marker; capture stops at the cap.
- **AC-15** Recording retrieval requires the device-scopable permission: an
  out-of-scope caller gets NotFound; EVERY successful retrieval emits an audit
  event (one per call).
- **AC-16** A recording past its RET-3 retention window becomes GC-eligible;
  fetching it after GC returns a structured error (ART-3, SPEC-010), and the
  session's lifecycle events remain.

## 5. Rejection paths

| Input / state | Required rejection behavior |
|---|---|
| UPDATE/DELETE on `events` outside the prune path | Rejected by the append-only trigger |
| Prune without emitting `EventLogPruned` markers | Impossible by construction; test asserts marker presence per prune batch |
| Archive requested as projection dump | No such path exists; archives are ciphertext event batches only |
| PII write with sealer absent | Refused (fail closed); never plaintext |
| Secret material in an audit payload | Build failure via redaction sweep; runtime fallback deny-set redacts unrecognized objects |
| Audit export by caller without the audit permission | Denied identically to the list path |
| Export path bypassing redaction | Does not exist; export shares the list path's schema dispatch |
| Recording capture with the opt-in OFF | Zero bytes captured; only lifecycle events recorded |
| "Input-only" recording configuration | Not representable; the setting is all-or-nothing |
| Recording retrieval, caller out of device scope | NotFound (uniform, AUTHZ-5) |
| Recording retrieval without emitting an audit event | Impossible path; read handler appends the audit event in the same request, and its append failure fails the read (ES-5) |
| Recording chunk stored unsealed | Guard/test failure; artifact table holds ciphertext only for recording refs |
| Fetch of a GC'd recording blob | Structured error; history (lifecycle events) never rewritten |
| Audit append failure during login/logout/refresh | Flow succeeds; loud log + doctor visibility (AUD-5) |
| Audit append failure during any other mutation | RPC fails (ES-5) |

## 6. Test plan (TDD)

All tests run against REAL Postgres via testcontainers (template-cloned per
test) and REAL handlers — never mocks or stubs: audit coverage claims are
worthless unless the actual handler emitted the actual event. Tests are written
first and confirmed RED for the right reason via a scoped neutralizing edit
(e.g. comment the trigger, drop one redaction schema entry), never a revert.

Order of work:

1. **Append-only + prune**: trigger rejection, prune exception, `EventLogPruned`
   markers, ciphertext archive round-trip (AC-6).
2. **Redaction**: AST sweep red case (drop a schema entry → build fails),
   list/export parity, fallback deny-set against a test-owned secret-key list
   (AC-4, AC-5).
3. **Secret-read audit**: permitted and denied paths for each secret-returning
   read, one event per call, zero secret material (AC-2, AC-3).
4. **Crypto-shred**: atomic shred + DEK delete, sealer-absent refusal
   (AC-7, AC-8).
5. **AUDIT GAP**: fault-injected audit append during login/logout/refresh vs.
   ordinary mutations (AC-9).
6. **Export**: unary chunked reassembly, permission parity (AC-10).
7. **Revert trail**: revert event content and per-device query (AC-11).
8. **Recording**: default-off zero-capture, sealed storage with AAD tamper
   checks, size cap + truncation marker, scoped retrieval + read audit,
   retention/GC behavior (AC-12..16).

## 7. Guards

Self-discovering, matches-zero protected (META-2, SPEC-000):

| Guard | Discovery source | Fails when |
|---|---|---|
| Mutation-reaches-event-store (AUD-1) | Composition: projection-write guard + no-dynamic-SQL guard (SPEC-005) | A write path to a projection exists outside a projector |
| Redaction completeness (AUD-3) | AST walk over all event-payload structs | A secret-bearing field lacks a redaction schema; zero structs discovered |
| Secret-read audit coverage (AUD-2) | Registry of secret-returning read RPCs derived from descriptors | A secret-returning read without an audit-emit site or without a denial-event path; zero RPCs discovered |
| Append-only trigger presence | Live schema walk | Trigger absent on `events`, or a second exception path exists beyond the guarded prune |
| PII tag coverage | AST walk over `pii:"true"` tags + sealer wiring | A PII field stored without envelope encryption; sealer absence not failing closed |
| Recording ciphertext discipline | Artifact references of recording class | A recording ref resolving to non-`enc:v1` content |
| Export/list redaction parity | Both paths dispatch through one schema entry point | A second dispatch site appears |
| Retention posture checks | Doctor check registry, each with a unit test | Prune backlog, exhausted prune attempts, or recording retention misconfiguration invisible (OPS-1, SPEC-016) |

## 8. Historical lessons

- **Lesson [AUD-3]:** The predecessor's on-read redaction was a hand-built type
  map disconnected from the real emit path — it was dead code, and secret-bearing
  audit payloads went unredacted for months while reviews passed. Redaction must
  dispatch from the emit path itself, and a self-discovering sweep must enforce
  schema coverage.
- **Lesson [AUD-3]:** New payload fields carrying secrets were added without
  redaction entries; nothing forced the schema to keep up. The AST sweep makes
  the omission a build failure.
- **Lesson [AUD-2]:** Secret-revealing read paths (local-password and disk-key
  views) were initially unaudited, and denials were invisible — an insider could
  probe for secrets without leaving a trace. Every secret read and every denial
  now emits its own event.
- **Lesson [AUD-4]:** With the PII sealer unconfigured, fields that should have
  been sealed were stored in plaintext — the absence of a security dependency
  must refuse the write, never silently skip the protection.
- **Lesson [AUD-4]:** An earlier archive design exported projections; projections
  are rebuildable views that omit immutable history, so the archive could not
  serve as evidence. Archives are encrypted ciphertext event batches, full stop.
- **Lesson [AUD-7]:** Auditing revert-on-unassign was declined in the predecessor
  as an infeasible retrofit — the tables simply never recorded what was reverted.
  Designing the revert event before the first revert ships is the entire fix.
- **Lesson [RET-2] / ES-12:** Execution output stored inside the event store
  bloated it unboundedly and made retention impossible without violating
  append-only; output is operational-tier with retention classes from day one.
- **Lesson (§7):** Deny-lists and coverage checks tested by iterating the
  implementation's own set prove nothing — the test must own its threat list.

## 9. Milestones

Each milestone is one implementation session ending green.

1. **M1 — Append-only + prune**: DB trigger, guarded prune exception,
   `EventLogPruned` markers, ciphertext archives to the artifact store.
   Tests: AC-6.
2. **M2 — Redaction**: schema dispatch on the emit path, AST sweep, fallback
   deny-set, list-path redaction. Tests: AC-4, AC-5 (list half).
3. **M3 — Secret-read audit + AUDIT GAP**: audit events for permitted and denied
   secret reads; gap posture for login/logout/refresh. Tests: AC-2, AC-3, AC-9.
4. **M4 — Erasure**: `pii:"true"` envelope encryption, atomic crypto-shred,
   sealer fail-closed. Tests: AC-7, AC-8.
5. **M5 — Export + revert trail**: unary chunked export with permission and
   redaction parity; revert event schema + projection. Tests: AC-10, AC-11,
   AC-5 (export half).
6. **M6 — Terminal recording**: opt-in config key (default OFF), sealed chunk
   storage with AAD binding, size cap + truncation marker, device-scoped
   retrieval with per-read audit, retention/GC wiring. Tests: AC-12..16.

## 10. Out of scope

- Event-store mechanics (append APIs, projectors, work tables, classification) —
  SPEC-005.
- Artifact-store internals (chunked upload, digest verification, GC algorithm) —
  SPEC-010.
- The recording capture path itself (agent PTY, gateway relay of recording
  chunks, mid-session control-outage posture) — SPEC-012, SPEC-013.
- Terminal grant issuance and verification — SPEC-003, SPEC-012.
- The permission catalog and grant scoping mechanics — SPEC-008.
- OTLP/SIEM export and its structural PII barrier — SPEC-016.
- The doctor binary — SPEC-016.
