---
title: "SPEC-010 — Artifact Store"
---
# SPEC-010 — Artifact Store

Status: READY FOR IMPLEMENTATION
Builds on: SPEC-003 (wire-contract), SPEC-005 (event-store)
Enables: SPEC-011 (audit-and-retention: terminal recordings, encrypted audit archives), SPEC-012 (gateway: stateless chunk relay), SPEC-013 (agent-core: fetch, cache, digest chokepoint), SPEC-014 (action-catalog: PACKAGE_FILE)
Module(s): `server` (store, upload RPC, GC); frames and ref message in `contract` (SPEC-003); consumers in agent and gateway per SPEC-012/013

## 1. Scope

One content-addressed blob store for every large binary the system holds: blob-class
action payloads (PACKAGE_FILE), terminal session recordings, and encrypted audit
archives. Covers the storage table and interface, the `(sha256, size)` reference
model and its inline-field exception, chunked upload with server-side digest
verification, agent fetch-by-digest over the stream with stateless gateway relay,
garbage collection, and the store's classification and backup posture. One storage
mechanism, one GC, three uses.

## 2. Context capsule

Minimum prior knowledge, restated:

- **Event store** (SPEC-005): every state change is an immutable event; reads come
  from projections maintained inside the append transaction. [ES-1] requires a
  **total table classification** — every Postgres table is exactly one of: events,
  projection (with rebuild target), work table (ES-8/ES-11), operational-telemetry
  table (ES-12), **content-addressed artifact table (this spec)**, or goose
  bookkeeping, plus the sanctioned exception `user_encryption_keys`. A
  schema-walking guard makes an unclassified table unmergeable.
- The artifact-table class is **non-replay-derivable by design**: events pin
  `(sha256, size)` references only; blob deletion is governed by [ART-3] GC, never
  by replay ([ES-1], SPEC-005).
- **[ES-12] operational-telemetry tier** (SPEC-005): execution-output bodies and
  terminal recordings are operational data, NOT events — lifecycle facts (created,
  completed, status, truncation) are events. Execution-output bodies live in
  bounded, prunable operational tables (NOT this store); terminal-recording bodies
  live in THIS store. The ES-12 retention window supplies the "past retention"
  input to this spec's GC.
- **Wire contract** (SPEC-003): the SignedCommand signature covers the full action
  payload, including any `(sha256, size)` artifact ref ([WIRE-14]); artifact-fetch
  stream frames `ArtifactFetchRequest { sha256, offset }`,
  `ArtifactChunk { sha256, offset, data }`, and the structured
  `ArtifactFetchError` are defined by [WIRE-28]; the relay is stateless with no
  per-chunk signatures per [WIRE-29].
- **Trust model** (SPEC-001): [TM-2] — the gateway holds no state and caches
  exactly one artifact, the control-signed CRL. Actor 4 (compromised relay) may
  corrupt or replay chunks; the defense is the agent's whole-artifact digest check,
  not per-chunk cryptography.
- **Agent chokepoint** (SPEC-013): [AG-13] — one digest-verification chokepoint
  for every fetched artifact, fail-closed at the agent boundary before any
  privileged work. For artifact-store fetches the expected digest is exclusively
  the `(sha256, size)` carried in the signed command — no checksum-file
  alternative exists on this path. (URL-fetched action types APP_IMAGE and
  AGENT_UPDATE follow AG-13a and never touch this store.)
- **Sealing** (SPEC-004/011): `enc:v1` is the AAD-bound AES-256-GCM at-rest AEAD;
  [AUD-8] terminal recordings are sealed with AAD = session|device|user; [AUD-4]
  audit archives are encrypted ciphertext event batches, never projections.
- **Seams, not optionality** (SPEC-000): flexibility is an interface at a
  boundary with exactly one implementation behind it — no fallback backends, no
  config-switched alternatives.

## 3. Requirements

### 3.1 The store

- **[ART-1]** ONE content-addressed blob store: key = SHA-256 of the content,
  stored once (identical content dedupes), size-capped; a `bytea` table now,
  behind a two-method Get/Put interface so object storage later is a swap, not a
  redesign (seam per SPEC-000). No second blob mechanism may exist anywhere in
  the system.
  - The table is classified under [ES-1]'s content-addressed artifact class
    (SPEC-005): non-replay-derivable, GC-governed deletion.
  - Upload-time metadata rides the artifact row (e.g. detected package format
    for PACKAGE_FILE — file magic evaluated at upload, SPEC-014).
  - The size cap is enforced at upload against the binary's typed config
    (SPEC-002). DECISION NEEDED (operator): the default and maximum blob size
    cap values.

### 3.2 Blob-class references and the inline exception

- **[ART-2]** **Blob-class action payloads** (today: `PACKAGE_FILE`; any future
  type whose payload is opaque binary content) carry `(sha256, size)` artifact
  refs — never inline bytes. The signed command covers the hash, so
  digest-verifying the fetched bytes IS verifying the signature's subject; agents
  fetch by digest over the agent stream (chunked, [WIRE-28]) and cache by digest.
  This kills megabyte events and megabyte signatures for blob payloads and lifts
  the historical inline-package-bytes size ceiling; events pin history exactly
  (old events reference old hashes).
  - **Bounded inline TEXT/key fields remain part of the action shape.** They are
    diffed, validated, sealed, or redacted as FIELDS — the redaction schema
    (AUD-3, SPEC-011) is the canonical enumeration — and content-addressing
    secret-bearing fields by plain SHA-256 would leak content equality across
    devices (two devices with the same Wi-Fi PSK would expose identical digests
    to anyone with digest visibility).

| Inline field | Action type | Bound | Why it stays inline |
|---|---|---|---|
| `script`, `detection_script` | SHELL | ≤1 MiB | Diffed and validated as text; redacted by the AUD-3 schema |
| `unit_content` | SERVICE | bounded | SHA-diffed to drive daemon-reload; validated; redacted |
| `content` | FILE | ≤10 MB product cap (unrelated to the lifted package ceiling) | SHA+attrs idempotency diffing; redacted |
| `gpgKey`, `customConfig` | REPOSITORY | bounded | Cross-field validated before write; redacted |
| PSK / EAP-TLS key material | WIFI | bounded | Secret-bearing: sealed/redacted as fields; a plain content hash would leak equality across devices |

  Sealed payloads that DO enter the store (recordings, archives — [ART-4]) enter
  as ciphertext, so their digests address unique ciphertext and leak nothing.

### 3.3 Upload and garbage collection

- **[ART-3]** Upload is a chunked control RPC; control computes the digest over
  the received bytes and rejects a mismatch against the declared digest (no row
  persisted on mismatch). Uploading content whose digest already exists is
  idempotent success (dedupe, [ART-1]).
  - **GC:** a blob is deletable only when it is unreferenced by EVERY live
    action, recording, and archive AND past the applicable retention window
    (ES-12 / SPEC-011 supply the windows). Historical events referencing the
    digest do NOT keep a blob alive and are never rewritten.
  - Fetching a GC'd blob is a **structured error** (`ArtifactFetchError` on the
    stream, an RPC status with a static message on unary reads) — history is
    never rewritten, and the error is honest instead of a silent empty result.
  - Reference discovery is self-discovering: the GC scanner derives the set of
    reference-holding surfaces (live actions, retained recordings, retained
    archives) from the schema/registry, never from a hand-maintained table list
    (guard G-4).

### 3.4 Second and third uses

- **[ART-4]** The same store holds terminal session recordings ([AUD-8],
  SPEC-011) and encrypted audit archives ([AUD-4], SPEC-011), stored as
  ciphertext (`enc:v1` / sealed): one storage mechanism, one GC, three uses.
  - Recordings: timestamped chunk streams relayed over the gateway control
    stream (SPEC-012), sealed control-side with `enc:v1`
    (AAD = session|device|user), per-session size cap with truncation marker,
    stored here under the ES-12 operational-retention tier. Session lifecycle
    events stay in the event store. Recording is opt-in, default off; retrieval
    policy and read-auditing are SPEC-011's contract.
  - Archives: encrypted ciphertext event batches produced by retention pruning —
    never projections (SPEC-011).
  - The store never unseals or inspects blob content; sealing and redaction are
    producer obligations (SPEC-011).

### 3.5 Fetch path (normative restatement)

1. The signed command delivers the `(sha256, size)` ref inside the
   signature-covered payload ([WIRE-14], SPEC-003).
2. The agent checks its digest-keyed cache; on miss it sends
   `ArtifactFetchRequest { sha256, offset }` on its stream; `offset` resumes an
   interrupted transfer ([WIRE-28]).
3. The gateway relays the request over InternalService, where it is bound to the
   calling gateway's certificate identity and reported connection set
   ([WIRE-19], SPEC-003) — fail-closed.
4. Control streams `ArtifactChunk` frames addressed to the device; chunk size
   stays within the gateway frame caps (GW-8, SPEC-012).
5. The gateway relays chunks **statelessly** — no caching, no buffering beyond
   the frame in flight, no retry on its own authority ([WIRE-29]; TM-2: the CRL
   remains the only cached artifact).
6. The agent verifies the WHOLE artifact against the signed `(sha256, size)` at
   the [AG-13] chokepoint before any privileged work; the declared `size` bounds
   the stream (the agent aborts a transfer exceeding it). Chunks carry no
   per-chunk signatures — the whole-artifact check subsumes them.
7. Verified artifacts are cached by digest on the agent; cache entries are
   content-addressed, so a cache hit is re-verified against the same digest
   before use.

## 4. Acceptance criteria

- **AC-1** Put/Get round-trips a blob through the two-method interface backed by
  the `bytea` table; storing identical content twice yields exactly one stored
  row (dedupe observable in SQL).
- **AC-2** A chunked upload whose computed digest differs from the declared
  digest is rejected with a structured error and persists no row.
- **AC-3** An upload exceeding the configured size cap is rejected; the cap comes
  from the typed config (SPEC-002), not a constant.
- **AC-4** For PACKAGE_FILE uploads, the package format is detected by file magic
  at upload and stored as artifact metadata; a payload matching neither known
  magic is handled per SPEC-014's applicability rules, not guessed.
- **AC-5** The [ES-1] schema-classification guard (SPEC-005) passes with the
  artifact table classified as content-addressed artifact class, and fails if the
  classification is removed.
- **AC-6** GC deletes a blob only when it is unreferenced by every live action,
  retained recording, and retained archive AND past retention; each single
  condition alone (referenced, or within retention) blocks deletion — proven by a
  test matrix.
- **AC-7** Fetching a GC'd or never-existing digest yields the structured error
  ([WIRE-28] frame on the stream; static-message RPC status on unary reads) — and
  the historical event still pins the original `(sha256, size)` unchanged.
- **AC-8** An end-to-end fetch through the relay harness delivers chunks, honors
  `offset` resume, and a single flipped bit anywhere in the stream causes the
  agent chokepoint to fail closed: the action fails, nothing privileged executed,
  nothing cached (with SPEC-012/013; the deployed-stack version rides the
  SPEC-017 E2E gate).
- **AC-9** A transfer exceeding the declared `size` is aborted by the agent.
- **AC-10** The gateway persists no artifact bytes: after relaying a fetch, its
  disk state contains the CRL cache and nothing else; its process holds no chunk
  buffers across relays (SPEC-012 harness).
- **AC-11** Recording and archive blobs are stored as ciphertext: a known
  plaintext written through the producer path is not discoverable in the stored
  bytes.
- **AC-12** Blob-class action payload messages carry `(sha256, size)` refs and no
  inline `bytes` payload field (guard G-2 over the contract descriptor).

## 5. Rejection paths

| Input / state | Required rejection behavior |
|---|---|
| Upload: computed digest ≠ declared digest | Structured error; no blob row persisted |
| Upload: blob exceeds the configured size cap | Structured error; nothing persisted |
| Upload: malformed digest string (not 64 lowercase hex) | InvalidArgument via validate tag ([WIRE-2], SPEC-003) |
| Fetch: unknown digest | Structured `ArtifactFetchError` / static-message status — never an empty success |
| Fetch: garbage-collected digest | Same structured error; events keep the historical ref |
| Fetch relayed for a device the calling gateway has not reported connected | Reject, fail-closed ([WIRE-19], SPEC-003) |
| Agent: fetched bytes fail the `(sha256, size)` check at the chokepoint | Action fails; no privileged work, no cache entry ([AG-13], SPEC-013) |
| Agent: stream delivers more bytes than the declared `size` | Abort the transfer; treat as verification failure |
| GC candidate still referenced by a live action, recording, or archive | GC refuses deletion |
| GC candidate unreferenced but within retention | GC refuses deletion |
| GC reference scanner discovers zero reference surfaces | Guard/G-4 failure — scanner is broken, GC must not run |
| Attempt to store a blob-class payload inline in an event or request | Build failure via guard G-2 |
| Gateway code path caching or persisting artifact chunks | Test failure (AC-10); forbidden by [WIRE-29]/[TM-2] |

## 6. Test plan (TDD)

Write these FIRST; confirm red for the right reason before implementing. Handler
and store tests run against REAL Postgres (testcontainer, template-cloned per
test) and REAL handlers — never mocks of either (TEST-2, SPEC-017).

1. Store unit: Put/Get round-trip; dedupe row-count assertion (AC-1); size-cap
   rejection (AC-3).
2. Upload RPC: chunked happy path; digest-mismatch rejection with no-row
   assertion (AC-2); idempotent re-upload; magic-detection metadata (AC-4).
3. GC matrix (AC-6): {referenced live action, retained recording, retained
   archive, unreferenced within retention, unreferenced past retention} — only
   the last is deleted; post-GC fetch returns the structured error and the
   pinned event is byte-identical (AC-7).
4. Classification: assert the [ES-1] guard covers the artifact table; red-check
   by removing the classification entry (AC-5).
5. Fetch integration (in-process harness with SPEC-012/013 seams): chunking,
   offset resume, bit-flip → chokepoint failure with nothing executed and
   nothing cached (AC-8), over-size abort (AC-9), gateway statelessness (AC-10).
6. Ciphertext-only: drive a recording and an archive through their producers and
   scan stored bytes for the known plaintext (AC-11) — the fixture plaintext is
   test-owned, never derived from the implementation's own sealing output.
7. Deployed-stack E2E: the artifact fetch scenario joins the self-discovering
   RPC-coverage registry of the deployment gate (SPEC-017).

## 7. Guards

Self-discovering, matches-zero protected: a guard that discovers zero subjects
fails.

| Guard | Mechanism |
|---|---|
| G-1 table classification | The [ES-1] schema-walking guard (SPEC-005) requires the artifact table to be classified content-addressed artifact class; an unclassified table is unmergeable |
| G-2 no inline blob payloads | Descriptor walk over `ActionParams` (SPEC-003): every blob-class payload type carries the `(sha256, size)` ref message and no `bytes` payload field; fails if it discovers zero blob-class types |
| G-3 inline-exception parity | The inline-field enumeration in [ART-2] must be a subset of the AUD-3 redaction/handling schema (SPEC-011), verified by a sweep over the real payload structs; fails on zero structs swept |
| G-4 GC reference discovery | The GC scanner derives reference-holding surfaces from the schema/registry; the guard fails if the derived set is empty or if a schema surface holding `(sha256, size)` refs is not in the scanner's set |
| G-5 single blob mechanism | Archtest: no package outside the store implements blob persistence (no second `bytea`-content table class, no file-blob writes in server request paths); fails on zero packages scanned |
| G-6 store opacity | Archtest: the store package does not import the AEAD open/unseal API — the store can never inspect sealed content |

## 8. Historical lessons

- Package payloads were carried as inline bytes, producing megabyte events and
  megabyte signing inputs, and imposing a hard size ceiling on installable
  packages → [ART-2] refs.
- Execution-output chunks stored in the event store bloated it without bound;
  moving bodies to prunable tiers (ES-12) and recordings to this store deletes
  the class at the root → context capsule tiering, [ART-4].
- A download path with an optional checksum was fail-open: omitting the checksum
  silently skipped verification → the artifact path has NO checksum-optional
  mode; the digest is always present in the signed command and always enforced
  at the chokepoint ([ART-2], [AG-13]).
- A middle-tier datastore wedge once cut off the entire fleet because durable
  state lived between control and the devices → the relay stays stateless; blobs
  live in Postgres, caches live at the agent edge ([WIRE-29], [TM-2]).
- Archiving projections instead of encrypted event batches produced archives
  that could not serve as faithful evidence → [ART-4] stores archives only as
  encrypted ciphertext event batches (AUD-4, SPEC-011).
- Hand-maintained lists of referencing tables go stale and fail open → GC
  reference discovery is schema-derived with a matches-zero guard (G-4).

## 9. Milestones

Each milestone is one implementation session ending green.

1. **M1 — Store core.** `bytea` table + migration, [ES-1] classification entry,
   two-method Get/Put interface, size cap from typed config, dedupe; tests 1 and
   4 red→green; guards G-1/G-5/G-6 in place.
2. **M2 — Upload RPC.** Chunked upload with server-side digest verification,
   idempotent re-upload, PACKAGE_FILE magic metadata; test 2 red→green.
3. **M3 — Fetch path.** Control-side chunk streaming with structured errors,
   offset resume; in-process relay/chokepoint harness with SPEC-012/013 seams;
   test 5 red→green; G-2 green against the contract.
4. **M4 — GC.** Schema-derived reference scanner, retention-window input wiring
   (ES-12 / SPEC-011), deletion + structured-error behavior; test 3 red→green;
   G-4 green.
5. **M5 — Recordings + archives.** Producer integration via the same Put
   interface (with SPEC-011), ciphertext-only assertions, G-3 green;
   artifact-fetch scenario registered in the SPEC-017 E2E gate; backup note:
   artifact blobs are UNRECOVERABLE if omitted from backup — the backup contract
   (SPEC-016) includes this table in the full-database dump.

## 10. Out of scope

- URL-fetched artifact types (`APP_IMAGE`, `AGENT_UPDATE`): they follow the
  AG-13a URL-transport rules (SPEC-013/014) and never touch this store.
- Execution-output bodies: bounded operational tables per ES-12 (SPEC-005/011),
  not blobs.
- The redaction/handling schema itself, recording enablement policy, retrieval
  permissions and read-audit events, retention-window configuration (SPEC-011).
- Gateway stream mechanics beyond stateless relay (SPEC-012); agent cache
  eviction policy and offline behavior (SPEC-013).
- An object-storage backend: the Get/Put seam exists, exactly one implementation
  (Postgres `bytea`) is built (SPEC-000 — seams, not optionality).
- PACKAGE_FILE applicability and install semantics (SPEC-014).
