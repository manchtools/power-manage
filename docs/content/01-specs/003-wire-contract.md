---
title: "SPEC-003 — Wire Contract"
---
# SPEC-003 — Wire Contract

Status: READY FOR IMPLEMENTATION
Builds on: SPEC-000 (development-process), SPEC-001 (architecture-and-trust-model), SPEC-002 (repo-module-and-config-contract)
Enables: SPEC-004 through SPEC-017 — every component consumes this contract; SPEC-006 issues the identities it requires, SPEC-009 generates boundary tests from its validate tags, SPEC-010 uses its artifact-fetch frames, SPEC-012/013 implement its stream protocols
Module(s): `contract` (proto sources, buf config, generated Go + TS, envelope framing and verification helpers); guard hooks in `server` and `agent`

## 1. Scope

The complete wire contract between components: proto design rules, the six services,
the single ActionParams registry, the SignedCommand envelope, certificate-only
identity, device-signed result envelopes, sealed secret transport, the signed sync
manifest, the artifact-fetch stream frames, and a normative deny-list of contract
shapes that must never return. Everything that crosses a process boundary is defined
here. Behavior behind the seams (storage, PKI issuance, gateway relay mechanics,
agent execution, authorization) belongs to later specs.

## 2. Context capsule

Minimum prior knowledge, restated:

- **Components** (SPEC-001): Control (single source of authority; sole Postgres
  writer; holds all three signing authorities — agent CA, gateway CA, command
  signing key). Gateway (stateless relay; no DB, no secrets custody, no CA keys;
  caches exactly one artifact: the control-signed CRL). Agent (runs as root on
  managed devices; executes signed actions via SDK primitives; offline scheduler;
  SQLite buffer). Web is a hosted SPA talking browser→control directly.
- **Control listeners**: `:8081` ControlService (HTTPS + JWT), `:8082`
  InternalService (mTLS, gateway-class certs only), `:8083` PkiService
  (server-auth TLS, per-operation authorization).
- **Five-actor trust model** (SPEC-001). Actor 4 — the **compromised relay** — is
  the pivotal actor for this spec: the gateway is assumed able to read, modify,
  replay, or drop anything transiting it. Consequences: every control→agent
  surface is CA-signed with freshness over the exact executed bytes; every
  device→control report is device-signed; secrets are sealed end-to-end; identity
  comes only from mTLS certificates. The worst a gateway compromise yields is
  denial of service on the devices routed through it.
- **[TM-4]** Connectivity is never authority. **[TM-5]** Fail closed, always:
  unknown enum → reject; decode error on persisted security state → deny;
  verifier not wired → refuse to boot.
- **Module rules** (SPEC-002): `contract` imports no in-repo module; `sdk` has
  zero proto/connect/protobuf imports; server, agent, and web consume `contract`.
- **Crypto allocation** (decided HERE, jointly with SDK-13, SPEC-004):
  signature-envelope framing and verification helpers (SignedCommand,
  DeviceSigned — hash/ECDSA over deterministic bytes) ship inside `contract`
  (stdlib crypto only) so signer and verifier share one implementation. The
  sealed-transport AEAD primitives (X25519 + HKDF-SHA256 + AES-256-GCM
  seal/open) live EXCLUSIVELY in `sdk` (SDK-13, SPEC-004) — `contract` defines
  only the sealed-blob message shapes, never a second seal/open implementation.
  Operator-string intent grammars live in `sdk` (SDK-10, SPEC-004); validate
  tags bind to the same grammars so server and agent run identical validation.
- **Guard doctrine** (SPEC-000): every invariant ships a self-discovering fitness
  test (descriptor walk, AST scan, registry walk) with matches-zero protection.
  Hand-maintained lists of files/handlers/fields are forbidden.

## 3. Requirements

### 3.1 Proto design rules

- **[WIRE-1]** One message, one definition. A shape used on both sides of a seam is
  a single shared message — mirrored near-copies are forbidden.
  Lesson: mirrored log-query and osquery message pairs drifted apart field by field.
- **[WIRE-2]** Every field crossing a trust boundary carries a `validate` tag with
  type, format, length, and range constraints (`required` alone is insufficient).
  Enum bounds in tags are **generated from the descriptor**, never hardcoded
  numbers. Tags must not over-constrain real inputs.
  Lesson: a `url` constraint on a repository field rejected legitimate values
  carrying `$releasever`-style template variables.
  A descriptor-walking guard proves every boundable request field is tagged.
- **[WIRE-3]** Validation has one source of truth. The proto tag IS the grammar;
  the agent and the server run the SAME validation (shared validators), so
  server/agent drift (repository-name charset, checksum case) cannot exist.
- **[WIRE-4]** Enum hygiene: every enum has `*_UNSPECIFIED = 0` and it is always
  invalid at boundaries. **No reserved or aspirational values**: an enum value with
  no implementation behind it does not exist in the contract.
  Lesson: enum values reserved for unimplemented backends were accepted at
  validation and became dead contract surface that failed only downstream.
  Every `switch` over an enum has an erroring `default`, enforced by a
  self-discovering exhaustiveness guard.
  Lesson: a non-exhaustive enum switch silently ignored an unhandled value instead
  of erroring.
- **[WIRE-5]** IDs are bare ULID strings, uniformly — no wrapper-vs-bare mixing, no
  UUIDs anywhere, and names are honest (`execution_id` means the execution, never
  the action). Charset-restricted to the ULID alphabet wherever an ID reaches a
  filesystem path or config filename.
  Lesson: an ID interpolated into a filesystem path without charset restriction
  allowed path escape.
- **[WIRE-6]** Booleans that change system state have **no dangerous zero value**.
  Anything where "unset" and "false" mean different things (service enable,
  gpgcheck, system_wide, recursive, allow_pubkey) is `optional bool` (explicit
  presence) or a three-value enum, and the handler rejects absence where absence
  is ambiguous. The unset-disables-your-unit family of footguns is a contract bug,
  not a docs gotcha.
- **[WIRE-7]** Errors travel as RPC status codes with static, non-oracular
  messages — never in-band `success`/`error` fields, never raw internal error text.
  Lesson: raw internal error text returned to callers acted as an information
  oracle.
- **[WIRE-8]** Times are `google.protobuf.Timestamp` (UTC). Never strings, never
  compared as strings. Maintenance windows are typed messages (weekday set,
  start/end minute-of-day, device-local evaluation), not strings.
  Lesson: schedule times stored and compared as strings broke ordering.
- **[WIRE-9]** Updates are full-object-replace with an expected-version field
  (OCC). No field masks, no singular+plural dual fields, no partial-update
  dialects. Assignments stay immutable: delete-and-recreate.
- **[WIRE-10]** Proto (de)serialization is protojson / deterministic-proto only;
  stdlib `encoding/json` on a proto message is a build failure.
  Lesson: stdlib JSON on a proto message silently mis-serialized oneofs and enums.

### 3.2 Services

Six externally visible service surfaces. Four are proto-defined Connect
services (one proto file each); `ScimService` and `ExportService` are
NON-proto boundaries — SCIM v2 is `application/scim+json` by RFC (modeling
it as proto would violate both the RFC's JSON semantics and [WIRE-10]) and
the exporter speaks standard OTLP. No proto declaration is minted for
either ([WIRE-4]: an RPC surface with no proto consumer is dead contract);
their implementations live with their owning specs.

| Service | Consumers | Transport | Purpose |
|---|---|---|---|
| `ControlService` | web UI, CLI | HTTPS + JWT (Bearer) | Full management API: users, RBAC, devices, actions, nestable sets, assignments, compliance, tokens, IdPs, search, audit, settings, terminal grants |
| `AgentService` | agents | mTLS via gateway | ONE bidirectional stream: Hello/Welcome, signed command delivery, signed sync manifest, result upload, artifact fetch by digest (request + chunked response — [WIRE-28]) |
| `PkiService` | agents (enroll via local socket relay + renewal), gateways (self-enroll) | `:8083` HTTPS server-auth TLS; authorization is per-operation, not per-transport (PKI-1a, SPEC-006) | The single enrollment/renewal/revocation surface. Lesson: three separate enrollment paths coexisted and drifted; one service replaces them all |
| `InternalService` | gateways | mTLS (gateway-class certs only) | ONE persistent bidi stream per gateway (registration-by-presence, device online/offline, command push, result relay, CRL updates, artifact-chunk relay) + ONE unary op: terminal token validation (SPEC-012). No sealed-credential unary op exists: every defined secret flow has other carriage (escrow → signed results [SEC-5, SPEC-015]; inline action-field secrets → sealed command payloads [SEC-11]; admin retrieval → B1 only [SEC-2]). Any future secret-bearing op carries sealed blobs only ([WIRE-24]) and requires its owning spec to define the flow first |
| `ScimService` | IdPs | HTTPS + bearer | SCIM v2 users/groups/discovery — pure HTTP surface in the server, NOT a proto service (AUTH-7, SPEC-007) |
| `ExportService` (optional binary) | SIEM | one-way | OTLP export, structurally PII-barriered — standard OTLP wire protocol, NOT a proto service (OPS-2, SPEC-016) |

- **[WIRE-11]** ControlService RPCs keep the established domain layout (the ~20
  domains are product surface, not debt), but every RPC obeys the 3.1 conventions
  and the handler-layer rules of SPEC-008/SPEC-009.

### 3.3 The single ActionParams registry

- **[WIRE-12]** There is exactly ONE `ActionParams` message containing the
  per-type `oneof`. `Action`, `SignedCommand` payloads, create/update requests,
  and the agent's stored copy all embed this one message.
  Lesson: the action-params oneof was historically duplicated across five
  messages, and the copies diverged.
- **[WIRE-13]** There is exactly ONE action shape. No parallel action/managed-
  action/request-embedded triplets; enrichment (assignment mode, schedule,
  resolved target) is composition around the one shape, not a parallel copy of
  its fields.

### 3.4 SignedCommand — one envelope for everything control tells an agent

One scheme replaces every hand-rolled signing variant.
Lesson: five hand-rolled one-directional signing schemes coexisted, each with its
own framing bugs; the unified envelope makes divergence unrepresentable.

```proto
message SignedCommand {
  bytes  payload            = 1; // deterministic serialization of the typed command
  string command_type       = 2; // "action", "osquery", "logquery", "inventory",
                                 // "luks-revoke", "lps-pubkey", "terminal-grant", "sync-manifest"
  string target_device_id   = 3; // ULID; agent refuses if not its own
  google.protobuf.Timestamp issued_at = 4;
  google.protobuf.Timestamp expires_at = 5;
  bytes  signature          = 6; // over domain-framed (2,3,4,5,payload)
}
```

- **[WIRE-14]** Signing input is length-prefixed and domain-separated:
  `"power-manage:cmd:" + command_type + ":v1"` framed with every covered field.
  ECDSA/RSA + SHA-256; Ed25519 CA keys are refused at boot. Sign-then-deliver at
  ONE seam; the agent verifies then executes **the exact verified bytes** — it
  deserializes `payload` after verification and never consults a second
  representation.
  Lesson: verifying one representation of a command while executing another let
  the executed content differ from what was signed.
- **[WIRE-15]** Freshness is mandatory and closes the replay hole:
  - *Instant* commands (SYNC, REBOOT, osquery, log query, terminal grant, LUKS
    revoke, inventory request): `expires_at − issued_at ≤ 15 min`; the agent
    rejects expired commands and persists nothing past expiry.
  - *Durable* assignments ride the **signed sync manifest** (3.8), whose
    `(epoch, generation)` monotonicity is the anti-replay authority; individual
    assignment envelopes may be long-lived because the manifest governs liveness.
- **[WIRE-16]** Terminal session start IS a SignedCommand (`terminal-grant`:
  device, user, session ULID, ≤60 s expiry). The gateway validates the WebSocket
  attach token against control, but the agent additionally verifies the CA-signed
  grant — a compromised gateway cannot mint PTYs. This closes the one historical
  unsigned root surface.
- **[WIRE-17]** Everything the agent treats as server-authoritative configuration
  (sync interval, inventory interval, maintenance windows, login URL, LPS public
  key) arrives inside signed material (manifest or command) — no unsigned Welcome
  fields a relay could rewrite.

### 3.5 Identity: certificates only

- **[WIRE-18]** No message anywhere in the contract carries a self-asserted
  `device_id`, `gateway_id`, or `auth_token` identity field for authentication.
  Identity at every seam is the mTLS certificate: SPIFFE URI SAN
  `spiffe://power-manage/{agent|gateway|control}` = class, CN = instance ULID,
  DNS SAN = server name only. `target_device_id` in SignedCommand is *addressing*
  (verified against the receiving agent's own identity), not authentication.
- **[WIRE-19]** InternalService binds every device-scoped operation to the CALLING
  gateway's certificate identity and verifies the (device, gateway) routing
  binding, fail-closed. A "no resolver wired → binding skipped" mode does not
  exist: an unwired resolver is a boot failure. A deliberate single-gateway
  deployment expresses the exception as explicit named configuration, never a nil
  check.
  Lesson: the binding check was historically skipped silently whenever the
  resolver was not wired — a fail-open authorization bypass.

### 3.6 Authenticated device→control results

Lesson: the entire device→control result path (executions, compliance, inventory,
alerts, offline queue drain) historically had zero cryptographic coverage — a
compromised relay or queue could forge any device's results. This was the largest
crypto gap in the old system.

- **[WIRE-20]** Every device-originated report is wrapped in a `DeviceSigned`
  envelope: deterministic payload bytes + device ULID + `issued_at` + signature by
  the device's enrolled private key (the mTLS key), domain
  `"power-manage:result:" + type + ":v1"`. Control verifies against the device's
  **DER-derived registered certificate** — never a projection copy (PKI-4,
  SPEC-006) — before recording.
- **[WIRE-20a]** The result `<type>` token set is CLOSED, mirroring the
  command-type set of §3.4: `execution`, `compliance`, `inventory`, `alert`,
  `osquery`, `logquery`. Each has a named `*SignatureDomain` constant and a
  registered verify site; an unknown token is a structured reject. Escrowed
  device secrets (LPS, LUKS, USER temp passwords) mint NO result type: the
  sealed blob rides the `execution` result of the rotation that produced it —
  the result domain binds the report context, the blob's sealing info string
  ([WIRE-23]) binds the secret. A new result type is a spec change here plus
  its owning-spec flow, never an ad-hoc token.
- **[WIRE-21]** Defense in depth retained: control additionally verifies the
  reported execution/query **resolves to the signing device** (device ID in the
  WHERE clause, drop+log on zero rows). Signature proves origin; resolution proves
  the device is reporting about its own outstanding work.
- **[WIRE-22]** Transport integrity for results is the mTLS gateway stream
  (B4 + B6, SPEC-001); the device signature is the end-to-end layer on top of it.
  No transport-level MAC envelope exists: its threat model (a forging relay) is
  covered end-to-end by [WIRE-20], which a transport MAC never achieved.

### 3.7 Sealed secret transport — uniform, both directions

- **[WIRE-23]** Device-originated secrets (LPS passwords, LUKS passphrases, USER
  temp passwords) are sealed on the agent to control's X25519 public key
  (X25519 + HKDF-SHA256 + AES-256-GCM) with mandatory domain info
  (`power-manage-lps-password:v1`, `power-manage-luks-passphrase:v1`) and context
  binding (device|action|username, or device|action). The relay sees only opaque
  blobs. The control-side sealing public key is delivered CA-signed (the
  `lps-pubkey` command type).
  Control-originated inline action-field secrets (WIFI PSK, EAP-TLS key
  material) travel the same envelope in the opposite direction: sealed at
  dispatch-mint time to the device's enrollment-registered X25519 public key,
  under a dedicated domain with device | action | field context binding.
  Surface registry and device key lifecycle: (SEC-11, SPEC-015). The
  device-directed sealing key is a recorded operator decision (decisions doc,
  2026-07-19).
- **[WIRE-24]** **No plaintext secret ever transits the gateway in either
  direction.** Every gateway-proxied secret RPC carries sealed blobs; control
  unseals only at its own edge (admin retrieval over B1 TLS+JWT, which never
  touches the gateway).
  Lesson: two RPCs historically carried plaintext LUKS material through the
  relay — a plaintext retrieval response and a plaintext store proxy — an
  asymmetry that handed the secret to a compromised gateway.
- **[WIRE-25]** Sealing APIs reject empty key material and empty plaintext
  symmetrically, at seal AND open.
  Lesson: seal/open historically accepted empty inputs on one side only, so a
  degenerate call succeeded in one direction and failed in the other.

### 3.8 Signed sync manifest

- **[WIRE-26]** Every sync response is a CA-signed manifest: monotonic
  `(epoch, generation)`, ≤15-min validity window, the device's complete desired
  state as occurrence keys (assignment × action), schedules, maintenance windows,
  and server-set intervals. Removal-by-omission is the SOLE cleanup authority.
  The agent rejects manifests older than its last accepted `(epoch, generation)`.
- **[WIRE-27]** A manifest that changes the *security class* of existing state
  ambiguously raises a durable operator alert rather than guessing. There is NO
  in-agent staleness kill-switch: an agent that cannot reach control keeps
  enforcing its last verified manifest indefinitely — offline autonomy is the
  product.

### 3.9 Artifact-fetch stream frames

New IDs minted by this spec; the transfer semantics live in (ART-2/ART-3,
SPEC-010), the relay in (GW-3, SPEC-012), and the verification chokepoint in
(AG-13, SPEC-013).

- **[WIRE-28]** The `AgentService` stream carries artifact fetch by digest:
  - `ArtifactFetchRequest { string sha256; uint64 offset; }` — agent→gateway;
    `sha256` is 64 lowercase hex characters (tag-validated per [WIRE-2]);
    `offset` supports resume after interruption. The gateway relays the request
    on its `InternalService` stream, where it is bound to the relaying gateway's
    certificate identity and reported connection set ([WIRE-19]).
  - `ArtifactChunk { string sha256; uint64 offset; bytes data; }` —
    control→gateway (addressed to a named connected device) → agent. Chunk size
    stays within the gateway frame caps (GW-8, SPEC-012). Completion is
    determined by the agent from the `(sha256, size)` reference carried in the
    signed command (ART-2, SPEC-010).
  - A fetch that cannot be served (unknown digest, garbage-collected blob) is
    answered with a structured `ArtifactFetchError { string sha256; code }`
    frame with a static message per [WIRE-7] — never silence, never a
    zero-length success.
- **[WIRE-29]** The gateway relays artifact chunks **statelessly** — it never
  caches them (TM-2 stands: the CRL is the only cached artifact). Chunks carry
  **no per-chunk signatures**: integrity is the agent's whole-artifact digest
  check at the AG-13 chokepoint, and the expected digest is covered by the
  SignedCommand signature (ART-2, SPEC-010) — digest-verifying the fetched bytes
  IS verifying the signature's subject.

### 3.10 Deleted from the old contract — normative deny-list

- **[WIRE-30]** The following shapes are banned. Reintroducing any of them is a
  build failure (guard G-7), not a review comment.

| Banned shape | Reason (one line) |
|---|---|
| `params_canonical` JSON second representation | Two representations of signed content let executed bytes diverge from verified bytes; single deterministic-proto representation only ([WIRE-14]) |
| Self-asserted `device_id` / `gateway_id` / `auth_token` identity fields | Identity comes only from the mTLS certificate ([WIRE-18]); asserted fields let a relay impersonate |
| Fail-open no-resolver binding mode | A skipped (device, gateway) binding check when the resolver is unwired is an authorization bypass; unwired = boot failure ([WIRE-19]) |
| `Welcome`-driven agent-update fields, a `TriggerAgentUpdate` RPC, server-side release polling | Multiple update trigger paths drifted; the signed `AGENT_UPDATE` action is the sole upgrade path (AG-16, SPEC-013) |
| Reserved backend enum values (GELI/CGD, ConnMan/wpa_supplicant/iwd, OpenRC/runit/s6, DOAS) | Values with no implementation are dead contract surface; add a value only WITH its implementation ([WIRE-4]) |
| Mirrored near-copy messages | Parallel shapes drift field by field ([WIRE-1]) |
| Singular+plural dual fields | Two ways to say one thing guarantees divergent handling ([WIRE-9]) |
| Stringly-typed maintenance windows / timestamps | String time comparison broke ordering; typed messages only ([WIRE-8]) |
| In-band `success`/`error` fields | Errors are RPC status codes with static messages ([WIRE-7]) |
| Legacy dual roles/role_grants model | One grant model exists: (principal, role, scope) (AUTHZ-3, SPEC-008) |
| Per-command C-locale opt-in | Opt-in locale control left some parsers running against localized output; C locale is an unconditional Runner invariant (SDK-3, SPEC-004) |
| A second "run it now" verb | ONE converge-now RPC dispatches assigned work through the normal signed path; SYNC-the-action-type remains the agent-side full-reconcile trigger; a duplicate control-side dispatch verb is redundant surface |
| Asynq, Valkey, per-service Valkey ACLs, the task-HMAC envelope and its drain-and-cut key rotation, the indexer binary | Dispatch, scheduling, CRL distribution, registries, and search have Postgres- or stream-based replacements (SPEC-005, SPEC-012); a middle tier holding state a restart can lose violates TM-1 (SPEC-001) |

## 4. Acceptance criteria

- **AC-1** Every field of every request/stream message reachable from the six
  service definitions carries a `validate` tag with type/format/length/range
  constraints; the descriptor-walking guard (G-1) passes and fails when any tag is
  removed.
- **AC-2** Every enum has `*_UNSPECIFIED = 0`; submitting an UNSPECIFIED or
  out-of-descriptor value at any boundary yields InvalidArgument with a static
  message.
- **AC-3** Exactly one `ActionParams` message exists; `Action`, SignedCommand
  payloads, create/update requests, and the agent-store schema all embed it by
  type reference (G-3 passes).
- **AC-4** A SignedCommand round-trips: sign with the command key, verify, and
  the verified payload bytes are byte-identical to the signed input. Tampering
  with any covered field (`command_type`, `target_device_id`, `issued_at`,
  `expires_at`, `payload`) fails verification.
- **AC-5** Signature domains are pairwise isolated: a valid signature under
  domain A never verifies under domain B, proven over the self-discovered set of
  `*SignatureDomain` constants (G-5).
- **AC-6** The verifier rejects: expired instant envelopes; instant envelopes
  whose `expires_at − issued_at` exceeds 15 min; envelopes whose
  `target_device_id` differs from the verifying agent's own ULID; and any
  envelope whose signature does not verify. Nothing is persisted past expiry.
- **AC-7** A `DeviceSigned` envelope verifies against the DER-derived registered
  certificate; a forged signature, a signature by a different enrolled device, or
  a report resolving to a different device's work is rejected before recording
  (drop + log).
- **AC-8** The sealed-blob message shapes exist with fields for ciphertext,
  ephemeral public key, and the domain/context identifiers mandated by
  [WIRE-23]; the mandated info strings are contract constants. The seal/open
  crypto itself (round-trip, wrong-info, wrong-context, empty-input symmetry)
  is implemented and tested in `sdk` (SDK-13/14 ACs, SPEC-004) — no seal/open
  code exists in `contract` (crypto allocation, §2).
- **AC-9** A sync manifest with `(epoch, generation)` ≤ the last accepted pair is
  rejected; a valid newer manifest is accepted; removal-by-omission is observable
  as the sole cleanup authority in the manifest schema (no delete verbs exist on
  the agent surface).
- **AC-10** `ArtifactFetchRequest`/`ArtifactChunk`/`ArtifactFetchError` frames
  exist on the AgentService and InternalService streams with the shapes of
  [WIRE-28]; a fetch for an unknown digest yields the structured error frame.
- **AC-11** No banned shape from [WIRE-30] exists in the contract; the deny-list
  guard (G-7) fails the build when one is introduced.
- **AC-12** `encoding/json` marshal/unmarshal of any proto message is a build
  failure (G-6).
- **AC-13** Generated Go and TS code compile from one `buf generate`; buf lint
  passes. `buf breaking` is deliberately NOT a gate: proto evolution re-tags in
  place with no `reserved` markers (recorded decision), which is exactly what a
  breaking-change gate would reject.
- **AC-14** Ed25519 command-signing or CA keys are refused at boot by the
  verification helper's key-load path.

## 5. Rejection paths

| Input / state | Required rejection behavior |
|---|---|
| Boundary field violating its validate tag | InvalidArgument, static message ([WIRE-7]) |
| Enum value `*_UNSPECIFIED` or outside the descriptor range | InvalidArgument; never a default fallback |
| Non-ULID ID, or ULID-charset violation on a path-reaching ID | InvalidArgument |
| Absent `optional bool` where absence is ambiguous | InvalidArgument (handler-level, SPEC-009) |
| SignedCommand: signature invalid or wrong domain | Reject; nothing executed, nothing persisted |
| SignedCommand: `expires_at` in the past (instant) | Reject; never persisted past expiry |
| SignedCommand: instant window > 15 min | Reject at verification |
| SignedCommand: `target_device_id` ≠ agent's own ULID | Refuse |
| Terminal grant older than 60 s | Reject; no PTY |
| Sync manifest `(epoch, generation)` ≤ last accepted | Reject manifest; keep prior verified state |
| Manifest ambiguously changes a security class of existing state | Durable operator alert; no guess, no partial apply |
| DeviceSigned report: bad signature | Drop + log before recording |
| DeviceSigned report: resolves to a different device's work | Drop + log (device ID in WHERE clause, zero rows) |
| Seal or open with empty key material or empty plaintext | Error, symmetric in both directions |
| Sealed blob with wrong info string or context binding | Open fails |
| Agent-class cert presented on InternalService | Connection rejected (SPIFFE class mismatch) |
| Device-scoped InternalService message for a device the calling gateway has not reported connected | Reject, fail-closed ([WIRE-19]) |
| `ArtifactFetchRequest` for an unknown or garbage-collected digest | Structured `ArtifactFetchError` frame, static message |
| Ed25519 key material for signing/verification | Boot refusal |
| stdlib `encoding/json` applied to a proto message | Build failure (G-6) |
| Any [WIRE-30] banned shape in a proto file | Build failure (G-7) |

## 6. Test plan (TDD)

Write these tests FIRST; confirm each fails for the right reason (scoped
neutralizing edit, never a revert) before implementing.

1. **Guard harness first** (they are tests): G-1 tag-coverage walk, G-2 enum
   hygiene, G-3 single-ActionParams, G-6 protojson-only, G-7 deny-list — all red
   against an empty/partial contract, then green as the contract lands.
2. **Envelope framing**: golden preimage tests for the SignedCommand framing
   (length-prefixed, domain-separated) — pin exact bytes so framing changes are
   loud; tamper matrix per AC-4/AC-6; domain pairwise-isolation per AC-5.
3. **DeviceSigned**: sign/verify round-trip; forged-key, cross-device, and
   tampered-payload rejections (AC-7).
4. **Sealed transport**: message-shape and info-string-constant assertions only
   (AC-8); the crypto round-trip/rejection matrix runs in `sdk` (SPEC-004).
5. **Manifest monotonicity**: property test over `(epoch, generation)` sequences
   (AC-9).
6. **Frame shape tests** for artifact fetch (AC-10) — schema-level here;
   relay/chokepoint behavior is tested in SPEC-010/012/013.
7. Contract tests are pure unit + descriptor walks — no database, no containers.
   Handler-level correct/absent/wrong coverage is GENERATED from the validate
   tags by the CRUD kernel (API-1, SPEC-009); this spec must leave the tags
   machine-readable for that generator.
8. Real-backend rules: none needed in `contract` itself; downstream specs run
   real Postgres and real handlers (TEST-2, SPEC-017).

## 7. Guards

All guards are self-discovering with matches-zero protection: a guard that
discovers zero subjects FAILS (an empty walk means the discovery broke, not that
the codebase is clean).

| Guard | Mechanism |
|---|---|
| G-1 validate-tag coverage | Descriptor walk over every message reachable from the six services; every boundable field must carry a `validate` tag; enum bounds in tags must equal the descriptor's value set (generated, then diff-checked) |
| G-2 enum hygiene | Descriptor walk: every enum has `*_UNSPECIFIED = 0`; AST scan: every `switch` over a contract enum has an erroring `default` |
| G-3 single ActionParams / single action shape | Descriptor walk: exactly one `ActionParams`; every action-bearing message embeds it by type reference; no second message declares a per-action-type oneof |
| G-4 explicit presence | Descriptor walk: any non-`optional` plain `bool` in `ActionParams` or another state-changing message fails unless it carries a recorded two-value rationale |
| G-5 signature domains | Discover `*SignatureDomain` constants; round-trip each; pairwise-isolation matrix; cross-repo parity: every domain has ≥1 sign site AND ≥1 fail-closed verify site (INV-6) |
| G-6 protojson only | AST scan banning `encoding/json` (un)marshal of proto message types across all modules |
| G-7 deny-list | Descriptor + AST scan for [WIRE-30] shapes (field names `auth_token`/`params_canonical`, banned enum values, banned RPC names, banned dependency imports); the scan fails if it processes zero proto files |
| G-8 near-copy detection | Descriptor walk flagging two messages with identical field-name/type sets outside an allowlisted equivalence (guards [WIRE-1]) |

## 8. Historical lessons

Inlined from the incident record; each is why a rule above exists.

- The action-params oneof was duplicated across five messages and the copies
  diverged → [WIRE-12].
- Two eras of gateway trust coexisted — self-asserted IDs next to certificate
  identity, with a fail-open binding mode when the resolver was unwired →
  [WIRE-18], [WIRE-19].
- Five hand-rolled signing schemes, none with freshness, none covering the
  agent→control direction → [WIRE-14], [WIRE-15], [WIRE-20].
- The device→control result path had zero cryptographic coverage; a compromised
  relay or queue could forge any device's results → [WIRE-20..22].
- Plaintext LUKS secrets transited the gateway in both a retrieval response and a
  store proxy → [WIRE-23], [WIRE-24].
- Mirrored log-query/osquery message pairs drifted → [WIRE-1].
- A `url` validate tag rejected legitimate `$releasever` template inputs →
  [WIRE-2] (tags must not over-constrain).
- Reserved enum values without implementations were accepted at validation and
  failed downstream → [WIRE-4].
- A non-exhaustive enum switch silently ignored a value → [WIRE-4] (erroring
  default).
- An ID reaching a filesystem path without charset restriction allowed path
  escape → [WIRE-5].
- Raw internal error text in responses served as an information oracle → [WIRE-7].
- String-compared schedule times broke ordering → [WIRE-8].
- stdlib JSON on proto messages silently mis-serialized oneofs/enums → [WIRE-10].
- Verifying one representation and executing another let executed bytes diverge
  from signed bytes → [WIRE-14], deny-list entry `params_canonical`.
- Unset booleans silently disabling units ("unset means false") caused field
  incidents → [WIRE-6].
- Sealing APIs accepted empty inputs asymmetrically → [WIRE-25].
- Multiple agent-update trigger paths (Welcome fields, a dedicated RPC, release
  polling) drifted → deny-list; the signed action is the sole path.
- Opt-in per-command C-locale left parsers reading localized tool output →
  deny-list; unconditional Runner invariant (SDK-3, SPEC-004).

## 9. Milestones

Each milestone is one implementation session ending green (all guards and tests
that exist so far pass).

1. **M1 — Scaffold + guard harness.** `contract` module, buf config, six service
   files (empty services compile), common types (ULID rules, Timestamp usage),
   descriptor-walk library with the matches-zero pattern, G-1/G-2/G-6 red then
   green on the skeleton.
2. **M2 — ActionParams + action shape.** The single oneof registry, the one
   action shape, validate tags with generated enum bounds, explicit-presence
   booleans; G-3/G-4 green; buf lint wired in CI (no breaking gate — AC-13).
3. **M3 — SignedCommand.** Envelope message, framing + verification helpers
   (stdlib crypto), domain constants, freshness rules, Ed25519 boot refusal;
   golden preimage + tamper matrix + G-5 green.
4. **M4 — Identity + results + sealing + manifest.** SPIFFE/CN certificate
   profile constants, `DeviceSigned` envelope, sealed-transport message shapes
   and info-string constants (crypto lives in `sdk` — §2 allocation), sync
   manifest message with `(epoch, generation)`; AC-7/8/9 tests green.
5. **M5 — Stream protocols + deny-list.** AgentService and InternalService
   stream frame sets including artifact fetch ([WIRE-28/29]), ScimService and
   ExportService surfaces, G-7/G-8 green; full contract test suite green under
   `-race`.

## 10. Out of scope

- Handler behavior, interceptor order, rate limiting (SPEC-007/008/009).
- PKI issuance, renewal, revocation mechanics (SPEC-006) — this spec only fixes
  the certificate *profile* the contract requires.
- Artifact storage, upload, GC (SPEC-010); gateway relay behavior (SPEC-012);
  agent verification chokepoint and execution (SPEC-013).
- Event store semantics (SPEC-005); audit/redaction schemas (SPEC-011).
- The action catalog's per-type parameter semantics (SPEC-014) — this spec fixes
  only the registry structure they plug into.
- Web UI consumption details; the generated TS package release flow (SPEC-017).
