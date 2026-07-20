# SPEC-003 M5 — stream protocols + deny-list

Milestone: SPEC-003 §9 M5 — AgentService and InternalService stream frame
sets including artifact fetch ([WIRE-28/29]), ScimService and ExportService
surfaces, G-7/G-8 green; full contract suite green under `-race`. Flips
SPEC-003 to Implemented.

## Recorded mechanical choices

1. **Frame envelopes.** Each stream multiplexes via a oneof-discriminated
   frame pair (the only proto encoding of "ONE bidi stream carrying N
   payload classes"; InternalService's frame names come verbatim from the
   GW-3 table, SPEC-012):
   - `agent.proto`: `rpc Stream(stream AgentFrame) returns (stream
     ServerFrame)`. `AgentFrame.frame` oneof: `Hello hello`, `DeviceSigned
     report`, `ArtifactFetchRequest artifact_fetch_request`.
     `ServerFrame.frame` oneof: `Welcome welcome`, `SignedCommand command`,
     `ArtifactChunk artifact_chunk`, `ArtifactFetchError
     artifact_fetch_error`. Both oneofs `(buf.validate.oneof).required`.
     The signed sync manifest is NOT a frame: it rides `SignedCommand`
     with `command_type = "sync-manifest"` ([WIRE-15/26]); a second
     manifest carriage would be a second freshness path.
   - `internal.proto`: `rpc Stream(stream GatewayFrame) returns (stream
     ControlFrame)`. `GatewayFrame.frame` oneof: `DeviceConnected`,
     `DeviceDisconnected`, `DeviceReport`, `TerminalRecordingChunk`,
     `ArtifactFetchRelay`. `ControlFrame.frame` oneof: `PushCommand`,
     `CrlUpdate`, `ArtifactChunkRelay`, `ArtifactErrorRelay`. Both
     required. No gateway hello/registration frame: stream presence IS
     registration (GW-3.1, operator decision 4); on reconnect the gateway
     re-reports its full connection set as `DeviceConnected` frames.
2. **Hello/Welcome.** `Hello { repeated string capabilities = 1
   [pattern ^[a-z0-9-]+$, max_len 64 per item] }` — AG-12a (SPEC-013): the
   boot-probe capability set is reported in Hello; tokens stay an open
   grammar until SPEC-004 pins the probe vocabulary (same posture as the
   M4 result-type grammar). `Welcome {}` — deliberately empty: [WIRE-17]
   defines Welcome negatively (everything server-authoritative rides
   signed material; no unsigned field a relay could rewrite is
   permissible), [WIRE-30] bans Welcome-driven update fields, [WIRE-18]
   bans identity fields. Welcome is a protocol acknowledgment; any future
   field needs a spec change. AG-3's drift/heartbeat field lands with
   SPEC-013 (additive re-tag; recorded ceiling).
3. **Addressing wrappers, no dual fields.** `DeviceReport { DeviceSigned
   report = 1 [required] }` and `PushCommand { SignedCommand command = 1
   [required] }` carry NO separate device_id: the envelope's own
   `device_id`/`target_device_id` is the addressing claim ([WIRE-9]
   anti-dual-field; control runs the [WIRE-19] set check on the claimed
   ID, then verifies). Artifact frames have no in-message device field
   ([WIRE-28]), so the internal stream wraps them: `ArtifactFetchRelay {
   string device_id = 1 [ULID]; ArtifactFetchRequest request = 2
   [required] }`, `ArtifactChunkRelay { device_id; ArtifactChunk chunk }`,
   `ArtifactErrorRelay { device_id; ArtifactFetchError error }` —
   composition, not near-copies (G-8 clean).
4. **Artifact frames ([WIRE-28] verbatim).** `ArtifactFetchRequest {
   string sha256 = 1 [pattern ^[a-f0-9]{64}$]; uint64 offset = 2 }`;
   `ArtifactChunk { sha256; offset; bytes data = 3 [min_len 1] }`;
   `ArtifactFetchError { string sha256 = 1 [same pattern];
   ArtifactFetchErrorCode code = 2 [defined_only, not_in 0] }` with enum
   `{ UNSPECIFIED = 0, UNKNOWN_DIGEST = 1, GONE = 2 }` — exactly the two
   unservable causes [WIRE-28] names (unknown digest, garbage-collected
   blob); static messages per [WIRE-7], so no message field exists.
   `offset` is deliberately untagged: full uint64 range is legal resume
   input, bounds are the artifact's size (ART-2, SPEC-010, server-side).
5. **Terminal recording chunks.** `TerminalRecordingChunk { string
   session_id = 1 [ULID]; TerminalDirection direction = 2 [defined_only,
   not_in 0]; bytes data = 3 [min_len 1] }`, enum `{ UNSPECIFIED = 0,
   INPUT = 1, OUTPUT = 2 }` (GW-7; operator decision 44: input AND
   output). Ordering is stream order ("serialized", GW-7) — no sequence
   field until a spec demands reassembly.
6. **CrlUpdate.** `CrlUpdate { bytes crl = 1 [min_len 1] }` — a standard
   X.509 DER CRL: PKI-6's mandated `issued_at` and monotonic sequence are
   the DER `thisUpdate` field and `crlNumber` extension, both inside the
   CA signature; a proto wrapper duplicating them would be a second
   representation of signed content (the [WIRE-14] lesson). Verification
   is gateway-side (GW-1.1).
7. **Terminal token validation unary.** `rpc ValidateTerminalToken(
   ValidateTerminalTokenRequest) returns (ValidateTerminalTokenResponse)`
   on InternalService. Request `{ string token = 1 [min_len 1, max_len
   512] }` — opaque token only; the caller is the gateway cert ([WIRE-18]:
   no self-asserted identity). Response `{ string device_id = 1 [ULID];
   string session_id = 2 [ULID]; string user_id = 3 [ULID] }` — the
   binding the gateway needs to bridge (GW-7); control enforces the
   [WIRE-19] connection-set check before answering (rejection row:
   device-scoped unary not matching caller's set → denied).
8. **No sealed-credential-proxying RPC is minted.** SPEC-015 allocates
   every secret flow to existing carriage: escrow rides the signed result
   path (SEC-5), inline action-field secrets ride `PushCommand`'s sealed
   command payload (SEC-11), admin retrieval is B1-only (SEC-2). §3.2's
   "sealed credential proxying" names the [WIRE-24] property of any
   gateway-proxied secret op, not a defined RPC; minting one with no
   spec'd consumer is dead contract surface (the [WIRE-4] principle).
   Open question filed (see issue).
9. **ScimService / ExportService surfaces = declarations + recorded
   ownership.** Neither SPEC-007 (AUTH-7: SCIM v2 users/groups/discovery,
   HTTPS + bearer, SCIM-JSON media type) nor SPEC-016 (OPS-2: the
   exporter binary speaks standard OTLP) defines contract RPCs, exactly
   as [WIRE-11] leaves ControlService's ~20 domains to SPEC-009. The M1
   service declarations with their doc comments ARE the M5 surface; RPC
   shapes land with the owning specs' implementation sessions. Open
   question filed for the SCIM proto-vs-passthrough encoding (latent
   [WIRE-10] tension) and the ExportService shape.
10. **Result-type set stays grammar-open; G-5 stays command-only.** The
    specs never enumerate the `power-manage:result:<type>:v1` token set
    (unlike command_type, SPEC-003 §3.4) and the escrow-report domain
    question is open — filed as a GitHub issue. The M4 ceiling
    (docs/plans/spec-003-m4.md) is updated to cite the issue instead of
    promising closure here. G-5 gains its `Guards: INV-5.` registration
    line (owed since the conformance harness landed).
11. **G-7 deny-list guard** (`TestGuard_DenyList`, archtest). Population:
    every contract proto file (matches-zero: fails on zero files). Scans,
    exactly the spec's G-7 row: field names `auth_token` /
    `params_canonical` anywhere; an RPC named `TriggerAgentUpdate`; enum
    value names carrying the reserved-backend tokens (GELI, CGD, CONNMAN,
    WPA_SUPPLICANT, IWD, OPENRC, RUNIT, S6, DOAS); banned dependency
    imports (asynq, valkey/redis client packages) via an AST import scan
    over all four modules (matches-zero on the module walk). Liveness:
    fixture protos plant each descriptor family; the import family gets a
    fixture-tree scan (same pattern as the conformance liveness).
12. **G-8 near-copy guard** (`TestGuard_NearCopies`, archtest).
    Descriptor walk over all contract messages; two messages whose
    field-name+type multisets are identical fail unless allowlisted with
    a per-entry rationale (allowlist keyed by sorted full-name pair;
    starts EMPTY). Matches-zero on the message walk; liveness fixture
    plants an exact near-copy pair. Wrappers/compositions (choice 3)
    differ in field sets and pass structurally.
13. **Enum-bounds ceiling retires.** `ArtifactFetchErrorCode` and
    `TerminalDirection` are the first service-reachable enum fields; the
    M2 vacuity note on `TestGuard_EnumBounds` is updated (the liveness
    row stays). The M4 SyncManifest-tagging note resolves as: the
    manifest never becomes G-1-reachable (it rides `SignedCommand.payload`
    bytes by design); its post-verification validation is agent-side
    (SPEC-013) — comments updated to say so.

## Files

- `contract/proto/powermanage/v1/agent.proto` — Stream RPC, Hello,
  Welcome, AgentFrame, ServerFrame (choices 1–3).
- `contract/proto/powermanage/v1/internal.proto` — Stream RPC + unary
  (choice 7), GatewayFrame, ControlFrame, DeviceConnected,
  DeviceDisconnected, DeviceReport, TerminalRecordingChunk +
  TerminalDirection, ArtifactFetchRelay, PushCommand, CrlUpdate,
  ArtifactChunkRelay, ArtifactErrorRelay (choices 1, 3, 5–7).
- `contract/proto/powermanage/v1/artifact.proto` — ArtifactFetchRequest,
  ArtifactChunk, ArtifactFetchError + code enum (choice 4; shared by both
  streams, [WIRE-1] one-definition).
- `contract/archtest/guards_test.go` — G-7 + G-8 + liveness (choices
  11–12); file floors 12 → 13; `Guards: INV-5.` line on
  TestGuard_SignatureDomains; ceiling-comment updates (choice 13).
- `contract/archtest/testdata/fixture/...` — deny-list + near-copy
  fixture plants; fixturepb regenerated.
- `contract/gen/**` — regenerated.
- `docs/plans/spec-003-m4.md` — ceiling note updated to cite the issue
  (choice 10).
- `docs/content/01-specs/00-index.md` — SPEC-003 → Implemented; M5
  ledger line.

## Test authorship

Trust-boundary milestone (stream frames carry the signed envelopes):
failing tests authored by the test-writer agent before implementation —
frame-shape descriptor tests (exact oneof member sets both directions,
required oneofs, wrapper field tags), artifact frame shapes vs [WIRE-28],
enum hygiene rows, G-7/G-8 guards with liveness, service-surface exact-set
update (AgentService/InternalService gain their RPCs; the G-2a RPC floor
rises), reachability arming checks (enum-bounds guard goes live).
