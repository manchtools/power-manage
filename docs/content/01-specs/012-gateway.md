---
title: "SPEC-012 — Gateway"
---
# SPEC-012 — Gateway

Status: See `00-index.md` (single status ledger)
Builds on: SPEC-003 (wire-contract), SPEC-006 (pki-and-identity)
Enables: SPEC-013 (agent-core), SPEC-016 (operations-and-ha)
Module(s): server (gateway binary; control-side InternalService stream, dispatch, routing config), contract (stream frame shapes)

## 1. Scope

The gateway: a dumb, stateless connection facilitator between agents and
control. This spec defines the gateway binary's behavior (agent mTLS
termination, CRL enforcement, frame relay, terminal WebSocket bridging,
artifact-chunk relay) and the control-side seam it terminates on (the
persistent InternalService stream, registration-by-presence, per-device
command dispatch from Postgres work tables, device-origin binding, and the
edge-routing config served to the TLS edge). Gateway certificate issuance and
CRL production are SPEC-006; this spec covers their gateway-side enforcement.

## 2. Context capsule

A fresh implementer needs the following from prior specs, restated:

- **Trust model (SPEC-001).** The compromised relay is the pivotal threat
  actor: a gateway is assumed able to read, modify, replay, or drop anything
  transiting it. Every control→agent surface is CA-signed with freshness;
  every device→control report is device-signed; secrets transit only as
  sealed blobs. The design goal: the worst a gateway compromise yields is
  denial of service on the devices routed through it — never forgery, never
  impersonation, never secret disclosure.
- **State placement (SPEC-001).** Everything durable lives in Postgres or the
  agent's local store; no middle tier holds state a restart can lose. The
  gateway holds no database, no secret custody, no CA keys, and no authority:
  nothing an agent or control trusts may *originate* at the gateway.
- **Wire contract (SPEC-003).** Commands travel as `SignedCommand` (CA
  signature over the exact executed bytes, domain-separated, with
  `issued_at`/`expires_at` freshness; instant commands ≤ 15 min validity).
  Device reports travel as `DeviceSigned` envelopes (device-key signature,
  verified by control against the DER-derived registered certificate).
  Identity at every seam is the mTLS certificate: SPIFFE URI SAN
  `spiffe://power-manage/{agent|gateway|control}` = class, CN = instance
  ULID. No message anywhere carries a self-asserted `device_id`/`gateway_id`
  identity field.
- **PKI (SPEC-006).** Agent certificates: 1-year lifetime, signed by the
  internal agent CA. Gateway certificates: 45-day lifetime, minted per boot
  via token-gated self-enrollment on PkiService; control stamps the DNS SAN.
  Revocation is a control-signed CRL carrying `issued_at` and a monotonic
  sequence number. A revoked gateway halts; rotating the gateway enrollment
  token is a durable lockout by design.
- **Event store (SPEC-005).** Async and future-dated work lives in Postgres
  work tables written atomically with events (outbox pattern) and drained by
  advisory-lock workers via `SELECT … FOR UPDATE SKIP LOCKED`. Pending
  instant commands are such a work table.
- **Availability model (SPEC-001).** Control going down pauses the management
  plane only: running gateways keep bridging fail-static on the cached signed
  CRL; agents run autonomously; open terminal bridges survive under the
  AUDIT-GAP posture. Postgres down: control RPCs error, running gateways keep
  bridging, agents run offline. One gateway down: its agents reconnect
  through edge routing to another.

- **Defended actors:** the compromised relay itself and on-path network
  attackers must gain no authority from gateway connectivity or routing state.

## 3. Requirements

### [GW-1] Stateless mTLS relay, fail-closed CRL enforcement

- The gateway terminates agent mTLS: `RequireAndVerifyClientCert`, TLS 1.3
  minimum, client certs validated against the internal agent CA, SPIFFE
  class checked (agent-class only on the agent port), CRL enforced
  fail-closed. It holds ONE persistent mTLS bidi stream to control
  (InternalService, gateway-class cert) and relays frames both ways.
- It has: no database, no credential custody, no CA keys, no queue, and no
  authority. Nothing in flight survives a gateway restart — and nothing needs
  to: durable state lives at the edges (desired state in the event store,
  unshipped results in the agent's local store).
- The control-signed CRL is the ONLY artifact the gateway caches, and it
  caches it to disk. CRL handling:
  - **GW-1.1** Control pushes the signed CRL over the stream on connect and
    on every change. The gateway verifies control's signature and rejects an
    update whose sequence is not newer than the current one; a rejected
    update never replaces the held CRL.
  - **GW-1.2** The verified CRL is applied fail-closed: new connections from
    revoked certificates are denied, and existing streams whose certificate
    appears in a newly applied CRL are terminated.
  - **GW-1.3** A running gateway that loses control fails STATIC: it keeps
    enforcing the last verified CRL and re-warns periodically while degraded.
  - **GW-1.4** A gateway cold boot without control reachable uses the
    disk-cached signed CRL only within a max-age window (default 7 days,
    measured from the CRL's `issued_at`). With no cache, an
    invalid-signature cache, or a cache older than max-age, the gateway
    REFUSES TO SERVE agent connections until it obtains a current CRL. There
    is no fail-open mode and no bypass knob.

### [GW-2] Certificate identity; device-origin binding

- **GW-2.1** The gateway's identity is its per-boot self-enrolled certificate
  (SPEC-006): every process start self-enrolls with the gateway registration
  token and receives a NEW gateway identity (fresh CN ULID). The control
  stream and all unary InternalService calls authenticate by this
  certificate; there is no gateway ID field anywhere.
- **GW-2.2** Control accepts gateway-class certificates ONLY on
  InternalService; agent-class certificates are rejected by SPIFFE class.
- **GW-2.3** Control binds every device-scoped message to the CALLING
  gateway's certificate identity AND to the connection set that gateway has
  reported, fail-closed: a `DeviceReport` (or any device-scoped operation)
  for a device the gateway has not reported connected is dropped and logged.
  A compromised gateway can therefore act only for devices actually streamed
  through it — and even for those, only within what signatures allow
  (relay/drop, never forge).
- **GW-2.4** The binding resolver is mandatory wiring: an unwired resolver is
  a control boot failure, never a silently skipped check. A single-gateway
  deployment that wants the binding relaxed expresses that as explicit named
  configuration, not a nil check.
- **GW-2.5** A gateway whose certificate is revoked halts: control refuses
  its stream, and the gateway treats a revocation rejection as fatal (exit),
  not a transient retry.

### [GW-3] The gateway stream protocol; presence is registration

The gateway↔control seam is small and enumerable. Complete frame set:

| Direction | Frame | Purpose |
|---|---|---|
| gateway → control | `DeviceConnected` | Device stream opened; feeds the routing registry |
| gateway → control | `DeviceDisconnected` | Device stream closed; removes the routing entry |
| gateway → control | `DeviceReport` | Relays the device-signed envelope unopened (results, compliance, inventory, alerts) |
| gateway → control | terminal recording chunks | Session-recording input/output chunks, serialized (SPEC-011; only when recording is enabled) |
| gateway → control | `ArtifactFetchRequest` | Relayed from a connected device: artifact digest + offset |
| control → gateway | `PushCommand` | A `SignedCommand` for a named connected device |
| control → gateway | `CrlUpdate` | Signed CRL (GW-1.1) |
| control → gateway | `ArtifactChunk` | Artifact bytes for a named connected device; chunk size within GW-8 frame caps |
| control → gateway | `ArtifactFetchError` | Structured error for an unservable fetch (unknown or garbage-collected digest), relayed to the named connected device (WIRE-28, SPEC-003; ART-3, SPEC-010) |

- **GW-3.1** Stream presence IS registration; disconnect IS deregistration.
  There is no registration RPC, no TTL refresh loop, and no one-shot publish
  that can fail silently. On reconnect the gateway re-reports its FULL
  connection set, so control's routing table is reconstructible at any
  moment.
- **GW-3.2** Gateway liveness, as control sees it, is stream presence and
  nothing else — no heartbeat timestamps, no staleness heuristics. The doctor
  (SPEC-016) checks gateway registry liveness and CRL cache age.
- **GW-3.3** Artifact relay is stateless: the gateway relays
  `ArtifactFetchRequest`/`ArtifactChunk` frames and never caches artifact
  bytes (the CRL remains the only cached artifact). Chunks carry no
  per-chunk signatures: the expected `(sha256, size)` is covered by the
  `SignedCommand` (SPEC-010), and integrity is the agent's whole-artifact
  digest check at its single verification chokepoint (SPEC-013). The
  `offset` field in the fetch request makes interrupted fetches resumable
  without gateway state.
- **GW-3.4** Every frame handler switches exhaustively with an erroring
  default; an unknown frame type is an error, never silently ignored.

### [GW-4] Delivery semantics: control owns retry

- Control persists pending instant commands in a Postgres work table
  (SPEC-005 outbox pattern) with their TTL from the `SignedCommand`
  freshness window.
- A `PushCommand` goes only to a gateway that reported the target device
  connected. On `DeviceConnected`, control re-pushes unexpired pending
  commands for that device; expired commands are never delivered.
- Retry is control's job exclusively. The gateway never buffers and never
  retries on its own authority; a frame it cannot deliver (device
  disconnected between report and push) is dropped and the disconnect is
  reported — control's work table and re-push-on-connect provide the
  delivery guarantee.

### [GW-5] The control-stream reconnect loop is availability-critical

- Validation and configuration errors at gateway boot are FATAL: the process
  exits rather than serving in a half-configured state.
- Every other stream failure (dial error, control restart, transient network)
  retries with capped backoff and periodic re-warn while degraded. While
  degraded, the gateway keeps bridging existing agent connections fail-static
  (GW-1.3).
- There is exactly ONE registration to heal — the stream itself (GW-3.1). A
  successful reconnect re-reports the full connection set and is then fully
  registered; no secondary registration state exists to drift.

### [GW-6] Edge routing: routable address, config served from control

- The gateway reports a ROUTABLE address for edge routing — an address the
  TLS edge can actually reach — never the process hostname or any
  container-internal name.
- Control serves the derived edge dynamic routing config over an HTTP
  provider endpoint that the edge (Traefik) polls; the config is derived from
  live-registered gateways (stream presence, GW-3.1). The edge never reads
  the container runtime socket.
- Routing wiring ships as binary defaults, not hand-wired environment
  variables (config discipline per SPEC-002).

### [GW-7] Terminal bridging

- The WebSocket attach token is carried via `Sec-WebSocket-Protocol` ONLY —
  never a query parameter (URLs land in logs and proxies).
- The gateway validates the attach token against control (unary
  InternalService call) before bridging. The agent ADDITIONALLY verifies the
  CA-signed terminal grant (`terminal-grant` SignedCommand: device, user,
  session ULID, ≤ 60 s expiry — SPEC-003): token validation alone never
  suffices, so a compromised gateway cannot mint PTYs.
- Session-recording chunks (input AND output, when recording is enabled —
  opt-in, default off, SPEC-011) ride the control stream serialized.
- If control drops mid-session, the bridge SURVIVES under the AUDIT-GAP
  posture: the session continues, the gap is logged loudly, and a gap marker
  is recorded on reconnect. Availability of an open admin session outranks
  recording continuity; the gap itself is the audited fact.

### [GW-8] Resource discipline

- Every inbound agent frame is size-capped; an over-cap frame is rejected and
  the offending connection closed.
- Every dispatch loop is panic-recovered: one malformed frame or handler
  panic must not crash the process serving the rest of the fleet.
- Per-connection transports are fully closed on reconnect — no goroutine or
  connection leak across agent reconnect cycles.

## 4. Acceptance criteria

- **AC-1** A TLS connection without a client certificate, or with a
  certificate not signed by the internal agent CA, fails the handshake.
- **AC-2** A gateway-class certificate is rejected on the agent port; an
  agent-class certificate is rejected on InternalService.
- **AC-3** A certificate listed on the current CRL cannot connect; applying a
  CRL that newly revokes a connected agent's certificate terminates that
  stream.
- **AC-4** A `CrlUpdate` with an invalid signature, or a sequence not newer
  than the held CRL, is discarded with a loud log; the held CRL remains in
  force.
- **AC-5** Cold boot with control unreachable: with a valid disk-cached CRL
  younger than max-age the gateway serves; with no cache, an invalid cache,
  or a cache older than max-age it refuses agent connections and logs why.
- **AC-6** A running gateway that loses control keeps bridging existing and
  new agent connections against the last verified CRL and emits periodic
  degraded warnings.
- **AC-7** Each process start yields a NEW gateway certificate identity;
  control's registry shows the new identity and drops the old on stream
  close.
- **AC-8** A `DeviceReport` for a device the calling gateway has not reported
  connected is dropped by control, logged, and never recorded.
- **AC-9** Control with no binding resolver wired fails at boot; the
  single-gateway relaxation works only via its explicit named configuration.
- **AC-10** A revoked gateway certificate is refused on InternalService, and
  the gateway process exits (no retry loop).
- **AC-11** Stream presence drives routing: after gateway reconnect, control's
  routing table equals the re-reported connection set with no manual
  re-registration and no TTL wait.
- **AC-12** A pending instant command persisted before the device connects is
  delivered on `DeviceConnected` if unexpired, and is NOT delivered if its
  TTL has lapsed.
- **AC-13** An artifact fetch relays end-to-end (request up, chunks down)
  with zero artifact bytes retained by the gateway after completion, and an
  interrupted fetch resumes from the requested offset. A fetch control cannot
  serve (unknown or garbage-collected digest) relays the structured
  `ArtifactFetchError` frame to the requesting device — never silence, never
  a dropped-as-unknown frame.
- **AC-14** A WS attach with the token in a query parameter is rejected; a
  token that fails control validation opens no bridge; a valid token with a
  missing/invalid CA-signed grant results in the agent refusing the session.
- **AC-15** Killing control mid-terminal-session leaves the bridge working;
  gap logs appear; a gap marker is recorded on reconnect.
- **AC-16** An inbound frame exceeding its size cap is rejected and the
  connection closed; a panicking frame handler is recovered and the process
  keeps serving other connections.
- **AC-17** Reconnecting the same agent N times leaves no leaked
  goroutines/transports from prior connections.
- **AC-18** A gateway boot with an invalid configuration exits nonzero;
  a transient control-dial failure at boot retries with backoff instead.
- **AC-19** The edge-routing config served by control lists exactly the
  live-registered gateways with their reported routable addresses.

## 5. Rejection paths

| Input / state | Required behavior |
|---|---|
| Agent TLS handshake without client cert | Handshake rejected (`RequireAndVerifyClientCert`) |
| Client cert from an unknown CA | Handshake rejected |
| Wrong SPIFFE class for the port (gateway cert on agent port, agent cert on InternalService) | Rejected, logged with class mismatch |
| Cert on the current CRL (new connection) | Connection denied |
| Cert newly revoked by an applied CRL (existing stream) | Stream terminated |
| `CrlUpdate` with bad signature | Discarded; held CRL retained; loud log |
| `CrlUpdate` with non-monotonic (stale/replayed) sequence | Discarded; held CRL retained |
| Cold boot: no CRL cache, control unreachable | Refuse to serve agent connections |
| Cold boot: CRL cache older than max-age (default 7 d) | Refuse to serve agent connections |
| Inbound agent frame over size cap | Frame rejected; connection closed |
| Unknown frame type on either stream | Erroring default; frame rejected, logged — never silently ignored |
| `DeviceReport` for a device not in the calling gateway's reported connection set | Dropped by control, fail-closed, logged |
| Device-scoped unary call not matching the caller's cert identity + connection set | Denied fail-closed |
| Control boot with binding resolver unwired | Boot failure (no silent skip) |
| Revoked gateway cert on InternalService | Stream refused; gateway halts (fatal, no retry) |
| `PushCommand` whose TTL lapsed before the device connected | Never delivered; expires in the work table |
| WS attach token in query parameter | Rejected before any control round-trip |
| WS attach token failing control validation | No bridge; connection closed |
| Valid WS token but missing/invalid CA-signed terminal grant | Agent refuses the session (SPEC-013 enforcement; probed by this spec's E2E) |
| Gateway config/validation error at boot | Fatal exit (nonzero), not retry |

## 6. Test plan (TDD)

Write these FIRST, confirm each fails for the right reason (red via a scoped
neutralizing edit — e.g., comment out the CRL max-age check or the binding
verification — never a revert), then implement.

1. **TLS gate tests** (AC-1..3): real TLS handshakes against a test-minted CA
   hierarchy (real certificates, real SPIFFE SANs — never stubbed verifiers).
   Include the revoke-while-connected case.
2. **CRL state machine** (AC-4..6): signature rejection, sequence
   monotonicity, disk cache round-trip, max-age refusal, fail-static
   degradation. Cold-boot cases run the real binary entrypoint path, not a
   unit facsimile.
3. **Stream registration** (AC-7, AC-11): real control-side handler with real
   Postgres (testcontainer) — presence-derived registry, full-set re-report
   on reconnect, identity turnover across gateway restarts.
4. **Binding fail-closed** (AC-8, AC-9): reports for unreported devices
   dropped; unwired-resolver boot failure; explicit single-gateway
   configuration path.
5. **Dispatch semantics** (AC-12): work-table rows with TTLs against real
   Postgres; re-push on connect; expiry non-delivery.
6. **Artifact relay** (AC-13): end-to-end request/chunk flow; assert the
   gateway process retains no artifact bytes (memory/disk inspection);
   offset resume; unknown/GC'd-digest fetch relays `ArtifactFetchError` to
   the device.
7. **Terminal path** (AC-14, AC-15): header-only token transport, unary
   validation, control-kill mid-session with gap-marker assertion.
8. **Resource discipline** (AC-16, AC-17): over-cap frames, injected handler
   panic, reconnect-loop leak detection (goroutine and fd counts before/after
   N cycles).
9. **Deployment E2E gate (SPEC-017).** Mandatory for this spec: boots the
   REAL compose stack from real deploy artifacts; drives every gateway trust
   path (agent→gateway, gateway→control, edge→gateway); negative probes
   (revoked cert, stale CRL cold boot, wrong-class cert) correlate 1:1 with
   expected log evidence; fails on TLS handshake errors, `bad certificate`,
   permission or connection errors; reproduces production key ownership,
   modes, and container UID drops; tests the dial address AND the TLS
   verification identity separately. Synthetic testcontainer green does NOT
   substitute for this gate.

Real-backend rule: control-side tests use real Postgres and real handlers;
TLS tests use real handshakes with real key material; no mocked
verifiers, no stubbed streams where a real loopback stream is constructible.

## 7. Guards

All guards are self-discovering with matches-zero protection: a guard whose
discovery step finds zero subjects FAILS.

| Guard | Discovers | Proves |
|---|---|---|
| Statelessness archtest | Every package in the gateway binary's import graph | No DB driver, no store/persistence package, no queue client imported; the only file-writing site is the CRL cache; graph non-empty |
| Frame exhaustiveness | Every frame type from the stream proto descriptors | Each has a registered handler and every dispatch switch has an erroring default; set non-empty |
| Size-cap coverage | Every inbound frame type from the descriptors | A cap is configured and enforced for each; set non-empty |
| Panic-recovery coverage | Every dispatch loop / background goroutine in the gateway (AST scan) | Wrapped in recover-and-log; scan non-empty |
| Identity-field ban | Every message on the gateway seams (descriptor walk) | No self-asserted `device_id`/`gateway_id`/token identity field for authentication exists (SPEC-003 rule, enforced here too) |
| E2E scenario exact-set | Every externally reachable RPC/stream from the proto registry | A registered deployed-E2E scenario exists per surface; adding a surface fails CI until covered (SPEC-017) |

## 8. Historical lessons

Inline rationale for rules above; each lesson is a real incident or bug class
this design makes structurally impossible.

- **Lesson (queue wedge vs. fail-closed revocation):** revocation state was
  distributed through an external queue/datastore product; when that process
  wedged (a post-fork deadlock in the product itself), gateways could not
  refresh revocation state, and fail-closed enforcement cut off the entire
  fleet. The fix is this design, not softening fail-closed: the CRL is
  control-signed, pushed over the one stream the gateway already needs,
  cached signed on disk, applied fail-static with a bounded max-age. The
  distribution path has no third-party moving part left to wedge (GW-1).
- **Lesson (one-shot registration):** gateway registration was a one-shot
  publish into a registry; when it was lost there was no refresh loop to heal
  it, and terminal routing stayed silently broken for five days. Presence IS
  registration, reconnect re-reports the full connection set, and there is
  nothing else to heal (GW-3.1, GW-5).
- **Lesson (unroutable advertised address):** the gateway advertised its
  process hostname, which the TLS edge could not resolve; routing broke in
  deployment while tests passed. Hence the routable-address discipline and
  control-derived edge config (GW-6).
- **Lesson (fail-open binding mode):** when no (device, gateway) binding
  resolver was wired, the binding check was silently skipped — a nil check
  turned a security control off. An unwired resolver is now a boot failure,
  and the sanctioned relaxation is explicit configuration (GW-2.4).
- **Lesson (unsigned result path):** the entire device→control report path
  once had zero cryptographic coverage — a compromised relay could forge any
  device's results. Reports are now device-signed end-to-end and the gateway
  relays envelopes it cannot open or mint (SPEC-003); this spec's binding
  (GW-2.3) is the defense-in-depth layer on top, not the primary control.
- **Lesson (gateway-minted PTYs):** terminal attach was validated by the
  gateway alone, making the terminal the one unsigned root-privileged
  surface — a compromised gateway could mint PTY sessions. The agent now
  independently verifies a CA-signed, short-expiry terminal grant (GW-7).
- **Lesson (reconnect transport leak):** per-connection transports were not
  closed on reconnect, leaking goroutines and connections across agent
  reconnect cycles until memory pressure; hence GW-8's explicit close and the
  leak-counting test (AC-17).
- **Lesson (CA key custody):** an earlier design placed signing capability
  near the relay tier. CA keys never leave control; the gateway holds no
  authority of any kind (GW-1) — a relay compromise must have nothing to
  steal.

## 9. Milestones

Each milestone is a single implementation session ending with the full suite
green (including all previously landed guards).

1. **mTLS front door + CRL enforcement.** Agent-port TLS termination, class
   checks, CRL verify/apply/cache/max-age state machine, statelessness
   archtest. (AC-1..6)
2. **Control stream + registration-by-presence.** Per-boot self-enroll
   integration (SPEC-006 client side), stream dial, fatal-vs-retry boot
   discipline, presence registry on control with real Postgres, full-set
   re-report. (AC-7, AC-11, AC-18)
3. **Device-origin binding.** Cert + connection-set binding on every
   device-scoped operation, unwired-resolver boot failure, explicit
   single-gateway configuration, revoked-gateway halt. (AC-8..10)
4. **Frame relay + dispatch.** DeviceConnected/Disconnected/DeviceReport
   relay, pending-command work table with TTL, push + re-push semantics,
   frame-exhaustiveness and size-cap guards, panic recovery, reconnect
   transport hygiene. (AC-12, AC-16, AC-17)
5. **Artifact relay.** Fetch-request/chunk/fetch-error relay, zero-retention
   assertion, offset resume. (AC-13)
6. **Terminal bridge.** Header-only token transport, unary validation,
   recording-chunk relay, AUDIT-GAP survival. (AC-14, AC-15)
7. **Edge routing.** Routable-address reporting, control-served HTTP-provider
   config from the live registry. (AC-19)
8. **Deployment E2E gate.** Real compose stack, negative probes with log
   correlation, E2E exact-set guard registration for every gateway surface.
   (test plan item 9)

## 10. Out of scope

- Gateway certificate issuance, self-enrollment token mechanics, CRL
  production and signing, CA rotation (SPEC-006 — this spec consumes and
  enforces).
- `SignedCommand` / `DeviceSigned` envelope formats and signature domains
  (SPEC-003).
- Agent-side verification: manifest handling, digest chokepoint, terminal
  grant verification (SPEC-013 — this spec's E2E probes exercise them).
- Artifact store internals, upload, GC (SPEC-010).
- Terminal recording storage, sealing, retention, and read-audit
  (SPEC-011); this spec only relays the chunks.
- Doctor checks and operational runbooks for gateway liveness and CRL cache
  age (SPEC-016 — semantics defined here, checks live there).
- Any gateway-local buffering, retry authority, artifact caching, or
  fail-open CRL mode — excluded by design, listed so they are not
  "rediscovered" as resilience improvements.
