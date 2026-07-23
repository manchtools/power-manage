---
title: "SPEC-006 — PKI and Identity"
---
# SPEC-006 — PKI and Identity

Status: See `00-index.md` (single status ledger)
Builds on: SPEC-003 (wire-contract), SPEC-005 (event-store)
Enables: SPEC-012 (gateway), SPEC-013 (agent-core), SPEC-015 (secret-surfaces), SPEC-016 (operations-and-ha)
Module(s): `contract/` (PkiService protos, identity conventions), `server/` (control: PkiService, CA custody, CRL issuance; gateway: self-enrollment, CRL enforcement), `agent/` (enroll flow, renewal loop, CA continuity)

## 1. Scope

The internal certificate authority, machine identity, and the full certificate
lifecycle: enrollment, renewal, revocation, CRL distribution, and CA rotation —
for both agents and gateways. Also the identity rules every other seam depends
on: certificate-only authentication, SPIFFE class separation, and the
enrollment trust flow up to the point a device holds a usable identity.

## 2. Context capsule

Minimum prior knowledge, restated:

- **Components.** Control is the single source of authority and the sole holder
  of all signing keys. Gateways are stateless relays: no DB, no secrets, no CA
  keys, no authority; the only artifact a gateway caches is the control-signed
  CRL. Agents run as root on managed devices and hold their own private key,
  which never leaves the device.
- **Threat actor that shapes this spec: the compromised relay.** A gateway is
  assumed able to read, modify, replay, or drop anything transiting it. Nothing
  an agent or control trusts may originate at the gateway. The worst a gateway
  compromise may yield is denial of service for the devices routed through it.
- **Connectivity is never authority.** Reaching a socket or TCP port grants
  nothing; possession of a token, certificate, or signature does.
- **Fail closed, always.** Revocation state unavailable → deny. Decode error on
  persisted security state → deny. Verifier not wired → refuse to boot.
- **Event store (SPEC-005).** All durable state changes are events.
  `AppendEventWithVersion` (expected-version CAS) is MANDATORY for every
  one-time or bounded-use consume — registration tokens, cert renewals
  (ES-4, SPEC-005). An auto-retrying append is designed to defeat the
  optimistic lock and must never guard a bounded-use consume.
- **Wire contract (SPEC-003).** Every control→agent surface is CA-signed with
  freshness over the exact executed bytes (WIRE-14/15, SPEC-003); every
  device→control report is wrapped in a `DeviceSigned` envelope signed by the
  device's enrolled (mTLS) private key (WIRE-20, SPEC-003).
  `target_device_id` in a SignedCommand is addressing, verified against the
  receiving agent's own identity — never authentication.
- **Trust boundaries this spec owns or constrains:** agent→gateway mTLS (B4),
  local enrollment socket (B5), gateway↔control mTLS (B6), and the PkiService
  listener (B10).

- **Defended actors:** compromised relays, on-path network attackers, and
  unauthenticated enrollment callers must not mint or substitute identities.

## 3. Requirements

### 3.1 Certificate-only identity

- **[WIRE-18]** (defined in SPEC-003; PKI is its issuer) No message anywhere in
  the contract carries a self-asserted `device_id`, `gateway_id`, or
  `auth_token` identity field for authentication. Identity at every internal
  seam is the mTLS certificate:
  - SPIFFE URI SAN `spiffe://power-manage/{agent|gateway|control}` = class,
  - CN = instance ULID,
  - DNS SAN = server name only (never identity class, never instance).
- **[WIRE-19]** Class separation is enforced at every mTLS surface: agent-class
  certificates are rejected on InternalService (gateway-class only);
  device-scoped operations bind to the calling gateway's certificate identity
  and its reported connection set, fail-closed. The fail-open
  "no resolver wired → binding skipped" mode does not exist: an unwired
  resolver is a boot failure. A deliberate single-gateway deployment is an
  explicit named configuration, never a nil check.
- All internal TLS is 1.3 minimum; agent-facing surfaces use
  `RequireAndVerifyClientCert`. Agents validate gateway certificates against
  the enrolled internal CA ONLY — system roots are ignored.

### 3.2 Signing authorities and domains

- **[PKI-1]** One `PkiService` owns enrollment, renewal, and revocation for
  BOTH agents and gateways. Three signing authorities exist — agent CA,
  gateway CA, command signing key — and all three live only on control. CA
  private keys never leave control; the gateway in particular holds none.
- Every signature surface is domain-separated with length-prefixed framing
  (WIRE-14, SPEC-003): commands under `"power-manage:cmd:<type>:v1"`, device
  results under `"power-manage:result:<type>:v1"`. Domains are pairwise
  isolated: a signature valid in one domain verifies in no other.
  ECDSA P-256/P-384/P-521 or RSA ≥2048 bits + SHA-256; malformed keys, other
  curves, weaker RSA, and Ed25519 are refused at boot.

### 3.3 PkiService transport and per-operation authorization

- **[PKI-1a]** PkiService listens on its own control port (`:8083`) with
  server-auth TLS only — enrollees have no client certificate yet, so the TLS
  layer requires none. Authorization is strictly per-operation:
  - enroll = registration token ([PKI-2]);
  - agent/gateway renewal = fingerprint match + proof-of-possession ([PKI-3]);
  - gateway self-enroll = gateway registration token.
  Every procedure on this listener is in the public rate-limit ladder
  (AUTH-4, SPEC-007) with anti-enumeration responses; this listener is
  boundary B10.

### 3.4 Enrollment

- **[PKI-2]** Enrollment is CSR-only: the server REFUSES any SAN present in
  the CSR and stamps the SPIFFE URI and CN=ULID itself. The private key never
  leaves the device. The enrollment request also carries the device's X25519
  sealing public key (generated beside the mTLS key, re-submitted at every
  renewal); the server binds it to the issued identity for device-directed
  sealing of inline action-field secrets (SEC-11, SPEC-015; recorded operator
  decision 2026-07-19 — decisions doc) — rotation is atomic on the device
  record at renewal. The registration token is the SOLE authorization:
  - 256-bit random, SHA-256-hash-stored, constant-time compare;
  - one-time or `max_uses`/`expires_at`, optional owner, disable = kill switch;
  - consume is version-pinned via `AppendEventWithVersion` (ES-4, SPEC-005) —
    N racing enrollments mint exactly the permitted number of devices, never
    more.
- **[AG-17]** Agent-side enrollment flow (agent relays the enrollment to
  PkiService):
  - enroll socket `/run/pm-agent/enroll.sock`, mode **0666** — DELIBERATE,
    a preserved operator decision reversed twice; do not tighten. The token is
    the sole authorization; the socket grants nothing.
  - rate-limited 5/min on BOTH sides (device socket and server);
  - trust-on-first-use for the CA, with an optional out-of-band
    CA-fingerprint pin;
  <!-- docref: begin src=contract/proto/powermanage/v1/pki.proto#EnrollAgentResponse.gateway_certificate_authority_der:d2abc1d1,contract/proto/powermanage/v1/pki.proto#RenewAgentResponse.gateway_certificate_authority_der:d2abc1d1,agent/internal/enroll/client.go#Client.Enroll:f7977f41,agent/internal/enroll/client.go#Client.Renew:b6d3352e -->
  - enrollment and renewal deliver the distinct gateway CA alongside the
    agent issuing CA. The agent validates and persists both trust anchors so
    gateway TLS verification uses only the enrolled gateway CA, never system
    roots.
  <!-- docref: end -->
  - the token is read from stdin (prompt on a TTY, pipe otherwise) or
    `--token-file` ONLY. No argv token flag exists anywhere in the
    install/enroll flow.

### 3.5 Renewal

- **[PKI-3]** Agents renew at 80% of certificate lifetime, retrying hourly on
  failure (a short control outage is a non-event). The renewal request
  presents the current certificate; the server requires all of:
  1. constant-time fingerprint match of the presented certificate against
     stored state in the DB;
  2. proof-of-possession — the CSR public key equals the current certificate's
     key;
  3. a per-device advisory lock held across the operation (concurrent
     renewals serialize; no orphan certificates).
  The superseded certificate is revoked on successful renewal.

### 3.6 Certificate state discipline

- **[PKI-4]** Certificate-authority state is DER-derived from the stored
  certificate, never trusted from a projection copy. Every verification of a
  device signature (WIRE-20, SPEC-003) parses the stored DER; a projection
  column is never key material. Per-device lifecycle operations (enroll,
  renew, revoke, delete) serialize on a per-device advisory lock; token
  admission serializes through version-pinned event appends (ES-4, SPEC-005).

### 3.7 Lifetimes and gateway identity

- **[PKI-5]** Agent certificates: 1 year — a deliberate offline-tolerance
  decision (preserved: long validity + fail-closed CRL enforcement, not short
  validity). Gateway certificates: 45 days, fresh per-boot identity via
  self-enrollment (token-gated, same PKI-2 rules; DNS SAN is
  control-authoritative). A revoked gateway halts. Gateway token rotation is a
  durable lockout by design.
- Gateway server-certificate requirements: the gateway certificate serves
  agents (server role on AgentService mTLS) and authenticates to control
  (client role on InternalService). It MUST carry both ServerAuth and
  ClientAuth EKUs and control-authoritative DNS SANs covering the exact
  identity agents dial. Dial address and TLS verification identity are two
  distinct correctness axes and are tested separately (TEST-6 doctrine,
  SPEC-017).

### 3.8 Revocation and CRL

- **[PKI-6]** Revocation is a control-signed CRL carrying `issued_at` and a
  monotonic sequence number. Distribution: pushed to every gateway over its
  persistent control stream on connect and on every change (GW-3, SPEC-012).
  Gateway obligations:
  - verify the CRL signature before applying; reject invalid signatures and
    non-monotonic sequences, keeping the current CRL;
  - apply fail-closed: a revoked certificate is refused at the TLS layer;
  - cache the signed CRL to disk; fail-static on staleness with periodic
    re-warn while control is unreachable;
  - a cold boot without control uses the disk-cached signed CRL within a
    max-age window (default 7 days); older than max-age → refuse to serve.
  Revocation rides `DeleteDevice` and renewal supersession, PLUS four
  first-class operations: a standalone revoke RPC, force-renew, live
  trust-bundle reload, and a per-device CA-migration report.

### 3.9 CA continuity and rotation

- **[PKI-7]** Agents adopt a new CA over renewal only if it is byte-identical
  to the enrolled CA or cross-signed by it; a hard CA swap requires
  re-enrollment. The 4-phase CA rotation procedure is first-class tooling
  shipped with control, never a hand-run openssl recipe (surfaced in
  SPEC-016 operations).

### 3.10 No re-enrollment

- **[AG-18]** There is NO re-enrollment machinery, online or offline. A device
  with broken or lost credentials is re-enrolled from scratch by an operator:
  `install.sh --reset` stops the agent, wipes `/var/lib/power-manage`
  (root-only, fd-anchored `O_NOFOLLOW` discipline), and runs a fresh
  enrollment. Fresh enrollment mints a NEW device identity; the stale device
  record remains until the operator deletes it (`DeleteDevice` revokes its
  certificate). No exit-class or credential-classifier apparatus exists.

## 4. Acceptance criteria

- **AC-1** Enrollment with a valid token returns a certificate whose SPIFFE
  URI SAN is `spiffe://power-manage/agent`, CN is a newly minted ULID, and
  whose public key equals the CSR key. Any SAN present in the CSR causes
  rejection with no certificate minted.
- **AC-2** A registration token with `max_uses = N`: N+k concurrent
  enrollment attempts succeed exactly N times; the k losers receive the same
  rejection as an invalid token. Verified against real Postgres under real
  concurrency.
- **AC-3** Token verification is hash-based (SHA-256 at rest) and
  constant-time; a disabled token rejects immediately regardless of remaining
  uses or expiry.
- **AC-4** Renewal succeeds only when the presented certificate's fingerprint
  matches stored state AND the CSR key equals the current certificate key.
  Either failing → rejection; the stored state is unchanged.
- **AC-5** Two concurrent renewals for one device produce exactly one new
  certificate; the superseded certificate is revoked; no orphan certificate
  exists afterward.
- **AC-6** An agent-class certificate presented on InternalService is
  rejected by SPIFFE class before any request processing.
- **AC-7** A revoked agent certificate cannot complete a TLS handshake at the
  gateway; revocation takes effect on the next CRL push without gateway
  restart.
- **AC-8** A gateway receiving a CRL with a bad signature or a sequence lower
  than its current one keeps its current CRL and logs the rejection.
- **AC-9** A gateway cold-booting with a disk-cached CRL younger than max-age
  serves agents fail-static; with a cache older than max-age (default 7 days)
  it refuses to serve.
- **AC-10** Gateway self-enrollment yields a 45-day certificate with
  control-authoritative DNS SANs and both ServerAuth and ClientAuth EKUs; an
  agent's TLS verification of the gateway succeeds against the enrolled
  internal CA with system roots absent.
- **AC-11** Signature domains are pairwise isolated: bytes signed under any
  discovered domain fail verification under every other discovered domain.
- **AC-12** `DeleteDevice` revokes the device certificate; the standalone
  revoke RPC and force-renew each produce a CRL push observable at a
  connected gateway.
- **AC-13** On renewal, an agent presented a CA that is neither byte-identical
  to nor cross-signed by its enrolled CA refuses adoption and keeps its
  current trust anchor.
- **AC-14** Device-signature verification (WIRE-20, SPEC-003) reads its key
  by parsing the stored DER certificate; corrupting the projection row does
  not change the verification outcome.
- **AC-15** Control refuses to boot when the CRL signer, a signature
  verifier, or the (device, gateway) binding resolver is unwired.
- **AC-16** The enroll client and installer accept the token only via stdin
  or `--token-file`; no argv token flag parses.

## 5. Rejection paths

| Input / state | Required behavior |
|---|---|
| CSR contains any SAN | Reject; server stamps identity itself; no cert minted |
| Token invalid / expired / disabled / exhausted | Uniform rejection, byte- and timing-identical across causes |
| Racing enrolls beyond `max_uses` | Exactly the permitted number succeed (CAS consume); rest rejected |
| Enrollment rate above 5/min (socket or server side) | Rate-limited rejection |
| Renewal: fingerprint mismatch vs stored state | Reject (constant-time compare); no state change |
| Renewal: CSR key ≠ current cert key | Reject (proof-of-possession failure) |
| Concurrent renewal, same device | Serialized on per-device advisory lock; exactly one new cert |
| Agent-class cert on InternalService | Reject by SPIFFE class before processing |
| Gateway-class cert where agent-class required | Reject by SPIFFE class |
| Revoked cert on any mTLS surface | TLS-layer refusal (CRL fail-closed) |
| CRL signature invalid or sequence non-monotonic | Reject the update; keep current CRL; log |
| Gateway cold boot, CRL cache older than max-age | Refuse to serve |
| Revocation state unavailable at handshake time | Deny (fail closed) |
| SignedCommand `target_device_id` ≠ agent's own identity | Agent refuses; nothing executes |
| Renewal delivers a CA neither byte-identical nor cross-signed | Agent refuses adoption; keeps enrolled CA |
| Ed25519, unsupported-curve, malformed, or RSA <2048 configured as a signing key | Refuse to boot |
| Verifier / resolver / CRL signer unwired | Refuse to boot (never a silent skip) |
| Token passed as argv | Structurally impossible — the flag does not exist |

## 6. Test plan (TDD)

Write these FIRST, confirm each fails for the right reason (scoped
neutralizing edit, never a revert), then implement:

1. **Token lifecycle** against real Postgres (testcontainer, template-cloned
   per test): mint → hash-at-rest assertion → constant-time verify → CAS
   consume race test (AC-2, AC-3). RED first by neutralizing the
   expected-version check and watching the race over-mint.
2. **Enrollment handler** through the REAL handler: correct / absent /
   malformed for every request field; CSR-SAN refusal (AC-1); rate-limit
   rejection.
3. **Renewal handler**: fingerprint mismatch, PoP failure, concurrent-renewal
   serialization (AC-4, AC-5); superseded-cert revocation.
4. **Class separation**: real TLS handshakes with agent-class and
   gateway-class certs against each surface (AC-6).
5. **CRL behavior** at a real gateway process: push/apply, bad-signature and
   stale-sequence rejection, disk cache, cold-boot max-age refusal
   (AC-7..AC-9).
6. **Domain isolation**: pairwise cross-verification over self-discovered
   domains (AC-11).
7. **DER-provenance**: projection-corruption test proving verification reads
   stored DER (AC-14).
8. **Boot fail-closed**: unwired verifier/resolver/signer boot tests (AC-15).
9. **Deployment E2E gate** (SPEC-017): any change to TLS material, listener
   wiring, or cert lifecycle boots the REAL compose stack from real
   artifacts. TLS tests reproduce production ownership/modes and image UID
   drops (including root-owned 0600 private keys) — a world-readable test key
   proves nothing about the production container user. Dial address and TLS
   verification identity are asserted separately. Synthetic testcontainer
   green does NOT substitute.

No mocks of Postgres or of handlers. Bug fixes ship a regression test that
fails on the buggy version.

## 7. Guards

Self-discovering, matches-zero protected (a guard that discovers nothing
fails):

- **GUARD-006-1** Descriptor walk over PkiService: every procedure is
  registered in the public rate-limit ladder. Zero procedures discovered =
  guard failure.
- **GUARD-006-2** Signature-domain parity: discover every `*SignatureDomain`
  constant; each has exactly one sign site and a fail-closed verify site
  (cross-module); pairwise-isolation test generated over the discovered set.
- **GUARD-006-3** Contract descriptor walk banning self-asserted identity
  fields (`device_id` / `gateway_id` / `auth_token` as authentication
  inputs); the walk must visit > 0 messages.
- **GUARD-006-4** Lifecycle-lock coverage: discover every cert-lifecycle
  handler (enroll, renew, revoke, force-renew, delete-device) and prove each
  acquires the per-device advisory lock.
- **GUARD-006-5** Key-provenance scan: every device-signature verification
  call site obtains key material exclusively through the DER-parse helper;
  the scan must find > 0 verification sites.
- **GUARD-006-6** Boot fail-closed probes: nil verifier, nil binding
  resolver, nil CRL signer each produce a boot failure (never a logged skip).

## 8. Historical lessons

- **Lesson (CRL distribution):** CRL state once lived in a shared in-memory
  datastore; when that store wedged after a background-save fork, fail-closed
  gateways cut off the entire fleet. The rewrite distributes a control-signed
  CRL over the gateway stream with a signed disk cache: fail-closed semantics
  are preserved, but a control outage degrades to fail-static instead of
  fleet-wide denial.
- **Lesson (dial identity):** an internal service was dialed by IP while its
  certificate carried only DNS SANs; TLS verification broke even though both
  endpoints were reachable. Gateway certs carry control-authoritative DNS
  SANs + ServerAuth EKU, and tests assert the dial address and the
  verification identity as separate axes.
- **Lesson (token race):** bounded-use registration tokens consumed through
  an auto-retrying append defeated the optimistic lock — racing enrollments
  minted more devices than the token permitted. Bounded-use consumes are
  version-pinned CAS appends, always (ES-4, SPEC-005).
- **Lesson (orphan cert):** two overlapping renewals for one device minted an
  orphaned certificate outside revocation tracking. Lifecycle operations
  serialize on a per-device advisory lock.
- **Lesson (possession):** renewal once accepted a CSR without proving the
  caller holds the enrolled key, so identity continuity rested on the
  fingerprint check alone. The CSR key must equal the current certificate
  key.
- **Lesson (fail-open binding):** when no (device, gateway) routing resolver
  was wired, the binding check was silently skipped — a fail-open mode
  discovered in review, not by a test. An unwired resolver is now a boot
  failure; sanctioned single-gateway operation is explicit configuration.
- **Lesson (CA custody):** an earlier design left CA material reachable
  outside control; a compromised relay could then have minted identities. All
  three signing authorities live only on control, and the gateway's cache
  contains exactly one artifact: the signed CRL.
- **Lesson (trust from projections):** verifying device signatures against a
  projection copy of the certificate creates a second, writable
  representation of trust material. Verification keys are re-derived from the
  stored DER certificate, every time.
- **Lesson (token exposure):** an enrollment token passed as argv lands in
  shell history and `ps` output for its whole validity window. Token intake
  is stdin or `--token-file` only; the flag was removed from every flow.

## 9. Milestones

Each ends green (vet, staticcheck, full `-race` suite):

1. **Identity primitives.** SPIFFE URI SAN + CN=ULID mint/parse helpers,
   class-check helpers, TLS config builders (1.3 min, class enforcement).
   GUARD-006-3 in place.
2. **CA custody and signing surfaces.** Three signing authorities on control;
   domain-separated sign/verify helpers; Ed25519 boot refusal;
   GUARD-006-2/6.
3. **Registration tokens.** Mint, hash-at-rest, constant-time verify,
   CAS consume, rate limiting; race regression test (AC-2).
4. **PkiService enrollment.** `:8083` listener (server-auth TLS), enroll RPC
   (CSR-only, SAN refusal, identity stamping), agent enroll-socket relay
   (0666, stdin/token-file intake). GUARD-006-1.
5. **Renewal.** Fingerprint + PoP + advisory lock + supersession revoke;
   agent renewal loop (80% lifetime, hourly retry). GUARD-006-4.
6. **Revocation + CRL.** Signed CRL (issued_at + monotonic sequence), stream
   push, gateway verify/apply/disk-cache/fail-static, cold-boot max-age;
   standalone revoke RPC; force-renew.
7. **Gateway identity.** Self-enrollment (45-day certs, per-boot identity,
   DNS SANs + dual EKU), revoked-gateway halt.
8. **CA continuity.** Cross-sign adoption rule on the agent, 4-phase rotation
   tooling, live trust-bundle reload, per-device CA-migration report.
   Deployment E2E gate wired for the whole surface.

## 10. Out of scope

- SignedCommand envelope, sync-manifest freshness, and DeviceSigned framing
  (SPEC-003).
- Event store mechanics, append API, projections (SPEC-005).
- Gateway stream protocol frames, delivery semantics, terminal bridging
  (SPEC-012).
- Sealed secret transport (SPEC-015).
- Authorization of PKI admin RPCs on ControlService (SPEC-008).
- Edge routing, compose topology, backup of CA material, rotation runbooks
  (SPEC-016).
- Human authentication, rate-limit ladder implementation (SPEC-007).
