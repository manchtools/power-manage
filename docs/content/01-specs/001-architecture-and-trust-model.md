---
title: "SPEC-001 — Architecture and Trust Model"
---
# SPEC-001 — Architecture and Trust Model

Status: See `00-index.md` (single status ledger)
Builds on: SPEC-000 (M2–M3: guard harness and invariant registry — this spec's guards register there)
Enables: SPEC-002..SPEC-017 (every design decision derives from this trust model)
Module(s): all (`contract/`, `sdk/`, `server/`, `agent/`); normative reference for the separate web repo

## 1. Scope

The system's components, the five-actor trust model, the normative trust-boundary
inventory B1–B11, the availability model, the trust-model invariants
[TM-1..TM-5], and the storage philosophy (Postgres only; durability lives at the
edges). Every other spec names which actor and boundary its rules defend.

## 2. Context capsule

Power Manage manages Linux endpoints: operators declare desired state (packages,
services, files, users, encryption, Wi-Fi, and more — SPEC-014); agents converge
devices to it, online or offline. The implementation process, guard doctrine,
and invariant catalog are SPEC-000; module layout and licensing are SPEC-002.
This spec is the root of the dependency chain: read it before any component
spec.

## 3. Requirements

### 3.1 Components [ARCH-1]

| Component | Role | State | Listens |
|---|---|---|---|
| **Control** | Single source of authority: RPC API for humans/CLI, event-store writer, all three signing authorities (agent CA, gateway CA, command signing), user/RBAC/SSO/SCIM, secret custody, gateway registry, work scheduler | Postgres (sole writer) | `:8081` ControlService (HTTPS+JWT), `:8082` InternalService (mTLS, gateway-class certs only; carries the persistent gateway stream), `:8083` PkiService (server-auth TLS; per-operation token/PoP authorization — PKI-1a, SPEC-006) |
| **Gateway** | Dumb, stateless connection facilitator: terminates agent mTLS, holds ONE persistent stream to control, relays frames both ways, hosts the terminal WebSocket | none (no DB, no credentials, no CA keys; only a disk-cached *signed* CRL) | `:8080` AgentService (mTLS), terminal WS behind the edge |
| **Agent** | Runs as root on managed devices; executes signed actions via SDK primitives; offline scheduler | SQLite (WAL) | local enroll socket, local luksd socket (transient) |
| **SDK** | OS-capability library (mechanism, never policy — SPEC-004) | — | — |
| **Contract** | Proto contract + generated code (SPEC-003) | — | — |
| **Web** | Hosted SPA thin client; talks directly browser→control (separate repo) | — | — |
| **Postgres** | Append-only `events` + projections (in-tx), work tables, FTS indexes | durable | mTLS only |

Four moving parts: Postgres, control, gateway(s), agent. There is no queue
product, no cache product, no search product, and no indexer binary (recorded
decision): every job such middleware would hold collapses into Postgres work
tables (ES-8, SPEC-005) or the gateway stream (GW-3/GW-4, SPEC-012).

### 3.2 Trust-model invariants

- **[TM-1]** Everything durable lives in Postgres, classified under total table
  classification (ES-1, SPEC-005) — a schema-walking guard makes any
  unclassified table unmergeable. Lesson: unclassified tables silently escaped
  the replay and backup guarantees. Durable buffering lives at the EDGES:
  desired state in the event store, unshipped results in the agent's SQLite. No
  middle tier holds state a restart can lose.
- **[TM-2]** The gateway holds no database, no secrets custody, no CA key, and
  no authority: nothing an agent or the control plane trusts may *originate* at
  the gateway. It relays sealed/signed material it cannot open or mint, and
  caches exactly one artifact: the control-signed CRL (SPEC-012).
- **[TM-3]** Control is single-writer, active/standby (§3.5; HA model in
  SPEC-016 — control down pauses the *management* plane, never the device
  plane). All singleton work (dynamic-group evaluation, stale-execution expiry,
  retention prune, scheduled dispatch) uses Postgres advisory locks + OCC
  appends uniformly — no process-local timers that silently assume one
  instance, no leader election.
- **[TM-4]** Connectivity is never authority. Reaching a socket (the 0666
  enroll socket, the gateway TCP port) grants nothing; possession of a
  token/certificate/signature does.
- **[TM-5]** Fail closed, always: revocation state unavailable → deny; decode
  error on persisted security state → deny; unknown enum → reject; verifier not
  wired → refuse to boot — never a silent `if x != nil` disable. Lesson: a
  nil-guarded verifier ran fail-open for months; the gate was off and nothing
  reported it.

### 3.3 Five-actor trust model [ARCH-2]

Every security decision derives from these five actors. Findings and designs
MUST name which actor they defend against.

1. **External unauthenticated attacker** — reaches the public edge (login,
   enroll, renewal, SSO/SCIM endpoints, gateway TLS). Defenses: rate-limit
   ladder on every public procedure, anti-enumeration (byte- and
   timing-identical responses), mTLS class separation, token hashing
   (SPEC-006, SPEC-007).
2. **Authenticated low-privilege user** — holds a valid session and tries to
   escalate (IDOR, scope bypass, grant escalation, information oracles).
   Defenses: behavioral scope enforcement on every read AND write, uniform
   NotFound, role-management permission as the sole grant gate, last-admin
   atomicity (SPEC-008).
3. **Control-plane administrator — TRUSTED.** Admin god-powers are design, not
   findings. Do not build controls that protect the system from its own admin;
   build *audit* so admin actions are attributable (SPEC-011). Recorded
   decision.
4. **Compromised relay (gateway)** — the pivotal actor. Assumed able to
   read/modify/replay/drop anything transiting it. Defenses: CA signatures
   with freshness over the exact executed bytes for every control→agent
   surface, device-signed results the relay cannot forge, sealed secret
   transport the relay cannot open, certificate-derived identity the relay
   cannot assert (SPEC-003). The worst a gateway compromise yields is denial of
   service on the devices routed through it.
5. **Network MITM** — TLS 1.3 everywhere, mTLS on every internal seam, the
   agent validates gateway certificates against the enrolled internal CA only
   (system roots ignored), https→http redirects refused.

### 3.4 Trust boundaries B1–B11 (normative inventory) [ARCH-3]

| # | Boundary | AuthN | AuthZ / integrity |
|---|---|---|---|
| B1 | Browser/CLI → Control | HTTPS + JWT (ES256 pinned — alg confusion rejected; setup-minted keypair, verification key non-secret — AUTH-1, SPEC-007) | interceptor order: validate → authenticate → rate-limit → authorize → handler |
| B2 | SSO callback | PKCE S256 + state + nonce, one-shot 10-min state consumed via atomic `DELETE…RETURNING` | server-side redirect allowlist (incl. loopback for CLI); bounded (12 s) outbound OIDC client |
| B3 | SCIM | per-provider bearer, bcrypt-hashed, identical-401 + dummy-bcrypt anti-oracle | rate limits BEFORE bcrypt (per-slug and per-slug+IP) |
| B4 | Agent → Gateway | mTLS RequireAndVerifyClientCert, TLS 1.3 min, SPIFFE class URI SAN, CN = device ULID, CRL fail-closed | every inbound frame size-capped; identity from cert only |
| B5 | Enrollment (local socket) | none (0666 by design — recorded decision) | registration token is the SOLE authorization; hash-stored; rate-limited 5/min both sides; version-pinned consume |
| B6 | Gateway ↔ Control (InternalService: persistent stream + unary proxy ops) | mTLS, **gateway-class certs only** (agent certs rejected by SPIFFE class) | every device-scoped message bound to the calling gateway's cert identity and its reported connection set, fail-closed |
| B7 | Control → Postgres | mTLS `verify-full`, cert auth | sqlc only, no dynamic SQL; at-rest AES-256-GCM `enc:v1` AAD-bound, no plaintext opt-out |
| B8 | Control → Agent (commands) | (via B4/B6 transport) | **CA signature over exact executed bytes, per-surface domain, with freshness** (WIRE-14/15, SPEC-003) |
| B9 | Agent → Control (results) | (via B4/B6 transport) | **device-key signature over the result envelope** (WIRE-20, SPEC-003) |
| B10 | Agent/Gateway → PkiService (`:8083`) | server-auth TLS only (no client cert exists yet); per-operation authorization: registration token (enroll) / fingerprint + proof-of-possession (renewal) — PKI-1a, SPEC-006 | rate-limit ladder on every procedure; anti-enumeration; version-pinned token consume |
| B11 | Browser → Gateway (terminal WS, behind the edge) | edge TLS; WS attach token via `Sec-WebSocket-Protocol` header ONLY (never query param), validated against control (unary InternalService op) before bridging (GW-7, SPEC-012) | the CA-signed terminal grant verified by the AGENT (WIRE-16, SPEC-003, ≤60 s expiry) is the authority to open a PTY — token validation alone never suffices; session recording per AUD-8 (SPEC-011) |

Every network listener and local socket in the codebase maps to exactly one
boundary above; a new listener requires a new boundary row in this table first.

### 3.5 Availability model [ARCH-4]

Control going down (or being updated) does NOT take the system down — it pauses
the management plane only:

- **Keeps working:** every agent (cached signed manifest, offline scheduler,
  local enforcement — offline autonomy is the product); running gateways
  (fail-static on the cached signed CRL, periodic re-warn); open terminal
  bridges (AUDIT-GAP posture: session survives, gap logged loudly); result
  durability (agents buffer in SQLite until acked — buffer caps are sized for
  realistic outage windows, not minutes; AG-10, SPEC-013).
- **Pauses:** UI/API, instant commands, new terminal sessions, enrollment, and
  certificate renewal (agents retry hourly starting at 80% lifetime — a short
  outage is a non-event). A gateway *cold boot* with a CRL cache older than
  max-age fails closed (SPEC-012).
- **Updates:** a routine control update is a seconds-long management-plane
  pause — restart in place (agents sync on a 30-min cadence with ≤5-min
  reconnect backoff; gateways reconnect automatically) or promote the standby
  behind the stable control address. Schema migrations follow expand/contract
  so the binary swap stays seconds (HA-3, SPEC-016). Postgres is the
  availability floor; Postgres HA (managed/Patroni) is an operator choice, and
  control is a well-behaved client (reconnects, statement timeouts).

Failure matrix: control down → management plane pauses, device plane autonomous.
Postgres down → control RPCs error; running gateways keep bridging fail-static;
agents run offline from verified local state. A gateway down → its agents
reconnect through edge routing to another.

### 3.6 Storage philosophy [ARCH-5]

Postgres is the ONLY durable store on the server side; the agent's SQLite is the
only durable store on the device side. No queue, cache, or search product
exists, and none may be reintroduced below the recorded ceiling (~100k devices
at 30-min sync cadence; active/active upgrade path named in SPEC-016). WHY:

1. **Durability lives at the edges** [TM-1]. Desired state is the event store;
   unshipped results are the agent's SQLite. A middle tier can only hold state a
   restart loses — it adds a failure mode without adding durability.
2. Every job a queue would hold has a strictly simpler home: dispatch and
   future-dated work are Postgres work tables drained via advisory-lock workers
   with `SELECT … FOR UPDATE SKIP LOCKED` (ES-8, SPEC-005); instant delivery
   and registries are the gateway stream, where presence IS registration
   (GW-3/4, SPEC-012); CRL distribution is a signed artifact pushed over that
   stream and disk-cached (PKI-6, SPEC-006); search is Postgres FTS over the
   projections, transactionally fresh (SRCH-1..3, SPEC-009).
3. Lesson: the predecessor's cache/queue middleware (Valkey) deadlocked after a
   background-save fork; because CRL distribution depended on it and gateways
   correctly failed closed, the entire fleet was cut off by a component that
   held nothing durable. The replacement — a control-signed CRL over the
   gateway stream with a disk cache — is strictly better under the same
   fail-closed posture.
4. Dead-letter triage is a WHERE clause on a work table, visible to the doctor
   and the admin UI — not a session inside a queue product's CLI.

### 3.7 Deployment topology (summary) [ARCH-6]

Compose stack: Traefik (TLS edge + SNI passthrough for agent mTLS; dynamic
routing via Traefik's HTTP provider polling control — control serves the config
derived from live-registered gateways; never the raw docker socket), Postgres,
Control (active + optional standby), Gateway (N≥1, self-enrolling). `setup.sh`
generates the cert chain, secrets, and configs; re-run-safe; generated secrets
are hex (URL/form-safe — lesson: a generated secret containing URL-unsafe
characters broke first boot). Multi-gateway scale-out: start a container with an
enrollment token — it self-enrolls (SPEC-006), dials control, and appears in
routing. Linux endpoints only. Full operations surface: SPEC-016.

## 4. Acceptance criteria

- **AC-1** A storage-dependency guard walks every module's dependency graph and
  fails on any datastore/queue/cache/search client library other than the
  Postgres driver (server) and the pure-Go SQLite driver (agent); matches-zero
  ratchet: module discovery (all four modules) is the floor until the
  sanctioned drivers exist — it rises to require the Postgres driver when
  SPEC-005 lands it and the SQLite driver when SPEC-013 does.
- **AC-2** A boundary-registry guard discovers every `net.Listen`/serve call
  site and unix-socket creation by AST walk and fails unless each is registered
  against exactly one of B1–B11; matches-zero floor rises as component specs
  land (final floor: five control/gateway listeners — `:8081`, `:8082`,
  `:8083`, `:8080`, terminal WS — plus two agent local sockets).
- **AC-3** A gateway-purity archtest walks the gateway binary's import closure
  and fails if it reaches the event store, secret custody, or CA-key packages
  [TM-2]; matches-zero: the closure must be non-empty once `server/cmd/gateway`
  exists (a reported skip before then; the liveness fixture stays active
  throughout).
- **AC-4** Fail-closed behavioral tests exist at each boundary as owning specs
  land: revocation unavailable → deny; persisted-security-state decode error →
  deny; unknown enum → reject; unwired verifier → boot failure [TM-5].
- **AC-5** A singleton-work guard proves every background loop in `server/`
  runs under the shared advisory-lock helper [TM-3] (lands with SPEC-016;
  registered against this spec in the invariant ledger).
- **AC-6** Every security-relevant spec section in SPEC-003..016 names the
  actor(s) it defends against (review-auditable; the spec template's §5
  rejection table is checked for actor references).

## 5. Rejection paths

| Input / state | Required behavior |
|---|---|
| Design or PR introducing a second datastore, queue, cache, or search product | Reject — recorded decision (§3.6); the ceiling and upgrade path are named in SPEC-016 |
| State, secret custody, CA key, or buffering authority placed on the gateway | Reject [TM-2] |
| Middle-tier component holding state a restart can lose | Reject [TM-1] |
| Design granting authority by reachability (socket/port access) | Reject [TM-4] |
| Revocation state unavailable at a verify site | Deny [TM-5] |
| Decode error on persisted security state | Deny (defer/refuse), never default-permissive [TM-5] |
| Unknown or UNSPECIFIED enum value at a boundary | Reject [TM-5] |
| Security verifier/resolver/sealer not wired at boot | Refuse to boot [TM-5] |
| New network listener without a boundary row in §3.4 | Guard failure; extend the table first [ARCH-3] |
| Design making agent enforcement depend on live control reachability | Reject — offline autonomy is the product (§3.5) |
| Security design that cannot name its defended-against actor | Reject (§3.3) |
| Process-local timer assuming a single control instance | Reject [TM-3] |

## 6. Test plan (TDD)

Write first, confirm red, then implement:

1. **Storage-dependency guard** (AC-1): fixture module with a queue-client
   dependency → guard red; remove → green. The sanctioned-driver
   discovery doubles as the matches-zero floor.
2. **Boundary-registry guard** (AC-2): red on an unregistered fixture listener;
   green once registration exists; floor test proves an empty discovery fails.
3. **Gateway-purity archtest** (AC-3): neutralizing edit adds a store import to
   a gateway package fixture → red.
4. **Fail-closed boundary tests** (AC-4): written red-first inside each owning
   spec's milestone against real backends (real Postgres, real handlers —
   SPEC-000 §3.5); this spec's ledger entry tracks their existence.
5. **Actor-declaration guard** (AC-6): discover SPEC-003..016; a fixture spec
   without an actor reference fails, and discovering fewer than all 14 specs
   fails closed.

## 7. Guards

| Guard | Discovery | Matches-zero floor |
|---|---|---|
| G-001-1 storage-dependency allowlist | Walks `go.mod`/import graphs of all modules; classifies storage/queue/cache/search clients | All four modules discovered; rises to the sanctioned drivers as SPEC-005/013 land them |
| G-001-2 boundary registry | AST walk for listen/socket call sites, joined to B1–B11 registrations | ≥1 listener once server code exists; final floor 7 |
| G-001-3 gateway purity | Import-closure walk of the gateway binary | Non-empty closure once `server/cmd/gateway` exists (reported skip before) |
| G-001-4 singleton advisory-lock coverage | AST walk for ticker/timer loops in `server/`, joined to the advisory-lock helper | ≥1 background loop (lands with SPEC-016) |
| G-001-5 defended-actor declarations | Discovers SPEC-003..016 and checks each pre-rejection-table design names an actor | Exactly 14 specs |

## 8. Historical lessons

- A cache/queue middleware wedge (post-fork futex deadlock) cut the entire
  fleet off because CRL distribution depended on it and gateways failed
  closed — correct posture, wrong substrate. Durable distribution now rides
  signed artifacts over the gateway stream with a disk cache.
- Unclassified tables escaped replay and backup guarantees; total table
  classification is guard-enforced (ES-1, SPEC-005).
- A "no resolver wired → skip the binding check" nil-check ran fail-open; an
  unwired verifier is now a boot failure [TM-5].
- A one-shot registration publish left terminal access dead for five days;
  stream presence IS registration, reconstructible at any moment (GW-3,
  SPEC-012).
- A gateway reported its container hostname as its routable address and broke
  edge routing; gateways report a routable IP, and control serves the derived
  routing config (GW-6, SPEC-012).
- Generated secrets containing URL-unsafe characters broke first boot;
  generated secrets are hex.
- The device→control result path once had zero cryptographic coverage — a
  compromised relay could forge any device's results; every device-originated
  report is now device-signed (WIRE-20, SPEC-003).
- Disk-encryption passphrases historically transited the relay in plaintext;
  sealed transport is now uniform in both directions (WIRE-23/24, SPEC-003).

## 9. Milestones

1. **M1 — Storage + purity guards**: G-001-1 and G-001-3 with red fixtures;
   boundary table B1–B11 encoded as the machine-readable registry data.
   Ends green.
2. **M2 — Boundary registry harness**: G-001-2 with its ratcheting floor;
   registration API for later specs. Ends green (floor = current listener
   count).
3. **M3 — Ledger wiring**: register AC-4 and AC-5 obligations in the SPEC-000
   invariant ledger so owning specs cannot complete without them. Ends green.

## 10. Out of scope

- Wire-contract mechanics: signing envelopes, manifests, sealed transport
  (SPEC-003).
- PKI procedures: enrollment, renewal, revocation, CA rotation (SPEC-006).
- Gateway stream protocol and delivery semantics (SPEC-012).
- HA runbook, standby promotion, backup contract, doctor (SPEC-016).
- The web repository and its hosting model.
