---
title: "SPEC-016 — Operations and HA"
---
# SPEC-016 — Operations and HA

Status: READY FOR IMPLEMENTATION
Builds on: SPEC-005 (event-store), SPEC-012 (gateway)
Enables: SPEC-017
Module(s): server

## 1. Scope

The operations contract of the deployed system: control high availability
(active/standby), the availability model (what keeps working and what pauses when
control is down), backup and restore, key rotations, the operational application
of the request-boundary limits, the `control doctor` self-check, telemetry export,
the deployment shape (compose stack, setup tooling, TLS material ownership), and
upgrade/migration discipline.

## 2. Context capsule

Minimum prior knowledge, restated:

- Control is the single Postgres writer (TM-3, SPEC-001). Postgres is the ONLY
  datastore: no queue product, no cache tier, no second search store. Async work
  is Postgres work tables drained by advisory-lock workers (ES-8, ES-11,
  SPEC-005).
- Projections run INSIDE the append transaction (ES-7, SPEC-005): there is no
  listener state, no watermark, and no queue position anywhere in control. This
  is what makes failover safe by construction.
- Agents are autonomous by design: they enforce their last verified signed
  manifest indefinitely; there is NO in-agent staleness kill-switch (WIRE-27,
  SPEC-003 — recorded decision). Unshipped results buffer in the agent's local
  store under a hard age ceiling and row cap sized for realistic outage windows
  (AG-10, SPEC-013).
- Gateways are stateless relays (GW-1, SPEC-012). They cache exactly one
  artifact — the control-signed CRL — apply it fail-closed, fail-static on
  staleness with periodic re-warn, and refuse to serve on a cold boot whose CRL
  cache exceeds max-age (PKI-6, SPEC-006).
- The gateway↔control stream re-reports the full connection set on reconnect, so
  control's routing table is reconstructible at any moment (GW-3, SPEC-012).
- Agents renew certificates from 80% lifetime with hourly retry (PKI-3,
  SPEC-006); agent certs live 1 year (recorded decision), so a short control
  outage is a renewal non-event.
- One typed config struct per binary, one file, mechanically derived `PM_*`
  override names, unknown key = boot failure, secrets by file indirection only
  (INV-18, CFG-1/2, SPEC-002).
- Request-boundary limits [LIM-1..4] are defined in SPEC-009: size caps,
  statement timeouts + per-handler deadlines, output budgets with truncation
  markers, trusted-proxy IP resolution.

## 3. Requirements

### 3.1 High availability [HA-1..4]

- **[HA-1]** Control is single-writer; horizontal control is ACTIVE/STANDBY.
  There is NO leader-election machinery: ALL singleton/background work acquires
  a Postgres advisory lock through ONE uniform helper, so a second control
  instance is safe-by-construction — the standby can run hot. No
  process-local-timer singleton that silently assumes one instance exists
  anywhere.
- **[HA-2]** Gateways and agents dial ONE stable control address (edge-routed).
  Failover = promote the standby + flip the route; clients recover through
  their normal reconnect loops. In-tx projection means the newly active
  instance reads Postgres and is current — nothing to hand over.
- **[HA-3]** Updates are a seconds-long management-plane pause: binary swap +
  restart in place, or standby promotion. Migrations follow expand/contract; a
  migration that would lock a large table for minutes is a DESIGN ERROR
  (unmergeable), not an ops problem. The device plane never participates in a
  control update.
- **[HA-4]** Active/active is an explicit NON-goal, with the upgrade path named
  so nobody redesigns for it prematurely: OCC already serializes concurrent
  appends; in-tx projection means the committing node projects; the missing
  pieces would be LISTEN/NOTIFY nudges for cross-node gateway routing and
  moving per-node in-memory state (rate limiters, routing table) into small
  tables. Revisit ONLY if a single Postgres writer is the measured bottleneck —
  well beyond ~100k devices at a 30-minute sync cadence.

### 3.2 Availability model [OPS-3]

Control going down (or updating) pauses the MANAGEMENT plane only:

| Keeps working | Pauses |
|---|---|
| Every agent: cached signed manifest, offline scheduler, local enforcement | UI / API |
| Running gateways: fail-static on the cached signed CRL, periodic re-warn | Instant commands |
| Open terminal bridges (AUDIT-GAP posture: session survives, gap logged loudly, gap marker on reconnect) | New terminal sessions |
| Result durability: agents buffer signed results locally until acked | Enrollment |
| — | Certificate renewal (agents retry hourly from 80% lifetime) |

- There is no staleness kill-switch anywhere: an agent that cannot reach
  control keeps enforcing its last verified manifest indefinitely — offline
  autonomy is the product (recorded decision).
- A gateway COLD BOOT with a CRL cache older than max-age (default 7 days)
  fails closed and refuses to serve (PKI-6, SPEC-006).
- Failure matrix: control down → this section. Postgres down → control RPCs
  error; running gateways keep bridging fail-static; agents run offline from
  verified local state. One gateway down → its agents reconnect through edge
  routing to another gateway.
- Postgres is the availability floor. Postgres HA (managed service or
  cluster-manager tooling) is an OPERATOR choice; control is a well-behaved
  client: reconnects with backoff, statement timeouts, no connection-state
  assumptions.

### 3.3 Doctor [OPS-1]

`control doctor`: a read-only posture pass that runs WITHOUT booting the server.

- Graduated exit codes: `0` OK / `1` warn / `100` critical / `2`
  check-could-not-run — and 2 takes highest precedence. `--json` output. NO
  auto-remediation.
- Checks include: secrets entropy; certificate permissions and expiry
  (lifetime-relative); work-table depth and exhausted-attempts rows; terminal
  wiring; DEK invariants; projection-drift sanity (structurally impossible in
  normal operation — check anyway); gateway registry liveness; CRL cache age;
  retention posture.
- Every check has a unit test, enforced by a self-discovering guard over the
  registered check list.
- Operational doctrine: doctor runs after every deploy and FIRST in every
  triage.

### 3.4 Telemetry export [OPS-2]

OTLP export is a SEPARATE binary with a STRUCTURAL PII barrier: no KEK, no DEK
grants, no linked opener — the process cannot decrypt PII even if compromised.
Attributes are allow-listed; semantics are export-all-minus-exclusions. SIEM
integration is this exporter or polling the audit-list RPC (AUD-6, SPEC-011);
no third path.

### 3.5 Backup [OPS-4]

The backup contract is FULL-database plus key material:

- `pg_dump` of the FULL database + the config and key files (the at-rest
  encryption key unlocks all secrets; config model per INV-18, SPEC-002) + CA
  material (losing the CA = fleet re-enrollment).
- Events alone are NOT a backup. Projections and work-table runtime columns
  (ES-11, SPEC-005) are the only rebuild-optimizable parts. The following are
  UNRECOVERABLE if omitted:

| Data | Why replay cannot restore it |
|---|---|
| `events` itself | It IS the source of record |
| `user_encryption_keys` DEKs | Excluded from replay so crypto-shred is real deletion (ES-1, SPEC-005) |
| Artifact blobs (ART-1, SPEC-010) | Events pin `(sha256, size)` references only — content is not in any event |
| Compliance-retained output bodies (ES-12, SPEC-005) | Operational tier, not event-sourced; retained as evidence |

  An events-only dump silently destroys secrets, evidence, and every action
  payload.

### 3.6 Backup aging vs. crypto-shred [OPS-5]

Backups taken BEFORE a crypto-shred contain the shredded user's DEK. Backups
MUST age out under a DOCUMENTED backup-retention window, or GDPR erasure is not
real. The retention window is part of the operator documentation and surfaced
by the doctor's retention-posture check.

### 3.7 Restore [OPS-6]

- Restore = restore the full dump + config/key files + CA material, then run
  the doctor before serving.
- Projection rebuild (`RebuildAll`, ES-3, SPEC-005) is a RECOVERY optimization
  for corrupt projections — never a substitute for the full backup, and CLI-only.
- Audit archives are encrypted ciphertext EVENT batches (AUD-4, SPEC-011) —
  never projections — so an archive restore replays through the same
  projectors as live traffic.

### 3.8 Key rotations [OPS-7]

| Key | Rotation mechanism | Blast radius |
|---|---|---|
| At-rest encryption key | FIRST-CLASS migration tool (re-wrap/re-encrypt walk) — never a hand-written script | None visible |
| JWT signing keypair (ES256) | Rotate + restart | Global logout |
| CA material | 4-phase rotation with first-class tooling (PKI-6/7, SPEC-006): standalone revoke, force-renew, live trust-bundle reload, per-device migration report | Per procedure |
| Gateway registration token | Rotate; a revoked gateway halts | Durable lockout by design (PKI-5, SPEC-006) |

There is no other key machinery to rotate — no transport-MAC key exists in this
architecture.

### 3.9 Deployment shape [OPS-8]

- Compose stack: Traefik (TLS edge + SNI passthrough for agent mTLS; dynamic
  routing via **Traefik's HTTP provider polling control** — control serves the
  routing config derived from live-registered gateways; NEVER the raw docker
  socket), Postgres, Control (active + optional standby), Gateway (N≥1,
  self-enrolling). Linux endpoints only.
- `setup.sh` generates the cert chain, secrets, and configs; it is
  RE-RUN-SAFE; generated secrets are HEX (URL- and form-safe).
- Multi-gateway scale-out: start a gateway container with an enrollment token;
  it self-enrolls (PKI, SPEC-006), dials control, and appears in routing.
  Routing wiring is binary defaults, not hand-wired env vars (GW-6, SPEC-012);
  configuration passes exclusively through the INV-18 contract (CFG-2,
  SPEC-002).
- The fresh-install walkthrough is a RELEASE GATE (TEST-7, SPEC-017).

### 3.10 TLS material ownership [OPS-9]

- Private keys on disk are root-owned mode 0600. Container images drop
  privileges; the deployment mounts keys such that the DROPPED runtime UID can
  read them, and this exact ownership/mode/UID combination is what the
  deployment E2E gate reproduces (TEST-6, SPEC-017).
- Lesson, inline and binding on every TLS test: a world-readable test key
  CANNOT prove that the production container user can read the mounted key.
  Tests that claim to cover key readability MUST reproduce root-owned 0600
  ownership and the image's UID drop.
- Internal service URLs are verified on BOTH axes: the dial address AND the TLS
  verification identity. An IP dial target with a DNS-only certificate is a
  regression even when both endpoints are otherwise reachable.

### 3.11 Upgrade and migration discipline [OPS-10]

- Schema migrations follow EXPAND/CONTRACT so the binary swap stays seconds
  (HA-3).
- A SHIPPED migration is NEVER edited — migration tools track applied
  migrations by version, not content, so an edited shipped migration silently
  never re-runs on existing installs. Fixes are always a new forward
  migration.
- Migration consolidation MAY be breaking BEFORE the first release; after it,
  only forward migrations exist (recorded decision).
- A control update never touches the device plane; agents sync on their normal
  cadence (default 30 min, ≤5-min reconnect backoff) and gateways reconnect
  automatically (ARCH-4, SPEC-001).

### 3.12 Operational limits and observability [OPS-11]

- The request-boundary limits [LIM-1..4] (SPEC-009) are OPERATIONAL controls:
  DB `statement_timeout` and per-handler deadlines bound every query the
  operator's database serves; output budgets with truncation markers bound
  storage growth; the trusted-proxy XFF walk feeds every rate limiter and every
  audit actor-IP field. Deployment configuration MUST NOT disable them.
- Structured logs throughout; degraded availability-critical loops re-warn
  periodically while retrying (INV-4, SPEC-000) — silence is reserved for
  health.
- The AUDIT-GAP posture is LOUD: audit append failure never blocks
  login/logout/refresh but logs loudly and is doctor-visible (AUD-5, SPEC-011).
- Agents surface capability/protection drift as an ERROR log plus a heartbeat
  field (AG-3, SPEC-013), so fleet-level drift is visible centrally.

## 4. Acceptance criteria

- **AC-1** Two control instances run concurrently against one Postgres: every
  singleton job executes exactly once per period (advisory lock proven by
  concurrent-instance test); no duplicate dispatch, prune, or eval occurs.
- **AC-2** Killing the active control and promoting the standby loses no
  committed state: the promoted instance serves reads consistent with every
  acknowledged write, with no rebuild or catch-up step.
- **AC-3** With control stopped: a connected agent continues enforcing its
  manifest and buffers results; a running gateway keeps bridging on its cached
  CRL and re-warns periodically; results buffered during the outage arrive
  after restart with nothing lost within the buffer bounds.
- **AC-4** A gateway cold boot with a CRL cache older than max-age refuses to
  serve; within max-age it serves fail-static.
- **AC-5** `control doctor` runs without a bootable server config, emits
  `--json`, and exits 0/1/100/2 with 2 taking precedence; every registered
  check has a unit test (guard-enforced); an unregistered check cannot ship.
- **AC-6** A restore drill from the documented backup set (full dump + config +
  keys + CA) yields a system where escrowed secrets decrypt, artifacts fetch,
  and agents reconnect without re-enrollment. A restore from an events-only
  dump demonstrably CANNOT decrypt secrets or serve artifact blobs — the drill
  proves the negative, and the backup docs state it.
- **AC-7** The at-rest encryption-key rotation tool re-encrypts the full secret
  inventory in place; old-key material fails to decrypt anything afterward; the
  tool is idempotent on re-run.
- **AC-8** JWT signing-key rotation invalidates every outstanding session
  (global logout) and nothing else.
- **AC-9** `setup.sh` re-run on an existing install changes nothing that was
  already generated (idempotence) and produces only hex secrets.
- **AC-10** The deployed stack serves with private keys root-owned 0600 under
  the image's dropped UID; the E2E gate (TEST-6, SPEC-017) fails if the runtime
  user cannot read a mounted key, and the test fixture reproduces the
  production ownership/mode/UID — a chmod-777 fixture fails review by guard.
- **AC-11** An edited shipped migration is rejected by the migration-immutability
  guard; a large-table-locking migration is rejected by review per [HA-3].
- **AC-12** The OTLP exporter binary contains no KEK/DEK code paths (import
  guard), exports only allow-listed attributes, and export-all-minus-exclusions
  semantics hold behaviorally.
- **AC-13** Unknown config key or unrecognized `PM_*` variable fails boot for
  every binary in the stack (INV-18, SPEC-002), demonstrated against the real
  compose stack.

## 5. Rejection paths

| Input / state | Required behavior |
|---|---|
| Second control instance starts a singleton job | Advisory lock denies; exactly-once per period holds [HA-1] |
| Gateway cold boot, CRL cache older than max-age | Refuse to serve (fail closed) |
| Gateway running, CRL stale but within policy | Fail-static + periodic re-warn; never fail-open |
| Postgres unreachable from control | RPCs error; no degraded write mode; reconnect with backoff + re-warn |
| Audit append failure during login/logout/refresh | Proceed + loud log + doctor visibility (AUD-5, SPEC-011); never block, never silent |
| Doctor check cannot run | Exit 2 (highest precedence), never a silent pass |
| Backup missing DEKs / blobs / config keys / CA | Restore drill fails; docs enumerate the loss; no tooling pretends success |
| Edited shipped migration | Immutability guard fails CI; fix ships as a new forward migration |
| Migration locking a large table for minutes | Unmergeable — design error [HA-3] |
| Unknown config key or `PM_*` typo | Boot failure (INV-18, SPEC-002) |
| Hand-wired env var bypassing the config contract | Not merged (CFG-2, SPEC-002) |
| Non-hex generated secret | `setup.sh` self-check fails |
| Exporter attribute outside the allowlist | Not exported; guard fails on an unregistered attribute |
| Key rotation attempted via ad-hoc script | Not supported; the migration tool is the only path [OPS-7] |

## 6. Test plan (TDD)

Server tests run against REAL Postgres (testcontainer, template-cloned per
test); HA and deployment behavior is additionally proven against the REAL
compose stack through the E2E gate (TEST-6, SPEC-017) — synthetic green does not
substitute. Every test is confirmed RED via a scoped neutralizing edit first.

1. **HA tests**: concurrent-instance singleton exclusivity (AC-1); kill-active
   promote-standby consistency (AC-2) — write, kill, promote, read.
2. **Availability tests**: control-stopped behavior for agent buffering and
   gateway fail-static (AC-3, with SPEC-012/013 harnesses); CRL cold-boot
   max-age boundary on both sides (AC-4).
3. **Doctor tests**: one unit test per check (self-discovering: the guard
   enumerates registered checks and fails on an untested one); exit-code
   precedence matrix (AC-5).
4. **Backup/restore drill**: scripted full-set restore into a fresh
   environment, then decrypt/fetch/reconnect assertions; events-only restore
   proves the negative (AC-6).
5. **Rotation tests**: encryption-key tool full-walk + idempotence + old-key
   failure (AC-7); JWT rotation global logout (AC-8).
6. **Deployment tests**: `setup.sh` idempotence + hex property (AC-9);
   root-owned 0600 + UID-drop readability in the E2E fixture (AC-10);
   config-contract boot failures against the real stack (AC-13).
7. **Guard tests**: migration-immutability fixture (AC-11); exporter import +
   attribute guards (AC-12).

## 7. Guards

Self-discovering, matches-zero protected (PROC-3, SPEC-000):

| Guard | Discovery source | Fails when |
|---|---|---|
| Singleton-work lock coverage | AST scan for background/periodic workers | A worker runs outside the uniform advisory-lock helper; zero workers discovered |
| Doctor-check test completeness | Registered doctor-check list | A check without a unit test; zero checks discovered |
| Migration immutability | Digest ledger of shipped migration files | Any shipped migration's digest changes; zero migrations discovered |
| Config-docs freshness | Generated from the config structs (INV-18, SPEC-002) | Docs drift from the struct; a knob exists that is never read |
| Exporter PII barrier | Import walk of the exporter binary | Any KEK/DEK/opener package imported; zero imports walked |
| Exporter attribute allowlist | Exporter attribute registry | An emitted attribute is unregistered; zero attributes discovered |
| TLS fixture fidelity | E2E fixture inspection | A key fixture is not root-owned 0600 under the dropped UID (see [OPS-9]) |
| Backup-set completeness | Table classification walk (ES-1, SPEC-005) | The backup script omits a table class or the key/CA/config file set |

## 8. Historical lessons

Inlined from the predecessor system's operating history:

- **Lesson [HA-1]:** Singleton background work relied on process-local timers
  that silently assumed one instance; documentation and code disagreed about
  whether a second instance was safe. Advisory locks through one helper make
  the question disappear.
- **Lesson [OPS-3], (ES-8, SPEC-005):** An external queue datastore wedged in
  production — a post-fork deadlock froze it — and the fail-closed revocation
  path it fed then cut the entire fleet off from the control plane. The rewrite
  keeps the fail-closed posture but moves distribution to a control-signed,
  disk-cached artifact that degrades to fail-static instead of fleet loss, and
  keeps all queues in Postgres where triage is a WHERE clause.
- **Lesson [OPS-3], (GW-3, SPEC-012):** A gateway registered a capability with
  a one-shot publish; when it was lost, a user-facing surface was silently dead
  for days. Registration is stream presence, reconstructible on every
  reconnect, and degraded loops re-warn periodically.
- **Lesson [OPS-8]:** A gateway once reported its container hostname as its
  routable address, silently breaking edge routing. The gateway reports a
  ROUTABLE address, and control serves the derived routing config to the edge
  itself — never the raw docker socket.
- **Lesson [OPS-8]:** A release-candidate fresh install failed on bootstrap
  ordering, and generated secrets containing URL-unsafe characters broke
  form/URL contexts. `setup.sh` is re-run-safe, secrets are hex, and the
  fresh-install walkthrough is a release gate.
- **Lesson [OPS-9]:** TLS tests passed with world-readable keys while the
  production container user could not read the root-owned 0600 mounted key.
  Ownership/mode/UID fidelity in fixtures is mandatory.
- **Lesson [OPS-9]:** An internal URL dialed an IP while the certificate held
  only DNS names; each endpoint was "reachable" and the pair was still broken.
  Dial address and TLS identity are tested separately.
- **Lesson [OPS-4]:** The backup story once implied events were sufficient.
  They never were: DEKs are excluded from replay by design, artifact content is
  referenced by hash only, and evidence-tier output is not event-sourced. The
  unrecoverable-data enumeration is part of the contract.
- **Lesson [OPS-10]:** Editing a shipped migration is invisible to migration
  tooling that tracks by version — existing installs silently diverge from
  fresh ones. Forward migrations only.

## 9. Milestones

Each milestone is one implementation session ending green.

1. **M1 — Deployment substrate**: compose stack, `setup.sh` (re-run-safe, hex
   secrets), Traefik HTTP-provider routing endpoint on control, TLS material
   modes + UID drop. Tests: AC-9, AC-10, AC-13.
2. **M2 — HA mechanics**: uniform advisory-lock helper adoption across all
   singleton work, concurrent-instance test, standby promotion drill. Tests:
   AC-1, AC-2. Guards: singleton-lock coverage.
3. **M3 — Doctor**: check framework, graduated exit codes, `--json`, the full
   check list, per-check unit tests. Tests: AC-5. Guards: doctor completeness.
4. **M4 — Backup/restore + rotations**: backup script from the classification
   walk, restore drill (positive and events-only negative), encryption-key
   rotation migration tool, JWT rotation. Tests: AC-6..8. Guards: backup-set
   completeness, migration immutability.
5. **M5 — Availability + telemetry**: control-stopped behavioral tests with
   the gateway/agent harnesses, CRL cold-boot boundaries, OTLP exporter binary
   with PII barrier and attribute allowlist. Tests: AC-3, AC-4, AC-12. Guards:
   exporter import + attribute.

## 10. Out of scope

- CRL issuance, signing, and revocation semantics — SPEC-006; gateway CRL
  application and stream protocol — SPEC-012.
- The deployment E2E gate's mechanics (scenario registry, log-evidence
  correlation) — SPEC-017; this spec supplies the stack it boots.
- Agent offline scheduler and buffering internals — SPEC-013.
- Audit retention values, crypto-shred semantics, archive format — SPEC-011.
- Request-boundary limit definitions [LIM-1..4] — SPEC-009.
- Config loader implementation [INV-18, CFG-1/2] — SPEC-002.
- Release process, versioning, and provenance — SPEC-017.
