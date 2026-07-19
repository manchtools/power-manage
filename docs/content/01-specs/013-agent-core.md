---
title: "SPEC-013 — Agent Core"
---
# SPEC-013 — Agent Core

Status: READY FOR IMPLEMENTATION / Builds on: SPEC-003, SPEC-004, SPEC-006, SPEC-010 / Enables: SPEC-014, SPEC-015, SPEC-017 / Module(s): `agent/` (GPL-3.0)

## 1. Scope

The device agent: process model and self-managed systemd unit, boot and
capability discovery, sync loop, offline scheduler, execution lifecycle,
executor discipline, artifact digest verification, self-update, enrollment,
stream robustness, and the local luksd/tty surfaces. The agent is a pure
orchestrator over SDK capabilities; per-action executor semantics live in
SPEC-014.

## 2. Context capsule

A fresh implementer needs exactly this from prior specs:

- **Wire contract (SPEC-003):** Everything control tells an agent arrives as a
  `SignedCommand` — CA signature over domain-framed exact bytes; the agent
  verifies then executes the exact verified bytes, never a second
  representation (WIRE-14). Instant commands carry `expires_at − issued_at ≤
  15 min` freshness; durable assignments ride the CA-signed sync manifest
  whose monotonic `(epoch, generation)` is the anti-replay authority
  (WIRE-15, WIRE-26). `target_device_id` is addressing, not authentication;
  identity at every seam is the mTLS certificate (WIRE-18). Every
  device-originated report is wrapped in a `DeviceSigned` envelope signed by
  the device's enrolled key (WIRE-20). Everything server-authoritative
  (intervals, windows, sealing key, login URL) arrives inside signed material
  — no unsigned Welcome fields a relay could rewrite (WIRE-17).
  Removal-by-omission in the manifest is the sole cleanup authority; there is
  NO in-agent staleness kill-switch — an agent that cannot reach control keeps
  enforcing its last verified manifest indefinitely (WIRE-27). Device-originated
  secrets are sealed to control's X25519 key; nothing plaintext transits the
  gateway (WIRE-23, WIRE-24; SPEC-015).
- **Trust model (SPEC-001):** the gateway is an assumed-compromised relay
  (actor 4). Connectivity is never authority (TM-4); possession of a
  token/certificate/signature is. Fail closed on decode errors, unknown
  enums, and unwired verifiers (TM-5).
- **SDK (SPEC-004):** one Runner seam with forced C locale, curated env,
  argv-only, process-group cancellation (SDK-3..5); fd-anchored
  symlink-refusing filesystem discipline (SDK-7/8); constructors fail closed
  on absent backends and the SDK never auto-detects (SDK-1).
- **PKI (SPEC-006):** enrollment is CSR-only through PkiService, registration
  token as sole authorization, version-pinned consume (PKI-2); renewal at 80%
  lifetime with fingerprint match + proof-of-possession (PKI-3); agent certs
  are 1-year (offline tolerance, PKI-5).
- **Artifact store (SPEC-010):** blob-class payloads carry `(sha256, size)`
  refs covered by the signed command; agents fetch by digest over the agent
  stream in chunks relayed statelessly by the gateway (ART-2; GW-3,
  SPEC-012) and cache by digest.

## 3. Requirements

### 3.1 Process model and systemd unit

- **[AG-1]** The agent runs as **root** (recorded operator decision — a
  dedicated user proved to be root-equivalent cosmetics). Real hardening is
  `ProtectSystem=strict` + `ReadWritePaths=` + MAC profiles. Unit directives
  MUST be validated against what package-manager children need (`setcap`,
  `/lib/modules`, `/proc/sys`): `ProtectKernelModules` and friends must not
  break apt/dpkg children.
- **[AG-2]** The unit is embedded in the binary (`go:embed`) and
  **self-managed**: the managed section is marker-delimited, re-applied by
  every self-update; operator customization is via drop-ins only, and
  drop-ins win; drift in the managed section is reverted loudly.
  `install-unit` is ONE function with NO flags (the unit is bundled; nothing
  to parameterize) — exactly one install/reconcile code path, never two
  near-duplicates. Unit reconcile NEVER self-restarts the agent (recorded
  decision — a reconciler that restarts its own process is an outage
  generator); a reverted unit takes effect at the next restart the operator
  or self-update flow ([AG-16]) performs.
- **[AG-3]** At startup the agent compares the live capability bounding set
  and protections against the unit's requirements and surfaces drift as an
  ERROR log + a heartbeat field. Documentation states that capability-drift
  remediation needs SSH/console, not the product terminal — terminal children
  inherit the broken bounding set.

### 3.2 Boot and backend discovery

- **[AG-4]** ONE runner, ONE backend probe. Boot sequence: construct the
  global SDK Runner (privilege backend resolved once — direct when euid 0),
  probe the system ONCE for available capabilities (package manager, systemd,
  NetworkManager, LUKS, accountsservice, osquery, flatpak, sessions), and
  construct managers by explicit injection. There is NO backend-override
  config layer — availability is discovered, not configured. Discovery lives
  in the agent; the SDK never auto-detects (SDK-1, SPEC-004). No subsystem
  creates its own runner.
- **[AG-5]** Self-referential paths are fd-anchored: the running binary is
  addressed via `/proc/self/exe` (opened once, all operations on the fd),
  never a re-resolved `os.Executable()` path (TOCTOU).

### 3.3 Sync, offline scheduler, execution lifecycle

- **[AG-6]** Sync tick (default 30 min; server-set per device/group; re-timed
  from every manifest): verify manifest → diff desired vs. actual → apply
  drifted actions in set order, **serial with abort-on-first-failure per set**
  (the one semantics) → report signed results.
- **[AG-7]** Offline scheduler: persist-before-execute, crash replay,
  monotonic clock. All schedule times are stored and compared as UTC
  instants, never strings. Decode failures of cached manifest, windows, or
  actions fail CLOSED — defer scheduled work, refuse dispatch, keep prior
  state — never default-permissive. A removed action that fails to decode is
  quarantined and alert-flagged, never delete-without-revert.
- **[AG-8]** Maintenance windows: union across groups, device-local timezone,
  midnight-crossing allowed, re-checked ~1/min. Instant commands bypass
  windows. An undecodable window ⇒ defer (fail closed).
- **[AG-9]** Execution results are honest: `success` and `changed` derive
  from actual sub-step outcomes; any swallowed sub-step failure (pin,
  disable, autoremove, reboot-schedule, timestamp write) fails the action.
  `NOT_APPLICABLE` is a first-class third outcome for structural
  inapplicability; a grep guard bans silent-success skips. Silent per-field
  skips (missing user, accountsservice absent) become structured per-field
  outcomes in the result.
- **[AG-10]** Local store (SQLite, WAL): offline results are bounded
  independently of sync state — hard age ceiling + row cap so a partitioned
  agent cannot exhaust disk — and sized generously: this buffer is the
  fleet's result durability during a control outage. Proto rows are stored
  via protojson only — recorded rationale: (a) buffered rows can straddle an
  agent self-update, and this contract re-tags proto fields in place, so
  field NAMES are the stable identity — name-keyed protojson survives a
  re-tag where tag-keyed binary bytes would silently misdecode; (b) the
  agent has the worst debug access in the fleet, and a self-describing row
  is readable with bare `sqlite3` on a wedged device, no matching
  descriptor set needed; (c) crypto is untouched — result signatures cover
  deterministic payload bytes inside the signed envelope (SPEC-003), and
  protojson `bytes` fields round-trip base64-lossless, so the row encoding
  never feeds a signature.
- **[AG-11]** Stream handling: `recover()` around every dispatch (one handler
  panic must not crash-loop the fleet), inbound frame size caps, bounded
  goroutine fan-out, sends honor ctx and never hold a mutex across a blocking
  `stream.Send`, reconnect backoff caps at 5 min.

### 3.4 Executor discipline

- **[AG-12]** Executors are thin: state-read → short-circuit
  (`changed=false`) → SDK primitive → verify. The agent implements NO OS
  feature itself — if an OS capability is missing from the SDK, extend the
  SDK.
- **[AG-12a]** **The agent binary is OS-agnostic and executes no system
  binary directly.** Zero `os/exec` outside the SDK Runner seam, zero
  hardcoded tool paths, zero distro assumptions — enforced by an agent-repo
  archtest. The agent is a pure orchestrator over SDK capabilities: whatever
  the boot probe ([AG-4]) finds is the device's capability set, reported in
  Hello/inventory so control can compute applicability; an action needing an
  absent capability resolves NOT_APPLICABLE — never a crash, never a
  hand-rolled fallback. The binary builds `CGO_ENABLED=0` static (pure-Go
  SQLite driver), so ONE artifact runs on anything the SDK supports.

### 3.5 Artifact verification (the split chokepoint)

- **[AG-13]** **One digest-verification chokepoint for every fetched
  artifact**, regardless of source, fail-closed at the agent boundary before
  any privileged work. For artifact-store fetches (`PACKAGE_FILE` and every
  blob-class ref — ART-2, SPEC-010) the expected digest is the
  `(sha256, size)` carried in the signed command — verifying the fetched
  bytes IS verifying the signature's subject; no checksum-file alternative
  exists on this path. For URL-fetched artifacts, the pin is the action's
  expected sha256 or checksum-file per [AG-13a].
- **[AG-13a]** URL-transport rules, applying ONLY to the two URL-fetched
  action types (`APP_IMAGE`, `AGENT_UPDATE`): HTTPS-only, mandatory pinned
  SHA-256 or checksum-file, https→http redirects refused, ≤10 redirect hops,
  cross-origin redirects only when checksum-pinned. Enforced through the
  SDK's fetch/SSRF primitives (SDK-9, SPEC-004).

### 3.6 Environment and self-healing

- **[AG-14]** Child environment is built from a curated allowlist baseline —
  NEVER from `os.Environ()`; the block set applies to inherited variables
  too; PATH is explicitly set (SDK-4, SPEC-004).
- **[AG-15]** Package-manager self-healing precedes operations: stale-lock
  clear only when provably unheld, `dpkg --configure -a`, read-only remount
  recovery, DNF history repair.

### 3.7 Self-update (`AGENT_UPDATE`)

- **[AG-16]** The sole upgrade path, a signed action. Flow: hash-verify →
  version compare on the PARSED version (strip the binary-name prefix before
  comparing) with anti-rollback unless the signed action carries
  `allow_downgrade` → 60 s self-test subprocess (credentials load, mTLS
  handshake, Hello/Welcome, sync round-trip) → `.bak` backup + atomic swap →
  the NEW binary's `install-unit` (re-applies the managed unit section,
  [AG-2]) → restart. A failed self-test keeps the old binary and FAILS the
  action. Integrity is operator choice: `checksum_url` (origin trust,
  default) OR opt-in `expected_sha256` pin — never a mandatory pin (recorded
  operator reversal; do not re-add).

### 3.8 Enrollment

- **[AG-17]** Enroll socket `/run/pm-agent/enroll.sock`, mode **0666** —
  DELIBERATE operator decision, reversed twice; do not tighten. The
  registration token is the SOLE authorization (TM-4, SPEC-001; PKI-2,
  SPEC-006); rate-limited 5/min on both sides; TOFU with an optional
  out-of-band CA-fingerprint pin. Token intake is stdin (prompt on a TTY,
  pipe otherwise) or `--token-file` ONLY — **no argv token flag exists
  anywhere in the install/enroll flow** (required decision: argv lands the
  token in shell history and `ps` for its whole validity; piped stdin keeps
  cloud-init and bulk imaging working).
- **[AG-18]** There is NO re-enrollment machinery (recorded decision). A
  device with broken or lost credentials is re-enrolled from scratch by an
  operator: `install.sh --reset` stops the agent, wipes
  `/var/lib/power-manage` (root-only, fd-anchored `O_NOFOLLOW` discipline),
  and runs a fresh enrollment. Fresh enrollment mints a NEW device identity;
  the stale device record remains until the operator deletes it
  (`DeleteDevice` revokes its certificate). No exit-class or
  credential-classifier apparatus exists.

### 3.9 luksd and tty

- **[AG-19]** luksd: a transient local daemon for interactive user-passphrase
  enrollment — one-shot token, policy server-authoritative, reuse check via
  local hash, the passphrase never sent to the server; shuts down after the
  post-boot window. Key-file scrub refuses non-regular files and opens
  `O_WRONLY|O_NOFOLLOW|O_NONBLOCK`.
- **[AG-20]** `tty enable` is a device-local root-gated flag checked per
  session start, layered with the CA-signed terminal grant (WIRE-16,
  SPEC-003) and server RBAC. Account lock and session shell are SEPARATE
  domains (recorded operator decision): USER `disabled` locks the account and
  does not touch live session shells — offboarding kills sessions through its
  own path. Root is lock-only, exempt from nologin-shell defaults.

## 4. Acceptance criteria

- **AC-1** Under the shipped unit in a systemd container, an apt/dpkg install
  that requires `setcap` and `/proc/sys` access succeeds; the hardening
  directives are present and validated against child needs.
- **AC-2** A modification inside the marker-delimited managed unit section is
  reverted (loudly logged) by reconcile; a drop-in override survives
  reconcile and takes precedence; the reconcile issues NO restart of the
  agent process (recorded decision, [AG-2]).
- **AC-3** `install-unit` takes no flags; the self-update path and the
  install path invoke the same function; after a simulated self-update the
  installed unit's managed section matches the new binary's embedded content.
- **AC-4** With a capability artificially removed from the bounding set,
  startup emits an ERROR log and sets the heartbeat drift field.
- **AC-5** The boot probe runs once; with a capability absent, an action
  needing it resolves a structured NOT_APPLICABLE result — no crash, no
  fallback execution.
- **AC-6** The agent-repo archtest proves zero `os/exec` imports outside the
  Runner-injection seam and zero hardcoded tool paths (red-verified via a
  planted violation).
- **AC-7** The release build is `CGO_ENABLED=0` and statically linked; the
  SQLite driver is pure Go; CI asserts no dynamic interpreter in the binary.
- **AC-8** Binary self-reference uses one fd from `/proc/self/exe`; replacing
  the binary path mid-operation does not change what is read/verified.
- **AC-9** Sync applies drifted actions in set order, serially, aborting the
  set on first failure; results are DeviceSigned and match actual outcomes.
- **AC-10** A manifest with `(epoch, generation)` ≤ the last accepted one is
  rejected; an action omitted from the manifest is cleaned up
  (removal-by-omission); with control unreachable past the manifest window,
  enforcement of the last verified manifest continues.
- **AC-11** Scheduler persists intent before executing; after a simulated
  crash mid-execution, replay resumes correctly; times are UTC instants.
- **AC-12** Corrupting a cached window/manifest/action blob causes deferral or
  refusal (fail closed), never permissive execution; an undecodable removed
  action is quarantined with an alert flag, not deleted.
- **AC-13** Windows union across groups, evaluate in device-local timezone,
  handle midnight crossing; an instant command executes inside a closed
  window.
- **AC-14** An injected sub-step failure (e.g., pin fails after install
  succeeds) fails the action; a missing-user field in GROUP yields a
  structured per-field outcome, not silence.
- **AC-15** With sync blocked, the result store enforces the row cap and age
  ceiling (oldest evicted, disk bounded); stored proto rows are protojson.
- **AC-16** A panicking command handler is recovered and logged without
  process exit; an oversized inbound frame is rejected; reconnect backoff
  never exceeds 5 min; no send path holds a mutex across `stream.Send`.
- **AC-17** Every fetched artifact fails closed on digest mismatch BEFORE any
  privileged work; for artifact-store fetches the pin is the signed command's
  `(sha256, size)` and a size mismatch also rejects.
- **AC-18** For `APP_IMAGE`/`AGENT_UPDATE`: an `http://` URL, an https→http
  redirect, an 11th redirect hop, and an unpinned cross-origin redirect are
  each refused.
- **AC-19** Self-update: a version string with the binary-name prefix parses
  correctly (no downgrade misdetection); a downgrade without signed
  `allow_downgrade` is rejected; a failed self-test leaves the old binary
  running and reports the action FAILED.
- **AC-20** The enroll socket is mode 0666; the sixth enrollment attempt in a
  minute is rate-limited; TOFU stores the CA and an explicit fingerprint pin
  mismatch aborts enrollment.
- **AC-21** The install/enroll CLI accepts the token via stdin (TTY prompt
  and pipe) and `--token-file`; no token-valued argv flag exists (guard
  G-6); an unreadable token file is an error.
- **AC-22** `install.sh --reset` wipes `/var/lib/power-manage` with
  `O_NOFOLLOW` discipline (a symlinked state dir is not followed), and the
  subsequent enrollment produces a NEW device ULID.
- **AC-23** luksd rejects a reused one-shot token, never transmits the
  passphrase off-device, exits after the post-boot window, and refuses to
  scrub a non-regular key file.
- **AC-24** With `tty enable` off, a session start is refused even with a
  valid CA-signed grant; with it on, a session without a verifiable grant is
  refused; disabling a USER leaves that user's live session shell running.

## 5. Rejection paths

| Input / state | Required behavior |
|---|---|
| SignedCommand signature invalid or domain mismatch | Reject, do not execute, do not persist |
| Instant command past `expires_at` | Reject; nothing persisted past expiry |
| `target_device_id` ≠ own identity | Refuse (addressing check) |
| Manifest `(epoch, generation)` not newer than last accepted | Reject manifest |
| Unsigned server-authoritative config field | Not representable; only signed material is consumed (WIRE-17, SPEC-003) |
| Artifact digest or size mismatch at the chokepoint | Fail closed before privileged work |
| `http://` URL, https→http redirect, >10 hops, unpinned cross-origin ([AG-13a]) | Refuse fetch |
| Cached manifest/window/action fails to decode | Defer / refuse dispatch / keep prior state (fail closed) |
| Removed action fails to decode | Quarantine + alert; never delete-without-revert |
| Managed-section unit drift detected by reconcile | Revert loudly; agent process is NEVER restarted by the reconciler ([AG-2], recorded decision) |
| Sub-step failure inside an executor | Action FAILED; no silent success |
| Capability absent for an action | Structured NOT_APPLICABLE result |
| Self-update: downgrade without signed `allow_downgrade` | Reject action |
| Self-update: self-test fails | Keep old binary; action FAILED |
| Enrollment: >5 attempts/min | Rate-limited on both sides |
| Enrollment: CA-fingerprint pin mismatch | Abort enrollment |
| Token offered via argv | Impossible — no such flag exists (guard G-6) |
| Result store at row cap / age ceiling | Bounded eviction; disk never exhausted |
| Inbound stream frame over size cap | Reject frame |
| Terminal session without local `tty enable` or without verified grant | Refuse session |
| luksd token reuse; non-regular key file at scrub | Reject / refuse |

## 6. Test plan (TDD)

Write tests FIRST from the ACs; confirm each fails red for the right reason
(scoped neutralizing edit, never a revert), then implement. Full suite under
`-race` in CI.

1. **Unit tier (FakeRunner, in-memory clock):** sync diff/ordering (AC-9),
   manifest monotonicity and removal-by-omission (AC-10), scheduler
   persist/replay with a fake clock (AC-11), fail-closed decode paths
   (AC-12), window evaluation across timezones and midnight (AC-13), result
   honesty with injected sub-step failures (AC-14), stream dispatch
   panic/backoff/mutex discipline against an in-process fake stream (AC-16).
2. **SQLite tier (real SQLite, pure-Go driver):** bounds and eviction under
   simulated partition (AC-15), protojson round-trip, crash-replay from a real
   WAL file (AC-11).
3. **Container tier (real systemd — mandatory for unit and process-model
   behavior):** unit install/reconcile/drop-in precedence (AC-1..3),
   capability-drift detection (AC-4), enroll socket mode and rate limit
   (AC-20), `install.sh --reset` wipe + fresh identity (AC-22), self-update
   end-to-end with a self-test subprocess against a fake control (AC-19).
   SDK-backed behaviors touching real package managers run in the SPEC-004
   container lanes; the agent tier stubs the SDK seam, not the OS.
4. **Crypto/verification tier:** signed-command verification vectors
   (good/bad signature, wrong domain, expired, wrong target), DeviceSigned
   result round-trip against SPEC-003 test vectors, digest chokepoint (AC-17)
   including a size-mismatch case, [AG-13a] transport matrix (AC-18) against
   a local test server.
5. **Reboot-adjacent tests:** real Runner allowed; the real `shutdown` binary
   must be unreachable from the test environment.
6. **Regression rule:** every bug fix ships a test that fails on the buggy
   version.

## 7. Guards

All guards are self-discovering with matches-zero protection.

| # | Guard | Mechanism |
|---|---|---|
| G-1 | No direct execution ([AG-12a]) | Archtest walks all agent packages; `os/exec` import banned outside the single Runner-injection seam; fails if <1 package discovered |
| G-2 | No hardcoded tool paths ([AG-12a]) | Scan string literals for absolute tool-path shapes; vetted allowlist keyed by symbol; must scan ≥1 file |
| G-3 | Directional imports (SPEC-002) | Agent imports only `contract` + `sdk`; module-discovering archtest (an agent→server import would also silently change the binary's license) |
| G-4 | Static build ([AG-12a]) | CI builds `CGO_ENABLED=0` and asserts no dynamic linkage in the artifact |
| G-5 | No silent-success skips ([AG-9]) | Grep/AST guard over executor result paths banning skip-without-structured-outcome patterns |
| G-6 | No token argv flag ([AG-17]) | Walk the CLI flag registry; assert no token-valued flag on install/enroll commands; registry must be non-empty |
| G-7 | protojson-only storage ([AG-10]) | AST scan: stdlib `encoding/json` on proto messages is a build failure |
| G-8 | Erroring enum defaults (SPEC-003 cross-cutting) | Descriptor-walking exhaustiveness guard over enum switches |
| G-9 | Clock seam (SPEC-000 cross-cutting) | No unabstracted `time.Now()` (includes `SetDeadline`); injected clock only |
| G-10 | Unit marker integrity ([AG-2]) | Test asserts the embedded unit contains both markers and reconcile is idempotent (two runs, zero diff) |

## 8. Historical lessons

- **Root cosmetics:** a dedicated non-root agent user was root-equivalent in
  practice (it managed packages, units, and files); the switch bought
  complexity, not containment. Hence [AG-1] runs as root with real unit/MAC
  hardening.
- **Sandbox vs. children:** hardening directives (`ProtectKernelModules` and
  friends) broke package-manager children needing `setcap`, `/lib/modules`,
  and `/proc/sys` — on three separate occasions. Hence [AG-1]'s validation
  requirement.
- **Unit drift:** the worst field incident was the installed unit drifting
  from the shipped one across self-updates, silently losing directives.
  Hence [AG-2]: embedded unit, marker-delimited managed section, re-applied
  on every self-update.
- **Duplicate install paths:** two near-duplicate install/reconcile code
  paths drifted apart. Hence ONE flag-less function.
- **Inherited broken bounding set:** remediating capability drift through the
  product terminal cannot work — terminal children inherit the broken set.
  Hence the SSH/console guidance in [AG-3].
- **Configured availability:** a backend-override config layer let
  configuration contradict reality and masked probe bugs. Hence [AG-4]:
  availability is discovered, not configured.
- **Executable TOCTOU:** re-resolving the executable path between check and
  use raced against binary replacement. Hence [AG-5]'s fd-anchored
  `/proc/self/exe`.
- **String time comparison:** schedule times stored and compared as strings
  broke ordering. Hence UTC instants in [AG-7].
- **Fail-open decode:** cached security state that failed to decode was
  treated as absent/permissive on two occasions. Hence fail-closed decode in
  [AG-7]/[AG-8].
- **Swallowed sub-steps:** pin, disable, autoremove, reboot-schedule, and
  timestamp-write failures were each silently swallowed while the action
  reported success. Hence [AG-9].
- **Disk exhaustion:** a partitioned agent buffered results without bound and
  filled the disk. Hence [AG-10]'s age ceiling + row cap.
- **Fleet crash-loop:** a single panicking stream handler crash-looped
  agents fleet-wide; a mutex held across a blocking send deadlocked the
  stream; unbounded reconnect hammered the gateway. Hence [AG-11].
- **Env leakage:** child environments inherited from `os.Environ()` leaked
  host variables into managed operations. Hence [AG-14].
- **Optional checksum, fail-open:** an optional artifact checksum meant
  unverified installs when unset. Hence mandatory pins at the [AG-13]
  chokepoint and in [AG-13a].
- **Version-parse reboot loop:** comparing an unparsed version string that
  still carried the binary-name prefix misdetected every update as a
  downgrade and reboot-looped a device. Hence PARSED version compare in
  [AG-16].
- **Token in argv:** an argv token lands in shell history and `ps` output
  for the token's whole validity window. Hence stdin/`--token-file` only in
  [AG-17].
- **Non-regular scrub target:** a key-file scrub on a non-regular file
  followed where it should have refused. Hence [AG-19]'s
  `O_WRONLY|O_NOFOLLOW|O_NONBLOCK` refusal.
- **Stale guard lists:** hand-maintained lists in fitness checks went stale
  and failed open. Hence matches-zero protection on every guard in §7.

## 9. Milestones

Each milestone ends with the full suite green (including guards) and is sized
for one implementation session.

1. **M1 — Skeleton + guards.** Agent module laid out; guards G-1..G-10
   implemented, red-verified via planted violations, then green. AC-6, AC-7.
2. **M2 — Unit management.** [AG-1..3]: embedded unit, install/reconcile,
   drift detection, heartbeat field. AC-1..4 (container tier).
3. **M3 — Boot + probe.** [AG-4, AG-5, AG-12a]: Runner construction,
   capability probe, manager injection, capability reporting, fd-anchored
   self-reference. AC-5, AC-8.
4. **M4 — Local store + scheduler.** [AG-7, AG-8, AG-10]: SQLite store,
   persist-before-execute, crash replay, windows, bounds. AC-11..13, AC-15.
5. **M5 — Stream + sync.** [AG-6, AG-11] with SPEC-003 verification:
   SignedCommand verify, manifest verify + monotonicity, diff/apply,
   DeviceSigned results, robustness. AC-9, AC-10, AC-16.
6. **M6 — Artifacts + env + self-heal.** [AG-13, AG-13a, AG-14, AG-15]:
   digest chokepoint, URL-transport matrix, env building, self-healing
   pre-ops. AC-17, AC-18.
7. **M7 — Enrollment.** [AG-17, AG-18]: socket, token intake, TOFU +
   fingerprint pin, `install.sh --reset`. AC-20..22.
8. **M8 — Self-update.** [AG-16]: full flow with self-test subprocess.
   AC-19.
9. **M9 — luksd + tty.** [AG-19, AG-20]. AC-23, AC-24.

## 10. Out of scope

- Per-action executor semantics, idempotency contracts, and the 21-type
  catalog (SPEC-014).
- Sealed-secret payload formats and LPS/LUKS/temp-password flows (SPEC-015);
  the agent only invokes them.
- Wire message shapes, signing domains, and manifest structure (SPEC-003).
- Server-side enrollment, token admission, renewal, CRL issuance (SPEC-006).
- Gateway relay behavior and the gateway↔control stream (SPEC-012).
- Compose/deployment E2E gates and release provenance (SPEC-017).
