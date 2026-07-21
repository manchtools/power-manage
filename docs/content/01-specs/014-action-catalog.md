---
title: "SPEC-014 — Action Catalog"
---
# SPEC-014 — Action Catalog

Status: See `00-index.md` (single status ledger) / Builds on: SPEC-003, SPEC-004, SPEC-009, SPEC-010, SPEC-013 / Enables: SPEC-015, SPEC-017 / Module(s): `contract/` (MIT), `sdk/` (MIT), `server/` (AGPL-3.0), `agent/` (GPL-3.0)

## 1. Scope

The normative operator-visible feature surface: the 21 action types with their
parameters, desired-state semantics, applicability rules, and outcome
semantics; the shared catalog rules (idempotency, `NOT_APPLICABLE`, blob-class
payload refs, the managed-policy-file composition); composition via nestable
action sets; assignment, resolution, per-assignment scheduling, and maintenance
windows as far as they shape the catalog; the compliance bundle; and the
adjacent on-demand surfaces (log collection, inventory, osquery). Executor
process discipline is SPEC-013; wire shapes are SPEC-003; kernel CRUD and set
storage are SPEC-009.

## 2. Context capsule

Minimum prior knowledge, restated:

- **Wire contract (SPEC-003):** exactly ONE `ActionParams` message holds the
  per-type oneof; exactly ONE action shape exists — enrichment (assignment
  mode, schedule, resolved target) is composition around it (WIRE-12, WIRE-13).
  Every field crossing a trust boundary carries a `validate` tag with
  type/format/length/range constraints; enum bounds are generated from the
  descriptor (WIRE-2). Server and agent run the SAME shared SDK validators —
  one grammar, zero drift (WIRE-3). Every enum has `*_UNSPECIFIED = 0`, always
  invalid at boundaries; no enum value exists without an implementation behind
  it (WIRE-4). State-changing booleans have no dangerous zero value: `optional
  bool` (explicit presence) or a 3-value enum, absence rejected where ambiguous
  (WIRE-6). Instant commands carry `expires_at − issued_at ≤ 15 min` freshness;
  durable assignments ride the CA-signed sync manifest whose monotonic
  `(epoch, generation)` is the anti-replay authority, carrying the device's
  complete desired state, schedules, and maintenance windows;
  removal-by-omission is the sole cleanup authority (WIRE-15, WIRE-26).
- **Agent (SPEC-013):** the agent is a pure orchestrator over probed SDK
  capabilities; the boot probe's capability set is reported in Hello/inventory
  so control can compute applicability; an action needing an absent capability
  resolves `NOT_APPLICABLE`, never a crash or fallback (AG-4, AG-12a).
  Executors are thin: state-read → short-circuit (`changed=false`) → SDK
  primitive → verify (AG-12). Results are honest: any swallowed sub-step
  failure fails the action; silent per-field skips become structured per-field
  outcomes (AG-9). Sets execute serial with abort-on-first-failure (AG-6).
  Every fetched artifact passes the single digest chokepoint before privileged
  work (AG-13); URL transport rules apply only to `APP_IMAGE` and
  `AGENT_UPDATE` (AG-13a). Package-manager self-healing precedes package
  operations (AG-15). Self-update flow per (AG-16, SPEC-013).
- **Artifact store (SPEC-010):** blob-class action payloads carry
  `(sha256, size)` artifact refs — never inline bytes; the signed command
  covers the hash, so digest-verifying the fetched bytes IS verifying the
  signature's subject. Bounded inline TEXT/key fields stay inline because they
  are diffed, validated, sealed, or redacted as fields (ART-2, SPEC-010).
- **Kernel and sets (SPEC-009):** actions and action sets are kernel CRUD
  domains; boundary tests are generated from validate tags (API-1). Sets are
  nestable: a member is an action OR another set; sets form a DAG with
  write-time cycle rejection; dispatch flattens depth-first in declared order
  with first-occurrence-wins dedup (SET-1..SET-4, SPEC-009). There is NO
  separate composition layer above sets — "client setup" is a set of sets.
- **SDK (SPEC-004):** the managed-policy-file behavior is ONE composition
  function — hash-compare → write candidate → validate the CANDIDATE → atomic
  swap → reload → restore-on-failure — with a three-row surface table for
  SSH / SSHD / ADMIN_POLICY (SDK-18, SPEC-004). Structured-file values reject
  newlines, control characters, and format-structural delimiters before
  writing, with cross-field validation where one file is written from several
  fields (SDK-11); protected paths are deny-by-default subtree prefixes,
  symmetric for create and delete (SDK-8); regexes reaching a backtracking
  engine pass a ReDoS guard (SDK-6).
- **Secrets (SPEC-003/SPEC-015):** device-originated secrets (LPS passwords,
  LUKS passphrases, USER temp passwords) are sealed to control's X25519 key; no
  plaintext secret transits the gateway (WIRE-23, WIRE-24, SPEC-003).
- **Defended actors:** low-privilege users must not smuggle unsafe values or
  exceed grant scope, and compromised relays/on-path attackers must not alter
  the signed action bytes an agent validates and executes.

## 3. Requirements

### 3.1 Shared catalog semantics

- **[CAT-1]** The catalog is CLOSED at exactly the 21 types in §3.2. The
  `ActionParams` oneof, the agent executor registry, and this spec's list are
  the same exact set, guard-proven (§7 G-1). Adding a type is a contract +
  executor + spec change in one release; no aspirational or reserved values
  exist (WIRE-4, SPEC-003).
- **[CAT-2]** Desired state `PRESENT`/`ABSENT` applies wherever sensible (see
  §3.2 per-type column). Idempotency is state-read + short-circuit: an action
  whose desired state already holds reports `changed=false` and performs no
  mutation. The assignment mode `UNINSTALL` forces `ABSENT` for every action it
  delivers WITHOUT editing the action (§3.5).
- **[CAT-3]** `NOT_APPLICABLE` is ONE first-class outcome enum value (recorded
  operator decision) for STRUCTURAL inapplicability: required capability absent
  from the boot probe, no parameter for the device's backend, or payload format
  mismatching the probed backend. It is never an error and never a silent
  success; control renders it distinctly. Field-level inapplicability (e.g. a
  USER `hidden` flag without accountsservice) is a structured per-field outcome
  inside an otherwise-executed result (AG-9, SPEC-013).
- **[CAT-4]** The non-idempotent set is exactly {`REBOOT`, `SYNC`,
  `SHELL` with `lifecycle: ONE_SHOT`, `SERVICE` with `desired_state:
  RESTARTED`} — enumerated in the type registry, documented to operators,
  guard-proven exact (§7 G-6). Everything else in the catalog is idempotent
  under [CAT-2].
- **[CAT-5]** Blob-class payloads (today: `PACKAGE_FILE`) carry `(sha256,
  size)` artifact refs, never inline bytes; the enumerated bounded inline
  TEXT/key fields — SHELL `script`/`detection_script`, SERVICE `unit_content`,
  FILE `content`, REPOSITORY `gpgKey`/`customConfig`, WIFI PSK/EAP-TLS
  material — remain inline fields of the action shape (ART-2, SPEC-010).
- **[CAT-6]** The audit redactor strips `script`, `detectionScript`,
  `content`, `unitContent`, `customConfig`, `gpgKey`, `presharedKey`, `psk`,
  and `clientKey` via the schema-dispatched redaction sweep (AUD-3, SPEC-011).
  A new secret- or content-bearing catalog field without a redaction schema
  entry is unmergeable.
- **[CAT-7]** `SSH`, `SSHD`, and `ADMIN_POLICY` land their files exclusively
  through the managed-policy-file composition (SDK-18, SPEC-004): hash-compare
  drift → candidate write → candidate validation (`sshd -t -f`,
  `visudo -c -f`) → atomic swap → reload → restore-on-failure.
  Revert-on-unassign replays the stored prior state through the same function.
  No executor writes these files any other way (§7 G-5).

### 3.2 Catalog overview

| # | Type | Group | PRESENT/ABSENT | Applicability probe | Non-idempotent |
|---|---|---|---|---|---|
| 1 | `PACKAGE` | Packages & updates | yes | package manager; per-manager name present | no |
| 2 | `UPDATE` | Packages & updates | n/a (operation) | package manager; `security_only` unsupported on pacman | no |
| 3 | `REPOSITORY` | Packages & updates | yes | package manager | no |
| 4 | `PACKAGE_FILE` | Packages & updates | yes | artifact format matches probed dpkg/rpm backend | no |
| 5 | `APP_IMAGE` | Packages & updates | yes | always (filesystem) | no |
| 6 | `FLATPAK` | Packages & updates | yes | flatpak present | no |
| 7 | `SHELL` | System | n/a (script) | interpreter present | `ONE_SHOT` only |
| 8 | `SERVICE` | System | yes | systemd present | `RESTARTED` only |
| 9 | `FILE` | System | yes | always | no |
| 10 | `DIRECTORY` | System | yes | always | no |
| 11 | `REBOOT` | System | n/a (instant) | always | yes |
| 12 | `SYNC` | System | n/a (instant) | always | yes |
| 13 | `USER` | Identity & access | yes | always; `hidden` needs accountsservice (per-field) | no |
| 14 | `GROUP` | Identity & access | yes | always | no |
| 15 | `SSH` | Identity & access | yes | sshd present | no |
| 16 | `SSHD` | Identity & access | yes | sshd present | no |
| 17 | `ADMIN_POLICY` | Identity & access | yes | sudo present | no |
| 18 | `LPS` | Identity & access | yes | always; grace rotation needs `sessions` capability (per-field) | no |
| 19 | `ENCRYPTION` | Security & networking | yes (ABSENT = agent state only) | LUKS present | no |
| 20 | `WIFI` | Security & networking | yes | NetworkManager present | no |
| 21 | `AGENT_UPDATE` | Lifecycle | n/a (operation) | always | no |

### 3.3 Per-type contracts

Package-manager self-healing (AG-15, SPEC-013) precedes every operation in the
first group.

**Packages & updates**

| ID | Type | Contract |
|---|---|---|
| [ACT-1] | `PACKAGE` | Install/remove via apt/dnf/pacman/zypper. Per-manager name overrides with NO silent fallback: no name for the device's manager ⇒ `NOT_APPLICABLE`. Exact `version`; `allow_downgrade`; `pin` (hold / versionlock / IgnorePkg / addlock) — a pin failure FAILS the action, never silent success. |
| [ACT-2] | `UPDATE` | Full upgrade. `security_only` (pacman cannot express it ⇒ `NOT_APPLICABLE`); `autoremove`; `reboot_if_required` triggers only if THIS run created the need, never a pre-existing one. The pending-updates probe drives `changed`. |
| [ACT-3] | `REPOSITORY` | Per-manager repo add/remove (deb822 + Signed-By, `.repo`, `pacman.conf`, zypper). `enabled` and `gpgcheck` are explicit-presence fields (WIRE-6, SPEC-003) — no unset-means-off security downgrade. Pre-side-effect validation including cross-field validation of every field landing in one file (SDK-11, SPEC-004); apt parse-failure ⇒ rollback-and-fail; post-change cache refresh. `gpgcheck=false` is ALLOWED — recorded operator decision, no refusal. |
| [ACT-4] | `PACKAGE_FILE` | ONE type for direct .deb/.rpm install — the former separate DEB and RPM types are merged. Payload is an artifact ref (ART-2, SPEC-010); format is detected by file magic AT UPLOAD and stored as artifact metadata (ART-1, SPEC-010). Applicability = format matches the device's probed backend (dpkg/rpm); wrong format ⇒ `NOT_APPLICABLE` — exactly the [ACT-1] pattern. Digest verification through the single chokepoint (AG-13, SPEC-013): the pin is the `(sha256, size)` in the signed command. Dependency resolution via apt/dnf/zypper. Repository GPG verification does not apply to a local file by design: per-package trust IS the pinned digest the signed command covers. |
| [ACT-5] | `APP_IMAGE` | Verified download (AG-13a URL rules, SPEC-013), mode 0755, `install_path` (default `/opt/appimages`); drift detection by re-hash; streamed atomic write (SDK-9, SPEC-004). **Checksum is MANDATORY** — an unset checksum is a validation error, not an unverified install. |
| [ACT-6] | `FLATPAK` | Install from a remote. `system_wide` is explicit-presence (WIRE-6). `pin` via mask. Per-user installs run per signed-in session via the explicit execution-context mode ([ACT-7]) — never an overloaded boolean. No flatpak ⇒ `NOT_APPLICABLE`. |

**System**

| ID | Type | Contract |
|---|---|---|
| [ACT-7] | `SHELL` | `script` ≤ 1 MiB (inline per [CAT-5]); `interpreter`; `execution_context` enum {`ROOT`, `PER_ACTIVE_SESSION`} — an explicit enum, replacing the predecessor's "not as root" boolean whose fan-out to every active session surprised operators; working dir; screened env (SDK-4, SPEC-004); script passed as argv. `detection_script` (exit 0 = compliant) gates execution and re-verifies after remediation. `is_compliance` per §3.6. `lifecycle` enum {`RECONCILE`, `ONE_SHOT`}: `ONE_SHOT` absorbs the former separate one-shot script type — never stored in the offline scheduler, re-runs on full reconcile only, documented non-idempotent ([CAT-4]). |
| [ACT-8] | `SERVICE` | systemd only — no non-systemd enum values exist (WIRE-4, SPEC-003). `unit_content` (inline, SHA-diffed; a diff triggers daemon-reload); `enable` explicit-presence (WIRE-6); `desired_state` {`STARTED`, `STOPPED`, `RESTARTED`}. Refuses `power-manage-agent.service`. Enabling a masked unit is an error, never a silent skip. |
| [ACT-9] | `FILE` | `content` ≤ 10 MB (product cap; inline per [CAT-5]); owner/group/mode applied when set; `managed_block` mode is marker-delimited so editing the block replaces the previous block instead of stranding it; idempotency by SHA + attributes; a symlink at the target is never converged through — refuse; atomic replace (SDK-7, SPEC-004); critical-file denylist with symlink resolution (SDK-8). |
| [ACT-10] | `DIRECTORY` | Presence + attributes. `recursive` explicit-presence (WIRE-6). `ABSENT` subtree removal runs under the deny-by-default protected prefixes, symmetric with `PRESENT` (SDK-8, SPEC-004). |
| [ACT-11] | `REBOOT` | Instant, parameterless; executes a scheduled `shutdown -r` via the SDK. Queued instant dispatches carry a TTL (`expires_at`, WIRE-15) — an expired reboot is dropped, never delivered late. |
| [ACT-12] | `SYNC` | Instant, parameterless; triggers a full desired-state reconcile on the agent; concurrent triggers coalesce. This is the ONLY reconcile-now verb — the control side exposes one converge-now RPC that dispatches assigned work through the normal signed path; no duplicate control-side dispatch verb exists (SPEC-003 deny-list). |

**Identity & access**

| ID | Type | Contract |
|---|---|---|
| [ACT-13] | `USER` | Linux account lifecycle: uid/gid/group, home, shell (validated against `/etc/shells` — SDK-12, SPEC-004), GECOS (delimiter-rejected — SDK-11), exact `ssh_authorized_keys` rewrite with newline-smuggling rejected (SDK-11), `system_user`, `create_home`, `disabled` (lock-only for root — AG-20, SPEC-013; account lock and session shell are separate domains), `hidden` (`NOT_APPLICABLE` per-field without accountsservice — never a silent skip), `no_password`. Temp passwords are sealed to control (WIRE-23, SPEC-003; SPEC-015). `ABSENT` kills the user's sessions and deletes the home directory. |
| [ACT-14] | `GROUP` | Exact-membership system group. Missing users are structured per-field outcomes (AG-9, SPEC-013), not failures or silence. `gid` applies at creation only. The `power-manage` group is protected from management. |
| [ACT-15] | `SSH` | Per-action system group + one `sshd_config.d` Match-Group drop-in, landed via [CAT-7]. Auth booleans are explicit-presence (WIRE-6). `sshd -t` validates the candidate, then reload. Multiple SSH policies stack. `ABSENT` removes both the group and the drop-in. |
| [ACT-16] | `SSHD` | Global sshd configuration via priority-ordered drop-ins; key/value directives only. `sshd -t` pre-commit; an invalid fragment is removed (restore-on-failure per [CAT-7]). `priority` is an operator-editable field — reordering never requires delete-and-recreate. |
| [ACT-17] | `ADMIN_POLICY` | Sudo policy: per-action system group + one `sudoers.d` file, landed via [CAT-7] with `visudo -c -f` pre-commit. Levels: `FULL`; `LIMITED` — a deny-by-default allowlist of RESOLVED binary paths, where `NOPASSWD` is load-bearing (recorded decision; rationale: prompting for a password the managed account does not have would brick the policy); `CUSTOM` — operator sudoers text with a `{group}` placeholder. `TERMINAL_ADMIN_*` group names are reserved to the server reconciler. No DOAS enum value exists (WIRE-4). |
| [ACT-18] | `LPS` | Scheduled local-password rotation for ANY local account, root included — recorded operator decision (parity with Windows LAPS; the safeguard is documentation, not an allowlist). `usernames`; length 8–128; charset class; interval 1–365 days. Login-triggered grace rotation via the SDK `sessions` capability (logind D-Bus); absent logind ⇒ structured `NOT_APPLICABLE` outcome for grace rotation. Passwords are sealed to control BEFORE being set — seal failure means the password is NOT set (fail closed); 60 s user notice, then session kill; sealed transport only (WIRE-23; SPEC-015). `ABSENT` clears rotation state but KEEPS the last escrowed passwords. |

**Security & networking**

| ID | Type | Contract |
|---|---|---|
| [ACT-19] | `ENCRYPTION` | LUKS only — no other backend enum values exist (WIRE-4). PSK bootstrap slot: consumed and wiped after the first managed rotation. Managed word-passphrase slot rotated on schedule; the NEW slot is server-round-trip-verified before the old one is wiped (a device is never left with zero working managed slots). Optional device-bound key: TPM2 (PCRs 7+14, best-effort) or `USER_PASSPHRASE` in slot 7 enrolled via luksd (AG-19, SPEC-013). Passphrases move only under sealed transport (WIRE-23; SPEC-015). `ABSENT` removes agent-side state only — it never strips LUKS slots. |
| [ACT-20] | `WIFI` | NetworkManager only. PSK (WPA2/3) or EAP-TLS profile named `pm-wifi-<id>`; configuration-only (profile management, not radio state). INI values are injection-rejected before write (SDK-11, SPEC-004); certificate/key files land mode 0600. PSK and EAP-TLS key material transit sealed device-directed (SEC-11, SPEC-015). The PSK cannot be read back for diffing; the resulting rewrite/`changed` semantics are DOCUMENTED contract, not a surprise. |

**Lifecycle**

| ID | Type | Contract |
|---|---|---|
| [ACT-21] | `AGENT_UPDATE` | The sole agent upgrade path, per (AG-16, SPEC-013). Per-arch HTTPS URL + `checksum_url` OR pinned `expected_sha256` — pinned wins when both are set; at least one is REQUIRED, server-enforced at validation; never a mandatory pin (recorded operator reversal — do not re-add; out-of-band release signing is an accepted risk, recorded deliberately). Anti-rollback unless the signed action carries `allow_downgrade`; 60 s self-test gate; managed-unit re-apply; maintenance windows apply. AG-13a URL transport rules. |

### 3.4 Composition: nestable action sets

- **[CAT-8]** Composition is nesting, nothing else. A set's ordered members are
  actions AND other sets; sets form a DAG with write-time cycle rejection,
  depth-first flatten in declared order at dispatch, and
  first-occurrence-wins dedup (SET-1..SET-3, SPEC-009). The flattened sequence
  executes serially with abort-on-first-failure (SET-4, SPEC-009; AG-6,
  SPEC-013). There is NO separate composition/definition layer above sets —
  "client setup" is a set containing the repo/runtime/monitoring sets. No
  catalog feature may depend on a member's nesting depth.

### 3.5 Assignment, resolution, scheduling, windows

- **[ASG-1]** The work-primitive chain is: Action → Action set → Assignment →
  Execution. An assignment binds an action or set to a target — device, user,
  device group, or user group — with a mode and an optional cron or interval
  schedule. Assignments are IMMUTABLE: delete-and-recreate, never update
  (WIRE-9, SPEC-003). Resolution expands group targets to the concrete device
  set; the device's complete resolved desired state travels as occurrence keys
  (assignment × action) in the signed sync manifest (WIRE-26, SPEC-003).
- **[ASG-2]** Assignment mode `UNINSTALL` forces desired state `ABSENT` for
  every action the assignment delivers, without editing the actions. The
  default mode applies actions as authored.
- **[ASG-3]** Maintenance windows are typed messages (weekday set, start/end
  minute-of-day — WIRE-8, SPEC-003), attached via device groups, delivered in
  the signed manifest, and evaluated DEVICE-LOCALLY: union across groups,
  device-local timezone, midnight-crossing allowed, re-checked ~1/min (AG-8,
  SPEC-013). **Instant dispatches BYPASS maintenance windows** — recorded
  operator decision. An undecodable window defers scheduled work (fail
  closed). Windows apply to `AGENT_UPDATE`.
- **[ASG-4]** Device-targeted timing ("run this at 02:00") is the AGENT
  scheduler's job, driven by the schedule fields in the signed manifest —
  NEVER a server-side delayed dispatch, which cannot be correct for offline
  devices (recorded operator decision). Server-side `run_at` work rows exist
  only for control-plane jobs and for minting one-shot fan-outs (ES-8,
  SPEC-005). Schedules execute offline: persist-before-execute, crash replay,
  UTC instants (AG-7, SPEC-013).

### 3.6 Compliance

- **[CMP-1]** Compliance is `SHELL` + `is_compliance: true` bundled into
  compliance policies (rules + grace hours) — a kernel domain (SPEC-009).
  `is_compliance: true` REQUIRES `lifecycle: RECONCILE` AND a
  `detection_script`, rejected at validation otherwise: a one-shot compliance
  rule can neither drive grace transitions nor be evaluated offline — the
  invalid state is unrepresentable.
- **[CMP-2]** Per-device compliance state transitions — `COMPLIANT`,
  `IN_GRACE_PERIOD`, `NON_COMPLIANT` — are event-sourced (SPEC-005), driven by
  detection results and the policy's grace hours. Compliance-linked execution
  output is evidence, retained per policy (ES-12, SPEC-005).
- **[CMP-3]** Group/fleet rollup views — percentages, in-grace and
  non-compliant counts, trend — are aggregated over the same compliance
  projections (SRCH-1, SPEC-009). No second aggregation store.

### 3.7 Adjacent on-demand surfaces

These are instant SignedCommand surfaces (WIRE-14/15, SPEC-003), not action
types, but they are catalog-adjacent product surface:

- **[CAT-9]** Log collection is journalctl on-demand only: unit, time range,
  priority, and grep filters (grep pattern ReDoS-guarded — SDK-6, SPEC-004);
  results carry an explicit truncation marker at the 1 MB cap. No second log
  source exists; a transport seam without a second implementation is not built
  (META-3, SPEC-000).
- **[CAT-10]** Inventory is server-initiated: a baseline collector plus osquery
  layering over the FIXED table allowlist; stored latest-snapshot
  (ES-10, SPEC-005).
- **[CAT-11]** osquery is on-demand SQL. Convenience tables sit behind a
  curated sensitive-table deny-list; RAW signed SQL is exempt by design — the
  recorded operator escape hatch. Both paths are read-audited per SPEC-011.

## 4. Acceptance criteria

Generic (run against every applicable type via the registry, §7 G-2):

- **AC-1** The catalog exact-set guard proves `ActionParams` oneof ≡ executor
  registry ≡ the 21 types of §3.2, and fails red when a type is added to one
  side only.
- **AC-2** For every PRESENT/ABSENT-capable type: applying twice yields
  `changed=true` then `changed=false` with no second mutation; applying
  `ABSENT` over an absent state yields `changed=false`.
- **AC-3** An assignment in `UNINSTALL` mode drives the same action to
  `ABSENT` without any modification of the stored action.
- **AC-4** Every applicability case in §3.2 resolves a structured
  `NOT_APPLICABLE` result — never an error, a crash, or `changed=false`
  success: PACKAGE without a name for the device's manager; UPDATE
  `security_only` on pacman; PACKAGE_FILE format ≠ probed backend; FLATPAK
  without flatpak; SERVICE/SSH/SSHD/ADMIN_POLICY/ENCRYPTION/WIFI without
  their probed capability.
- **AC-5** Boundary tests generated from validate tags (API-1, SPEC-009) cover
  correct/absent/wrong for every catalog field; every explicit-presence
  boolean (`enabled`, `gpgcheck`, `enable`, `system_wide`, `recursive`, SSH
  auth booleans) rejects absence where absence is ambiguous.

Per-type:

- **AC-6** PACKAGE: a pin/hold sub-step failure after a successful install
  FAILS the action; exact `version` and `allow_downgrade` behave per contract.
- **AC-7** UPDATE: `reboot_if_required` does not trigger when the reboot need
  predates the run; the pending-updates probe drives `changed`.
- **AC-8** REPOSITORY: a cross-field combination that would produce an invalid
  repo file is rejected BEFORE any write; an apt parse failure after write
  rolls back to the prior file and fails the action; `gpgcheck=false` is
  accepted.
- **AC-9** PACKAGE_FILE: upload detects .deb/.rpm by file magic and stores it
  as artifact metadata; a digest or size mismatch at the agent chokepoint
  fails closed before any package operation; dependency resolution installs
  via the native resolver; the wrong-format device reports `NOT_APPLICABLE`.
- **AC-10** APP_IMAGE: a params message without a checksum is rejected at
  validation; drift is detected by re-hash; the write is streamed and atomic.
- **AC-11** FLATPAK: `system_wide` absent is rejected; per-user install
  executes per signed-in session; `pin` masks updates.
- **AC-12** SHELL: a 1 MiB + 1 byte script is rejected; `PER_ACTIVE_SESSION`
  fans out per session and `ROOT` does not; `detection_script` exit 0 skips
  remediation and non-zero gates it, with post-remediation re-verification;
  `ONE_SHOT` is never persisted into the offline scheduler and re-runs only on
  full reconcile.
- **AC-13** SERVICE: managing `power-manage-agent.service` is refused;
  enabling a masked unit errors; a `unit_content` change triggers exactly one
  daemon-reload; `RESTARTED` restarts on every reconcile (non-idempotent, per
  [CAT-4]).
- **AC-14** FILE: editing `managed_block` content replaces the previous
  marker-delimited block (no stranded stale block); a symlinked target is
  refused; a critical-file denylist hit (including via symlink resolution) is
  refused; content > 10 MB is rejected at validation.
- **AC-15** DIRECTORY: `recursive` absent is rejected; `ABSENT` under a
  protected prefix is refused exactly like `PRESENT` would be.
- **AC-16** REBOOT: an instant reboot delivered after `expires_at` is dropped
  by the agent; nothing persists past expiry.
- **AC-17** SYNC: N rapid SYNC commands coalesce into one reconcile; the
  converge-now RPC dispatches through the normal signed path.
- **AC-18** USER: `ABSENT` kills live sessions and removes the home; a GECOS
  value with `:` or newline is rejected; an `ssh_authorized_keys` entry with
  an embedded newline is rejected; `disabled` on root locks the account but
  leaves the shell untouched; `hidden` without accountsservice yields a
  structured per-field outcome; the temp password is sealed before transport.
- **AC-19** GROUP: a missing member user yields a structured per-field outcome
  while remaining members converge; managing `power-manage` is refused; `gid`
  changes on an existing group are not applied.
- **AC-20** SSH/SSHD/ADMIN_POLICY route every file mutation through the
  SDK-18 composition: an invalid candidate (`sshd -t -f` / `visudo -c -f`
  failure) restores the prior file and fails the action; two SSH policies
  stack; SSHD `priority` edits reorder without recreate; `TERMINAL_ADMIN_*`
  names are rejected for operator actions; LIMITED sudo emits resolved-path
  NOPASSWD allowlist entries.
- **AC-21** LPS: length/interval bounds reject 7/129 and 0/366; a sealing
  failure leaves the current password unchanged (fail closed); grace rotation
  without logind yields structured `NOT_APPLICABLE`; session kill happens 60 s
  after notice; `ABSENT` keeps the last escrowed passwords; rotation for root
  is accepted.
- **AC-22** ENCRYPTION: the bootstrap PSK slot is wiped only after the first
  successful managed rotation; the old managed slot is wiped only after the
  new slot round-trips against the server; `ABSENT` leaves all LUKS slots
  intact.
- **AC-23** WIFI: an SSID or identity value with INI-structural characters is
  rejected before write; EAP-TLS material lands 0600; the profile is named
  `pm-wifi-<id>`.
- **AC-24** AGENT_UPDATE: a params message with neither `checksum_url` nor
  `expected_sha256` is rejected server-side; with both, the pin wins; a
  scheduled update waits for the maintenance window while an instant dispatch
  would not (ASG-3).

Composition, assignment, compliance, adjacent:

- **AC-25** A nested set dispatch flattens depth-first in declared order,
  dedups to the first occurrence, and aborts the remainder of the flattened
  sequence on first failure (with SET write-time cycle rejection covered in
  SPEC-009).
- **AC-26** An assignment schedule appears in the signed manifest and fires
  from the agent scheduler while the device is OFFLINE; no server-side
  delayed-dispatch path exists for device-targeted timing (guard §7 G-7).
- **AC-27** A scheduled action inside a closed maintenance window defers; an
  instant command inside the same window executes; window union across two
  groups and a midnight-crossing window evaluate correctly device-locally.
- **AC-28** `is_compliance: true` without `lifecycle: RECONCILE` or without
  `detection_script` is rejected at validation; detection-driven transitions
  walk COMPLIANT → IN_GRACE_PERIOD → NON_COMPLIANT per grace hours and back on
  remediation; rollups report correct percentages/counts/trend over the same
  projections.
- **AC-29** A log query over the 1 MB cap returns truncated output WITH the
  truncation marker; a catastrophic-backtracking grep pattern is rejected by
  the ReDoS guard.
- **AC-30** A convenience-table osquery against a deny-listed table is
  refused; the same table via raw signed SQL succeeds; inventory ingest
  replaces the latest snapshot (ES-10, SPEC-005).

## 5. Rejection paths

| Input / state | Required behavior |
|---|---|
| Action type value outside the 21-type enum, or `*_UNSPECIFIED` | Validation error at the boundary (WIRE-4) |
| Explicit-presence boolean absent where absence is ambiguous | Validation error (WIRE-6) |
| SHELL script > 1 MiB; FILE content > 10 MB | Validation error |
| `is_compliance: true` without `RECONCILE` lifecycle + `detection_script` | Validation error; never persisted |
| LPS length ∉ 8–128 or interval ∉ 1–365 d | Validation error |
| AGENT_UPDATE with neither checksum source | Validation error, server-enforced |
| APP_IMAGE without checksum | Validation error (mandatory pin) |
| Blob payload offered inline instead of `(sha256, size)` ref | Unrepresentable in the contract (ART-2, SPEC-010) |
| Set write introducing a cycle at any depth | Write-time validation error (SET-2, SPEC-009) |
| Assignment update attempt | Unrepresentable — delete-and-recreate only (WIRE-9) |
| Artifact digest/size mismatch at the agent | Fail closed before privileged work (AG-13, SPEC-013) |
| Instant command past `expires_at` (incl. REBOOT) | Dropped; nothing persisted (WIRE-15) |
| PACKAGE name missing for device's manager; PACKAGE_FILE wrong format; capability absent | Structured `NOT_APPLICABLE`, never silent success |
| Pin/hold or any sub-step failure | Action FAILED (AG-9, SPEC-013) |
| Candidate fails `sshd -t -f` / `visudo -c -f` | Restore prior file; action FAILED ([CAT-7]) |
| Repo cross-field combination producing an invalid file | Rejected pre-write; post-write parse failure rolls back |
| GECOS/authorized_keys/INI value with delimiters, newlines, control chars | Rejected before write (SDK-11) |
| SERVICE targeting `power-manage-agent.service`; GROUP targeting `power-manage`; `TERMINAL_ADMIN_*` group names | Refused |
| FILE/DIRECTORY operation on protected prefix or through a symlinked target | Refused, symmetric for PRESENT and ABSENT (SDK-8) |
| LPS seal failure before set | Password unchanged; action FAILED (fail closed) |
| ENCRYPTION old-slot wipe before new-slot round-trip verification | Unreachable by construction; verification precedes wipe |
| Undecodable cached window/schedule | Defer scheduled work (fail closed; AG-8, SPEC-013) |
| osquery convenience query on deny-listed table | Refused (raw signed SQL exempt) |
| Log grep pattern failing the ReDoS guard | Rejected |

## 6. Test plan (TDD)

Write tests FIRST from the ACs; confirm each fails RED for the right reason via
a scoped neutralizing edit, never a revert. Full suites under `-race`.

1. **Contract tier (generated):** the API-1 generator (SPEC-009) emits
   correct/absent/wrong cases for every catalog field from the validate tags —
   AC-5 and every validation row of §5. Add hand-written cases only for
   cross-field rules (AC-8, AC-28's validation half, AC-24's one-of-checksum).
2. **Server tier (REAL Postgres, REAL handlers — never mocks):** catalog CRUD
   through the kernel, assignment immutability, manifest content (schedules,
   windows, occurrence keys), compliance transitions and rollups (AC-26 server
   half, AC-28), PACKAGE_FILE upload magic detection (AC-9 upload half),
   NOT_APPLICABLE rendering.
3. **Agent executor tier (FakeRunner + fake capability probe):** per-type
   idempotency (AC-2), UNINSTALL forcing (AC-3), the NOT_APPLICABLE matrix
   (AC-4) by removing capabilities from the fake probe, sub-step failure
   honesty (AC-6), lifecycle/scheduler behavior (AC-12, AC-16, AC-17, AC-26,
   AC-27), per-field outcomes (AC-18, AC-19, AC-21).
4. **SDK container lanes (REAL tools, per SPEC-004/SPEC-017):** every executor
   path that touches a real package manager, sshd, visudo, systemd,
   NetworkManager, or LUKS runs round-trip against the real binary in
   containers — apt/dnf/pacman/zypper matrices for ACT-1..4, candidate
   validation and restore (AC-20), unit reload (AC-13), file/directory
   protection (AC-14, AC-15), WIFI profile writes (AC-23), LUKS slot rotation
   (AC-22) — under non-English locales per the Runner invariant (SDK-3).
   Reboot tests: real runner allowed, real `shutdown` binary unreachable.
5. **Cross-component:** signed-manifest → offline execution → DeviceSigned
   result round-trip for a scheduled assignment (AC-26) against SPEC-003 test
   vectors; PACKAGE_FILE end-to-end upload → ref → fetch → chokepoint →
   install against a fake backend (AC-9).
6. **Regression rule:** every bug fix ships a test that fails on the buggy
   version.

## 7. Guards

All guards are self-discovering with matches-zero protection (SPEC-000).

| # | Guard | Mechanism |
|---|---|---|
| G-1 | Catalog exact-set ([CAT-1]) | Walk the `ActionParams` descriptor oneof, the agent executor registry, and this spec's §3.2 list; all three are the identical exact set; fails on zero types discovered |
| G-2 | Per-type test coverage | Registry walk emits the generic AC-2/AC-3/AC-4 suites per registered type; fails if any type lacks its suite or zero types are discovered |
| G-3 | Explicit presence (WIRE-6) | Descriptor walk over `ActionParams`: every state-changing plain `bool` must be `optional` or carry a recorded two-value rationale (shared with SPEC-003) |
| G-4 | Redaction parity ([CAT-6]) | AST sweep over catalog payload structs: every content/secret-bearing field has an AUD-3 redaction schema entry (shared with SPEC-011); fails on zero structs |
| G-5 | Policy-file chokepoint ([CAT-7]) | Archtest: within the SSH/SSHD/ADMIN_POLICY executors, file mutation calls resolve only to the SDK-18 composition entry point; fails if it discovers fewer than the three surfaces |
| G-6 | Non-idempotent exact set ([CAT-4]) | Registry walk: the types/modes flagged non-idempotent equal exactly {REBOOT, SYNC, SHELL:ONE_SHOT, SERVICE:RESTARTED} |
| G-7 | No server-side device-delayed dispatch ([ASG-4]) | Scan of work-table writers (ES-8/ES-11 registry, SPEC-005): no `run_at` row targets a device-plane execution; allowlist is control-plane job kinds; fails on zero writers scanned |
| G-8 | Shared validators (WIRE-3) | Registry walk: every operator-string catalog field maps to one SDK validator symbol imported by BOTH server and agent; fails on zero fields |
| G-9 | Applicability declared | Registry walk: every type declares an applicability predicate over the probed capability set (possibly "always"); fails on zero types |

## 8. Historical lessons

- **Unset-means-off:** proto booleans defaulting to `false` silently disabled
  service units and dropped repository GPG checking when operators omitted the
  field — a recurring footgun family, treated as a contract bug. Hence
  explicit presence on every state-changing boolean ([CAT-5]/G-3; WIRE-6).
- **Reserved enum values:** enum values with no implementation behind them
  (alternative init systems, DOAS, non-LUKS encryption backends) shipped as
  aspirational contract and became dead surface and fail-open validation
  holes. Hence [CAT-1]: a value exists only WITH its implementation.
- **Swallowed sub-steps:** pin, disable, autoremove, and reboot-schedule
  failures were silently swallowed while the action reported success. Hence
  pin-failure-fails-the-action in [ACT-1] and honesty per (AG-9, SPEC-013).
- **Optional checksum, fail-open:** an optional download checksum meant
  unverified installs whenever it was unset. Hence the mandatory APP_IMAGE
  checksum ([ACT-5]) and the server-enforced one-of rule in [ACT-21].
- **The overloaded boolean:** a "not as root" boolean silently fanned scripts
  out to every active session. Hence the explicit `execution_context` enum in
  [ACT-7], reused by FLATPAK per-user installs.
- **Repo file bricking:** a repository file assembled from several fields
  passed per-field validation yet produced a file that broke the package
  manager fleet-wide until manually repaired. Hence cross-field pre-write
  validation and parse-failure rollback in [ACT-3].
- **Stranded managed blocks:** editing a managed block's content left the
  previously written block in place beside the new one. Hence marker-delimited
  `managed_block` in [ACT-9].
- **Stale instant commands:** a reboot queued while a device was offline
  landed days later. Hence the TTL on queued instant dispatches ([ACT-11];
  WIRE-15).
- **Immutable drop-in priority:** server-assigned immutable SSHD priorities
  made reordering impossible without delete-and-recreate. Hence the
  operator-editable `priority` field in [ACT-16].
- **Two types, one behavior:** separate DEB and RPM types duplicated one
  install behavior, differing only in a format the device's probed backend
  already determines. Hence `PACKAGE_FILE` ([ACT-4]).
- **Two script types:** a separate one-shot script type duplicated SHELL's
  whole surface for one lifecycle difference. Hence the `lifecycle` enum in
  [ACT-7].
- **A separate composition layer:** the predecessor's definitions layer
  duplicated set semantics one level up with no capability sets could not
  express. Hence [CAT-8]: nesting replaces it with zero capability lost.
- **Server-side delayed dispatch:** delaying dispatch on the server cannot be
  correct for a device that is offline at fire time — the device plane owns
  device-local timing. Hence [ASG-4] and guard G-7.
- **Inline package bytes:** package payloads carried as inline bytes produced
  megabyte events and megabyte signing inputs, and capped package size. Hence
  artifact refs for blob-class payloads ([CAT-5]; ART-2, SPEC-010).
- **Half-wired alternatives:** a second, half-wired log source shipped without
  an implementation behind its config surface. Hence journalctl-only [CAT-9].
- **Hash-equality leaks:** content-addressing secret-bearing fields by plain
  SHA-256 would expose secret equality across devices (identical Wi-Fi PSKs →
  identical digests). Hence the inline exception in [CAT-5].

## 9. Milestones

Each milestone is one implementation session ending green (including guards).

1. **M1 — Contract + registries.** `ActionParams` per-type messages with
   validate tags (SPEC-003), the type registry (applicability predicates,
   non-idempotent flags), guards G-1..G-4, G-6, G-8, G-9 red-verified then
   green. AC-1, AC-5.
2. **M2 — Generic executor frame.** Desired-state/idempotency frame,
   UNINSTALL forcing, NOT_APPLICABLE resolution from the probe, per-field
   outcome plumbing. AC-2..AC-4.
3. **M3 — Packages I.** [ACT-1..3] against FakeRunner + container lanes.
   AC-6..AC-8.
4. **M4 — Packages II.** [ACT-4..6]: PACKAGE_FILE upload metadata + end-to-end
   ref/fetch/install, APP_IMAGE, FLATPAK. AC-9..AC-11.
5. **M5 — System.** [ACT-7..12]: SHELL lifecycle + execution contexts,
   SERVICE, FILE, DIRECTORY, REBOOT TTL, SYNC coalescing. AC-12..AC-17.
6. **M6 — Policy-file surfaces.** [ACT-15..17] over the SDK-18 composition +
   guard G-5. AC-20.
7. **M7 — Identity.** [ACT-13, ACT-14, ACT-18]: USER, GROUP, LPS (sealed
   flows stubbed at the SPEC-015 seam). AC-18, AC-19, AC-21.
8. **M8 — Security & lifecycle.** [ACT-19..21]: ENCRYPTION, WIFI,
   AGENT_UPDATE params + server-side one-of enforcement. AC-22..AC-24.
9. **M9 — Assignment + scheduling.** [ASG-1..4] + guard G-7: manifest
   schedules, windows, instant bypass, offline firing. AC-25..AC-27.
10. **M10 — Compliance + adjacent.** [CMP-1..3], [CAT-9..11]. AC-28..AC-30.

## 10. Out of scope

- Wire shapes, SignedCommand/manifest envelopes, signing domains — SPEC-003.
- SDK primitive implementations (Runner, filesystem, validators, SDK-18
  internals, sessions/LUKS backends) — SPEC-004.
- Kernel CRUD mechanics, set storage and cycle validation, search, limits —
  SPEC-009.
- Artifact store internals: upload RPC, GC, fetch frames — SPEC-010.
- Agent process model, scheduler machinery, digest chokepoint implementation,
  self-update flow — SPEC-013.
- Sealed-secret formats and the LPS/LUKS/temp-password server flows —
  SPEC-015.
- Dispatch transport and pending-command delivery — SPEC-012.
- Deployment E2E gates and release provenance — SPEC-017.
