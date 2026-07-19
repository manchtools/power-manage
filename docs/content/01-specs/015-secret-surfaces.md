---
title: "SPEC-015 — Secret Surfaces"
---
# SPEC-015 — Secret Surfaces

Status: READY FOR IMPLEMENTATION
Builds on: SPEC-006 (pki-and-identity), SPEC-009 (crud-kernel-search-and-domains), SPEC-013 (agent-core)
Enables: SPEC-017
Module(s): server, agent

## 1. Scope

The normative inventory of every secret-bearing product surface and its transport,
storage, retrieval, and audit discipline: the local password solution (LPS), LUKS
key escrow, temporary user passwords, the sealed-transport surface registry and its
key lifecycles, at-rest `enc:v1` encryption, secret-read auditing, the accepted
device-group scope pierce, and the global secret-hygiene invariants. The sealed
envelope's cryptographic definition lives in the wire contract (WIRE-23..25,
SPEC-003); this spec defines WHICH surfaces use it and how their keys live and die.

## 2. Context capsule

Minimum prior knowledge, restated:

- The gateway is assumed compromised (actor 4, SPEC-001): it can read, modify,
  replay, or drop anything transiting it. Sealed transport exists so the worst a
  relay compromise yields against secrets is denial of service, never disclosure.
- The control-plane administrator is TRUSTED (actor 3, SPEC-001). The control for
  admin actions is audit and attribution, never admin-proofing.
- Sealed envelope (WIRE-23..25, SPEC-003): X25519 + HKDF-SHA256 + AES-256-GCM with
  a MANDATORY versioned domain-info string and MANDATORY context binding. Empty key
  material and empty plaintext are rejected symmetrically at seal AND open.
- One AEAD implementation surface (SDK-13, SDK-14, SPEC-004): `SealWithAAD` /
  `OpenWithAAD` with mandatory non-empty AAD; no nil-AAD API exists; constant-time
  compares; `crypto/rand` only; hash/MAC preimages length-prefixed and
  domain-separated.
- Every control→agent surface is a CA-signed `SignedCommand` with freshness
  (WIRE-14/15, SPEC-003); everything the agent treats as server-authoritative
  configuration — including the LPS sealing public key — arrives inside signed
  material (WIRE-17, SPEC-003). Device-originated reports are device-signed
  (WIRE-20/21, SPEC-003).
- The agent runs luksd, a transient local daemon for interactive user-passphrase
  enrollment (AG-19, SPEC-013): one-shot token, server-authoritative policy, local
  reuse check by hash, the user passphrase never leaves the device.
- Authorization scope lives on the grant (AUTHZ-3, SPEC-008); secret-retrieval
  permissions are device-scope-confinable. Object-scope READ is transitive
  (recorded decision — do not tighten).
- Secret-returning reads emit their own audit events, including denial events
  (AUD-2, SPEC-011); on-read redaction is schema-dispatched from the real emit path
  (AUD-3, SPEC-011).
- Every state change is an event; projections rebuild 1:1 (ES-2, SPEC-005).
  `user_encryption_keys` is the sanctioned non-replay exception so crypto-shred is
  real deletion (ES-1, SPEC-005).

## 3. Requirements

### 3.1 Secret-surface inventory [SEC-1]

Every secret in the product is exactly one of the classes below. A new
secret-bearing surface MUST be added to this table (and to the guards in §7) in
the same change that introduces it.

| Secret | Origin | Transport | At rest | Read path |
|---|---|---|---|---|
| LPS rotated local passwords | Agent | Sealed envelope, device→control | `enc:v1`, row-bound AAD | B1 only, audited per read |
| LUKS passphrases (bootstrap + managed slot) | Agent | Sealed envelope, device→control | `enc:v1`, row-bound AAD | B1 only, audited per read |
| USER temporary passwords | Agent | Sealed envelope, device→control | `enc:v1`, row-bound AAD | B1 only, audited per read |
| luksd user passphrase | Device user | NEVER transmitted (local slot only; reuse check by local hash) | Agent-local LUKS slot | none (no server copy exists) |
| Terminal recordings | Gateway stream | Serialized chunks on the control stream | Sealed `enc:v1` ciphertext in the artifact store (AUD-8, SPEC-011; ART-4, SPEC-010) | Scoped permission, audited per read |
| Encrypted audit archives | Control | — | Ciphertext event batches in the artifact store (AUD-4, SPEC-011) | Restore tooling |
| IdP client secrets, other server-held credentials | Operator config | B1 (TLS+JWT) | `enc:v1`, row-bound AAD | Never returned after write |
| Per-user DEKs | Control | — | `user_encryption_keys` (KEK-wrapped, non-replay) | Internal only (SPEC-011) |
| Registration/enrollment tokens | Control | Stdin or `--token-file` only (AG-17, SPEC-013) | SHA-256 hash | Shown once at mint |
| SCIM bearer tokens | Control | — | bcrypt hash (AUTH-7, SPEC-007) | Shown once at mint |
| API tokens (PATs), refresh tokens | Control | — | Hashed (AUTH-9, SPEC-007) | Shown once at mint |
| WIFI PSK / EAP-TLS key material | Operator | Sealed device-directed inline fields inside the signed command (see [SEC-11]) | `enc:v1` mandate + AUD-3 redaction | Never returned after write |

Secrets stored as hashes are compared in constant time and are never
recoverable; secrets stored as `enc:v1` ciphertext are recoverable only through
their defined read path.

### 3.2 Sealed-transport surface registry [SEC-2]

The envelope of (WIRE-23, SPEC-003) is used by exactly these flows:

| Flow | Direction | Domain info | Context binding |
|---|---|---|---|
| LPS password escrow | device→control | `power-manage-lps-password:v1` | device \| action \| username |
| LUKS passphrase escrow | device→control | `power-manage-luks-passphrase:v1` | device \| action |
| USER temporary password escrow | device→control | `power-manage-user-temp-password:v1` | device \| action \| username |
| Inline action-field secrets (WIFI PSK, EAP-TLS key material) | control→device | `power-manage-action-field-secret:v1` | device \| action \| field |

Rules:

- Every sealed surface has its OWN versioned domain-info string; domain strings
  are pairwise non-interchangeable (a blob sealed under one domain fails to open
  under any other).
- Context binding is verified at open: a blob presented for a (device, action,
  username) tuple other than the one it was sealed for fails to open. Blob
  swapping across devices, actions, or accounts is therefore an integrity
  failure, not a data leak.
- Adding a sealed surface requires: a new domain string, a context tuple, a seal
  site, a fail-closed open site, and a registry entry — the §7 domain-isolation
  guard discovers all of them.
- The relay sees only opaque blobs (WIRE-24, SPEC-003). No gateway-proxied secret
  RPC carries plaintext in either direction; control unseals only at its own
  edge. Admin retrieval runs over B1 (TLS + JWT) and never touches the gateway.

### 3.3 Control sealing-key lifecycle [SEC-3]

- Control holds ONE X25519 sealing keypair, minted at setup from `crypto/rand`.
  The private key never leaves control and is never logged, exported, or copied
  to the gateway.
- The public key reaches agents ONLY inside CA-signed material: the `lps-pubkey`
  command type and/or signed sync-manifest fields (WIRE-17, SPEC-003). An agent
  seals exclusively to a CA-verified key.
- An agent that holds NO verified sealing key FAILS any operation that would
  produce a secret (seal-before-set, [SEC-5]) — it never sends plaintext, never
  skips escrow silently, and never proceeds on an unverified key.
- Key replacement is delivered through the same signed channel. Control retains
  a superseded private key until no unshipped sealed blob can remain in any
  agent's offline buffer (bounded by the agent buffer age ceiling, AG-10,
  SPEC-013), then destroys it. Blobs sealed to a destroyed key are a structured
  ingest error, never a silent drop.

### 3.4 Escrow ingest discipline [SEC-4]

On receiving a sealed device secret, control — in order, each step fail-closed:

1. Verifies the device-signed report envelope and resolves the report to the
   signing device's own outstanding work (WIRE-20/21, SPEC-003).
2. Opens the sealed blob at its own edge, verifying domain and context binding
   against the claimed (device, action, username).
3. Re-seals the plaintext under `enc:v1` with AAD binding the ciphertext to its
   owner row identity.
4. Appends the escrow event whose payload carries the `enc:v1` CIPHERTEXT —
   plaintext never lands in an event, a log, or an error (INV-7, SPEC-000).

Any step failing rejects the report with a static error and logs the drop.
Plaintext exists in control's memory only between steps 2 and 3.

### 3.5 LPS — local password solution [SEC-5]

- LPS manages ANY local account, root included — intended parity with the
  Windows local-administrator-password-solution model. The safeguard is
  DOCUMENTATION, not an account allowlist (recorded decision — do not add an
  account-class guard).
- Parameters (validated per WIRE-2, SPEC-003): target usernames, password length
  8–128, charset class, rotation interval 1–365 days.
- Rotation: the agent generates the password locally from CSPRNG material per
  the length/charset parameters, then **seal-before-set, fail-closed**: the
  password is sealed to control's verified key BEFORE the account is changed.
  Sealing failure (no verified key, seal error) aborts the rotation with the old
  password intact. The sealed blob rides the signed result path and buffers in
  the agent's local store while offline.
- Login-triggered grace rotation: session detection via the SDK `sessions`
  capability (systemd-logind). Absent logind, grace rotation resolves as a
  structured NOT_APPLICABLE outcome — never a silent skip.
- When rotation must displace a live session: 60-second user notice, then
  session kill.
- `ABSENT` clears rotation state on the device and KEEPS the last escrowed
  passwords server-side (an operator who removes LPS does not lose access to the
  final credential).
- Retrieval: a device-scope-confinable permission; every read emits an audit
  event, including denials (AUD-2, SPEC-011).

### 3.6 LUKS key escrow [SEC-6]

- Bootstrap: the pre-shared bootstrap credential admits the agent to the volume
  for its FIRST managed rotation and is consumed and wiped after that rotation
  succeeds.
- Managed slot: a word-passphrase slot rotated on schedule. The new passphrase
  is **server-round-trip-verified** — confirmed escrowed at control — BEFORE the
  old slot is wiped. A rotation that cannot complete the round trip (offline,
  ingest failure) defers and leaves the old slot intact; escrow durability
  strictly precedes local destruction.
- Optional device-bound key: TPM2 (PCRs 7+14, best-effort) or a USER_PASSPHRASE
  slot enrolled interactively via luksd (AG-19, SPEC-013). The user passphrase
  is NEVER sent to the server; reuse is checked by local hash only.
- `luks-revoke` is a SignedCommand type under the instant-command freshness
  window (WIRE-15, SPEC-003).
- `ABSENT` removes agent-side state only; escrowed passphrases are retained.
- Retrieval: B1 only, device-scope-confinable permission, one audit event per
  read including denials.

### 3.7 At-rest encryption [SEC-7]

- ONE at-rest AEAD format: `enc:v1` (AES-256-GCM), AAD binding every ciphertext
  to its owner row identity — moving a ciphertext to another row, table, or
  owner fails open() (INV-8, SPEC-000).
- Encryption at rest is MANDATORY. No plaintext fallback, no opt-out
  configuration of any kind (recorded decision — do not re-add an opt-out knob).
  A missing or unloadable encryption key is a boot failure, never a
  degraded-plaintext mode.
- PII fields (`pii`-tagged) are envelope-encrypted under per-user DEKs; DEKs
  live KEK-wrapped in `user_encryption_keys`, outside replay; crypto-shred
  semantics are owned by (AUD-4, SPEC-011). PII sealing fails CLOSED when the
  sealer is absent.
- At-rest key rotation is a FIRST-CLASS migration tool that re-wraps/re-encrypts
  in place — never a hand-written script (see also OPS-8, SPEC-016).

### 3.8 Secret-read auditing [SEC-8]

Applies AUD-2 (SPEC-011) to every escrow surface: every read of an escrowed
secret (LPS password view, LUKS passphrase view) emits exactly ONE audit event
per call; denied attempts emit their own `*ViewDenied` events; audit payloads
carry ZERO secret material. Secret-returning RPCs never batch multiple secrets
into one audit event.

### 3.9 Accepted scope pierce [SEC-9]

A principal holding a device-group-scoped secret-read grant over a DYNAMIC group
gains read of LPS/LUKS secrets for any device an administrator labels into that
group's query. This label→dynamic-group pierce is ACCEPTED BY DESIGN: labels are
admin-controlled and the admin is trusted (actor 3). Do not add label-change
controls, group-freeze modes, or secret-specific scope tightening for this; the
control is the audit trail (label changes and secret reads are both evented).

### 3.10 Secret hygiene invariants [SEC-10]

Applies to every surface in [SEC-1]:

- No plaintext secret in logs, audit payloads, RPC error messages, URLs or query
  parameters, argv, or child environment (curated env allowlist — AG-14,
  SPEC-013; SDK-4, SPEC-004).
- Errors touching secret paths are static and non-oracular (WIRE-7, SPEC-003).
- Tokens are hashed at rest, always; hash comparisons are constant-time.
- File-or-stdin indirection everywhere a secret enters the system: secrets are
  never config VALUES (file-path indirection only — INV-18, SPEC-002) and never
  argv (enrollment token via stdin or `--token-file` only — AG-17, SPEC-013).
- The AUD-3 redaction schema (SPEC-011) is the canonical enumeration of
  secret-bearing payload fields; a secret-bearing field without a redaction
  schema fails the sweep.
- Documentation claims about the algorithms in use are doc-anchored and checked,
  so an algorithm-name drift between docs and code fails the gate.

### 3.11 Inline secret-bearing action fields [SEC-11]

WIFI PSK and EAP-TLS key material remain bounded inline FIELDS of the action
shape (ART-2, SPEC-010): they are validated, diffed, and redacted as fields, and
content-addressing them by plain SHA-256 would leak content equality across
devices. Their normative handling: `validate`-tagged at the boundary, covered by
the `enc:v1` at-rest mandate, enumerated in the AUD-3 redaction schema, written
by the agent with mode 0600, and delivered inside the CA-signed command over the
B4/B6 mTLS seams.

The rule of (WIRE-24, SPEC-003) is unqualified — no plaintext secret ever
transits the gateway in either direction — so these fields transit SEALED,
device-directed, inside the signed command:

- At enrollment, and again at every certificate renewal, the agent generates an
  X25519 sealing keypair beside its mTLS key and submits the public key with
  the CSR; control stores it on the device record, bound to the certificate
  identity (PKI-2, SPEC-006). The private key never leaves the device and
  follows the same custody rules as the mTLS key (0600, root).
- Control seals the enumerated fields at dispatch-mint time — commands are
  already minted and signed per device, so per-device sealing adds no new
  fan-out path — under the `power-manage-action-field-secret:v1` domain with
  device | action | field context binding ([SEC-2]).
- The gateway relays opaque ciphertext. The agent unseals at apply time, after
  command signature verification, and only in memory — the sealed form is what
  persists in the agent's action buffer.
- A dispatch sealed to a superseded device key fails to open, fails the action
  honestly, and self-heals on re-dispatch: control always seals to the
  currently registered key, and key rotation is atomic on the device record at
  renewal.
- At rest on control these fields remain under the `enc:v1` mandate ([SEC-7]) —
  control must re-seal them for future dispatches, so device-directed sealing
  replaces nothing at rest.
- Per-device ciphertext also removes the cross-device content-equality leak
  that ruled out content-addressing these fields (ART-2, SPEC-010).

## 4. Acceptance criteria

- **AC-1** A blob sealed under one registered domain string fails to open under
  every other registered domain string (pairwise, over the discovered registry).
- **AC-2** A sealed blob presented with a context tuple differing in device,
  action, OR username fails to open; the ingest path rejects and logs the drop.
- **AC-3** Sealing with empty key material or empty plaintext fails at seal;
  opening with empty key material or empty ciphertext fails at open.
- **AC-4** An agent with no CA-verified sealing key fails an LPS rotation
  without changing the account password, and fails a USER temp-password flow
  without setting the password.
- **AC-5** LPS rotation escrows before it sets: a forced seal failure leaves the
  account password unchanged; a forced set failure after successful sealing
  fails the action honestly (no silent success).
- **AC-6** LPS `ABSENT` clears device rotation state; the last escrowed password
  remains retrievable server-side.
- **AC-7** LPS grace rotation without logind resolves NOT_APPLICABLE as a
  structured outcome, never silent success.
- **AC-8** LUKS managed-slot rotation wipes the old slot ONLY after control
  confirms escrow; a blocked round trip leaves the old slot intact and defers.
- **AC-9** The LUKS bootstrap credential is unusable and wiped after the first
  successful managed rotation.
- **AC-10** Escrow ingest verifies the device signature and work resolution
  BEFORE opening the blob; a report about another device's work is dropped and
  logged (zero rows → drop, WIRE-21).
- **AC-11** Escrow event payloads contain `enc:v1` ciphertext only; a scan of
  every escrow event payload finds zero plaintext secret material; swapping an
  `enc:v1` ciphertext onto another owner row fails open().
- **AC-12** Every LPS/LUKS read emits exactly one audit event; a denied read
  emits a denial event; audit payloads contain no secret material.
- **AC-13** A device-group-scoped grant reads secrets for devices labeled into
  the group's dynamic query (pierce accepted); an out-of-scope read returns
  NotFound plus a denial audit event.
- **AC-14** No secret appears in logs, error strings, URLs, argv, or child env
  across the surfaces in [SEC-1], demonstrated by the §7 guards' liveness
  fixtures.
- **AC-15** Boot with a missing at-rest encryption key fails; no code path
  writes a classified secret column in plaintext.
- **AC-16** A WIFI dispatch captured at the gateway contains no plaintext PSK
  or EAP-TLS key material; the agent unseals and applies it; an agent whose
  sealing keypair does not match the registered public key fails the action
  with no partial profile write.

## 5. Rejection paths

| Input / state | Required behavior |
|---|---|
| Sealed blob with wrong domain string | Open fails; ingest rejects; static error |
| Sealed blob with mismatched context tuple | Open fails; drop + log; no partial state |
| Empty key material or empty plaintext/ciphertext at seal/open | Symmetric rejection (WIRE-25, SPEC-003) |
| Agent has no CA-verified sealing public key | Secret-producing operation fails closed; account state unchanged |
| Sealing key delivered outside signed material | Agent refuses the key (WIRE-17, SPEC-003) |
| Inline action-field secret sealed to a superseded device key | Unseal fails; action fails honestly; re-dispatch under the current key succeeds |
| Escrow report fails device-signature verification | Reject before opening; drop + log |
| Escrow report resolves to zero rows for the signing device | Drop + log (WIRE-21, SPEC-003) |
| LUKS round-trip confirmation absent at rotation | Old slot NOT wiped; rotation defers |
| luksd one-shot token reuse | Refused (AG-19, SPEC-013) |
| Secret read without permission / out of scope | NotFound; `*ViewDenied` audit event |
| Plaintext secret field on a gateway-proxied secret RPC | Contract violation; §7 descriptor guard fails the build |
| Secret-bearing payload field without a redaction schema | AUD-3 sweep fails the build |
| At-rest encryption key absent at boot | Boot failure; never a plaintext mode |
| `enc:v1` ciphertext decode/auth failure on read | Error to caller; never empty-secret success (INV-1, SPEC-000) |
| Secret offered as a config value or argv token | Loader/CLI refuses (INV-18, SPEC-002; AG-17, SPEC-013) |

## 6. Test plan (TDD)

Server-side tests run against REAL Postgres (testcontainer, template-cloned per
test) through REAL handlers; agent-side tests use the SDK seams (FakeRunner,
injected clocks/keys) with real crypto — never mocked crypto. Every test is
confirmed RED via a scoped neutralizing edit first.

1. **Envelope surface tests**: domain pairwise isolation over the discovered
   registry (AC-1); context-binding mismatch matrix — device, action, username
   each varied independently (AC-2); empty-material symmetry (AC-3).
2. **Key-lifecycle tests**: unverified/absent sealing key fails closed (AC-4);
   key replacement over signed delivery; superseded-key retention window;
   destroyed-key blob → structured ingest error.
3. **LPS tests**: seal-before-set ordering under forced seal failure and forced
   set failure (AC-5); ABSENT retention (AC-6); logind-absent NOT_APPLICABLE
   (AC-7); grace-rotation session kill after notice interval (injected clock).
4. **LUKS tests**: round-trip-before-wipe under blocked ingest (AC-8);
   bootstrap consume+wipe (AC-9); `luks-revoke` freshness rejection past expiry.
5. **Ingest tests**: signature-then-resolve-then-open order, cross-device report
   drop (AC-10); ciphertext-only event payloads and AAD row binding (AC-11).
6. **Read-path tests**: one audit event per read, denial events, zero secret
   material in audit payloads (AC-12); behavioral scope tests including the
   dynamic-group label pierce and out-of-scope NotFound (AC-13) against the
   real DB.
7. **Hygiene tests**: guard liveness fixtures — planted secret in a log line,
   an error string, a URL, argv, and env must each be detected (AC-14); boot
   without encryption key (AC-15).

## 7. Guards

Self-discovering, matches-zero protected (PROC-3, SPEC-000):

| Guard | Discovery source | Fails when |
|---|---|---|
| Sealing-domain registry | Walk of domain-info constants in contract/server/agent | A seal/open site uses an unregistered domain; two surfaces share a domain; zero domains discovered |
| Domain isolation liveness | Same registry | Any registered domain pair is interchangeable at open |
| Gateway-plaintext descriptor walk | Proto descriptors of gateway-transiting services | A secret-classified field (per the AUD-3 enumeration) appears as plaintext on a proxied secret RPC; zero fields classified |
| Redaction-schema sweep | AST walk over all payload structs (AUD-3, SPEC-011) | A secret-bearing field lacks a redaction schema; zero structs swept |
| enc:v1 write-path scan | AST scan over server store code | A secret-classified column is written outside the AEAD surface; zero writes discovered |
| Read-audit parity | Secret-returning RPCs discovered from the permission catalog | An RPC returns escrowed secret material without a view + denied emit site; zero RPCs discovered |
| Hygiene liveness fixtures | Planted-violation fixtures (log/error/URL/argv/env) | Any planted secret survives undetected |
| Seal-API surface | AST scan over crypto call sites | Direct AEAD/HKDF use outside the single SDK crypto surface; zero call sites scanned |

## 8. Historical lessons

Inlined from the predecessor system's operating history:

- **Lesson [SEC-2]:** The predecessor's contract carried a plaintext LUKS
  passphrase through the relay in BOTH directions — a plaintext retrieval
  response and a plaintext store proxy. A compromised gateway could read fleet
  disk credentials. Sealed blobs in both directions is a contract rule, not a
  handler habit.
- **Lesson [SEC-2]:** Sealing APIs accepted empty key material and empty
  plaintext, producing blobs that "opened" meaninglessly. Rejection must be
  symmetric at seal and open.
- **Lesson [SEC-8]:** Secret-revealing read paths shipped without their own
  audit events; escrowed credentials could be viewed without attribution. Every
  read — and every denial — is an event.
- **Lesson [SEC-10]:** On-read redaction was a hand-built type map that drifted
  from the emitters until it redacted nothing that was actually emitted — found
  as a Critical. Redaction is schema-dispatched from the REAL emit path, and an
  AST sweep fails on any secret-bearing field without a schema.
- **Lesson [SEC-7]:** PII sealing silently no-opped when the sealer was absent,
  writing plaintext PII. Fail closed: absent sealer is an error, never a
  pass-through.
- **Lesson [SEC-10]:** An enrollment token passed as an argv flag landed in
  shell history and process listings for its whole validity window. Token
  intake is stdin or `--token-file` only, everywhere.
- **Lesson [SEC-10]:** Documentation claimed a different hash algorithm than
  the code used; nothing failed. Algorithm claims in docs are anchored to code
  and checked.
- **Lesson [SEC-6]:** A key-file scrub helper followed symlinks and operated on
  non-regular files. Scrub refuses non-regular files and opens
  `O_WRONLY|O_NOFOLLOW|O_NONBLOCK` (AG-19, SPEC-013).

## 9. Milestones

Each milestone is one implementation session ending green.

1. **M1 — Sealed-surface registry + key lifecycle**: domain registry, control
   X25519 keypair at setup, CA-signed public-key delivery, agent-side verified
   key store, fail-closed no-key behavior. Tests: AC-1..4. Guards: domain
   registry + isolation liveness.
2. **M2 — Escrow ingest + at-rest storage**: signature→resolve→open→re-seal
   pipeline, escrow events with ciphertext payloads, AAD row binding, boot-time
   key requirement. Tests: AC-10, AC-11, AC-15.
3. **M3 — LPS end-to-end**: rotation flow with seal-before-set, grace rotation
   via `sessions`, notice + session kill, ABSENT retention. Tests: AC-5..7.
4. **M4 — LUKS escrow end-to-end**: bootstrap consume, round-trip-verified
   rotation, `luks-revoke`, ABSENT semantics. Tests: AC-8, AC-9.
5. **M5 — Read paths + hygiene**: retrieval RPCs with per-read audit and denial
   events, behavioral scope tests incl. the pierce, remaining guards and
   liveness fixtures. Tests: AC-12..14.

## 10. Out of scope

- The sealed envelope's cryptographic construction and proto shapes — SPEC-003;
  the AEAD implementation surface — SPEC-004.
- luksd process lifecycle, socket handling, and tty gating — SPEC-013.
- Action-catalog semantics of `LPS`, `ENCRYPTION`, and `USER` beyond their
  secret flows (scheduling, desired state, results) — SPEC-014.
- Audit substrate, redaction schema mechanics, crypto-shred, retention — 
  SPEC-011.
- Enrollment/registration token minting and consumption — SPEC-006.
- Session tokens, PAT semantics — SPEC-007.
- Backup interaction with crypto-shredded DEKs — SPEC-016.
