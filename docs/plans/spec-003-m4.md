# SPEC-003 M4 — Identity + results + sealing + manifest

Milestone: SPEC-003 §9 M4. Builds on M3 (SignedCommand + contract/sign,
PR #16). Delta only; the spec is authoritative. Trust-boundary milestone
(envelope/sealing): failing tests authored by the test-writer lane first.

## Scope

SPIFFE/CN certificate-profile constants ([WIRE-18]), the `DeviceSigned`
envelope + helpers ([WIRE-20], AC-7), sealed-transport message shapes and
info-string constants ([WIRE-23], SEC-11, AC-8 — crypto lives in `sdk`, §2),
the sync-manifest message with `(epoch, generation)` monotonicity
([WIRE-26/27], AC-9).

## Recorded mechanical choices

1. **Three new proto files**, one concern each (M1–M3 pattern):
   `device_signed.proto`, `sealed.proto`, `sync_manifest.proto`.
   G-1/G-2 file floors rise 9 → 12.
2. **DeviceSigned shape.** `{ bytes payload = 1 (min_len 1); string
   result_type = 2; string device_id = 3 (ULID rule); Timestamp issued_at =
   4 (required); bytes signature = 5 (min_len 1) }`. [WIRE-20] names the
   covered content (payload, device ULID, issued_at, signature by the
   enrolled key); `result_type` is carried because the domain
   `"power-manage:result:" + type + ":v1"` derives from it — the framing
   mirror of SignedCommand's command_type. No expires_at: results are
   records, not commands; staleness policy is control-side (SPEC-005/007).
3. **Result-type set is OPEN at M4 (recorded ceiling).** Unlike §3.4's
   explicit 8-type command list, the spec names report families only in
   prose; the closed set arrives with M5's stream frames. `ResultDomain`
   accepts a grammar-checked token (`[a-z0-9-]+`, non-empty, fail-closed
   otherwise); per-type `*SignatureDomain` result constants and their G-5
   exact-set registration arm at M5. G-5's discovered set stays 8 until
   then.
4. **Result helpers in `contract/sign`** (same §2 allocation as commands):
   `ResultDomain(resultType) (string, error)`,
   `ResultPreimage(env) ([]byte, error)` — framing mirrors plan-003-m3
   choice 5: `lp(domain) || lp(result_type) || lp(device_id) ||
   lp(ts(issued_at)) || lp(payload)`, golden-pinned;
   `SignResult(key crypto.Signer, env) error`;
   `VerifyResult(pub, env, opts ResultVerifyOptions) ([]byte, error)` with
   `ResultVerifyOptions{DeviceID string}` — the caller resolves the claimed
   reporter to its DER-derived registered key (PKI-4; resolution itself is
   SPEC-006/007) and states which device it expects; checks fail-closed:
   key valid (shared ValidateSigningKey) → grammar/domain → device_id is a
   ULID and equals opts.DeviceID → payload non-empty → signature. Returns a
   copy of the exact verified bytes.
5. **Sealed shapes in `sealed.proto`, constants in new Go package
   `contract/seal`.** `SealedBlob { bytes ciphertext = 1 (min_len 1);
   bytes ephemeral_public_key = 2 (len 32, X25519); string info = 3 (in
   the closed info set); string context = 4 (min_len 1) }` — the AC-8
   fields. Info constants: `LpsPasswordSealInfo =
   "power-manage-lps-password:v1"`, `LuksPassphraseSealInfo =
   "power-manage-luks-passphrase:v1"`, `ActionFieldSecretSealInfo =
   "power-manage-action-field-secret:v1"` (SEC-11, recorded operator
   decision 2026-07-19). No seal/open code in contract (AC-8); `sdk`
   cannot import contract (SDK-0), so its seal/open takes info/context as
   parameters and agent/server pass these constants.
6. **Identity constants in new Go package `contract/identity`.**
   `SPIFFETrustDomain = "power-manage"`, class URIs
   `AgentSPIFFEURI/GatewaySPIFFEURI/ControlSPIFFEURI =
   "spiffe://power-manage/{agent|gateway|control}"` ([WIRE-18]: URI SAN =
   class, CN = instance ULID, DNS SAN = server name only — profile
   constants only; parsing/enforcement is SPEC-006/007).
7. **SyncManifest shape.** `{ uint64 epoch = 1; uint64 generation = 2;
   Timestamp issued_at = 3 (required); Timestamp expires_at = 4
   (required); repeated Occurrence occurrences = 5; repeated
   MaintenanceWindow maintenance_windows = 6; Intervals intervals = 7
   (required — [WIRE-26]: every manifest carries server-set intervals, and
   an absent message field is not an empty one; review finding, PR #17) }`;
   epoch/generation and the repeated fields stay deliberately untagged:
   their validity is relational (`manifest.Newer` against agent state) or
   legitimately empty (removal-by-omission) — M5 resolves their tagging
   when the manifest becomes G-1-reachable.
   `Occurrence { string assignment_id = 1 (ULID); string action_id = 2
   (ULID); string cron_schedule = 3 (max_len 100); uint64
   interval_seconds = 4 }` (ASG-1: optional cron OR interval; both-empty =
   unscheduled/immediate); `MaintenanceWindow { repeated DayOfWeek days =
   1 (defined_only + not_in 0); uint32 start_minute = 2 (lte 1439); uint32
   end_minute = 3 (lte 1439) }` (WIRE-8 typed, midnight-crossing allowed so
   start > end is legal); `Intervals { uint64 sync_seconds = 1 (gte 1);
   uint64 inventory_seconds = 2 (gte 1) }` ([WIRE-17/26] server-set
   intervals). New enum `DayOfWeek` (UNSPECIFIED=0, MONDAY=1..SUNDAY=7) —
   the first real contract enum; the enum-bounds guard's real-contract
   vacuity ceiling (plan-003-m2 choice 4) retires when reachability
   arrives at M5. The manifest carries occurrence KEYS; action content
   rides the signed assignment envelopes ([WIRE-15] durable class).
8. **Removal-by-omission is schema-observable (AC-9).** The manifest
   subtree carries no removal/deletion vocabulary: a descriptor walk over
   the SyncManifest closure asserts no field name contains
   remove/delete/tombstone/revoke — the never-check that keeps
   removal-by-omission the sole cleanup authority.
9. **Monotonicity helper in new Go package `contract/manifest`.**
   `Newer(epoch, generation, lastEpoch, lastGeneration uint64) bool` —
   strict lexicographic; equal pairs are NOT newer (AC-9 "≤ the last
   accepted pair is rejected"). Property test over generated sequences.
   The ≤15-min validity window ([WIRE-26]) is issuer policy enforced at
   verification via the existing instant-window mechanics when the
   manifest rides its `sync-manifest` SignedCommand (M3 helper); no second
   freshness implementation.
10. **The 15-min window note.** WIRE-26's "≤15-min validity" is satisfied
    by the manifest traveling as the `sync-manifest` command payload with
    Instant=true at the chokepoint (SPEC-013); contract adds no
    manifest-local expiry logic beyond the required timestamps.

## Files

- `contract/proto/powermanage/v1/device_signed.proto` — new (choice 2).
- `contract/proto/powermanage/v1/sealed.proto` — new (choice 5).
- `contract/proto/powermanage/v1/sync_manifest.proto` — new (choice 7).
- `contract/sign/result.go` — new: `ResultDomain`, `ResultPreimage`,
  `SignResult`, `VerifyResult`, `ResultVerifyOptions` (choices 3–4).
- `contract/sign/result_test.go` — test-writer: golden result preimage,
  AC-7 round-trip + forged-key + cross-device + tamper matrix, grammar
  fail-closed rows.
- `contract/seal/seal.go` — new: the three info constants + closed set
  (choice 5). `contract/seal/seal_test.go` — test-writer: constant pins,
  closed-set exactness, shape assertions (AC-8).
- `contract/identity/identity.go` — new: profile constants (choice 6).
  `contract/identity/identity_test.go` — test-writer: value pins.
- `contract/manifest/manifest.go` — new: `Newer` (choice 9).
  `contract/manifest/manifest_test.go` — test-writer: AC-9 property test,
  boundary rows (equal pair, epoch rollover precedence, generation reset
  on epoch bump).
- `contract/archtest/guards_test.go` — floors 9 → 12; AC-9 schema
  never-check (choice 8) as `TestGuard_ManifestNoRemovalVerbs` with a
  fixture liveness row.
- `contract/archtest/testdata/fixture/...` — planted removal-verb fixture
  for the liveness row; regenerate fixturepb.
- `contract/gen/**` — regenerated.
- `docs/content/01-specs/00-index.md` — SPEC-003 → In progress (M4 done).

## Test authorship

Trust-boundary milestone: the test-writer agent authors the failing tests
from AC-7/8/9 and choices 2–9 before implementation; observed red for the
right reasons (scoped neutralizing edits, never reverts).
