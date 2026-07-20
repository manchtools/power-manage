# SPEC-003 M3 — SignedCommand

Milestone: SPEC-003 §9 M3. Builds on M2 (registry + action shape, PR #15).
Delta only; the spec is authoritative. Trust-boundary milestone: the failing
tests are authored by the test-writer agent before implementation.

## Scope

The SignedCommand envelope (§3.4 verbatim shape), framing + verification
helpers in `contract` (stdlib crypto — §2 allocation), the signature-domain
constants, freshness rules ([WIRE-15]), Ed25519 boot refusal (AC-14); golden
preimage + tamper matrix (AC-4/AC-6) + G-5 (AC-5) green.

## Recorded mechanical choices

1. **Proto placement.** New `contract/proto/powermanage/v1/signed_command.proto`
   carrying exactly the §3.4 message (field numbers 1–6 as written). G-1/G-2
   file-count floors rise 8 → 9.
2. **Validate tags on the envelope.** `payload` bytes `min_len: 1` ([WIRE-25]
   lesson: empty inputs rejected symmetrically); `command_type` string
   `in: ["action","osquery","logquery","inventory","luks-revoke","lps-pubkey","terminal-grant","sync-manifest"]`
   (the §3.4 comment set, closed — fail-closed on unknown types at the
   boundary as well as in the verifier); `target_device_id` carries the ULID
   rule; `issued_at`/`expires_at` `required`; `signature` bytes `min_len: 1`.
3. **Helper package.** `contract/sign` (import path
   `github.com/manchtools/power-manage/contract/sign`), stdlib crypto only.
   Signer (server) and verifier (agent) share this one implementation.
4. **Domain constants.** Eight exported constants, one per command type,
   named `<Type>SignatureDomain` (G-5's discovery grammar), each equal to
   `"power-manage:cmd:" + type + ":v1"` ([WIRE-14] formula), e.g.
   `ActionSignatureDomain = "power-manage:cmd:action:v1"`. A
   `CommandDomain(commandType string) (string, error)` maps command_type →
   domain and errors on anything outside the closed set (fail-closed; the
   verifier uses it, so an unknown type can never frame a preimage).
5. **Preimage framing.** SHA-256 over length-prefixed, domain-separated
   covered fields, in this order:
   `lp(domain) || lp(command_type) || lp(target_device_id) || lp(ts(issued_at)) || lp(ts(expires_at)) || lp(payload)`
   where `lp(x) = u64be(len(x)) || x` and `ts(t)` is 12 deterministic bytes
   `s64be(seconds) || u32be(nanos)` — no proto marshal inside the preimage.
   Golden tests pin exact preimage bytes and digest.
6. **Algorithms.** ECDSA via `SignASN1`/`VerifyASN1` and RSA PKCS#1 v1.5,
   both over the SHA-256 digest ([WIRE-14]). Key validation
   (`ValidateSigningKey`) accepts only `*ecdsa.PublicKey`/`*rsa.PublicKey`
   (and their signers) and refuses `ed25519` explicitly (AC-14) — the boot
   path and both Sign/Verify call it, so an Ed25519 key can never sign or
   verify.
7. **API shape.** `SignCommand(key crypto.Signer, cmd *SignedCommand) error`
   fills `signature` over the covered fields;
   `VerifyCommand(pub crypto.PublicKey, cmd *SignedCommand, opts VerifyOptions) ([]byte, error)`
   returns the exact verified payload bytes ([WIRE-14]: the caller
   deserializes only what was verified — no second representation).
   `VerifyOptions{DeviceID string; Now time.Time; Instant bool}` — `Now` is
   the clock seam (contract is a leaf; callers pass time), `Instant` is the
   freshness class.
8. **Verifier checks, all fail-closed, in order:** key valid (choice 6) →
   command_type in the closed set → `target_device_id == opts.DeviceID` →
   signature verifies under the type's domain → `issued_at ≤ expires_at` →
   `expires_at ≥ now` → if instant, `expires_at − issued_at ≤ 15 min`
   (`MaxInstantWindow`) → for `terminal-grant`, `expires_at − issued_at ≤
   60 s` unconditionally ([WIRE-16]'s normative "≤60 s expiry"). Any failure
   returns a nil payload.
9. **Freshness classification is caller-supplied.** WHICH commands are
   instant ([WIRE-15]'s list names action semantics like SYNC/REBOOT) is the
   agent chokepoint's decision (SPEC-013); the helper enforces the mechanics.
   The terminal-grant window is the one per-type bound the helper hard-codes,
   because §3.4 fixes it normatively.
10. **G-5 mechanics.** Lives in `contract/archtest` (the sanctioned harness
    module): AST scan over `contract/sign` non-test source discovers
    `*SignatureDomain` constants — floor 8 + exact-set both directions
    against the command-type catalog and the [WIRE-14] formula; then with a
    test ECDSA key, round-trip each domain and run the full pairwise matrix
    (signed under A never verifies under B). Recorded ceiling: INV-6
    cross-repo parity (≥1 sign site AND ≥1 fail-closed verify site per
    domain OUTSIDE contract) arms when SPEC-013's chokepoint lands; at M3
    both sites are `contract/sign` itself.
11. **Golden values.** Preimage bytes/digest are pinned for a fixed envelope;
    the RSA PKCS#1 v1.5 signature (deterministic) is also pinned; ECDSA
    signatures are randomized and only round-trip-verified.

## Files

- `contract/proto/powermanage/v1/signed_command.proto` — new (choice 1, 2).
- `contract/sign/sign.go` — new: domain constants, `CommandDomain`,
  `SignCommand`, `VerifyCommand`, `VerifyOptions`, `ValidateSigningKey`,
  `MaxInstantWindow`, preimage builder (choices 3–9).
- `contract/sign/sign_test.go` — authored by the test-writer agent: golden
  preimage, AC-4 round-trip + tamper matrix (each covered field), AC-6
  rejection matrix (expired, window > 15 min, terminal-grant > 60 s, target
  mismatch, bad signature, unknown command_type, empty payload), AC-14
  Ed25519 refusal on sign, verify, and key-load paths.
- `contract/archtest/guards_test.go` — G-5 (`TestGuard_SignatureDomains`,
  choice 10); G-1/G-2 floors 8 → 9 (test-file change: strengthening only,
  red-checked against the 8-file tree).
- `contract/archtest/` — AST discovery helper for the constant scan
  (choice 10) if the existing harness lacks one.
- `contract/gen/**` — regenerated.
- `docs/content/01-specs/00-index.md` — SPEC-003 → In progress (M3 done).

## Test authorship

Trust-boundary milestone: the test-writer agent authors the failing tests
from AC-4, AC-5, AC-6, AC-14 and choices 5–11 before implementation; each is
observed red for the right reason (scoped neutralizing edits, never reverts).
