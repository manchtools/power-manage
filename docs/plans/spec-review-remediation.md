# Specification review remediation

Governing specifications: SPEC-000 AC-1/AC-3/AC-5, SPEC-001 AC-6,
SPEC-003 AC-6/AC-13/AC-14, SPEC-004 AC-13, and the status ledger.

## 1. Overview

Repair the compliance gaps found in the 2026-07-21 specification review so a
green gate and an `Implemented` ledger entry describe their actual scope. The
change keeps the existing architecture and dependencies: it tightens three
security boundaries, makes verification failure-safe and reproducible, and
removes misleading or contradictory documentation.

## 2. Acceptance criteria

1. Given the status ledger, when a reader inspects an implemented spec, then
   deferred cross-spec obligations and dormant guards are explicit, and the
   individual spec header points to the ledger instead of claiming a second
   status.
2. Given SPEC-003 through SPEC-016, when the architecture guard discovers the
   specs, then every spec names at least one defended actor before its rejection
   table; zero discovered specs or a missing actor fails the test.
3. Given INV-3, when invariant coverage is evaluated, then SPEC-006 is its owner
   and no ownerless exemption exists; the guard becomes mandatory when SPEC-006
   is implemented.
4. Given repository documentation, when `docref check` runs, then at least one
   approved behavioral claim exists and every reference is current; deleting
   all references or introducing drift fails `scripts/verify.sh`.
5. Given committed generated code, when Buf generation fails or produces a
   difference, then verification fails without changing `contract/gen`; matching
   generation succeeds.
6. Given CI, when verification tools are installed, then repository-pinned Buf,
   staticcheck, and docref versions are used instead of floating releases.
7. Given the SDK fetch boundary, when a URL contains userinfo, then it is
   rejected before network or DNS activity. Query-bearing HTTPS URLs remain
   accepted, and their query and fragment remain sanitized in every error.
8. Given command-signing key material, when it is validated, then only ECDSA
   P-256/P-384/P-521 or RSA keys of at least 2048 bits are accepted; nil,
   Ed25519, other curves, and undersized RSA keys are rejected.
9. Given a signed command, when `issued_at` is more than five minutes after the
   verifier's injected clock, then verification rejects it; timestamps within
   that skew remain accepted and existing expiry/window checks still apply.
10. Given contributor documentation, when a developer follows it, then it does
    not request `buf breaking` and does not present unimplemented server/agent
    build targets as currently available.
11. Given the repository guard doctrine, when a guard's owning code does not yet
    exist, then a surfaced dormant skip is permitted only while its violation
    fixture remains active; once applicable subjects exist, matching zero fails.

## 3. Out of scope

- Implementing SPEC-004 M6/M7 or starting SPEC-005; those are product
  milestones, not review remediation.
- Code-audit issues #25–#29: fsafe symlink TOCTOU, escalated-ReadFile parity,
  contract domain-map completeness, GroupList validation, and fetch
  write-before-verify ordering. They remain a separate remediation track;
  completing this plan does not declare the implementation code-clean.
- Creating server or agent boot paths solely to make future guards appear live.
- Adding dependencies or configuration knobs.
- Changing the recorded clean-break protobuf policy.

## 4. Technical design

- Extend existing Go guard tests for actor discovery and invariant ownership.
- Configure the already-installed `docref` CLI, add a small initial set of
  claims for implemented behavior, and add strict/non-vacuous checks to the
  existing verification script and its self-test.
- Generate protobuf output under `mktemp -d` and compare its `gen` tree with the
  committed tree; never regenerate in place during verification.
- Pin current working CI tool versions directly in the workflow.
- Add boundary checks to the existing fetch and signing/freshness chokepoints;
  no new helper layer or dependency.
- Mechanically reconcile the ledger, spec headers, README, contributor rules,
  and the affected requirements/rejection tables.

Affected implementation files are limited to `scripts/verify.sh` and its test,
the existing guard suite, `sdk/fetch`, `contract/sign`, CI configuration, and
the directly governing documentation.

## 5. Security considerations

- URL userinfo is rejected, matching the repository's existing URL validators.
  Presigned artifact and checksum query parameters remain supported, and their
  raw values are stripped from every error.
- Weak or unintended signing-key profiles fail closed at the shared key
  validation chokepoint.
- A bounded five-minute skew accommodates real clocks without accepting
  arbitrarily future-dated work.
- No secret value is included in errors or test output.
- Generated sources remain intact even when external code generation fails.

## 6. Test requirements

| Acceptance criterion | Red-first automated check |
|---|---|
| AC-1, AC-10, AC-11 | Documentation/guard tests reject stale status semantics, contradictory Buf guidance, and an unsurfaced dormant guard |
| AC-2 | Actor guard fixture omits an actor and is rejected; the real SPEC-003..016 set is non-empty and passes only after missing declarations are added |
| AC-3 | Invariant coverage fails after removing INV-3's owner and contains no ownerless exemption |
| AC-4 | Verification self-test supplies zero refs and a stale ref; both fail, while current claims pass |
| AC-5 | Fake Buf deletes/writes its output and exits nonzero; committed fixture output remains byte-identical |
| AC-6 | Workflow test or convention assertion rejects `@latest` for verification tools |
| AC-7 | Fetch tests cover plain and query-bearing URLs with and without an inline pin, query redaction on errors, userinfo rejection, and proof that the network seam is not called for userinfo |
| AC-8 | Signing tests cover every accepted curve plus P-224, 1024-bit RSA, Ed25519, nil, and typed-nil rejection |
| AC-9 | Verification tests cover now, exactly +5 minutes, beyond +5 minutes, and expired/malformed windows |

Each behavior-changing test is observed red against the pre-fix implementation
before the smallest shared-boundary fix is applied.

## 7. Rejection paths

| Input / state | Observable result | Client message / logged context |
|---|---|---|
| Missing/stale/zero docref claims | Verification exits nonzero | Static gate message; no document contents logged |
| Buf generation error or diff | Verification exits nonzero; committed `gen` unchanged | Tool error or concise out-of-sync message |
| Spec without defended actor | Guard test fails | Spec path only |
| Fetch URL with userinfo | Error before transport | Sanitized URL without userinfo/query |
| Presigned artifact/checksum fetch fails | Normal sanitized fetch error | URL without userinfo/query/fragment |
| Unsupported/weak signing key | Validation error | Key family/profile only; no key material |
| Command issued beyond allowed skew | Verification error | Timestamp relationship only; no payload |
| Dormant guard after subjects exist | Guard test fails | Guard name and discovered floor |

## 8. Approval checkpoint

Implementation starts only after operator approval of the three material policy
choices in AC-7 through AC-9 and the remediation scope above.
