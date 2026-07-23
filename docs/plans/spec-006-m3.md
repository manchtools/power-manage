# SPEC-006 M3 — Registration tokens

## Scope

Implement the server-side registration-token lifecycle required by [PKI-2]
and AC-2/AC-3:

- mint a public locator plus a 256-bit random secret;
- persist only `SHA-256(secret)`, never the raw token;
- model mint, consume, and disable as events with an atomic Postgres
  projection and a registered rebuild target;
- authenticate with a constant-time hash comparison;
- consume with expected-version CAS under real concurrency;
- leave network failure limiting to the public handler's independent per-IP
  and per-account ladder; and
- make invalid, malformed, expired, disabled, exhausted, and losing-race
  token failures indistinguishable to the enrollment caller.

The agent enrollment socket and its separate five-per-minute limiter land in
M4 with the socket itself. No PkiService procedure or enrollment handler is
introduced in this milestone.

<!-- docref: begin src=server/internal/store/migrations/005_registration_tokens.sql#@registration-tokens-schema:314937fd -->
The projection schema enforces a canonical token locator, a unique 32-byte
hash, positive and bounded use counts, required expiry, bounded optional-owner
representation, a durable disabled bit, and a positive projection version.
<!-- docref: end -->

## Design decisions

1. **Token wire form.** A token is
   `<canonical-ULID>.<base64url-without-padding-secret>`. The locator permits
   one indexed projection read without storing or searching by the secret.
   The secret is exactly 32 bytes from `crypto/rand`; the ULID uses the current
   48-bit millisecond timestamp plus independent random entropy.
2. **Hash-only durability.** The mint event and projection contain the
   locator, SHA-256 digest, use bound, expiry, optional owner, and disabled
   state. The raw token exists only in the mint return value. Tests inspect
   both `events` and `registration_tokens` to prove the raw token is absent.
3. **Event model.** `RegistrationTokenMinted`,
   `RegistrationTokenConsumed`, and `RegistrationTokenDisabled` share one
   token stream. Their projectors are the only writers of the
   `registration_tokens` projection. The production registry, golden corpus,
   table classification, projection-write guard, and recovery target list all
   expand in the same change.
4. **CAS consumption.** Every consume calls `AppendEventWithVersion` with the
   projection version just authenticated. A conflict is never hidden inside
   the append. When capacity may remain, the service re-reads the projection,
   repeats the hash/state authorization, and submits a new explicit CAS. For a
   one-use token the first conflict observes exhaustion and returns the
   uniform rejection; for `max_uses=N`, N concurrent callers can each claim a
   distinct permitted version and no caller can exceed N. Conflicts use a
   short jittered backoff and a finite retry budget so a caller without its
   own deadline cannot spin forever under sustained contention or corrupt
   projection state.
5. **Disable precedence.** After the constant-time secret check, disabled is
   evaluated before expiry or remaining uses and no consume event is
   attempted. The administrative disable operation is idempotent and retries
   its own fresh CAS after a concurrent consume until the kill switch is
   durable.
6. **Uniform rejection.** Token-state failures return one exported sentinel
   with identical bytes and no token/state detail. Every such path waits until
   the same minimum rejection deadline captured at admission. The clock and
   waiter are injectable in package tests so equality is deterministic rather
   than asserted with flaky wall-clock thresholds. Infrastructure and caller
   cancellation errors remain operational errors.
7. **Rate limiting ownership.** The token component verifies and consumes
   credentials without counting successful uses. The real public handler owns
   the failure-only per-IP and per-account ladder delivered by SPEC-007 M3, so
   repeated failures never lock out a subsequent correct token.
8. **No new dependency.** Randomness, SHA-256, constant-time comparison,
   base64url encoding, ULID encoding, synchronization, and timing use the Go
   standard library. Existing pgx/sqlc/testcontainer infrastructure is reused.

## Acceptance criteria

<!-- docref: begin src=server/internal/pki/registration_tokens_test.go#TestRegistrationTokens_MintStoresOnlyHash:89c8b475,server/internal/pki/registration_tokens_test.go#TestRegistrationTokens_ConcurrentConsumeHonorsMaxUses:6a8d48c3,server/internal/pki/registration_tokens_test.go#TestRegistrationTokens_CASRetriesAreBoundedAndBackedOff:c51621ed,server/internal/pki/registration_tokens_test.go#TestRegistrationTokens_RejectionsAreUniform:c7a34554,server/internal/pki/registration_tokens_test.go#TestRegistrationTokens_SuccessfulUsesAreNotRateLimited:4fbb2a1e,server/internal/pki/registration_tokens_test.go#TestRegistrationTokens_MintFailureWritesNothing:bbb2974c,server/internal/pki/registration_tokens_test.go#TestRegistrationTokens_ConstantTimeHashGate:d7cf6207,server/internal/store/registration_tokens_test.go#TestRegistrationTokenProjection_RebuildsCompleteState:d58eb145,server/internal/store/registration_tokens_test.go#TestRegistrationTokenProjection_RejectsInvalidTransitions:1845167b,server/cmd/power-manage-recovery/main_test.go#TestRecoveryCLI_RebuildsRegisteredTokenTarget:f4dfc3f6 -->
- **AC-M3-1 — Mint and hash at rest.** A successful mint returns a canonical
  locator and a 32-byte secret, persists exactly the secret's SHA-256 digest,
  and leaves no raw token bytes in either the event payload or projection.
  Randomness failure or invalid options write nothing.
- **AC-M3-2 — Bounded-use race.** With `max_uses=N`, N+k callers released
  concurrently against real Postgres produce exactly N grants. Every loser
  receives the same sentinel as an unknown token, and projection/event counts
  stop at N consumes.
- **AC-M3-3 — State rejection.** Malformed, unknown, wrong-secret, expired,
  disabled, exhausted, and losing-CAS inputs return the same error bytes and
  the same injected rejection deadline. Disabled state prevents any consume
  regardless of expiry or remaining uses.
- **AC-M3-4 — Constant-time gate.** Correct and adversarial secrets are hashed
  to fixed-size digests and compared only with
  `subtle.ConstantTimeCompare`; malformed tokens still take the dummy lookup,
  digest, compare, and rejection-equalization path.
- **AC-M3-5 — Kill switch.** Disable is durable and idempotent. A disabled
  token never consumes again, and rebuild reproduces its hash, bounds, owner,
  use count, expiry, and disabled state byte-for-byte.
- **AC-M3-6 — No success lockout.** Every permitted successful token consume
  reaches its version-pinned admission regardless of earlier successful uses.
  Network failure limiting is applied by the shared public-handler ladder.
- **AC-M3-7 — Store discipline.** All three event types have golden payloads,
  exactly one projector, one rebuild target, and only sqlc-inventoried
  projection mutations. The new table is classified exactly once and is
  reachable through the CLI-only recovery target registry.
<!-- docref: end -->

## Red-first test order

1. Add real-Postgres lifecycle tests for hash-only minting, reconstruction,
   disable, and `N+k` concurrent consumption. Confirm the package initially
   fails because the registration-token API and schema do not exist.
2. Add uniform-rejection tests with an injected clock/waiter, including wrong
   secrets differing at opposite ends and disabled+expired state. Confirm the
   service API is absent.
3. Add the successful-use no-lockout matrix and RNG/option failure tests.
4. Add registry, golden-corpus, projection-write, table-classification, and
   recovery-target expectations. Confirm their exact-set floors fail before
   implementation.
5. Implement migration and static queries, regenerate sqlc output, wire event
   projectors/rebuild metadata, then implement the token service.
6. Run focused race tests, the full server race suite, strict docref, the full
   repository verification gate, and CodeRabbit review before publishing.

## Out of scope

- PkiService descriptors, listener wiring, enrollment CSR validation, and
  certificate issuance (M4).
- The local agent enrollment socket, token-file/stdin CLI, and device-side
  limiter (M4).
- Renewal, revocation, CRL distribution, gateway enrollment, and CA rotation
  (M5–M8).
- The reusable public authentication rate-limit ladder (SPEC-007). M3 leaves
  network admission to the public handler that owns the client-IP boundary.
