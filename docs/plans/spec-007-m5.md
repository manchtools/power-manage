# SPEC-007 M5 — Scoped personal access tokens

Spec milestone: SPEC-007 M5 (AC-5, AC-6; GUARD-007-3).

## Acceptance criteria

1. Minting returns a PAT secret exactly once while events and projections
   persist only its SHA-256 digest.
2. A PAT carries a canonical non-empty scope set, expiry, subject, stable
   token ID, and per-token audit identity through successful authentication.
3. Revocation appends one durable event and immediately prevents subsequent
   authentication without changing the token's audit identity.
4. Malformed, nonexistent, expired, and revoked PATs return the same static
   response bytes and meet the same minimum rejection duration.
5. PAT projections rebuild exactly from their hash-only event streams and
   reject invalid mint/revoke transitions without partial writes.
6. Concurrent or repeated revocation is idempotent: at most one revocation
   event is appended, and the token remains revoked.
7. The enumeration-parity registry discovers both refresh and PAT verifiers;
   each carries its exact failure-cause set, and empty or missing coverage
   fails.

## Delta

<!-- docref: begin src=server/internal/store/migrations/015_personal_access_tokens.sql#@personal-access-token-schema:cecd9470,server/internal/store/personal_access_tokens.go#PersonalAccessTokenMintedEvent:1730a962,server/internal/store/personal_access_tokens.go#PersonalAccessTokenRevokedEvent:2f5f75ca,server/internal/store/personal_access_tokens.go#Store.PersonalAccessTokenByHash:1f7def0b,server/internal/store/personal_access_tokens.go#PersonalAccessTokenRebuildTarget:1e3821dc,server/internal/auth/pats.go#PATService:a6081812,server/internal/auth/pats.go#PATService.Mint:a3523af4,server/internal/auth/pats.go#PATService.Authenticate:18d1900c,server/internal/auth/pats.go#PATService.Revoke:8c1bf3c2,server/internal/auth/enumeration.go#EnumerationParityProfiles:d0b10b59 -->

- `server/internal/store/migrations/015_personal_access_tokens.sql`
- `server/internal/store/queries/personal_access_tokens.sql`
- generated SQL bindings
- `server/internal/store/personal_access_tokens.go`
  - hash-only mint and revoke events
  - digest/ID reads and rebuild target
- `server/internal/auth/pats.go`
  - `PATService`, `PATCredential`, `PATPrincipal`
  - normalized mint scopes, expiry/revocation authentication, audit identity
- `server/internal/auth/enumeration.go`
  - PAT verifier and failure causes
- storage-classification, recovery, event-definition, and golden-corpus
  registries
- `docs/content/01-specs/00-index.md`

<!-- docref: end -->

## Tests

<!-- docref: begin src=server/internal/store/personal_access_tokens_test.go#TestPersonalAccessTokenProjection_MintsRevokesAndRebuilds:f2de2994,server/internal/store/personal_access_tokens_test.go#TestPersonalAccessTokenProjection_RejectsInvalidTransitions:3ed640be,server/internal/store/personal_access_tokens_test.go#TestPersonalAccessTokenEvents_ContainHashesButNeverRawSecrets:f4d0bad4,server/internal/control/pats_test.go#TestPATService_MintStoresOnlyHashAndCanonicalScopes:acb0e50b,server/internal/control/pats_test.go#TestPATService_MintRejectsInvalidInputAndEntropyWithoutWriting:8723aa42,server/internal/control/pats_test.go#TestPATService_AuthenticationCarriesPerTokenAuditIdentityUntilRevoked:636ed98c,server/internal/control/pats_test.go#TestPATService_ConcurrentRevocationIsIdempotent:256e2ef9,server/internal/control/pats_test.go#TestPATService_FailureCausesHaveParity:585b1617,server/internal/auth/enumeration_guard_test.go#TestGuard_PATEnumerationParityCoverage:40965cd4 -->

- `TestPersonalAccessTokenProjection_MintsRevokesAndRebuilds`
- `TestPersonalAccessTokenProjection_RejectsInvalidTransitions`
- `TestPersonalAccessTokenEvents_ContainHashesButNeverRawSecrets`
- `TestPATService_MintStoresOnlyHashAndCanonicalScopes`
- `TestPATService_MintRejectsInvalidInputAndEntropyWithoutWriting`
- `TestPATService_AuthenticationCarriesPerTokenAuditIdentityUntilRevoked`
- `TestPATService_ConcurrentRevocationIsIdempotent`
- `TestPATService_FailureCausesHaveParity`
- `TestGuard_PATEnumerationParityCoverage`

<!-- docref: end -->

<!-- docref: begin src=server/internal/auth/pats_test.go#TestPATService_RejectsMalformedBeforeStoreLookup:a5752b39 -->

- `TestPATService_RejectsMalformedBeforeStoreLookup`

<!-- docref: end -->

## Out of scope

- PAT permission enforcement and grant-scope confinement (SPEC-008)
- OIDC session creation (M6)
- break-glass session creation (M7)
- SCIM bearer authentication (M8)
- centralized `session_version` invalidation and the complete auth-event golden
  corpus gate (M9)
