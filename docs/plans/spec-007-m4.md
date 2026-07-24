# SPEC-007 M4 — Refresh-token families

Spec milestone: SPEC-007 M4 (AC-4, AC-5; GUARD-007-3).

## Acceptance criteria

1. Starting a session returns one access token and one refresh token while
   persisting only the refresh token's SHA-256 digest in events and projections.
2. Presenting active refresh token R1 atomically rotates it to R2. R1 is then
   superseded and cannot rotate again.
3. Replaying any superseded family token appends a family-revocation event.
   R2 and every later family token are rejected after that revocation.
4. Two concurrent R1 rotations have one CAS winner; the losing replay revokes
   the family, so the winner's R2 is no longer usable.
5. Malformed, nonexistent, expired, superseded, and revoked refresh failures
   return the same static response bytes and meet the same minimum rejection
   duration. Parser or storage details never reach the caller.
6. Refresh-family and token-history projections rebuild exactly from their
   hash-only event streams and reject invalid transitions without partial
   writes.
7. `RefreshSession` is a public ControlService procedure with both rate-limit
   dimensions. The real handler runs through the ordered interceptor boundary
   and counts only failed authentication outcomes.
8. The enumeration-parity registry discovers the refresh verifier and carries
   every required failure cause; empty discovery and missing causes fail.

## Delta

<!-- docref: begin src=contract/proto/powermanage/v1/control.proto#ControlService.RefreshSession:5d231aa2,server/internal/store/migrations/014_refresh_families.sql#@refresh-family-schema:41c6013f,sdk/ulidx/ulidx.go#NewWithReader:261c18c6,server/internal/store/refresh_families.go#RefreshFamilyStartedEvent:f9e0ad88,server/internal/store/refresh_families.go#RefreshTokenRotatedEvent:1683d36c,server/internal/store/refresh_families.go#RefreshFamilyRevokedEvent:e2ac6bb5,server/internal/store/refresh_families.go#Store.RefreshFamilyToken:3cab0e63,server/internal/auth/refresh.go#RefreshService:6cf85d40,server/internal/auth/refresh.go#RefreshService.StartSession:ea1fc26d,server/internal/auth/refresh.go#RefreshService.Rotate:35d4dbc6,server/internal/control/session.go#SessionService.RefreshSession:6690b168,server/internal/auth/enumeration.go#EnumerationParityProfiles:d0b10b59 -->
- `contract/proto/powermanage/v1/control.proto`
  - `ControlService.RefreshSession`
  - `RefreshSessionRequest`, `RefreshSessionResponse`
- `server/internal/store/migrations/014_refresh_families.sql`
- `server/internal/store/queries/refresh_families.sql`
- generated SQL bindings
- `sdk/ulidx`
  - first consumer-activated stdlib ULID generator from SDK-13
- `server/internal/store/refresh_families.go`
  - hash-only start, rotate, and revoke events
  - family/token-history reads and projectors
  - refresh-family rebuild target
- `server/internal/auth/refresh.go`
  - `RefreshService`, `SessionTokens`
  - session start, CAS rotation, reuse detection, parity padding
- `server/internal/control/session.go`
  - real `RefreshSession` handler with trusted-proxy failure limiting
- procedure classification, public rate-limit, storage-classification, recovery,
  event-definition, and golden-corpus registries
- affected generated-surface and handler tests
- `docs/content/01-specs/00-index.md`
<!-- docref: end -->

## Tests

<!-- docref: begin src=sdk/ulidx/ulidx_test.go#TestNew_EncodesTimeAndCheckedRandomnessAsCanonicalULID:338545ba,sdk/ulidx/ulidx_test.go#TestNew_RejectsInvalidTimeAndRandomFailure:75d84c2e,server/internal/store/refresh_families_test.go#TestRefreshFamilyProjection_RotatesRevokesAndRebuilds:f66c28e9,server/internal/store/refresh_families_test.go#TestRefreshFamilyProjection_RejectsInvalidTransitions:bdef0476,server/internal/store/refresh_families_test.go#TestRefreshFamilyEvents_ContainHashesButNeverRawSecrets:9d6cc74e,server/internal/control/refresh_test.go#TestRefreshService_RotatesAndReplayRevokesFamily:046f8e49,server/internal/control/refresh_test.go#TestRefreshService_ConcurrentRotationHasOneWinnerAndRevokesFamily:9a64647a,server/internal/control/refresh_test.go#TestRefreshService_FailureCausesHaveParity:71b0f649,server/internal/control/refresh_test.go#TestRefreshService_StartPersistsOnlyHash:ed9b242e,server/internal/control/session_test.go#TestRefreshHandler_UsesRealBoundaryAndFailureOnlyLimits:74509a09,server/internal/auth/enumeration_guard_test.go#TestGuard_RefreshEnumerationParityCoverage:5bd80f09 -->
- `TestNew_EncodesTimeAndCheckedRandomnessAsCanonicalULID`
- `TestNew_RejectsInvalidTimeAndRandomFailure`
- `TestRefreshFamilyProjection_RotatesRevokesAndRebuilds`
- `TestRefreshFamilyProjection_RejectsInvalidTransitions`
- `TestRefreshFamilyEvents_ContainHashesButNeverRawSecrets`
- `TestRefreshService_RotatesAndReplayRevokesFamily`
- `TestRefreshService_ConcurrentRotationHasOneWinnerAndRevokesFamily`
- `TestRefreshService_FailureCausesHaveParity`
- `TestRefreshService_StartPersistsOnlyHash`
- `TestRefreshHandler_UsesRealBoundaryAndFailureOnlyLimits`
- `TestGuard_RefreshEnumerationParityCoverage`
<!-- docref: end -->

## Out of scope

- PAT issuance and revocation (M5)
- OIDC session creation (M6)
- break-glass session creation (M7)
- SCIM bearer authentication (M8)
- centralized `session_version` invalidation and the complete auth-event golden
  corpus gate (M9)
