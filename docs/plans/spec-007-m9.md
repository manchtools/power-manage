# SPEC-007 M9 — centralized session invalidation

Spec milestone: SPEC-007 M9 (`AUTH-2`; AC-14; GUARD-007-4).

## Acceptance criteria

1. Every live user projection starts with positive `session_version = 1` and
   retains that value across ordinary non-invalidating events.
2. `UserDisabled`, `RoleRevoked`, `OIDCIdentityUnlinked`, and
   `SCIMUserDeprovisioned` are the exact invalidating event set. All four are
   registered to one store projector and no fifth event reaches it.
3. The central projector is the only production caller of the generated
   `session_version` mutation. Each accepted invalidating event advances the
   user stream and session version atomically; event-specific disable, unlink,
   or terminal deprovision projection changes occur in the same transaction.
4. Access and refresh JWTs carry a required positive session version.
   Cryptographic verification still distinguishes only genuine access-token
   expiry from the generic invalid-token class.
5. Store-aware access authentication accepts a current enabled user and
   rejects a missing, disabled, or version-mismatched user on the next use of
   a previously minted token.
6. Refresh rotation checks the current enabled user and session version before
   minting a successor, so an old refresh token cannot revive an invalidated
   session.
7. Tests prove next-use rejection for all four invalidating events through the
   one projector. A SCIM unlink with another identity still present is the
   negative control and leaves the existing session valid.
8. Rebuild reproduces positive session versions and terminal user deletion;
   every new auth event is pinned in the golden corpus.
9. GUARD-007-4 is matches-zero protected and asserts both the exact event set
   and the sole `session_version` writer/caller.

## Design

- `server/internal/store`
  - add user session/disable projection columns and exact event facts;
  - route all four facts through `projectSessionInvalidation`;
  - retain SCIM terminal cleanup and OIDC unlink projection work as helpers
    invoked only by the central projector.
- `server/internal/auth`
  - require a positive session version in both JWT purposes;
  - add store-aware access authentication;
  - bind refresh start/rotation to current user session state.

## Red-first tests

- tokens missing, zeroing, or changing `session_version` reject;
- each exact invalidating event makes a previously accepted access token fail;
- a pre-bump refresh token cannot rotate after invalidation;
- SCIM non-terminal unlink leaves a pre-existing access token valid;
- replay rebuild reproduces session versions and deleted users;
- the AST/SQL guard fails when a fifth event or second writer is introduced.

## Implementation

<!-- docref: begin src=server/internal/store/migrations/019_session_invalidation.sql#@session-invalidation-schema:4497a448,server/internal/store/session_invalidation.go#projectSessionInvalidation:7b89659f,server/internal/auth/tokens.go#tokenClaims.SessionVersion:e6bd9366,server/internal/auth/session_invalidation.go#SessionAuthenticator.AuthenticateAccess:3fbec363,server/internal/auth/refresh.go#RefreshService.Rotate:f2a0775d -->
The user projection stores a positive session version. The single invalidation
projector owns all four invalidating reactions, while access authentication and
refresh rotation compare the signed version with current durable user state.
<!-- docref: end -->

## Verification

<!-- docref: begin src=server/internal/store/session_invalidation_test.go#TestSessionInvalidationProjection_ExactEventsBumpOrDeleteUser:465a385e,server/internal/control/session_invalidation_test.go#TestSessionAuthenticator_InvalidatingEventsRejectExistingAccess:549caa33,server/internal/control/session_invalidation_test.go#TestSessionAuthenticator_NonInvalidatingSCIMUnlinkKeepsAccess:98dc73be,server/internal/control/session_invalidation_test.go#TestRefreshService_InvalidatedSessionCannotRotate:549494d6,server/internal/store/session_invalidation_test.go#TestGuard_SessionInvalidatingEventsUseOneProjector:b7f0ef66 -->
The tests cover every invalidating event, refresh rejection, rebuild parity, the
non-terminal unlink control, and exact-set/writer centrality guards.
<!-- docref: end -->

## Out of scope

- role/grant projection storage, grant resolution, authorization groups, and
  last-admin policy (SPEC-008);
- user/role management RPCs and CRUD handlers (SPEC-009);
- historical audit-payload crypto-shred mechanics (SPEC-011);
- wiring a network control binary beyond the authenticated components owned
  by SPEC-007.
