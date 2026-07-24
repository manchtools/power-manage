# SPEC-008 M3 — authorization interceptor and RPC classification

Spec milestone: SPEC-008 M3 (`AUTHZ-7`; AC-17 and AC-18 scaffolding).

## Files and symbols

<!-- docref: begin src=server/internal/auth/interceptors.go#ProcedureAuthorization:da7c63ba,server/internal/auth/interceptors.go#ProcedureAuthorizations:f7f7afaa,server/internal/auth/interceptors.go#InterceptorChain.ValidateWiring:af744a58,server/internal/auth/authorization.go#AuthorizationGate:8cd4b517,server/internal/auth/authorization.go#NewAuthorizationGate:91031a87,server/internal/auth/authorization.go#ContextWithSessionClaims:c2b05ff8,server/internal/auth/authorization.go#ContextWithPATPrincipal:1a0797ae,server/internal/auth/authorization.go#AuthorizationDecisionFromContext:7ba96b41,server/internal/auth/authorization.go#AuthorizationGate.AuthorizeContext:09da2d98 -->
- `server/internal/auth/interceptors.go`: `ProcedureAuthorization`,
  `ProcedureAuthorizations`, and `InterceptorChain.ValidateWiring`
- `server/internal/auth/authorization.go`: `AuthorizationGate`,
  `NewAuthorizationGate`, `ContextWithSessionClaims`,
  `ContextWithPATPrincipal`, `AuthorizationDecisionFromContext`, and
  `AuthorizationGate.AuthorizeContext`
- `server/internal/auth/authorization_test.go`
- `server/internal/auth/authorization_postgres_test.go`
- `server/internal/control/handler_test.go`
- `server/internal/control/oidc_test.go`
- `server/internal/control/session_test.go`
- `docs/content/01-specs/00-index.md`
<!-- docref: end -->

## Test names

<!-- docref: begin src=server/internal/auth/authorization_test.go#TestGuard_RPCClassificationCarriesExactlyOneAuthorizationMode:8d0424d0,server/internal/auth/authorization_test.go#TestAuthorizationGate_FailsClosedForUnknownUnaryAndStreamingProcedures:1c705f72,server/internal/auth/authorization_test.go#TestAuthorizationGate_PATScopeNarrowsRoleAccessBeforeLookup:ea75eca3,server/internal/auth/authorization_test.go#TestAuthorizationGate_DirectAndInterceptorCallsShareDecision:f72a9a35,server/internal/auth/authorization_postgres_test.go#TestAuthorizationGate_DirectCallUsesRealEffectiveAccess:82c8852e,server/internal/auth/authorization_test.go#TestNewInterceptorChain_RejectsNonAuthorizationFinalStage:3ea97313 -->
- `TestGuard_RPCClassificationCarriesExactlyOneAuthorizationMode`
- `TestAuthorizationGate_FailsClosedForUnknownUnaryAndStreamingProcedures`
- `TestAuthorizationGate_PATScopeNarrowsRoleAccessBeforeLookup`
- `TestAuthorizationGate_DirectAndInterceptorCallsShareDecision`
- `TestAuthorizationGate_DirectCallUsesRealEffectiveAccess`
- `TestNewInterceptorChain_RejectsNonAuthorizationFinalStage`
<!-- docref: end -->

## Acceptance criteria

1. One procedure-policy registry classifies every descriptor RPC as exactly
   public, permission-gated, or alternate-auth. Permission-gated entries name
   one catalog permission; public and alternate-auth entries name none.
2. Descriptor discovery and the registry form an exact non-empty set. A new
   unclassified RPC fails the guard, and unknown runtime procedures deny
   without calling a resolver or handler.
3. The fixed validate → authenticate → rate-limit → authorize chain accepts
   only the production authorization-gate type for its final stage; an
   arbitrary or typed-nil interceptor cannot replace it.
4. Public and alternate-auth procedures pass authorization without user-grant
   resolution. Permission-gated procedures require authenticated context,
   resolve current effective access, and require the exact named permission.
5. PAT authorization is the intersection of its per-token scope set and the
   subject's current effective permissions. A PAT lacking the required scope
   denies before durable grant lookup.
6. Permission absence and unknown procedures return a static
   `PermissionDenied`; missing authenticated context returns static
   `Unauthenticated`; resolver uncertainty returns static `Unavailable`.
7. Successful authorization attaches a defensively copied decision containing
   the principal and effective access for M4 object-scope predicates.
8. The same gate exposes a direct-call method for handler defense in depth;
   interceptor and direct calls produce the same decision and rejection
   behavior.

## Design

- Replace the class-only map with one map of procedure policies. Preserve the
  existing class-only read API as a derived view for SPEC-007 rate-limit
  guards; do not create a second registry.
- Keep the production descriptor surface unchanged. Current Control RPCs are
  authentication/session procedures and remain public; machine streams remain
  alternate-auth. Permission-gated CRUD procedures arrive with SPEC-009 and
  must enter this registry before they compile green.
- Add an authorization gate in `server/internal/auth`, where the interceptor
  chain and authenticated session/PAT types already live. The gate consumes
  the M2 effective-access resolver through a narrow interface.
- Keep resource IDs and object predicates out of the interceptor. M3 proves
  the caller holds an active permission and carries the M2 reach into context;
  M4 applies that reach in handler queries.
- Permit an unexported policy lookup seam only for tests, so the dormant
  permission path can be exercised without adding a fake production RPC.

## Red-first tests

- descriptor and policy keys differ when a fixture classification is removed;
- a permission policy with an unknown permission and a public policy carrying
  a permission fail registry validation;
- unknown unary and streaming procedures deny before handler work;
- a non-gate final interceptor and a typed-nil gate fail chain construction;
- unauthenticated permission calls reject without resolver work;
- permission absence rejects, permission presence attaches the exact decision,
  and resolver failure maps to static unavailable;
- PAT missing the required scope rejects before the resolver, while a scoped
  PAT with both token scope and role access succeeds;
- direct-call and interceptor-call authorization use the same gate result.

## Rejection paths

| Input or state | Expected outcome |
|---|---|
| Descriptor RPC absent from registry | Guard failure; runtime `PermissionDenied` |
| Permission policy names no/unknown permission | Registry validation failure |
| Public/alternate-auth policy names a permission | Registry validation failure |
| Final chain stage is nil, typed-nil, or arbitrary interceptor | Construction failure |
| Permission RPC without authenticated principal | Static `Unauthenticated`; no resolver |
| PAT lacks the required token scope | Static `PermissionDenied`; no resolver |
| Subject lacks the effective permission | Static `PermissionDenied` |
| Effective-access lookup fails | Static `Unavailable`; handler not called |
| Corrupt zero-reach permission entry | Static `Unavailable`; fail closed |
| Public or alternate-auth RPC | Authorization pass-through; no user resolver |

## Out of scope

- object-level scope predicates, self-ID checks, NotFound remapping, and
  list/search filtering (M4);
- last-admin protection (M5);
- grant mutation authorization and no-ceiling regression fence (M6);
- system-managed object invisibility (M7);
- concrete role/grant/domain CRUD RPCs and handler registration (SPEC-009);
- access-token/PAT header parsing and authentication mechanics (SPEC-007).
