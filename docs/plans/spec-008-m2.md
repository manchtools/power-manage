# SPEC-008 M2 — grant model and effective-access resolution

Spec milestone: SPEC-008 M2 (`AUTHZ-1`, `AUTHZ-3`, `AUTHZ-3a`,
`AUTHZ-3b`; AC-2, AC-3, AC-4, AC-6, AC-7).

## Acceptance criteria

1. Roles and grants are immutable event facts with in-transaction Postgres
   projections, golden payloads, table classification, and one replay target.
2. A role contains only distinct catalog permissions. Role and grant IDs,
   principal IDs, and scope IDs are canonical ULIDs; malformed or unknown
   values write neither events nor projections.
3. Grants address one user or user group and carry exactly one scope:
   global, device-group set, user-group set, or self. Global/self scopes carry
   no IDs; group-set scopes carry a non-empty, distinct, bounded ULID set.
4. Effective access resolves direct grants plus grants inherited through the
   existing event-sourced SCIM/user-group membership projection.
5. A global grant activates every role permission. A scoped grant activates
   only confinable permissions and reports the exact sorted global-only set it
   strips.
6. Grant contributions union by permission without widening unrelated
   permissions. Multiple scoped grants union their scope IDs; a global
   contribution dominates narrower contributions only for that same
   permission.
7. The contract exposes typed principal/scope enums and a grant view whose
   active and stripped permission lists are explicit and validated.
8. Resolution, rebuild, and rejection tests use real Postgres and the
   production store; no mocked persistence or authorization context.

## Design

- Add authorization role and grant projections in migration 021.
- Keep user-group membership single-sourced: M2 resolves group grants through
  `scim_group_members`, the event-derived membership projection already
  present from SPEC-007.
- Put scope composition in `server/internal/authz`; the store loads canonical
  grant/role rows and passes them to that pure policy function.
- Return both per-grant active/stripped permissions and the effective
  per-permission reach. This makes AC-4 visible without a second
  authorization representation.
- Add contract wire shapes only; management RPCs remain owned by SPEC-009.

## Red-first tests

- group-only grant authorizes a member but not a non-member;
- global and scoped grants of the same role differ only by the exact
  global-only stripped set;
- two scoped grants union reach and an unrelated broad group grant does not
  widen a direct grant's other permission;
- invalid scope shape, unknown catalog permission, missing role/principal,
  duplicate permissions, and duplicate scope IDs write nothing;
- rebuild reproduces role/grant rows and the same effective access;
- contract round-trip preserves active and stripped permission sets.

## Implementation

<!-- docref: begin src=server/internal/authz/grants.go#Resolve:1c77ecd6,server/internal/store/authorization.go#AuthorizationRoleCreatedEvent:dd42dc2a,server/internal/store/authorization.go#AuthorizationGrantCreatedEvent:41e59c62,server/internal/store/authorization.go#Store.ResolveEffectiveAccess:cf05718c,server/internal/store/inventory.go#productionRebuildTargets:da889341,contract/proto/powermanage/v1/authorization.proto#GrantView:c264df0b -->
Role and grant constructors canonicalize immutable event facts before append.
The production projectors validate the same payloads again, maintain the two
authorization projections in the append transaction, and participate in one
rebuild target. Effective-access loading joins direct grants with group grants
through the SCIM membership projection, rejects missing or disabled users, and
passes normalized facts to the deterministic additive resolver. The contract
exposes typed principals/scopes and separate active/stripped permission lists.
<!-- docref: end -->

## Verification

<!-- docref: begin src=server/internal/authz/grants_test.go#TestResolve_GlobalGrantActivatesEntireRole:4b987fe6,server/internal/authz/grants_test.go#TestResolve_ReportsScopedStripping:fda09a52,server/internal/authz/grants_test.go#TestResolve_UnionsOnlyMatchingPermissionReach:b9e9b7b5,server/internal/store/authorization_test.go#TestAuthorization_GroupGrantResolvesOnlyForMembersAndRebuilds:eb5c9e84,server/internal/store/authorization_test.go#TestAuthorization_InvalidFactsWriteNothing:a8550747,server/internal/store/authorization_test.go#TestAuthorization_ResolutionFailsClosedOnCorruptProjection:aa74e0d4,contract/authorization_test.go#TestGrantView_RoundTripPreservesVisibleActivation:4a74b58c -->
- Passed: global activation, scoped stripping, per-permission scope union, and
  unrelated-grant non-widening.
- Passed against real Postgres: member/non-member group resolution, append
  rollback for missing dependencies, projection replay, disabled-user denial,
  and fail-closed corrupt-projection handling.
- Passed: generated contract round trip preserves active and stripped sets.
- Failed or skipped: none.
<!-- docref: end -->

## Rejection paths

| Input or state | Expected outcome |
|---|---|
| Role with unknown or duplicate permission | Validation failure; no event |
| Grant with missing role or principal | Projector failure; append transaction rolls back |
| Global/self scope with IDs | Validation failure |
| Device/user-group scope with no IDs | Validation failure |
| Malformed, duplicate, or excessive scope IDs | Validation failure |
| Missing or disabled user during resolution | Rejected; no effective access |
| Scoped grant containing global-only permission | Permission omitted from active set and listed in stripped set |
| User outside a granted group | Group grant absent from resolution |
| Corrupt persisted grant/role row | Resolution fails closed |

## Out of scope

- grant mutation authorization and no-ceiling behavior (M6);
- grant revoke, role edit, and last-admin protection (M5–M6);
- RPC interceptor binding and total permission classification (M3);
- object predicates, NotFound mapping, and list/search filtering (M4);
- system-managed object invisibility (M7);
- CRUD handlers for roles and grants (SPEC-009).
