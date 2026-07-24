# SPEC-008 M5 — last-admin protection

Spec milestone: SPEC-008 M5 (`AUTHZ-2`; AC-12–14).

## Files and symbols

<!-- docref: begin src=server/internal/store/last_admin.go#protectLastAdminMutation:bef4c405,server/internal/store/last_admin.go#validateLastAdminEffects:7874ee62,server/internal/store/store.go#appendPrepared:259b3537,server/internal/control/crud_kernel.go#mapCRUDStoreError:7c9b0f45 -->
- `server/internal/store/last_admin.go`: total event-effect classification,
  enabled-admin policy, and the single advisory-lock/count wrapper
- `server/internal/store/store.go`: production append integration for every
  classified admin-reducing event
- `server/internal/store/queries/authorization.sql` and generated SQL:
  transaction lock plus direct, group-inherited, and bootstrap-admin count
- authorization, user, managed-group, SCIM-group, and session-invalidation
  event definitions: explicit last-admin effects
- `server/internal/control/crud_kernel.go` and `scim.go`: static
  FailedPrecondition/Conflict boundary mapping
<!-- docref: end -->

## Test names

<!-- docref: begin src=server/internal/store/last_admin_postgres_test.go#TestLastAdminProtection_RejectsDirectRemovalPaths:e2c7213c,server/internal/store/last_admin_postgres_test.go#TestLastAdminProtection_PreservesGroupInheritedAdmin:f96a81ce,server/internal/store/last_admin_postgres_test.go#TestLastAdminProtection_ConcurrentRemovalsLeaveOne:3d65df67,server/internal/store/last_admin_postgres_test.go#TestLastAdminProtection_ProtectsBootstrapRoleRevocation:72ecc2af,server/internal/store/last_admin_postgres_test.go#TestEnabledAdminCount_MalformedHistoricalRevocationDoesNotFail:16c7daf4,server/internal/store/last_admin_guard_test.go#TestGuard_LastAdminSensitiveEventsAreTotallyClassified:ede77aef,server/internal/store/last_admin_guard_test.go#TestLastAdminEffectGuard_RejectsMissingUnknownAndZeroReducing:38dceff0,server/internal/control/last_admin_postgres_test.go#TestAuthorizationHandlers_LastAdminMapsStaticFailedPrecondition:b6da855f,server/internal/control/last_admin_scim_test.go#TestSCIMStoreError_LastAdminMapsStaticConflict:a9cc389c -->
- `TestLastAdminProtection_RejectsDirectRemovalPaths`
- `TestLastAdminProtection_PreservesGroupInheritedAdmin`
- `TestLastAdminProtection_ConcurrentRemovalsLeaveOne`
- `TestLastAdminProtection_ProtectsBootstrapRoleRevocation`
- `TestEnabledAdminCount_MalformedHistoricalRevocationDoesNotFail`
- `TestGuard_LastAdminSensitiveEventsAreTotallyClassified`
- `TestLastAdminEffectGuard_RejectsMissingUnknownAndZeroReducing`
- `TestAuthorizationHandlers_LastAdminMapsStaticFailedPrecondition`
- `TestSCIMStoreError_LastAdminMapsStaticConflict`
<!-- docref: end -->
