# SPEC-008 M4 — object-scope enforcement and denial mapping

Spec milestone: SPEC-008 M4 (`AUTHZ-4`, `AUTHZ-5`, `AUTHZ-7`; AC-5,
AC-8–11, AC-18, and AC-19).

## Files and symbols

<!-- docref: begin src=server/internal/control/crud_kernel.go#CRUDKernel.authorize:6b428dda,server/internal/control/crud_kernel.go#CRUDKernel.requireScopedMutationTarget:d8857053,server/internal/control/operational_read_domains.go#executionDomain:0ef9ee9b,server/internal/control/authorization_scope_postgres_test.go#TestAuthorizationScopeBehavior:9d601299,server/internal/control/authorization_scope_postgres_test.go#TestAuthorizationDenialParityAndExecutionException:7638600b,server/internal/control/authorization_scope_guard_test.go#TestGuard_ScopablePermissionsHaveBehavioralCoverage:31f0d2dc -->
- `server/internal/control/crud_kernel.go`: scoped read-denial metadata and
  shared NotFound/PermissionDenied mapping
- `server/internal/control/operational_read_domains.go`: execution-detail
  exception registration
- `server/internal/control/operational_read_postgres_test.go`: execution
  exception expectation
- `server/internal/control/authorization_scope_postgres_test.go`: real-handler,
  real-Postgres scope behavior and denial parity
- `server/internal/control/authorization_scope_guard_test.go`: registry-derived
  behavioral coverage and denial-metadata guards
- `docs/plans/spec-009-m3.md`: align the earlier rollout record with the
  recorded execution exception
<!-- docref: end -->

## Test names

<!-- docref: begin src=server/internal/control/authorization_scope_postgres_test.go#TestAuthorizationScopeBehavior:9d601299,server/internal/control/authorization_scope_postgres_test.go#TestAuthorizationDenialParityAndExecutionException:7638600b,server/internal/control/authorization_scope_guard_test.go#TestGuard_ScopablePermissionsHaveBehavioralCoverage:31f0d2dc -->
- `TestAuthorizationScopeBehavior`
- `TestAuthorizationDenialParityAndExecutionException`
- `TestGuard_ScopablePermissionsHaveBehavioralCoverage`
- `TestScopableCoverageGuard_RejectsMissingUnexpectedAndZero`
- `TestScopedReadDenialMetadata_RejectsMissingAndUnexpectedExceptions`
<!-- docref: end -->
