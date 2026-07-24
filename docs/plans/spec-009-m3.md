# SPEC-009 M3 — management-domain rollout

Spec milestone: SPEC-009 M3 (`WIRE-11`, `DOM-1`; AC-4).

## Design

1. Roll out the normative management inventory in four implementation batches:
   identity/RBAC, device/configuration, action/work, and read-only operational
   views. Device groups remain the reference domain delivered by M1.
2. A domain registration declares its exact supported operations. Full CRUD,
   create/delete-only, read/update/delete, and read-only domains do not acquire
   placeholder RPCs for operations the normative table excludes.
3. Every exposed ControlService RPC delegates to the shared CRUD kernel or is
   present in the existing explicit custom-flow registry. No handler is exposed
   merely to satisfy the descriptor classification guard.
4. Mutations remain immutable events with in-transaction projectors and rebuild
   targets. Reads use the resulting projections; no direct projection writes
   or second state store are introduced.
5. Scope reach is carried through the one kernel predicate as global,
   device-group, user-group, and self reach. Domain registrations select the
   resource relation needed to turn that reach into a fail-closed object/list
   predicate; they do not perform independent authorization.
6. Secret-bearing domains return public metadata from list/detail/update
   operations. Create or rotate returns a freshly generated credential exactly
   once, while events and projections retain only its verifier; callers never
   submit a verifier/hash as object state.

## Acceptance criteria

1. A registry guard discovers exactly the normative kernel domain inventory and
   its operation sets, with a non-zero floor and a planted missing-operation
   failure.
2. Descriptor walking proves every ControlService RPC is classified exactly
   once as kernel or custom, and every kernel procedure names the permission in
   the authorization policy catalog.
3. The boundary generator emits correct, absent, and invalid cases for every
   field of every registered request message, including domains with operation
   subsets, and rejects a registered operation with missing metadata.
4. Each registered mutation appends one registered event and is recoverable
   through its production rebuild target. OCC updates/deletes use the expected
   stream version; assignments remain create/delete-only.
5. The generated real-Postgres scope suite proves, per confinable domain, that
   in-scope get/list/write succeeds, out-of-scope access is NotFound, and empty
   reach matches nothing. Executions are the recorded exception: scoped detail
   reads return PermissionDenied so operators can distinguish inaccessible
   live output from an absent execution. Global-only domains accept only
   global reach.
6. Read-only domains expose no mutation RPCs; devices expose no create RPC;
   assignments expose no update RPC.
7. Contract messages use bare ULIDs, typed enums/messages, bounded collections,
   explicit expected versions, and validate tags on every trust-boundary field.
8. Token metadata contains no bearer, verifier, hash, or secret field. A
   create/rotate response may carry the generated credential in a separate
   one-time field required by SPEC-006/007.

## Red-first checks

- Add the exact domain/operation inventory test before adding RPCs or registry
  entries; confirm it fails on the current device-group-only registry.
- Add operation-subset kernel tests before generalizing registry validation.
- Add descriptor and boundary-generator expectations before generating the
  expanded contract.
- Add one real-Postgres behavioral scope case per batch before its store and
  handler adapters.
- For every new event family, add golden-corpus and rebuild-parity assertions
  before its projector implementation.

## Verification

<!-- docref: begin src=server/internal/control/device_groups.go#managementDomains:178b7675,server/internal/control/crud_kernel.go#CRUDKernel:e7e7405c,server/internal/control/identity_domains.go#identityDomains:b92810b6,server/internal/control/action_work_domains.go#actionDomain:5aee1e40,server/internal/control/operational_read_domains.go#auditDomain:e1323271,server/internal/auth/oidc.go#OIDCService.provider:cd6414e0,server/internal/store/management_reads.go#Store.ListAuditEvents:5d6dcdab,server/internal/store/telemetry.go#TelemetryStore.BindExecutionOutputToDevice:9b4cc57f,server/internal/control/rpc_guards_test.go#TestGuard_ManagementDomainInventoryAndOperations:e207e039,server/internal/control/boundary_generator_test.go#TestGuard_CRUDRequestBoundaryCasesCoverEveryRegisteredField:b90dcb09,server/internal/control/identity_postgres_test.go#TestIdentityHandlers_CRUDAndScopeConfinement:4cc4ce36,server/internal/control/scim_configuration_postgres_test.go#TestScimConfigurationHandlers_OneTimeRotationDisableAndDelete:d3dc50f3,server/internal/control/action_work_postgres_test.go#TestActionWorkHandlers_CRUDScopeAndRebuild:29328313,server/internal/control/operational_read_postgres_test.go#TestOperationalReadHandlers_RealViewsAndScope:99283513 -->
- The shared registry contains the exact 19-domain operation inventory, and
  every registered request remains inside the validated, permission-bound CRUD
  kernel.
- Identity, configuration, action/work, and operational-read handlers exercise
  real Postgres projections. Their tests cover OCC, rebuild parity, direct and
  transitive scope, global-only refusal, payload-free audit metadata, and
  one-time SCIM credential rotation.
- Managed OIDC configurations are resolved at request time before the static
  fallback. Execution scope is stored as an immutable device binding rather
  than inferred from an execution identifier.
<!-- docref: end -->

- Targeted contract, auth, control, and store tests per batch.
- Generated protobuf and SQL code are reproducible and in sync.
- `docref check`
- `./scripts/verify.sh`
- local and remote CodeRabbit review, with every actionable finding resolved.

## Out of scope

- Nestable-set cycle detection and flattening (M4).
- FTS, list/search unification, and global search (M5).
- Request/output/deadline/XFF limits (M6).
- Last-admin locking, grant no-ceiling behavior, and system-managed
  invisibility (SPEC-008 M5–M7).
- Action parameter semantics beyond the single `Action` shape already owned by
  SPEC-014.
