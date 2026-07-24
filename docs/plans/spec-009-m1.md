# SPEC-009 M1 — CRUD kernel core

Spec milestone: SPEC-009 M1 (`API-1` through `API-4`; AC-1, AC-2).

## Acceptance criteria

1. One kernel starts every registered operation in the fixed order:
   validate → authorize with resolved scope. Get/list then respond from the
   projection without writing; create/update/delete append and project in the
   existing event-store transaction before responding from the projection.
2. Invalid requests cause neither authorization resolution nor target-object
   reads. Authorization failures append no event and do no target-object work.
3. The device-group reference registration supplies its message type,
   `devices.manage` permission, projector-backed persistence callbacks, and
   future searchable-column metadata. Its Connect methods contain transport
   adaptation only; domain behavior lives in the registration and shared kernel.
4. Create, scoped get/list, full-replace update with expected-version OCC, and
   delete work through real handlers and real Postgres.
5. A global reach sees every device group. A device-group-set reach sees and
   mutates only the named group IDs. Empty and wrong scope sets match nothing;
   direct out-of-scope access returns a static NotFound response.
6. Create, update, and delete append registered immutable events whose
   projectors update the device-group projection in the append transaction.
   Rebuild reproduces the same final projection.
7. Unknown domains, mismatched permissions, nil wiring, malformed projections,
   missing rows, and persistence failures fail closed with static RPC errors.

## Design

- Add the device-group wire messages and five domain RPCs to ControlService.
  Requests carry validate tags, updates are full replacement plus
  `expected_version`, and deletes are version-pinned.
- Add one `CRUDKernel` in `server/internal/control`. A validated domain registry
  is immutable after construction and owns all domain-specific callbacks.
  Kernel methods accept protobuf messages so the pipeline is implemented once;
  typed Connect methods only adapt generated request/response types.
- Reuse the production authorization gate for direct handler enforcement. The
  kernel verifies that its registration permission matches the gate decision,
  derives one immutable object scope from that decision, and applies target
  checks before any domain callback.
- Add the device-group projection, queries, events, projectors, golden payloads,
  table classification, and rebuild target to `server/internal/store`. The
  kernel calls only `AppendEvent` or `AppendEventWithVersion`; it introduces no
  alternate write or projection mechanism.
- Keep scoped reads fail-closed in SQL: both detail and list queries always
  receive an explicit global flag and ID set. An empty non-global set is a
  matches-nothing predicate.

## Red-first tests

- registry construction rejects empty, duplicate, nil, incomplete, and
  permission-mismatched registrations;
- a validate-tag failure causes no authorization resolution, domain read, or
  append;
- an authorization failure causes no domain read or append;
- real-handler tests create, immediately get/list, full-replace update, reject a
  stale version, delete, and observe the projection disappear;
- real-handler scope tests prove global, correct-set, wrong-set, and empty-set
  behavior for reads and writes, including uniform NotFound;
- store tests prove projector atomicity, event payload validation, delete
  projection, OCC, and rebuild parity.

## Implementation

<!-- docref: begin src=contract/proto/powermanage/v1/control.proto#ControlService.CreateDeviceGroup:4fb80d95,server/internal/control/crud_kernel.go#CRUDKernel.create:86a90cdc,server/internal/control/crud_kernel.go#CRUDKernel.authorize:6c5ae7b6,server/internal/control/device_groups.go#deviceGroupDomain:66d2a50d,server/internal/store/device_groups.go#DeviceGroupCreatedEvent:26bd76ae,server/internal/store/device_groups.go#projectDeviceGroupUpdated:08a9d60d,server/internal/store/inventory.go#productionRebuildTargets:da889341 -->
The ControlService exposes operation-specific device-group RPCs around one
canonical object shape. Their adapters call the shared kernel, which validates
descriptor-tagged requests, obtains and verifies the permission decision, and
applies the registered target scope. Reads stop at the projection; mutations
then append the domain event and read the in-transaction projection result. The device-group
registration binds all operations to `devices.manage`, the exact RPC policy
entries, projector-backed event metadata, and searchable columns. Create,
full-replacement update, and delete events participate in the production event
registry and the ordinary projection rebuild target.
<!-- docref: end -->

## Verification

<!-- docref: begin src=server/internal/control/crud_kernel_test.go#TestCRUDKernel_ValidationPrecedesAuthorizationAndDomainWork:42245401,server/internal/control/crud_kernel_test.go#TestCRUDKernel_AuthorizationPrecedesDomainWorkAndAppend:e76458a1,server/internal/control/device_groups_postgres_test.go#TestDeviceGroupHandlers_CRUDScopeOCCAndDelete:146af412,server/internal/store/device_groups_test.go#TestDeviceGroupEvents_ProjectUpdateDeleteAndRebuild:27a7ebc2,server/internal/store/device_groups_test.go#TestDeviceGroupReads_RequireExplicitScope:ae98f283 -->
- Passed: the order tests prove invalid input reaches neither authorization nor
  domain work and denied input reaches no domain callback or append.
  Real-handler and real-Postgres tests prove create/read/list freshness, global
  versus exact-set scope behavior, uniform out-of-scope NotFound,
  full-replacement OCC, deletion, empty-scope fail-closed reads, and replay
  parity. `env -C contract buf lint` passes, and a fresh `buf generate` output
  matches the committed generated tree.
- Failed or skipped: none.
<!-- docref: end -->

## Rejection paths

| Input or state | Expected outcome |
|---|---|
| Request violates a validate tag | Static InvalidArgument; no resolver, target read, or append |
| Missing or invalid authorization decision | Static Unauthenticated/PermissionDenied; no target read or append |
| Registration permission differs from RPC policy | Construction failure or static Unavailable; fail closed |
| Out-of-scope ID | Static NotFound; no target read or append |
| Empty non-global scope | List is empty; detail/write is static NotFound |
| Unknown domain or malformed domain callback result | Static Unavailable |
| Stale `expected_version` | Static Aborted conflict; no partial update |
| Missing row | Static NotFound |
| Duplicate create | Static AlreadyExists |
| Store/projector failure | Static Unavailable; append transaction rolls back |

## Out of scope

- generated boundary suites, RPC classification, authorization-order, and
  `context.Background()` guards (M2);
- remaining management domains and their generated scope suites (M3);
- nestable action sets (M4);
- FTS, list/search unification, honest totals, and global search (M5);
- transport/body/parser/deadline/output/XFF limits (M6);
- SPEC-008 object relationship predicates beyond the reference domain,
  last-admin protection, grant mutation rules, and system-managed invisibility
  (SPEC-008 M4–M7).
