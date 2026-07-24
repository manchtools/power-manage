# SPEC-009 M2 — Boundary generators and request-path guards

Spec milestone: SPEC-009 M2 (`DOM-1`, `LIM-3`; AC-3, AC-12).

## Acceptance criteria

1. A registry-driven boundary generator walks every request descriptor of every
   registered CRUD domain and emits correct, absent, and wrong cases for every
   field. Correct messages pass Protovalidate; every wrong value violates that
   field's declared rule and is rejected by the kernel boundary.
2. Generation fails closed when a registered domain exposes zero request
   fields, a field has no validation rule, or a rule kind has no safe
   correct/wrong value generator. No field or domain allowlist may make such a
   case disappear.
3. A descriptor-driven exact-set guard classifies every ControlService RPC as
   either one kernel operation or one enumerated custom flow. Duplicate,
   overlapping, missing, and zero-subject classifications fail.
4. The authorization-order guard joins the same descriptor population to the
   complete RPC authorization registry. Kernel procedures must be
   permission-gated with the registration's exact permission; custom flows
   must carry their declared authentication class. Generated invalid requests
   reach neither authorization nor domain/store work.
5. Production Go files in the Control, authentication, PKI, and gateway
   request-path packages contain no `context.Background()` call. The scan
   discovers its file population, and its planted fixture proves it can turn
   red.
6. Detached work may use `context.WithoutCancel` only inside an exact,
   rationale-bearing function allowlist and only as the parent passed directly
   to `context.WithTimeout`. The current server shutdown path remains the sole
   allowed call.

## Design

- Centralize production CRUD-domain construction in one registry function used
  by both service construction and the guards. A new domain therefore enters
  the classification and boundary suites without a second list.
- Keep the boundary generator test-only. It resolves message types through the
  protobuf registry, reads `buf.validate` field rules, builds messages through
  reflection, and fails on unsupported rule shapes instead of guessing.
- Keep the custom-flow catalog small and explicit because custom flows are the
  exception to the kernel. The exact-set join prevents it from becoming a
  shadow handler registry.
- Reuse the established RPC authorization registry and ordered interceptor
  chain; M2 adds the cross-check from Control descriptors and kernel metadata
  rather than another authorization representation.
- Pass constructor context into CA-rotation bootstrap reads so request-path
  packages need no `context.Background()` exemption.
- Implement the detached-context check as an AST guard keyed by containing
  function, not file path, so moving or adding an unrelated function cannot
  silently inherit an exemption.

## Red-first tests

- generator coverage for all device-group request fields, with three emitted
  cases per field and actual Protovalidate/kernel rejection of every wrong case;
- zero-field, missing-rule, and unsupported-rule fixtures fail generation;
- an injected unclassified or doubly classified RPC fails the exact-set join;
- a policy mismatch between a kernel registration and authorization registry
  fails the auth join;
- a generated wrong request records zero resolver, callback, and append calls;
- the planted `context.Background()` fixture is detected;
- a `context.WithoutCancel` call outside the exact function allowlist, or not
  directly wrapped by `context.WithTimeout`, is rejected.

## Implementation

<!-- docref: begin src=server/internal/control/device_groups.go#managementDomains:951691af,server/internal/control/boundary_generator_test.go#generateCRUDBoundaryCases:2d3773a7,server/internal/control/rpc_guards_test.go#TestGuard_ControlRPCsHaveExactlyOneImplementationClass:d2762cfc,server/internal/control/rpc_guards_test.go#TestGuard_ControlAuthorizationMatchesImplementationClass:e31852d8,server/request_context_guard_test.go#TestGuard_RequestPathsDoNotCreateBackgroundContexts:0cdf60f3,server/request_context_guard_test.go#TestGuard_DetachedContextsAreBoundedAndAllowlisted:b2de0f54,server/internal/pki/rotation.go#NewRotationManager:41995439 -->
The management service and guard suites consume the same domain-construction
function. The boundary generator reflects over each registered request message
and its validation rules, while descriptor exact-set guards join every Control
RPC to one implementation class and the existing authorization policy.
Request-path guards scan the production package population for background and
detached-context calls. CA-rotation bootstrap now accepts its caller's context;
the only detached call is the timeout-bounded TLS shutdown path.
<!-- docref: end -->

## Verification

<!-- docref: begin src=server/internal/control/boundary_generator_test.go#TestGuard_CRUDRequestBoundaryCasesCoverEveryRegisteredField:b90dcb09,server/internal/control/boundary_generator_test.go#TestCRUDBoundaryGenerator_FailsClosed:f66bd042,server/internal/control/boundary_generator_test.go#TestGeneratedWrongCasesStopBeforeAuthorizationAndWork:87d67f54,server/internal/control/rpc_guards_test.go#TestGuard_ControlRPCsHaveExactlyOneImplementationClass:d2762cfc,server/internal/control/rpc_guards_test.go#TestGuard_ControlAuthorizationMatchesImplementationClass:e31852d8,server/request_context_guard_test.go#TestGuard_RequestPathsDoNotCreateBackgroundContexts:0cdf60f3,server/request_context_guard_test.go#TestRequestContextBackgroundGuard_FixtureDetected:c565a225,server/request_context_guard_test.go#TestGuard_DetachedContextsAreBoundedAndAllowlisted:b2de0f54,server/request_context_guard_test.go#TestDetachedContextGuard_FixtureDetected:bb0e7987 -->
- Passed: all generator, exact-set classification, authorization parity,
  request-path context, and liveness tests; server-wide vet, static analysis,
  and tests; and the complete `./scripts/verify.sh` gate.
- Failed: none.
- Skipped: the pre-existing dormant `TestGuard_GatewayPurity` guard, which the
  verification gate reports explicitly and which is unrelated to M2.
<!-- docref: end -->

## Rejection paths

| Input or state | Expected outcome |
|---|---|
| Registered request descriptor has zero fields | Generator error; CI failure |
| Request field lacks a supported validate rule | Generator error naming the field |
| Generated wrong value unexpectedly validates | Generator/test failure |
| Control RPC is kernel and custom, or neither | Classification guard failure |
| Kernel procedure policy or permission differs | Authorization-order guard failure |
| Request-path `context.Background()` call | AST guard failure |
| Unallowlisted or unbounded `context.WithoutCancel` | AST guard failure |

## Out of scope

- remaining CRUD-domain registrations and generated scope suites (M3);
- nestable action sets (M4);
- FTS, search parity, and global search (M5);
- transport limits, handler deadlines, output budgets, and trusted proxy
  resolution (M6).
