---
title: "SPEC-008 — Authorization"
---
# SPEC-008 — Authorization

Status: See `00-index.md` (single status ledger) / Builds on: SPEC-005 (event-store), SPEC-007 (authentication) / Enables: SPEC-009 (crud-kernel-search-and-domains), SPEC-011 (audit-and-retention), SPEC-015 (secret-surfaces) / Module(s): server (catalog, enforcement, guards), contract (grant and scope wire shapes)

## 1. Scope

The authorization model of the control server: dynamic RBAC, grant-level
scoping, the permission catalog as ground truth, enforcement order, object
visibility, denial semantics, and the self-discovering guards that keep
enforcement complete. Applies to every RPC on ControlService and to every read
path (detail, list, search, dispatch). Authentication — who the caller is — is
SPEC-007; this spec begins where an authenticated identity (user session or
API token) already exists.

Several rules in this spec are settled operator decisions. They are marked
**(operator decision — final)** and MUST NOT be re-litigated, "improved," or
re-proposed in an alternative form.

## 2. Context capsule

A fresh implementer needs the following from prior specs, restated:

- **Event store (SPEC-005).** Every state change is an immutable event;
  projections are written only by projectors inside the append transaction;
  reads come exclusively from projections. Roles, grants, group memberships,
  and user enable/disable state are event-sourced like everything else.
  One-time and bounded-use consumes use expected-version CAS
  (ES-4, SPEC-005); multi-event operations use the atomic batch append.
- **Authentication (SPEC-007).** Human sign-in is OIDC-only; sessions are
  Bearer ES256 JWTs; API consumers use scoped personal access tokens. The
  interceptor chain authenticates before this spec's authorization runs, and
  rate limiting for public procedures sits in SPEC-007's ladder.
  Session invalidation on permission-relevant events (user disable, role
  revoke, IdP unlink, SCIM deprovision) is centralized in one store-side
  reaction (AUTH-2, SPEC-007) — authorization here may assume a caller's
  session reflects a bounded-staleness view of their grants.
- **Trust model (SPEC-001).** The actor this spec defends against is the
  authenticated low-privilege user attempting escalation: IDOR, scope bypass,
  grant escalation, information oracles. The control-plane administrator is
  TRUSTED — admin god-powers are design, not findings; build audit
  (SPEC-011), not admin-proofing **(operator decision — final)**.
- **CRUD kernel (SPEC-009).** The management API is one table-driven kernel:
  validate → authorize(+scope) → append(+project in-tx) → respond. Scope
  filtering is implemented in exactly one place — this spec defines the
  semantics; SPEC-009 owns the single implementation site.

Terminology used below:

| Term | Meaning |
|---|---|
| Permission | Atomic capability, named in the permission catalog |
| Role | Named set of permissions |
| Principal | A user or a user group |
| Grant | A tuple (principal, role, scope) |
| Scope | One of: global, a device-group set, a user-group set, self |
| Confinable | A permission whose effect can be narrowed by a grant scope |
| Global-only | A permission that activates only through a global grant |

- **Defended actors:** low-privilege authenticated users must not exceed their
  permissions or learn whether out-of-scope objects exist.

## 3. Requirements

### [AUTHZ-1] Dynamic RBAC, additive only

- Roles are permission sets. A caller's effective permissions are the UNION
  across all grants reaching them: grants to the user directly and grants to
  user groups the user belongs to.
- Additive only. There are no deny rules, no negative permissions, no
  precedence tiers.
- The role-management permission is the SOLE gate on creating, modifying, and
  deleting grants. There is **no grant-subset ceiling**: a caller holding
  role-management may grant roles containing permissions the caller does not
  hold **(operator decision — final; do not re-add a ceiling in any form)**.

### [AUTHZ-2] Atomic last-admin protection

- Last-admin protection is centralized in ONE function, not scattered across
  handlers.
- It counts *enabled* admins, including admin capability inherited through
  user-group grants — a user disabled at the account level never counts.
- It is atomic with the mutation: a Postgres advisory lock spans every
  admin-removing handler (role revoke, role edit that removes the admin-class
  permission, user disable, user delete, user-group membership removal,
  user-group role change), so two concurrent removals cannot interleave past
  the count check. A self-discovering guard proves lock coverage (Section 7).
- A mutation that would leave zero enabled admins fails with
  FailedPrecondition and a static message.

### [AUTHZ-3] Scope lives on the grant; the catalog is ground truth

- A grant is (principal, role, scope) with scope ∈ {global, device-group set,
  user-group set, self}. Scope is a property of the GRANT — permission names
  carry no scope suffixes, ever. There is no `:self`/`:assigned` naming
  dialect **(operator decision — final)**.
- EVERY permission is scope-confinable by construction, EXCEPT an enumerated
  global-only set whose scoping would be escalation theater:
  1. role/permission management,
  2. user-group membership management,
  3. IdP/SSO/SCIM configuration,
  4. server settings,
  5. PKI/CA operations,
  6. retention/audit administration.
- The permission catalog is the single machine-readable ground truth: it
  classifies every permission as `confinable` or `global-only` WITH a recorded
  rationale for each global-only entry. Every self-discovering authorization
  guard (Section 7) derives its work list from the catalog, never from a
  hand-maintained list.
- `scopable == enforced`: for every confinable permission, scoped-grant
  confinement is proven BEHAVIORALLY per handler (a scoped grant that should
  not reach an object demonstrably does not), not by presence of a check in
  the type system.

### [AUTHZ-3a] Scoped grants strip global-only permissions — visibly

- A scoped grant of a role confers only the role's confinable permissions.
  Global-only permissions in that role activate exclusively through a global
  grant of it.
- The grant API and UI surface EXACTLY which permissions a scoped grant
  strips. Silent partial activation is forbidden; silent full activation
  (a scoped grant quietly acting global) is forbidden more so.

### [AUTHZ-3b] Scope composition is intersection (narrowing-only)

- Multiple grants union their reach: each grant contributes
  (role's confinable permissions) ∩ (grant's scope), and the caller's
  effective access is the union of these contributions.
- A single grant's scope NEVER widens what its role would reach. Group-granted
  roles compose with scoped direct grants under the same rule — there is no
  path where holding a group membership silently widens a scoped grant.
- `self` scope never short-circuits to allow on an empty resource ID. An
  absent or empty ID is rejected; it is never interpreted as "the caller's
  own."
- The `linux_username` attribute on user records is admin-only: mutable only
  under a global grant of the relevant permission, never self-serviceable
  **(operator decision — final)**.

### [AUTHZ-4] Object scope: transitive READ, direct WRITE

- READ is effective/transitive: an object reachable through an in-scope
  object (e.g., an action referenced by an in-scope assignment) is readable.
  This is INTENDED — do not tighten reads **(operator decision — final)**.
- WRITE requires direct scope on the object being mutated.
- Enforcement is BEHAVIORAL: scope confinement is the handler's own WHERE
  clause / query predicate, exercised against the real database by tests.
  Presence-based type-level checks ("the handler references a scope type")
  prove nothing and are not accepted as enforcement.
- List and search apply the SAME scope predicates as every other read,
  fail-closed sentinel included, in the query itself — out-of-scope rows are
  absent from results AND from totals (SRCH-2, SPEC-009). There is no second
  authorization representation to keep in parity.
- Accepted risk **(operator decision — final)**: a caller able to edit device
  labels can move devices into a dynamic device group and thereby into a
  device-group-scoped grant's reach for LUKS/LPS surfaces. This
  label→dynamic-group pierce is accepted by design; do not build a
  countermeasure.

### [AUTHZ-5] Uniform NotFound — existence never leaks

- Cross-actor and out-of-scope object access returns NotFound uniformly —
  never PermissionDenied. Denial responses are byte-identical to the response
  for a truly absent object (static messages, no timing-relevant divergent
  work after the decision point).
- The scope/permission check runs BEFORE any DB observation wherever the
  grant is resolvable from the auth context alone. Where the row must be
  loaded first to decide, the denial is REMAPPED to NotFound before it leaves
  the handler.
- Recorded exception **(operator decision — final)**: execution and log-read
  handlers return PermissionDenied (not NotFound) to callers whose grant is
  scoped. Keep it, document it at the handler, and exclude exactly these
  handlers from the uniformity guard with an inline rationale.
- A caller lacking the required permission entirely (no grant of any scope)
  receives PermissionDenied with a static message; object-level denial for a
  caller who holds the permission but not the object follows the NotFound
  rule above.

### [AUTHZ-6] System-managed objects are invisible and immutable

- System-managed objects (reconciler-owned actions and their kin) are
  immutable and invisible through EVERY path: get, list, search, add-to-set
  at ANY nesting depth, and dispatch.
- Enforcement is ONE self-discovering guard over all read/list/search/
  set-composition/dispatch paths — never per-RPC patches.
- Mutation or read attempts against a system-managed object return NotFound
  (the object does not exist for callers).

### [AUTHZ-7] Enforcement order and total RPC classification

- Handler order everywhere: validate → authenticate → authorize → work.
  Validation precedes authentication **(operator decision — final:
  validate-then-authorize canonical order)**; rate limiting sits between
  authentication and authorization in the interceptor chain (SPEC-007).
- The order holds at the interceptor AND at the handler (defense in depth):
  a handler invoked without the interceptor still validates and authorizes.
- Every RPC is classified exactly one of: `public` (no session required —
  SPEC-007 ladder applies), `permission` (named catalog permission required),
  or `alt-auth` (non-session authorization, e.g., mTLS class — SPEC-003/006
  seams). A descriptor-walking guard proves the classification is total and
  that every RPC validates before work. An unclassified RPC is denied
  fail-closed at the interceptor AND fails the build.

## 4. Acceptance criteria

Each criterion is independently testable against a real database and real
handlers.

- **AC-1** The permission catalog exists as machine-readable data; every
  permission is classified `confinable` or `global-only`; every global-only
  entry carries a rationale string. Adding an unclassified permission fails
  the catalog guard.
- **AC-2** A permission granted only via user-group membership is effective:
  the member passes authorization; a non-member with no other grant does not.
- **AC-3** A global grant activates all of a role's permissions. A scoped
  grant of the same role activates only its confinable permissions; a
  global-only permission in that role does not authorize anything under the
  scoped grant.
- **AC-4** The grant read API returns, for a scoped grant, the exact set of
  permissions the scope strips.
- **AC-5** Under a device-group-scoped grant: an object in the scope is
  readable and writable; an object outside the scope returns NotFound for
  both read and write.
- **AC-6** Two scoped grants union their reach: an object in either scope is
  accessible; an object in neither returns NotFound.
- **AC-7** A single grant never exceeds (role permissions ∩ scope): holding
  an unrelated broad group grant does not widen a narrow direct grant's role
  beyond that role's own permissions.
- **AC-8** Transitive READ: an object referenced by an in-scope object is
  readable without direct scope. Direct-WRITE: mutating that transitively
  reachable object without direct scope returns NotFound.
- **AC-9** Self scope: the caller reaches their own resource; another user's
  resource returns NotFound; an empty resource ID is rejected and never
  resolves to the caller.
- **AC-10** Cross-actor NotFound is byte-identical (status, message) to the
  true-absence NotFound for the same RPC.
- **AC-11** The recorded exception holds: an execution/log read by a scoped
  caller outside scope returns PermissionDenied.
- **AC-12** Removing/disabling the last enabled admin fails with
  FailedPrecondition; the state after the failed call still contains at least
  one enabled admin.
- **AC-13** Two concurrent admin-removing mutations (two admins removing each
  other) cannot both succeed: at least one enabled admin remains
  (advisory-lock atomicity, tested with real concurrency).
- **AC-14** A user whose only admin capability is group-inherited counts for
  last-admin purposes; removing them (or their group link) as the last such
  admin is refused.
- **AC-15** Grant mutations require the role-management permission; a caller
  holding ONLY role-management can grant a role containing permissions the
  caller does not hold (no ceiling).
- **AC-16** System-managed objects are absent from get, list, search,
  add-to-set (tested at nesting depth ≥ 2), and dispatch; direct mutation
  returns NotFound.
- **AC-17** Every RPC in the service descriptors carries exactly one
  classification; the guard fails when a test RPC is added unclassified; an
  unclassified RPC at runtime is denied.
- **AC-18** Calling a handler directly (interceptor bypassed) still enforces
  validation and authorization (defense in depth).
- **AC-19** List/search responses under a scoped grant exclude out-of-scope
  rows from items AND from reported totals.

## 5. Rejection paths

| Input / state | Required behavior |
|---|---|
| Unauthenticated call to a non-public RPC | Unauthenticated (interceptor; SPEC-007) — before any authorization or DB work |
| Malformed request field | InvalidArgument from validation, before authentication/authorization/DB work (AUTHZ-7 order) |
| Caller holds no grant of the required permission | PermissionDenied, static message |
| Caller holds the permission, object owned by another actor / outside every grant scope (read or write) | NotFound, byte-identical to true absence |
| WRITE to an object reachable only transitively (no direct scope) | NotFound |
| Execution/log read by a scoped caller outside scope | PermissionDenied (recorded exception — exactly these handlers) |
| `self`-scoped call with empty/absent resource ID | Rejected (validation); never resolved to the caller |
| Scoped grant used to exercise a global-only permission | Not authorized — the permission is inactive under that grant; object-level requests behave as "permission not held" |
| Grant create/modify/delete without role-management permission | PermissionDenied |
| Mutation that would leave zero enabled admins | FailedPrecondition, static message; state unchanged |
| Concurrent admin removals racing past the count | Impossible — serialized on the advisory lock; loser fails FailedPrecondition |
| Any access to a system-managed object (get/list/search/add-to-set at any depth/dispatch/mutate) | Invisible: absent from results; direct requests return NotFound |
| Self-service mutation of `linux_username` | Denied (admin-only; global grant required) |
| RPC with no classification | Fail-closed deny at runtime; build failure via guard |

## 6. Test plan (TDD)

Write these FIRST, confirm each fails for the right reason (red via a scoped
neutralizing edit — e.g., comment out the scope predicate or the advisory
lock — never via a revert), then implement.

1. **Catalog tests** (AC-1): load the catalog, assert total classification and
   rationale presence; add a fixture permission without classification and
   assert the guard fails.
2. **Effective-permission resolution** (AC-2, AC-3, AC-6, AC-7): pure
   resolution tests over event-sourced grants in real Postgres — union,
   stripping, intersection narrowing.
3. **Behavioral scope suites** (AC-5, AC-8, AC-9, AC-19): per confinable
   permission, against the REAL database and REAL handlers — never mocks or
   handler stubs. The correct/absent/wrong request-field cases are generated
   from validate tags by the SPEC-009 kernel harness; the scope cases here are
   the authorization-specific additions.
4. **Denial-parity tests** (AC-10, AC-11): capture the NotFound for a truly
   absent ID and the NotFound for a cross-actor ID; assert byte equality of
   status and message.
5. **Last-admin suite** (AC-12..14): includes a real-concurrency test — two
   goroutines, two sessions, opposing removals — asserting at least one
   enabled admin survives.
6. **No-ceiling test** (AC-15): granter with only role-management grants a
   super-role; assert success. This test is the regression fence against
   re-adding a ceiling.
7. **System-managed invisibility** (AC-16): seed a system-managed action;
   assert absence through every discovered path, including a set nested in a
   set.
8. **Defense-in-depth** (AC-18): invoke a handler function directly without
   the interceptor chain; assert validation and authorization still run.

Real-backend rule: every test in this spec runs against real Postgres
(testcontainer, template-cloned per test) and real handlers. No mocked store,
no stubbed authorization context beyond constructing a genuine session.

## 7. Guards

All guards are self-discovering with matches-zero protection: a guard whose
discovery step finds zero subjects FAILS (a stale discovery predicate must
never pass silently). Hand-maintained lists of permissions, handlers, or RPCs
are forbidden.

| Guard | Discovers | Proves |
|---|---|---|
| Catalog classification | Every permission in the catalog | Classified `confinable`/`global-only`; global-only entries carry rationale; catalog non-empty |
| RPC classification | Every RPC from the service descriptors | Exactly one of public/permission/alt-auth; validates before work; set non-empty |
| scopable == enforced | Every `confinable` permission from the catalog | A registered behavioral scoped-denial test exists per permission; registry non-empty; unmatched permission fails |
| Last-admin lock coverage | Every mutation path that can reduce the enabled-admin set (discovered from the event types that revoke roles, edit role permissions, disable/delete users, and change group membership/roles) | Each path acquires the last-admin advisory lock before the count check |
| System-managed invisibility | Every get/list/search/set-composition/dispatch path from the RPC registry | Each excludes system-managed objects; discovery non-empty |
| NotFound uniformity | Every object-denying handler | Denial maps to NotFound, except the enumerated execution/log handlers, each carrying an inline documented rationale |

## 8. Historical lessons

Inline rationale for rules above; each lesson is a bug class this design makes
structurally impossible.

- **Lesson (suffix-scope non-composition):** scoping encoded in permission-name
  suffixes did not compose with group-granted roles — a scoped user's group
  membership silently widened their reach. Grant-level scope with
  intersection-only composition (AUTHZ-3b) removes the composition seam
  entirely.
- **Lesson (empty-ID self bypass):** a self-scope check that treated an empty
  resource ID as "the caller's own" allowed cross-actor access via a blank
  ID. `self` never short-circuits on empty input.
- **Lesson (presence-based enforcement):** type-level checks that a handler
  "references" scope machinery passed while sibling list/dispatch handlers
  omitted the actual scope filter — the bypass shipped green. Enforcement is
  behavioral, proven against the real database (AUTHZ-4).
- **Lesson (sibling scope-filter drift):** hand-copied scope filters drifted
  between sibling handlers; one had the WHERE clause, its sibling did not.
  The single kernel implementation site (SPEC-009) makes the missing-filter
  class structurally impossible.
- **Lesson (existence oracle):** cross-actor denials that returned
  PermissionDenied leaked object existence to low-privilege callers. Uniform
  NotFound (AUTHZ-5).
- **Lesson (scattered last-admin checks):** per-handler last-admin checks
  missed group-inherited admins and raced concurrent removals, allowing an
  instance with zero admins. Centralized count + advisory-lock atomicity
  (AUTHZ-2).
- **Lesson (per-RPC invisibility patches):** system-managed objects were
  hidden from list but stayed reachable through search, add-to-set at depth,
  and dispatch — each hole patched individually as found. One
  self-discovering guard over all paths (AUTHZ-6).
- **Lesson (stale hardcoded guard lists):** hand-maintained lists of
  handlers/fields in enforcement checks went stale and failed open — new
  surfaces were simply never checked. Every guard discovers its subjects and
  fails on zero matches (Section 7).

## 9. Milestones

Each milestone is a single implementation session ending with the full suite
green (including all previously landed guards).

1. **Permission catalog + classification guard.** Catalog data structure,
   confinable/global-only classification with rationales, catalog-walking
   guard with matches-zero. (AC-1)
2. **Grant model + resolution.** Grant events and projections (SPEC-005
   patterns), effective-permission resolution: union, stripping,
   intersection narrowing. (AC-2, AC-3, AC-6, AC-7; AC-4 API surface)
3. **Interceptor chain + RPC classification guard.** Order
   validate → authenticate → authorize; descriptor-walk classification guard;
   runtime fail-closed deny for unclassified. (AC-17, AC-18 scaffolding)
4. **Object-scope enforcement + denial mapping.** Scope predicates wired
   through the SPEC-009 kernel seam; transitive-read/direct-write semantics;
   uniform NotFound with the recorded exception; behavioral scope test
   harness + scopable==enforced guard. (AC-5, AC-8..11, AC-19, AC-18)
5. **Last-admin protection.** Centralized count, advisory lock, lock-coverage
   guard, concurrency tests. (AC-12..14)
6. **Grant gate + no-ceiling fence.** Role-management as sole grant gate;
   the no-ceiling regression test. (AC-15)
7. **System-managed invisibility.** The single guard across all discovered
   paths; nested-set and dispatch coverage. (AC-16)

## 10. Out of scope

- Authentication, session lifecycle, token models, rate limiting (SPEC-007).
- The CRUD kernel's implementation of the single scope-filter site and the
  generated boundary tests (SPEC-009 — this spec defines semantics and the
  behavioral proof obligations).
- Audit events for authorization denials and secret-read views (SPEC-011).
- mTLS class authorization on machine seams (SPEC-003, SPEC-006) — this
  spec's `alt-auth` classification only names them.
- Web UI grant-editing surfaces (they consume AC-4's API; the UI itself is
  the web repo's concern).
- Any grant ceiling, deny rules, or read-tightening — rejected by operator
  decision, listed here so they are not "rediscovered" as improvements.
