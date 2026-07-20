---
title: "SPEC-009 — CRUD Kernel, Search, and Domains"
---
# SPEC-009 — CRUD Kernel, Search, and Domains

Status: READY FOR IMPLEMENTATION
Builds on: SPEC-005 (event-store), SPEC-007 (authentication), SPEC-008 (authorization)
Enables: SPEC-011, SPEC-012, SPEC-014, SPEC-015
Module(s): server (kernel, search, limits), contract (domain messages, validate tags)

## 1. Scope

The management API of the control server: the single table-driven CRUD kernel
[API-1], the ~20 management domains as product surface [WIRE-11], nestable action
sets, the single Postgres-FTS read path for lists and search [SRCH-1..4], and
request-boundary hardening [LIM-1..4].

## 2. Context capsule

Minimum prior knowledge, restated:

- **Event store (SPEC-005):** every state change is an append via `AppendEvent`,
  `AppendEventWithVersion` (CAS — mandatory for bounded-use consumes), or
  `AppendEvents` (all-or-nothing). Projectors run inside the append transaction;
  appending an unregistered event type is a hard error; a projector error aborts
  the transaction (ES-4, ES-7). Async work is a Postgres work table written in the
  same transaction (ES-8).
- **Authentication (SPEC-007):** browser/CLI requests carry Bearer JWTs (ES256);
  API consumers use scoped API tokens. Interceptor order on the management
  surface: validate → authenticate → rate-limit → authorize → handler.
- **Authorization (SPEC-008):** scope lives on the GRANT — (principal, role,
  scope) with scope ∈ {global, device-group set, user-group set, self}. Every
  permission is scope-confinable except an enumerated global-only set (AUTHZ-3).
  READ is effective/transitive; WRITE requires direct scope (AUTHZ-4). Cross-actor
  access returns NotFound uniformly (AUTHZ-5). System-managed objects are
  immutable and invisible through every path (AUTHZ-6). Enforcement is
  behavioral — proven against the real database, never presence-based type checks.
- **Wire contract (SPEC-003):** every field crossing a trust boundary carries a
  `validate` tag with type/format/length/range constraints; enum bounds are
  generated from the descriptor (WIRE-2). Updates are full-object-replace with an
  expected-version field (OCC); assignments are immutable — delete-and-recreate
  (WIRE-9). Errors are RPC status codes with static, non-oracular messages
  (WIRE-7). IDs are bare ULIDs (WIRE-5). There is exactly ONE `ActionParams`
  message and ONE action shape (WIRE-12/13).
- **Threat focus:** the primary adversary at this surface is the authenticated
  low-privilege user (actor 2, SPEC-001) — IDOR, scope bypass, information
  oracles — plus resource-exhaustion from anyone who can reach the edge.

## 3. Requirements

### 3.1 The CRUD kernel

- **[API-1]** The management API is ONE table-driven CRUD kernel:
  `validate → authorize(+scope) → append(+project in-tx) → respond`, implemented
  once. A domain is CONFIGURATION: message type, permission, projector,
  searchable columns. Scope filtering exists in exactly one place — the
  missing-scope-filter sibling-drift class becomes structurally impossible — and
  the correct/absent/wrong boundary tests are GENERATED from the validate tags,
  not hand-written per handler. Genuinely custom flows (dispatch, terminal
  grants, PKI, audit export, artifact upload) sit BESIDE the kernel, never wedged
  inside it.
- **[API-2]** Kernel pipeline order is absolute: validation completes before any
  authorization observation; authorization (permission + scope) completes before
  any domain work or database observation of the target object beyond what scope
  resolution requires; the append (with in-tx projection) is the only mutation
  path. Where the row must be loaded before denial can be decided, denial is
  remapped to NotFound (AUTHZ-5, SPEC-008).
- **[API-3]** Kernel updates implement WIRE-9 exactly: full-object replace with
  expected version; a version mismatch is a conflict error, never a partial
  merge. Kernel deletes append a delete event; projections drop the row via the
  registered projector.
- **[API-4]** Every kernel domain's mutation events and projections follow
  SPEC-005 discipline unchanged; the kernel adds NO second projection mechanism.

### 3.2 Management domains [WIRE-11]

The ~20 domains of the predecessor are product surface, not debt. The contract
(SPEC-003) is the authoritative RPC enumeration; the table below is the normative
domain inventory and its kernel/custom classification.

| Domain | Kernel CRUD | Custom flows beside the kernel |
|---|---|---|
| Users | yes | SCIM provisioning writes (SPEC-007) |
| Roles & grants | yes | last-admin atomicity lock (AUTHZ-2, SPEC-008) |
| User groups | yes | — |
| Devices | read/update/delete | enrollment via PkiService (SPEC-006); delete triggers cert revocation |
| Device groups (static + dynamic query) | yes | dynamic-group evaluation is async work (ES-8, SPEC-005) |
| Actions | yes | — |
| Action sets (nestable) | yes | write-time cycle validation (§3.3) |
| Assignments | create/delete only (immutable, WIRE-9) | converge-now dispatch (SPEC-012) |
| Compliance policies | yes | group/fleet rollup read views |
| Registration tokens | yes | CAS consume inside PkiService (SPEC-006) |
| API tokens | yes | — |
| Identity providers (OIDC) | yes | SSO callback flow (SPEC-007) |
| SCIM provisioning config | yes | SCIM endpoints (SPEC-007) |
| Server settings | yes | — |
| Audit | read (list) | export is unary chunked (AUD-6, SPEC-011) |
| Executions | read | output reads LIMIT-bounded (LIM-2) |
| Inventory | read | snapshot ingest from the device plane (ES-10, SPEC-005) |
| Terminal grants | — | signed-command flow (SPEC-003, SPEC-012) |
| Gateways | read | registration is stream presence (SPEC-012) |
| Artifacts | — | chunked upload RPC (ART-3, SPEC-010) |

- **[DOM-1]** Every ControlService RPC is either (a) served by the kernel via a
  domain registration, or (b) on the enumerated custom-flow list. A
  descriptor-walking guard proves the classification is total (exact-set,
  matches-zero protected). Adding an RPC without classifying it fails CI.

### 3.3 Nestable action sets

There is NO separate Definitions layer. Composition ("client setup") is a set of
sets.

- **[SET-1]** An action set is an ordered list of members; a member is an action
  OR another set. Sets form a DAG.
- **[SET-2]** Cycle rejection happens at WRITE time: creating or updating a set
  that would introduce a cycle (including self-reference, at any depth) is a
  validation error. No cyclic state is ever persisted.
- **[SET-3]** Dispatch flattens the DAG depth-first in declared order. An action
  reachable more than once executes ONCE — first occurrence wins.
- **[SET-4]** Execution semantics of the flattened sequence are serial with
  abort-on-first-failure (agent-side contract, SPEC-013).
- **[SET-5]** System-managed actions are immutable and invisible through
  add-to-set at ANY nesting depth, as through every other path (AUTHZ-6,
  SPEC-008) — enforced by the same self-discovering guard, not a per-RPC patch.

### 3.4 Search and lists

- **[SRCH-1]** ONE read path for list pages: Postgres FTS over the projections
  (`tsvector` + GIN for full-text, `pg_trgm` for fuzzy/substring), in the same
  database as everything else. Detail RPCs read the same projections. Honest
  totals. No second search store, no indexer binary, no client-side filtering.
- **[SRCH-2]** Scope confinement IS the handler's scope filter: list/search
  queries apply the same WHERE-clause scope predicates as every other read,
  fail-closed sentinel included — an empty resolved scope set produces a
  matches-nothing predicate, never an absent predicate. There is no second
  authorization representation to keep in parity: one code path, behaviorally
  tested (AUTHZ-4, SPEC-008).
- **[SRCH-3]** FTS columns are maintained in-tx with the projection write
  (generated columns or projector-set), so search is transactionally fresh —
  read-after-write everywhere, no reconcile loop, no rebuild RPC (projection
  rebuild rebuilds search by construction, ES-2/ES-7, SPEC-005). A
  descriptor-walking parity test proves every filterable API field maps to an
  indexed column, matches-zero guarded.
- **[SRCH-4]** Global search: ONE cross-domain endpoint on ControlService
  drives the UI's global search box. It fans the query out to the per-domain
  FTS queries (SRCH-1) and returns results grouped by domain with honest
  per-domain totals. The domain set is discovered from the domain registry —
  never a hardcoded entity list — so a newly registered searchable domain is
  globally searchable by construction. Each per-domain sub-query IS the
  domain's own list/search query: same scope predicates and fail-closed
  empty-scope sentinel (SRCH-2), same system-managed invisibility (AUTHZ-6).
  A domain the caller lacks list permission for is simply absent from the
  response — never an error, never a count leak.

### 3.5 Request-boundary hardening

- **[LIM-1]** `ReadMaxBytes` on every handler surface (Control, Internal,
  Gateway, agent stream — the shared helper is consumed by SPEC-012/013);
  pagination-offset ceiling; DB `statement_timeout` plus a per-handler deadline;
  parser recursion depth cap (~100); rate-limited whole-table dynamic-group
  evaluations.
- **[LIM-2]** Per-execution output budget enforced where results enter control
  (the gateway-stream boundary): byte cap AND chunk-count cap with an explicit
  truncation marker in the execution record. Output-chunk reads are
  LIMIT-bounded.
- **[LIM-3]** No `context.Background()` in request paths. Detached work uses
  `context.WithoutCancel` + timeout, allowlisted by function. Background
  goroutines carry `recover()`.
- **[LIM-4]** Trusted-proxy IP resolution: right-to-left X-Forwarded-For walk
  from configured trusted peers only. The resolved client IP is used by every
  rate limiter and every audit actor-IP field. A request arriving from an
  untrusted peer uses the peer address; its XFF header is ignored.

## 4. Acceptance criteria

- **AC-1** Kernel pipeline order: a request failing validation produces no
  database observation of the target object and no authorization evaluation
  side effects; a request failing authorization produces no append.
- **AC-2** Registering a new domain (message type, permission, projector,
  searchable columns) — with NO new handler code — yields working create, get,
  list/search, update (OCC), and delete, all scope-filtered, on a sample domain.
- **AC-3** The boundary-test generator discovers every kernel-domain request
  field from the proto descriptors and emits correct / absent / wrong cases per
  field, where "wrong" violates the field's validate tag; the generator fails if
  it discovers zero fields for any registered domain.
- **AC-4** Scoped-grant behavior, per domain, against real Postgres: list, search,
  and get return only in-scope rows; an out-of-scope get returns NotFound; an
  out-of-scope write is denied with NotFound (uniform per AUTHZ-5, SPEC-008);
  an empty scope set matches nothing.
- **AC-5** Writing a set that references itself, or that closes a cycle through
  N≥2 intermediate sets, is rejected at write time with a validation error and
  persists nothing.
- **AC-6** Dispatching a nested set flattens depth-first in declared order; an
  action reachable through two paths appears exactly once, at its first
  occurrence position.
- **AC-7** A row created in one request is visible to list, search, and detail
  reads in the immediately following request (transactional freshness — no
  eventual consistency window).
- **AC-8** List totals equal the count of scope-confined, filter-confined rows —
  never the unfiltered table count.
- **AC-9** The FTS parity guard maps every filterable API field to an indexed
  column and fails when it discovers zero filterable fields.
- **AC-10** Oversized request bodies are refused at the transport
  (`ReadMaxBytes`); pagination offsets beyond the ceiling are rejected; every
  handler runs under a deadline and every statement under `statement_timeout`;
  parser recursion beyond the cap is rejected.
- **AC-11** Execution output beyond the byte or chunk budget is truncated with an
  explicit truncation marker persisted in the execution record; output reads are
  LIMIT-bounded.
- **AC-12** The `context.Background()` guard fails on an injected violation in a
  request path and passes on the allowlisted detached-work functions.
- **AC-13** A forged XFF from an untrusted peer does not change the resolved
  client IP; a trusted-proxy chain resolves right-to-left to the true client;
  rate-limit buckets and audit actor-IP use the resolved value.
- **AC-14** For a caller with mixed grants, the global-search response equals
  the union of what each domain's own search returns for the same query,
  grouped per domain with honest totals; domains the caller cannot list and
  out-of-scope rows are absent (not errors); a row created in the previous
  request is found (AC-7 freshness holds through the global path).

## 5. Rejection paths

| Input / state | Required rejection behavior |
|---|---|
| Field violating its validate tag (any kernel domain) | Invalid-argument status, static message; no DB observation, no append |
| Update with stale expected version (WIRE-9 OCC) | Conflict error; no partial merge, no append |
| Out-of-scope object read (get/list/search) | Row absent from results; direct get returns NotFound (AUTHZ-5) |
| Out-of-scope write | Denied with uniform NotFound (AUTHZ-5, SPEC-008) |
| System-managed object via get/list/search/add-to-set/dispatch | Invisible/refused uniformly at any nesting depth (AUTHZ-6) |
| Set write introducing a cycle (any depth, incl. self-reference) | Validation error at write time; nothing persisted |
| Request body over `ReadMaxBytes` | Refused at the transport before handler code runs |
| Pagination offset above the ceiling | Invalid-argument status |
| Parser recursion beyond the cap | Invalid-argument status; no unbounded descent |
| Statement exceeding `statement_timeout` / handler deadline | Query canceled; deadline error to the caller |
| Execution output beyond byte/chunk budget | Stored truncated with explicit truncation marker; never unbounded |
| XFF header from an untrusted peer | Ignored; peer address used for rate limiting and audit |
| Global search touching a domain the caller cannot list | Domain absent from the response — no error status, no count leak |
| Unclassified ControlService RPC (neither kernel nor custom list) | CI failure via DOM-1 guard; unmergeable |

## 6. Test plan (TDD)

All tests run against REAL Postgres via testcontainers (template-cloned per test)
and REAL handlers — never mocks or stubs of either: the kernel's value claim is
that validation, authorization, and scope filtering actually run, which only a
real handler proves. Every test is written first and confirmed RED for the right
reason via a scoped neutralizing edit, never a revert.

Order of work:

1. **Kernel pipeline tests** on one reference domain: AC-1 (order), AC-2
   (registration completeness), OCC conflict, delete projection.
2. **Generator tests**: the correct/absent/wrong generator against the reference
   domain; assert the generated wrong-case actually violates the tag and is
   rejected (AC-3). Confirm the generator itself fails on zero discovered fields.
3. **Scope suite** (generated per domain): AC-4 across list/search/get/write,
   empty-scope sentinel, cross-actor NotFound.
4. **Set tests**: cycle rejection (self, deep), flatten order, first-wins dedup
   (AC-5, AC-6); system-managed invisibility at depth (SET-5).
5. **Search tests**: read-after-write freshness (AC-7), honest totals (AC-8),
   substring/fuzzy behavior via `pg_trgm`, parity guard red case (AC-9);
   global-search union parity against per-domain search under mixed grants,
   permission-absent domains, freshness through the global path (AC-14).
6. **Limit tests**: transport-level size refusal, offset ceiling, deadline and
   statement-timeout behavior, recursion cap, output truncation marker
   (AC-10, AC-11), XFF resolution matrix (AC-13).

## 7. Guards

Self-discovering, matches-zero protected (META-2, SPEC-000):

| Guard | Discovery source | Fails when |
|---|---|---|
| RPC classification (DOM-1) | ControlService proto descriptors | An RPC is neither kernel-registered nor on the custom-flow list; zero RPCs discovered |
| Validate-before-work / auth order (AUTHZ-7) | Proto descriptors + interceptor wiring | Any RPC unclassified as public / permission / alt-auth, or reachable without validation |
| Boundary-test generation | Proto descriptors + validate tags | Any kernel-domain field without generated correct/absent/wrong cases; zero fields discovered |
| FTS parity (SRCH-3) | Descriptor walk of filterable fields → index catalog | A filterable field with no indexed column; zero fields discovered |
| Global-search coverage (SRCH-4) | Domain registry walk vs the global endpoint's fan-out set | A registered searchable domain absent from global search; zero domains discovered |
| Scope-filter behavior | Domain registry walk emitting per-domain behavioral tests | Any registered domain lacking the scope suite; zero domains discovered |
| System-managed invisibility (SET-5 / AUTHZ-6) | Registry of read/list/search/add-to-set/dispatch paths | Any path returning a system-managed object |
| `context.Background()` ban (LIM-3) | AST scan of request paths, allowlist keyed by function | A request path constructs `context.Background()`; zero paths scanned |
| Enum switch exhaustiveness (WIRE-4) | Descriptor walk | A switch over a contract enum without an erroring default |

## 8. Historical lessons

- **Lesson [API-1]:** Scope filtering was reimplemented per handler in the
  predecessor; list and dispatch siblings drifted, and some shipped with no scope
  filter at all — a read-bypass class found repeatedly in audits. One kernel, one
  filter site, ends the class structurally.
- **Lesson [SRCH-1]:** A dedicated search store brought a second query syntax
  whose escaping broke (user input produced syntax errors), boot loops when its
  index was missing, and a duplicated copy of scope tags that had to be kept in
  parity with the database by hand. One store, one read path.
- **Lesson [SRCH-1]:** List pages and search returned different result sets and
  totals because two read paths coexisted; client-side filtering papered over the
  difference and broke pagination honesty.
- **Lesson [LIM-1]:** Unbounded request sizes, unbounded parser recursion, and
  unthrottled whole-table dynamic-group evaluation each produced
  denial-of-service conditions in the predecessor.
- **Lesson [LIM-2]:** Execution output entered the server uncapped, flooding
  durable storage; caps and truncation markers were retrofitted after the fact.
  Here they are boundary contract from day one.
- **Lesson [AC-3]:** An over-strict `url` validate tag rejected legitimate
  repository URLs carrying template variables (e.g. `$releasever`); tags must
  encode the REAL input grammar — the generated wrong-cases test the tag, and
  round-trip tests keep the tag honest against real inputs.
- **Lesson (§7):** Hand-maintained lists of handlers/files/fields in checks went
  stale and failed open — a dead redaction map passed review for months. Every
  guard above discovers its population and fails on an empty match set.

## 9. Milestones

Each milestone is one implementation session ending green.

1. **M1 — Kernel core**: pipeline (validate → authorize(+scope) → append →
   respond), domain registry, one reference domain end-to-end with OCC updates
   and scope filtering. Tests: AC-1, AC-2.
2. **M2 — Generators + guards**: boundary-test generator from validate tags;
   DOM-1 classification guard; auth-order guard; `context.Background()` ban.
   Tests: AC-3, AC-12.
3. **M3 — Domain rollout**: register the remaining kernel domains in batches;
   generated scope suites green per batch. Tests: AC-4 per domain.
4. **M4 — Nestable sets**: DAG storage, write-time cycle rejection, depth-first
   flatten with first-wins dedup, system-managed invisibility at depth.
   Tests: AC-5, AC-6.
5. **M5 — Search**: FTS columns in-tx, one list/search read path, honest totals,
   parity guard, global-search endpoint over the domain registry (SRCH-4).
   Tests: AC-7..9, AC-14.
6. **M6 — Limits**: size caps, offset ceiling, deadlines/statement timeouts,
   recursion cap, output budgets + truncation marker, XFF resolution.
   Tests: AC-10, AC-11, AC-13.

## 10. Out of scope

- The concrete RPC/message definitions and validate-tag grammar — SPEC-003.
- Authentication mechanics (JWT, tokens, OIDC, SCIM) — SPEC-007.
- The permission catalog, grant model, last-admin lock — SPEC-008.
- Dispatch transport, pending-command delivery, gateway streams — SPEC-012.
- Action-type semantics and the flattened sequence's on-device execution —
  SPEC-013, SPEC-014.
- Audit events for kernel mutations (structural via the event store) and audit
  export — SPEC-011.
- Artifact upload/fetch internals — SPEC-010.
- PKI enrollment/renewal flows — SPEC-006.
