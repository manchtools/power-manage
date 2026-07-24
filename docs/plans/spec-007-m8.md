# SPEC-007 M8 — SCIM v2 provisioning

Spec milestone: SPEC-007 M8 (`AUTH-7`; AC-12, AC-13).

## Acceptance criteria

1. SCIM remains a pure `application/scim+json` HTTP boundary. No protobuf
   service, RPC, or credential field is added.
2. A provider bearer is generated from 256 bits of entropy, returned only at
   create or rotation, bcrypt-hashed at rest, and can be rotated or disabled
   through the internal provider-management service.
3. Every SCIM request is checked against independent per-provider and
   per-provider-plus-client-IP failure windows before any bcrypt comparison.
   Requests over either limit return a static 429 without bcrypt work.
4. Existing-provider wrong bearers, disabled providers, malformed bearers,
   and nonexistent providers make exactly one real-or-dummy bcrypt comparison
   and return byte-identical static 401 responses.
5. The provider-scoped HTTP surface implements SCIM discovery plus bounded
   user and group create/read/list/replace/deprovision operations. JSON bodies
   are bounded and strict, responses are cache-disabled and cookie-free, and
   client errors disclose no parser, database, or bcrypt detail.
6. User creation either links the provider to the existing canonical-email
   user or atomically creates and links a new user. Deprovision removes only
   that provider link while another OIDC/SCIM link remains; removing the last
   link also emits `SCIMUserDeprovisioned` and deletes the live user/identity
   projection.
7. Historical audit-payload encryption-key destruction remains owned by
   SPEC-011 as stated in SPEC-007's out-of-scope section. M8 emits the
   PII-free terminal deprovision fact that activates that mechanism and proves
   no live PII remains after last-link deprovision.
8. Group create/replace writes the group fact and complete membership mapping
   as one all-or-nothing event batch. Missing members roll back both events.
9. Every SCIM/provider/group event is in the golden corpus and its projections
   are rebuildable, classified, and covered by projection-write and
   secret-hygiene guards.
10. The enumeration parity registry discovers SCIM alongside refresh and PAT
    and pins malformed, nonexistent, disabled, and wrong-secret causes.

## Design

<!-- docref: begin src=server/internal/store/migrations/018_scim.sql:9dec120d,server/internal/store/scim.go#SCIMProviderCreatedEvent:1ef3ffff,server/internal/store/scim.go#SCIMIdentityUnlinkedEvent:da35bd94,server/internal/store/scim.go#SCIMUserDeprovisionedEvent:f396cedb,server/internal/store/scim.go#SCIMGroupMembershipsReplacedEvent:47e5ccb8,server/internal/auth/scim.go#NewSCIMProviderManager:067fa74b,server/internal/auth/scim.go#NewSCIMFailureLimiter:9456c090,server/internal/auth/scim.go#SCIMAuthenticator.Authenticate:69201277,server/internal/control/scim.go#NewSCIMHTTPHandler:7e0cb919 -->
- `server/internal/store`
  - event-derived provider, SCIM identity, group, and membership projections;
  - provider tokens persist only bcrypt hashes;
  - user-link removal and terminal deprovision are distinct events so M9 has
    one explicit invalidation fact.
- `server/internal/auth`
  - provider token mint/rotation/disable manager;
  - a bounded sliding-window SCIM failure limiter with separate provider and
    provider+IP keys;
  - an authenticator that performs the limiter check before one real/dummy
    bcrypt comparison.
- `server/internal/control`
  - provider-scoped `/scim/v2/{provider}/...` discovery, Users, and Groups
    endpoints using SCIM JSON rather than protobuf.
<!-- docref: end -->

## Tests — implemented and passing

<!-- docref: begin src=server/internal/store/scim_test.go#TestSCIMProviderProjection_RotatesDisablesAndRebuildsHashOnly:457e6129,server/internal/store/scim_test.go#TestSCIMIdentityProjection_UnlinksOneOfTwoAndDeletesLastLink:97e30981,server/internal/store/scim_test.go#TestSCIMGroupProjection_AtomicMembershipReplaceAndRebuild:a48515a6,server/internal/auth/scim_test.go#TestSCIMFailureLimiter_ChecksProviderAndProviderIPBeforeRecording:89e77341,server/internal/control/scim_test.go#TestSCIMAuthentication_IdenticalFailuresBurnOneRealOrDummyBcrypt:d7b365ac,server/internal/control/scim_test.go#TestSCIMAuthentication_FailureCausesHaveTimingParity:e78b4570,server/internal/control/scim_test.go#TestSCIMHTTP_UserGroupAndDiscoveryRoundTrip:b65cc009,server/internal/control/scim_test.go#TestSCIMHTTP_GroupReplacementRejectsMissingMemberAtomically:58aa0861 -->
The following red-first acceptance tests are implemented and pass:

- provider create/rotate/disable, one-time secret return, bcrypt-only durable
  state, and rebuild;
- identical wrong/nonexistent/disabled/malformed 401 bytes with one comparison;
- limiter-before-bcrypt ordering for provider and provider+IP dimensions;
- actual bcrypt timing-distribution comparison for existing and missing
  providers;
- discovery resources and strict bounded SCIM JSON;
- user create/read/list and existing-email linking;
- two-link deprovision keeps the user; last-link deprovision removes live PII
  and emits the terminal fact;
- group create/replace round trip and invalid-member atomic rollback;
- event corpus, rebuild, table classification, recovery registry,
  projection-write guard, no-cookie scan, no-proto-service guard, and extended
  enumeration parity profile.
<!-- docref: end -->

## Out of scope

- centralized `session_version` invalidation (M9);
- general roles, grants, and authorization-group resolution (SPEC-008);
- CRUD management RPCs for SCIM provider configuration (SPEC-009);
- audit-payload encryption and historical PII key destruction (SPEC-011);
- a networked control-server binary (its owning runtime milestone).
