# SPEC-007 M6 — OIDC sign-in

Spec milestone: SPEC-007 M6 (`AUTH-3`, `AUTH-6`; AC-7..AC-9).

## Acceptance criteria

1. `StartOidcSession` rejects an unknown provider or a redirect URI absent
   from that provider's exact server-side allowlist. HTTPS redirects and an
   explicitly allowlisted loopback HTTP redirect are accepted.
2. A successful start returns an authorization URL carrying
   `response_type=code`, `scope=openid email`, one-shot `state`, `nonce`, and
   PKCE S256 challenge fields. The raw state and code verifier never enter an
   event payload.
3. Login state is stored under a SHA-256 digest, expires after 10 minutes, and
   is consumed through one atomic `DELETE ... RETURNING`. Replay and expiry
   reject before session creation.
4. Callback consumes the state before exchanging the code through a
   no-redirect HTTP client with a fixed 12-second total timeout. Provider,
   redirect URI, and PKCE verifier come only from the consumed server state.
5. ID tokens accept only configured issuer, client audience, supported pinned
   signature algorithms/keys, valid expiry/issued-at bounds, non-empty
   subject, and the exact one-shot nonce.
6. A verified first identity creates a user and identity link as one
   all-or-nothing event batch; projections rebuild exactly with no partial
   user or link on invalid transitions.
7. Email auto-link requires `email_verified=true`. A claim for an account
   already linked to another provider additionally requires that provider's
   explicit `trust_email_assertions` opt-in.
8. Successful callback returns the ordinary access/rotating-refresh session;
   failed state, token exchange, ID-token, and trust checks return static
   non-oracular errors and create no session.
9. Both OIDC procedures are public, carry independent per-IP and per-account
   failed-attempt limits, and are covered by the exact RPC classification and
   public-policy guards.
10. The projection-write guard covers PAT and OIDC user/identity projection
    mutations, closing the carried-forward PAT table ownership gap.

## Design

<!-- docref: begin src=contract/proto/powermanage/v1/control.proto#ControlService.StartOidcSession:764ca368,contract/proto/powermanage/v1/control.proto#ControlService.CompleteOidcSession:2fde6e66,server/internal/store/migrations/016_oidc.sql#@oidc-schema:506e4a4b,server/internal/store/oidc_states.go#Store.StoreOIDCLoginState:657d14fb,server/internal/store/oidc_states.go#Store.ConsumeOIDCLoginState:702dc3e3,server/internal/store/users.go#UserCreatedEvent:7a3e5aff,server/internal/store/users.go#OIDCIdentityLinkedEvent:d53439d4,server/internal/auth/oidc.go#OIDCService:a1f9fe2e,server/internal/auth/oidc.go#NewOIDCService:bde6a5af,server/internal/auth/oidc.go#OIDCService.Start:27d8e356,server/internal/auth/oidc.go#OIDCService.Complete:b5434b73,server/internal/control/oidc.go#SessionService.StartOidcSession:d0fb85b5,server/internal/control/oidc.go#SessionService.CompleteOidcSession:cc47931b -->
- `contract/proto/powermanage/v1/control.proto`
  - `StartOidcSession`, `CompleteOidcSession`, and bounded request/response
    messages
- `server/internal/store/migrations/016_oidc.sql`
  - event-derived `users` and `oidc_identities` projections
  - operational, hash-keyed `oidc_login_states`
- `server/internal/store/users.go`
  - user-create and OIDC-link events, reads, projectors, rebuild target
- `server/internal/store/oidc_states.go`
  - insert, expiry cleanup, and atomic consume
- `server/internal/auth/oidc.go`
  - immutable provider registry and redirect allowlists
  - state/nonce/PKCE generation
  - bounded code exchange and RS256/ES256 JWKS verification
  - verified-email auto-create/link trust matrix
  - normal refresh-family session issuance
- `server/internal/control/oidc.go`
  - public RPC error mapping, trusted-proxy client IP resolution, and
    failure-only rate limiting
- generated contract/SQL bindings plus classification, recovery,
  projection-write, RPC, public-limit, event-definition, and corpus registries
<!-- docref: end -->

The implementation uses the Go standard library for OAuth form handling,
JWT/JWKS parsing, and signature verification; no new dependency is introduced.
OIDC discovery and dynamic provider registration are not required by the
approved milestone: endpoints, issuer, client credentials, trust policy, and
redirects are injected as validated provider configuration.

## Tests

<!-- docref: begin src=server/internal/store/oidc_states_test.go#TestOIDCState_ConsumesOnceExpiresAndStoresOnlyHash:307840e0,server/internal/store/users_test.go#TestUserProjection_CreatesLinksAndRebuildsAtomically:5279c090,server/internal/control/oidc_test.go#TestOIDCService_StartBuildsBoundPKCENonceAndAllowlistedRedirect:ba69620f,server/internal/control/oidc_test.go#TestOIDCService_CompleteRejectsReplayExpiryNonceIssuerAndAudience:7cd27724,server/internal/control/oidc_test.go#TestOIDCService_AutoLinkRequiresVerifiedEmailAndProviderTrust:0f735ba5,server/internal/control/oidc_test.go#TestOIDCService_CompleteCreatesOrdinaryRotatingSession:a1dec642,server/internal/control/oidc_test.go#TestOIDCHandler_UsesStaticErrorsAndFailureOnlyLimits:74db74e0,server/internal/auth/oidc_test.go#TestOIDCIDTokenVerification_AcceptsConfiguredRS256AndES256Keys:2f75bf1c -->
- `TestOIDCState_ConsumesOnceExpiresAndStoresOnlyHash`
- `TestUserProjection_CreatesLinksAndRebuildsAtomically`
- `TestOIDCService_StartBuildsBoundPKCENonceAndAllowlistedRedirect`
- `TestOIDCService_CompleteRejectsReplayExpiryNonceIssuerAndAudience`
- `TestOIDCService_AutoLinkRequiresVerifiedEmailAndProviderTrust`
- `TestOIDCService_CompleteCreatesOrdinaryRotatingSession`
- `TestOIDCHandler_UsesStaticErrorsAndFailureOnlyLimits`
- existing RPC-classification, public-rate-limit, golden-corpus,
  table-classification, recovery, and projection-write guards
<!-- docref: end -->
<!-- docref: begin src=server/internal/control/oidc_test.go#TestOIDCService_CompleteTreatsProviderOutageAsUnavailable:fa43e831 -->
- `TestOIDCService_CompleteTreatsProviderOutageAsUnavailable`
<!-- docref: end -->

## Verification status

- Passed: canonical four-module verify gate, including vet, staticcheck, full
  race suites, contract/architecture guards, generated-code checks, and docref.
- Failed: none.
- Skipped: the pre-existing dormant gateway-purity guard, reported explicitly
  by the canonical gate.

## Out of scope

- dynamic IdP CRUD APIs (SPEC-009)
- authorization roles and grants (SPEC-008)
- bootstrap-admin and first-boot admin grant (M7)
- SCIM users/groups and bearer authentication (M8)
- centralized `session_version` invalidation (M9)
