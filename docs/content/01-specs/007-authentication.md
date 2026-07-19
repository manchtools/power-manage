---
title: "SPEC-007 — Authentication"
---
# SPEC-007 — Authentication

Status: READY FOR IMPLEMENTATION
Builds on: SPEC-003 (wire-contract), SPEC-005 (event-store)
Enables: SPEC-008 (authorization), SPEC-009 (crud-kernel-search-and-domains), SPEC-011 (audit-and-retention)
Module(s): `contract/` (ControlService auth RPCs, ScimService), `server/` (control: token service, OIDC client, SCIM server, rate limiting, `bootstrap-admin` CLI); the web UI (separate repo) consumes this surface

## 1. Scope

Human and API-consumer authentication to control: OIDC sign-in, SCIM v2
provisioning, ES256 session JWTs, rotating refresh tokens with reuse
detection, scoped personal access tokens (PATs), the `control bootstrap-admin`
break-glass, per-account rate limiting, anti-enumeration, and session
invalidation. Machine identity (agents, gateways) is certificates and lives in
SPEC-006.

## 2. Context capsule

Minimum prior knowledge, restated:

- **Topology.** Control serves ControlService on `:8081` (HTTPS + JWT) to the
  browser and CLI, and ScimService to IdPs. The web UI is a vendor-hosted
  static SPA talking directly browser→control — it is CROSS-SITE to control.
  There is no shared cache tier; rate-limiter state is per-node in-memory
  (control is active/standby single-writer).
- **Interceptor order (boundary B1):** validate → authenticate → rate-limit →
  authorize → handler. Authorization itself is SPEC-008; this spec owns
  everything up to an authenticated principal.
- **Event store (SPEC-005).** Every state change is an event.
  `AppendEventWithVersion` (CAS) is MANDATORY for every one-time or
  bounded-use consume — including break-glass login URLs (ES-4, SPEC-005).
  Multi-event operations (user + role grant, SCIM group + mapping, SSO
  auto-create) use the all-or-nothing multi-append (ES-4, SPEC-005).
- **Wire contract (SPEC-003).** Errors travel as RPC status codes with
  static, non-oracular messages (WIRE-7, SPEC-003). Every request field
  crossing the boundary carries a full validate tag (WIRE-2, SPEC-003).
- **Audit (SPEC-011).** The event store IS the audit log. AUDIT-GAP posture:
  an audit append failure never blocks login/logout/refresh, but logs loudly
  and is doctor-visible (AUD-5, SPEC-011).
- **Client IP resolution (LIM-4):** rate limiters and audit actor-IP fields
  resolve the client IP by a right-to-left X-Forwarded-For walk from
  configured trusted proxies only — never the raw leftmost header value.

## 3. Requirements

### 3.1 Session tokens

- **[AUTH-1]** JWTs are ES256, pinned — any other `alg` is rejected
  (algorithm-confusion refusal). The signing keypair is minted at setup;
  the verification key is NON-secret (verification never confers minting).
  Access token lifetime 5 minutes; refresh token lifetime 7 days; token type
  is pinned (an access token never passes as a refresh token or vice versa).
  Expiry is distinguished from ALL other validation failures so clients
  refresh only on genuine expiry.
- JWT signing-key rotation invalidates all sessions (global logout) — a
  documented operational property, not an incident (SPEC-016).

### 3.2 Session invalidation

- **[AUTH-2]** `session_version` invalidation is centralized in ONE
  store-side projector reaction on the events that require it: user disable,
  role revoke, IdP unlink, SCIM deprovision. Never scattered per-handler. A
  session token minted before the bump fails authentication on next use.

### 3.3 OIDC-only sign-in and break-glass

- **[AUTH-3]** Human sign-in is OIDC-only. No local passwords, no TOTP, no
  backup codes, no passkeys — MFA, phishing resistance, lockout policy, and
  conditional access are the IdP's job. The ONLY non-IdP path is break-glass:
  - `control bootstrap-admin` runs on the control HOST. Host access IS the
    authorization — it is never an RPC.
  - It mints a single-use login URL (~10 min TTL), consumed via
    version-pinned CAS like every bounded-use token (ES-4, SPEC-005).
    Consuming the URL yields a normal Bearer session for the named admin
    identity.
  - First boot: no IdP is configured, so no user can exist. If the named
    identity does not exist, the command CREATES it with its admin role
    grant as ordinary events BEFORE minting the URL — no bootstrap
    circularity.
  - Every use is loudly audited. It never becomes an interactive login form.
  - Intended uses: first boot and IdP outage.
- **[AUTH-6]** OIDC is authorization-code flow with PKCE (S256) + `state` +
  `nonce`. The `state` is one-shot with a 10-minute TTL, consumed via atomic
  `DELETE … RETURNING`. Redirect targets come from a server-side allowlist
  (including loopback for the CLI flow). The outbound OIDC client is
  time-bounded (12 s). Auto-link by email happens ONLY when the IdP asserts
  `email_verified` AND — for accounts with existing higher-trust links — an
  explicit per-provider `trust_email_assertions` opt-in is set. A
  cross-provider claim of an already-linked user requires the same trust
  gate. Unknown or unconfigured issuer → rejected.

### 3.4 Token model (Bearer everywhere)

- **[AUTH-9]** Bearer tokens everywhere; no cookies. The vendor-hosted UI is
  cross-site to control, so ambient cookie credentials would resurrect CSRF
  for nothing. (A licensed customer serving the origin-agnostic UI bundle
  same-origin with control technically reopens the cookie option; the
  product default stays Bearer.)
  - Access token: 5 minutes, held in memory by the UI.
  - Refresh tokens ROTATE on every use with reuse detection: presenting a
    superseded refresh token revokes the ENTIRE token family, so a stolen
    refresh token dies at the victim's next legitimate refresh. Family
    revocation emits an audit event.
  - API consumers use first-class scoped PATs: hashed at rest, per-token
    audit identity, expiry, revocable. Never the browser flow.
  - Refresh tokens and PATs are hashed at rest; no secret appears in a URL
    query parameter.
  - The UI bundle ships strict CSP + Trusted Types.

### 3.5 Rate limiting and anti-enumeration

- **[AUTH-4]** Every `Public` procedure is in the rate-limit ladder — OIDC
  start/callback, token refresh, logout, SCIM, enrollment/renewal (the PKI
  listener, SPEC-006) — with BOTH per-IP and per-account failed-attempt
  limits. Limits count FAILURES only; there is NO hard lockout — a lockout
  is a targeted denial-of-service primitive against known usernames.
- **[AUTH-5]** Anti-enumeration on the remaining secret-bearing paths:
  refresh, PAT, and SCIM failures are byte- and timing-identical across
  nonexistent / revoked / expired / malformed causes. OIDC-only deletes the
  password-oracle surface outright.
- **[AUTH-8]** Trimming/normalization of tokens and identifiers happens
  BEFORE validation; token parsing failures return static errors carrying no
  parser detail.

### 3.6 SCIM v2 provisioning

- **[AUTH-7]** ScimService implements SCIM v2 users, groups, and discovery
  (boundary B3):
  - Authentication: per-provider bearer token, shown once at creation,
    bcrypt-stored, rotatable and disableable.
  - Failures return identical 401s; a missing provider burns a dummy bcrypt
    verification so timing does not distinguish existence.
  - Rate limits run BEFORE bcrypt (per-slug and per-slug+IP) — bcrypt cost
    must not be attacker-reachable ahead of the limiter.
  - Deprovision semantics: unlink the IdP identity; delete the user only
    when it was the LAST link, with crypto-shred of PII (AUD-4, SPEC-011).
  - Group sync maps SCIM groups to user groups; compound writes (group +
    mapping) are all-or-nothing multi-appends (ES-4, SPEC-005).

## 4. Acceptance criteria

- **AC-1** A JWT signed with any algorithm other than ES256 — including an
  HMAC token keyed with the public verification key — is rejected.
- **AC-2** An expired access token yields the distinct expiry error; every
  other invalid-token cause yields the generic static rejection. A client
  can distinguish exactly these two classes and nothing more.
- **AC-3** A refresh token presented as an access token (and vice versa) is
  rejected (token type pinned).
- **AC-4** Refresh rotation: using refresh token R1 yields R2 and invalidates
  R1. Presenting R1 again revokes the whole family — R2 and any successor
  stop working — and emits an audit event.
- **AC-5** Refresh/PAT failure responses are byte-identical and
  timing-indistinguishable (within test tolerance) across nonexistent,
  revoked, expired, and malformed inputs.
- **AC-6** A revoked PAT fails authentication; its per-token audit identity
  appears on actions performed before revocation.
- **AC-7** OIDC callback: a replayed `state` is rejected (one-shot atomic
  consume); a `state` older than 10 minutes is rejected; a nonce mismatch is
  rejected; an issuer not matching a configured provider is rejected.
- **AC-8** A redirect target absent from the server-side allowlist is
  rejected; the loopback CLI redirect is accepted.
- **AC-9** Auto-link: an ID token without `email_verified` never links to an
  existing account. A cross-provider claim of an already-linked user without
  `trust_email_assertions` is rejected; with the opt-in it links.
- **AC-10** `control bootstrap-admin` on first boot creates the admin
  identity + role grant as ordinary events, then mints a URL. The URL logs
  in exactly once; a second use is rejected (CAS); use after ~10 minutes is
  rejected. Both mint and consume are audited.
- **AC-11** No RPC in the contract accepts a password credential; no local
  password, TOTP, backup-code, or passkey surface exists (structural).
- **AC-12** SCIM: wrong bearer and nonexistent provider return identical
  401s; the nonexistent-provider path burns a dummy bcrypt; the limiter
  rejects before any bcrypt work once the rate is exceeded.
- **AC-13** SCIM deprovision of a user with two links removes only the link;
  deprovision of the last link deletes the user and crypto-shreds PII.
- **AC-14** After user disable, role revoke, IdP unlink, or SCIM
  deprovision, a previously minted session fails on next use — proven for
  all four events through the ONE central invalidation projector.
- **AC-15** Per-account failed-attempt limiting throttles after repeated
  failures but a subsequent CORRECT authentication still succeeds (no
  lockout); per-IP limiting is enforced independently, with the client IP
  resolved via the trusted-proxy XFF walk.
- **AC-16** Control sets no cookies and reads no cookies on any
  ControlService procedure.

## 5. Rejection paths

| Input / state | Required behavior |
|---|---|
| JWT `alg` ≠ ES256 (incl. HS256 with public key) | Reject, static message |
| Expired access token | Distinct expiry status (the only distinguishable failure) |
| Malformed / wrong-type / bad-signature token | Generic static rejection, identical across causes |
| Session minted before `session_version` bump | Reject on next use |
| Superseded (replayed) refresh token | Revoke entire family; audit event; generic rejection |
| Nonexistent / revoked / expired refresh token | Byte- and timing-identical generic rejection |
| Revoked / expired / nonexistent PAT | Byte- and timing-identical generic rejection |
| OIDC `state` replayed, expired, or unknown | Reject; state is one-shot (`DELETE … RETURNING`) |
| OIDC nonce mismatch | Reject |
| ID token from unknown / unconfigured issuer | Reject |
| Redirect target not allowlisted | Reject before redirect |
| `email_verified` absent/false on auto-link path | No link, no account creation via that claim |
| Cross-provider claim without per-provider trust opt-in | Reject link |
| Break-glass URL reused | Reject (CAS consume already spent) |
| Break-glass URL past TTL (~10 min) | Reject |
| Break-glass attempted as an RPC | Does not exist — host-side command only (structural) |
| Password / TOTP / passkey credential | Does not exist in the contract (structural) |
| SCIM wrong or missing bearer | Identical 401 + dummy bcrypt on nonexistent provider |
| SCIM rate exceeded | Reject BEFORE bcrypt |
| Failed-attempt limit exceeded | Throttle failures only; correct credential still succeeds (no lockout) |
| Cookie-borne credential | Ignored; never read |
| Unknown `PM_*` env var / unknown config key at boot | Boot failure (config discipline, SPEC-002) |

## 6. Test plan (TDD)

Write these FIRST, confirm each fails for the right reason (scoped
neutralizing edit, never a revert), then implement. Real Postgres
(testcontainer, template-cloned per test), REAL handlers through the real
interceptor chain — never stubs.

1. **Token service unit + handler tests:** AC-1..AC-3 (alg pinning, expiry
   distinction, type pinning). RED by disabling the alg pin and watching the
   HS256-with-public-key forgery pass.
2. **Refresh-family tests:** rotation chain, replay → family revocation,
   audit event emission (AC-4). Concurrency: two racing refreshes of the
   same token produce one winner and one family-revoking replay.
3. **Anti-enumeration parity:** table-driven byte-equality plus
   timing-distribution comparison across failure causes for refresh, PAT,
   SCIM (AC-5, AC-12).
4. **OIDC flow tests** against a local test IdP: PKCE enforcement, state
   one-shot/TTL, nonce, issuer allowlist, redirect allowlist, `email_verified`
   and trust-gate matrix (AC-7..AC-9). Correct / absent / wrong for every
   callback field per its validate tag.
5. **bootstrap-admin:** first-boot identity creation, single-use CAS consume
   race (two concurrent redemptions → one session), TTL expiry, audit
   events (AC-10). RED by swapping the CAS append for an auto-retrying
   append and watching the double-spend.
6. **PAT tests:** mint (shown once), hash-at-rest assertion, scope carriage,
   expiry, revocation, audit identity (AC-6).
7. **SCIM tests:** bearer auth matrix, dummy-bcrypt timing, limiter-before-
   bcrypt ordering, user/group sync round-trip, deprovision link-vs-last-link
   semantics with crypto-shred verification (AC-12, AC-13).
8. **Invalidation projector:** all four event types through the ONE
   projector; a fifth mutation path that should NOT invalidate leaves the
   session valid (AC-14).
9. **Rate limiting:** per-account failure throttling without lockout,
   per-IP independence, trusted-proxy XFF resolution (spoofed leftmost XFF
   from an untrusted peer is ignored) (AC-15).
10. **Golden corpus:** every auth event type's serialized form pinned
    (ES-9, SPEC-005).

Bug fixes ship a regression test that fails on the buggy version.

## 7. Guards

Self-discovering, matches-zero protected (a guard that discovers nothing
fails):

- **GUARD-007-1** Descriptor walk over every service: every RPC is
  classified exactly one of public / permission-gated / alt-auth, and the
  interceptor chain enforces validate → authenticate → rate-limit →
  authorize before the handler. Zero RPCs discovered = failure.
- **GUARD-007-2** Ladder coverage: every RPC classified `public` has a
  registered rate-limit policy with both per-IP and per-account dimensions
  where an account is in scope.
- **GUARD-007-3** Enumeration parity harness: discovers the secret-verifying
  endpoints (refresh, PAT, SCIM) and generates the byte- and
  timing-parity tests over their failure causes.
- **GUARD-007-4** Invalidation centrality: AST scan proves `session_version`
  is written only by the one registered projector; the invalidating event
  set in that projector is asserted against the enumerated list (user
  disable, role revoke, IdP unlink, SCIM deprovision).
- **GUARD-007-5** No-cookie scan: discovers all control HTTP handler
  surfaces and fails on any cookie read/write API usage; must visit > 0
  handlers.
- **GUARD-007-6** No-password-surface walk: contract descriptor walk fails
  on any field whose name/type indicates a password, TOTP, or WebAuthn
  credential; must visit > 0 messages.
- **GUARD-007-7** Secret-hygiene scan: refresh tokens, PATs, and SCIM
  bearers never appear in log fields, audit payloads, or URL query
  parameters (redaction-schema sweep, SPEC-011).

## 8. Historical lessons

- **Lesson (expiry ambiguity):** clients could not distinguish genuine
  expiry from other token-validation failures and refreshed on every error,
  masking real faults and hammering the refresh endpoint. The error contract
  distinguishes expiry from everything else — and only expiry.
- **Lesson (scattered invalidation):** session invalidation implemented
  per-handler left gaps — some disable/revoke paths never bumped the session
  version, so disabled principals kept working sessions. Invalidation is one
  projector reaction on an enumerated event set, guarded.
- **Lesson (lockout as a weapon):** hard account lockout on failed attempts
  hands an attacker a targeted denial-of-service against any known username.
  Rate limiting counts failures and throttles; it never locks out.
- **Lesson (enumeration oracle):** failure responses that differed across
  nonexistent / revoked / malformed credentials let an attacker enumerate
  valid accounts and tokens. Secret-verification failures are byte- and
  timing-identical, tested by a generated parity harness.
- **Lesson (email auto-link takeover):** auto-linking IdP identities by
  email allowed an account claim via an attacker-influenced provider
  asserting a victim's address. Linking requires `email_verified` plus an
  explicit per-provider trust opt-in for higher-trust targets, including
  cross-provider claims of already-linked users.
- **Lesson (bcrypt before limits):** running bcrypt verification before rate
  limiting makes the hash cost itself an amplification primitive. SCIM
  limits run before any bcrypt work, and nonexistent providers burn a dummy
  hash so timing stays flat.
- **Lesson (double-spend consumes):** bounded-use tokens consumed via an
  auto-retrying append defeated the optimistic lock (racing consumers each
  succeeded). Every one-time consume — break-glass URLs included — is a
  version-pinned CAS append (ES-4, SPEC-005).

## 9. Milestones

Each ends green (vet, staticcheck, full `-race` suite):

1. **Token primitives.** Setup-minted ES256 keypair, mint/verify with alg
   and type pinning, expiry-distinct errors (AC-1..AC-3). GUARD-007-6.
2. **Interceptor chain + classification.** validate → authenticate →
   rate-limit → authorize ordering; RPC classification registry.
   GUARD-007-1, GUARD-007-5.
3. **Rate-limit ladder.** Per-IP + per-account failure limiting,
   trusted-proxy XFF resolution, ladder registry (AC-15). GUARD-007-2.
4. **Refresh families.** Rotation, reuse detection, family revocation,
   hashed-at-rest storage, audit events (AC-4, AC-5). GUARD-007-3 for
   refresh.
5. **PATs.** Mint/scope/expiry/revoke, hashed at rest, per-token audit
   identity (AC-6); parity harness extended to PATs.
6. **OIDC sign-in.** Provider configuration, code flow with PKCE/state/nonce,
   one-shot state, redirect allowlist, auto-link trust matrix
   (AC-7..AC-9).
7. **bootstrap-admin.** Host-side CLI, first-boot identity creation,
   CAS-consumed single-use URL, audit trail (AC-10, AC-11).
8. **SCIM.** Bearer auth with dummy-bcrypt parity, limiter-before-bcrypt,
   users/groups sync, deprovision + crypto-shred integration
   (AC-12, AC-13); parity harness extended to SCIM.
9. **Central invalidation.** The one `session_version` projector over the
   four event types (AC-14). GUARD-007-4. Golden corpus for all auth
   events.

## 10. Out of scope

- Authorization: roles, grants, scope confinement, last-admin protection
  (SPEC-008).
- Audit mechanics, redaction schemas, crypto-shred implementation
  (SPEC-011).
- Machine identity: agent/gateway certificates, enrollment, CRL (SPEC-006).
- The CRUD kernel the authenticated RPCs flow into (SPEC-009).
- Web UI implementation (separate repo; it consumes this contract).
- Config loading and env-override discipline (SPEC-002).
- HA/failover behavior of limiter state and key rotation runbooks
  (SPEC-016).
