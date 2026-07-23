# SPEC-007 M7 — bootstrap-admin break-glass

Spec milestone: SPEC-007 M7 (`AUTH-3`; AC-10, AC-11).

## Acceptance criteria

1. `control bootstrap-admin` is a host-side command only. It is absent from
   every protobuf service and accepts no password, TOTP, backup-code, or
   passkey credential.
2. On first boot, the command creates the named user and its bootstrap admin
   role grant as an all-or-nothing event batch before minting the login URL.
   Existing users are reused without creating a second identity.
3. Minting uses a fresh 256-bit secret and persists only its SHA-256 digest.
   The raw secret appears only in the returned URL fragment, never in an event,
   database row, log field, argv value, or query parameter.
4. The login URL is derived from one configured HTTPS base URL (explicit
   loopback HTTP is accepted), carries a ten-minute expiry, and is emitted only
   after the durable mint event commits.
5. Consumption normalizes and bounds the presented token, resolves it by
   digest, and appends `BootstrapLoginConsumed` with the projection's exact
   expected version. It never uses the auto-retrying append path.
6. Two concurrent consumers of one URL produce exactly one ordinary
   access/rotating-refresh session. Replay, unknown token, malformed token, and
   expiry return the same static rejection.
7. Mint and consume are ordinary golden-corpus events. Their projection is
   rebuildable and every new table remains covered by classification,
   recovery, and projection-write guards.
8. The non-RPC HTTP consume surface is POST-only, bounded, JSON-only,
   cache-disabled, cookie-free, and maps rejection and unavailability to static
   responses without parser or persistence detail.
9. The shipped `control` binary uses the shared typed config loader, reads the
   Postgres DSN from an owner-only bounded regular file, and has a config
   documentation test.

## Design

<!-- docref: begin src=server/internal/store/migrations/017_bootstrap_admin.sql#@bootstrap-admin-schema:a9c8f730,server/internal/store/users.go#BootstrapAdminRoleGrantedEvent:99fd0323,server/internal/store/bootstrap_admin.go#BootstrapLoginMintedEvent:95b92d6d,server/internal/store/bootstrap_admin.go#BootstrapLoginConsumedEvent:625f77ef,server/internal/auth/bootstrap_admin.go#BootstrapAdminMinter.Mint:396dff40,server/internal/auth/bootstrap_admin.go#BootstrapAdminConsumer.Consume:d223a188,server/internal/control/bootstrap_admin.go#NewBootstrapAdminHTTPHandler:5e07128d,server/cmd/control/main.go#run:d0d6edf4 -->
- `server/internal/store`
  - `BootstrapAdminRoleGranted` advances the user stream after first-boot
    creation; authorization resolution remains owned by SPEC-008.
  - `BootstrapLoginMinted` and `BootstrapLoginConsumed` own a dedicated
    one-time-login stream and hash-only projection.
- `server/internal/auth`
  - a minter owns user creation, admin-grant audit, entropy, expiry, and URL
    construction;
  - a consumer owns digest lookup, exact-version consume, and ordinary refresh
    session creation.
- `server/internal/control`
  - a small non-Connect POST handler decodes the fragment-derived token from a
    bounded JSON body and returns the ordinary Bearer token pair.
- `server/cmd/control`
  - `bootstrap-admin --config <path>` is the only M7 command;
  - email, login base URL, and DSN-file path come from typed configuration, so
    no secret-valued argv flag exists.
<!-- docref: end -->

## Tests

<!-- docref: begin src=server/internal/store/bootstrap_admin_test.go#TestBootstrapAdminProjection_FirstBootAndLoginRebuild:8dd8a105,server/internal/control/bootstrap_admin_test.go#TestBootstrapAdmin_FirstBootMintsHashOnlySingleUseSession:1b651c43,server/internal/control/bootstrap_admin_test.go#TestBootstrapAdmin_ConcurrentConsumeHasOneWinner:0945a8dd,server/internal/control/bootstrap_admin_test.go#TestBootstrapAdmin_ExpiryAndMalformedTokensShareStaticRejection:f44508ef,server/internal/control/bootstrap_admin_test.go#TestBootstrapAdminHTTPHandler_IsBoundedPostOnlyAndCookieFree:8c697ec6,server/internal/auth/bootstrap_admin_test.go#TestGuard_BootstrapConsumeUsesOnlyVersionPinnedAppend:7bc2337a,server/cmd/control/main_test.go#TestBootstrapAdminCLI_LoadsTypedConfigAndPrintsOnlyURL:34603ca7 -->
Write and run these before implementation:

- first-boot user + admin grant atomicity and existing-user reuse;
- hash-only mint persistence and fragment-not-query URL construction;
- exact ten-minute TTL boundary;
- real-Postgres two-consumer race with one winner;
- replay, expiry, malformed, and unknown-token rejection parity;
- successful consume returns a normal rotating refresh family;
- scoped RED proof replaces exact-version consume with the auto-versioned
  append path after a real-Postgres barrier makes both consumers read the same
  unspent version, producing two successful sessions; the restored CAS yields
  exactly one session and the mechanism guard pins that call site;
- POST-only bounded handler, static status/body mapping, no-store headers, and
  no cookies;
- descriptor walk continues to prove no bootstrap/password-like RPC surface;
- event golden corpus, rebuild, table classification, recovery registry,
  projection-write guard, config docs, and secure DSN-file handling.
<!-- docref: end -->

## Out of scope

- general role/grant resolution and permission enforcement (SPEC-008);
- OIDC provider management (SPEC-009);
- SCIM users/groups/bearer authentication (M8);
- centralized `session_version` invalidation (M9);
- web UI fragment parsing and navigation (separate repository).
