---
title: "Preserved operator decisions"
---
# Preserved operator decisions

These decisions were made by the operator during the design of this system and
its predecessor. They are **final**. Do not re-litigate them, do not "improve"
on them, do not quietly implement the alternative. If a spec seems to conflict
with one of these, stop and ask the operator.

Bracketed IDs (e.g. AUTH-3, ES-8) refer to requirement IDs in `docs/content/01-specs/`.

## Identity, enrollment, PKI

1. **Enroll socket is mode 0666.** The registration token is the sole
   authorization for enrollment; filesystem permissions on the local socket are
   deliberately not a second gate. (Reversed twice in earlier iterations —
   final.)
2. **Agent certificates are 1-year with fail-closed revocation at the
   gateway** — not short-validity certificates. Revocation is distributed as a
   control-signed CRL over the gateway stream; the fail-closed posture (no
   current CRL → deny) is the preserved decision.
3. **No re-enrollment flow, online or offline.** A broken device is wiped with
   `install.sh --reset` and enrolled fresh; the stale device record is deleted
   in the UI (AG-18).
4. **Self-registering gateways stay.** Gateway registration is stream presence
   on the internal service; edge routing configuration is served from control.
5. **Enrollment token via stdin or `--token-file` ONLY — never argv** (argv is
   world-readable via /proc). Install remains curl-pipe for now (packaging
   capacity); revisit later.

## Authentication and authorization

6. **Human sign-in is OIDC + SCIM only.** No local passwords, no TOTP, no
   passkeys. Break-glass is `control bootstrap-admin`: host-side command,
   single-use URL (AUTH-3).
7. **Bearer tokens everywhere** — refresh rotation with reuse detection
   (family revocation on replay), strict CSP/Trusted Types, first-class scoped
   PATs for API consumers. Cookies rejected: the hosted UI is cross-site
   (AUTH-9).
8. **Session JWTs are ES256**; the verification key is non-secret.
9. **No grant ceiling.** The role-management permission is the sole gate on
   what roles an admin can construct; there is no "you can only grant what you
   hold" rule.
10. **Scope lives on the grant.** Every permission is scope-confinable except
    the enumerated global-only escalation set (AUTHZ-3).
11. **Object-scope READ is transitive; confinement is on WRITE.** Do not
    tighten reads to match write confinement — the asymmetry is intended.
12. **Validate-then-authorize** is the canonical handler order.
13. **Per-account failed-attempt rate limiting, never hard lockout** (lockout
    is a denial-of-service primitive against admins).
14. **`linux_username` is admin-only** — never self-serviceable by the user it
    names.
15. **Admin is trusted.** The trust model's admin actor is not an adversary;
    build audit (evidence of what admins did), not admin-proofing.

## Data plane and storage

16. **Postgres is the only datastore.** No Valkey/queue/cache/search product.
    Queues are work tables (`FOR UPDATE SKIP LOCKED`, in-transaction outbox),
    search is Postgres FTS, locks are advisory locks. Do not reintroduce a
    second datastore below the named ceiling (~100k devices); durability lives
    at the edges (TM-1). (An earlier iteration ran a Valkey-based queue; a
    production incident — a post-fork futex deadlock in the bundle image
    wedging the queue and, via fail-closed revocation checks, cutting off the
    fleet — plus the design review retired it.)
17. **Projections run inside the append transaction** (in-tx CQRS). Async work
    exists only as Postgres work tables (ES-8, ES-11).
18. **ONE read path for lists** — no parallel list/search endpoints, no
    client-side filtering. The search path IS the list path.
19. **ULID everywhere, never UUID.**
20. **Shipped migrations are never edited** — append a forward migration.
    Consolidating migrations may be breaking; that is acceptable pre-release.
21. **Execution output is operational-tier data** (ES-12): compliance-linked
    output is retained per policy; the rest defaults to short retention.
22. **Audit export is unary chunked** — not a stream.
23. **The content-addressed artifact store is THE blob mechanism** — action
    payloads, terminal recordings, encrypted audit archives all go through it
    (ART-1..4). No second blob path.
24. **Encryption at rest is mandatory** — no opt-out flag for running without
    an encryption key.

## Control plane and API

25. **The management API is one table-driven CRUD kernel** (API-1) — not N
    hand-written handler families.
26. **Control HA is active/standby.** Active/active is a non-goal with a named
    upgrade path.
27. **No env-config sprawl** (INV-18): one typed config struct per binary, one
    file, mechanically derived env override names, unknown-key boot failure,
    generated docs, secrets via file indirection only.
28. **Instant dispatches bypass maintenance windows** (an explicit operator
    "run now" outranks the window).
29. **Device-targeted timing is the agent scheduler's job** via the signed
    manifest — never a server-side delayed dispatch, which cannot be correct
    for offline devices. Server-side scheduling exists only for control-plane
    jobs and minting one-shot fan-outs.
30. **`NOT_APPLICABLE` is a first-class execution outcome** — one enum value,
    not an error and not a silent skip.
31. **Compliance rollups (group/fleet) are in scope.**

## Agent and SDK

32. **SDK = mechanism, never policy.** The SDK exposes OS capability; the
    agent decides what to do with it. The agent adapts to the SDK, not vice
    versa.
33. **The agent executes no system binary directly** and ships as one static
    artifact; capability comes exclusively from the SDK probe (AG-12a).
34. **The agent runs as root.** Hardening is unit directives + MAC, not a user
    switch.
35. **No in-agent staleness kill-switch.** Offline autonomy is the product; an
    agent that cannot reach control keeps applying its last signed manifest
    indefinitely.
36. **Agent unit reconcile never self-restarts the agent** (a reconciler that
    restarts its own process is an outage generator).
37. **Agent update integrity**: `checksum_url` or opt-in `expected_sha256` —
    never a mandatory pin. Out-of-band release signing is an accepted risk,
    recorded deliberately.
38. **Repository trust is operator choice with a floor** — the system does not
    refuse `gpgcheck=false`-style repo configurations outright.
39. **Raw signed osquery SQL is the operator escape hatch** — exempt from the
    sensitive-table deny-list that applies to unsigned queries.
40. **The TTY login lock and the session shell are SEPARATE domains** — the
    account-lock mechanism must never be coupled to session-shell handling.
    The offboarding guarantee (lock means no new TTY login) is the invariant.
41. **LPS manages ANY local account, root included** — intended parity with
    Windows LAPS. The safeguard is documentation, not an allowlist.
42. **Label→dynamic-group pierce** for device-group-scoped LUKS/LPS reads is
    accepted by design (labels are admin-controlled; see decision 15).
43. **Session detection is an SDK `sessions` capability** (logind D-Bus); no
    speculative fallback backends.
44. **Terminal session recording captures input AND output, OPT-IN with
    default OFF** — no input-only middle ground; recordings are sealed at rest
    and reads are audited (AUD-8).

## Actions

45. **Action sets are NESTABLE** — a DAG with write-time cycle rejection,
    depth-first flattening, first-wins dedup. The former "Definitions" layer
    is deleted; nesting replaces it.
46. **DEB + RPM merge into `PACKAGE_FILE`** (artifact ref, magic-detected
    format, probed-backend applicability). **SCRIPT_RUN folds into SHELL** as
    `lifecycle: ONE_SHOT`.
47. **The policy-file engine is a COMPOSITION of existing SDK primitives** —
    one function plus a table, never a new subsystem.

## Contract, licensing, repo

48. **The proto contract and the OS capability library are separate modules**;
    the contract is never absorbed into the server (SDK-0).
49. **Proto evolution: no `reserved` markers** — re-tag in place. V1 makes
    clean breaks; no compat shims or deprecation aliases.
50. **Monorepo** for contract/sdk/server/agent; **web stays a separate repo**;
    the generated TS contract is published as a package per release.
51. **Per-module licenses survive the monorepo**: server AGPL-3.0, agent
    GPLv3, sdk MIT, contract MIT; contract/sdk are permissive dependency
    leaves; agent never imports server code (INV-19 guard); root tooling and
    `install.sh` are MIT.
52. **UI stays vendor-hosted**; self-hosting is a licensed option; the web
    bundle is origin-agnostic.
53. **Web repo commits direct to main; this monorepo's code goes through
    PRs.** No AI attribution anywhere, in any repo.
54. **Tags `vYYYY.MM.PP` only on explicit operator instruction.**
55. **Release provenance is the monorepo SHA** (+ web SHA recorded at release
    time).
