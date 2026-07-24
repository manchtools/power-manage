# SPEC-008 M1 — permission catalog and classification guard

Spec milestone: SPEC-008 M1 (`AUTHZ-3`; AC-1).

## Acceptance criteria

1. The server exposes one machine-readable permission catalog. Every entry has
   a non-empty permission name and exactly one classification:
   `confinable` or `global-only`.
2. Every global-only permission carries a non-empty rationale. The initial
   global-only entries cover role/grant management, user-group membership,
   IdP/SCIM configuration, server settings, PKI/CA operations, and
   audit/retention administration.
3. Permission names use a stable lower-case dotted grammar and contain no
   scope suffix dialect. Scope remains a future grant property.
4. Catalog reads are deterministic and defensively copied. Lookup fails closed
   for empty, malformed, or unknown permission names.
5. The catalog guard discovers its work from the production catalog, fails
   when it discovers zero entries, and rejects duplicate, unclassified,
   malformed, or rationale-free fixture entries.

## Design

- Add `server/internal/authz` as the authorization-policy package, separate
  from SPEC-007 authentication.
- Represent the catalog as one sorted slice of typed entries. A small linear
  lookup is sufficient for the bounded catalog and avoids a second
  representation.
- Keep the M1 catalog to permissions needed by SPEC-008 enforcement. Later
  domain specs extend the same catalog and automatically enter the guard.
- Use only the standard library plus the existing guard harness.

## Red-first tests

- an empty catalog fails;
- an entry with the zero classification fails;
- a global-only entry without a rationale fails;
- duplicate or malformed permission names fail;
- a scope-suffixed name fails the permission grammar;
- mutation of a returned catalog copy cannot alter production data;
- unknown lookup fails closed.

## Implementation

<!-- docref: begin src=server/internal/authz/catalog.go#Catalog:661e3992,server/internal/authz/catalog.go#Lookup:2530248a,server/internal/authz/catalog.go#validateCatalog:f3ebf508 -->
The authorization package exposes one deterministic, defensively copied
catalog. Validation accepts only the two defined classifications, requires
global-only rationales, and rejects malformed, duplicate, or unsorted names
under stable error categories. Lookup validates the requested name and never
defaults an unknown permission.
<!-- docref: end -->

## Verification

<!-- docref: begin src=server/internal/authz/catalog_test.go#TestGuard_PermissionCatalogClassification:44f2623e,server/internal/authz/catalog_test.go#TestValidateCatalog_RejectsIncompleteEntries:d31aeec7,server/internal/authz/catalog_test.go#TestCatalog_DefensivelyCopiedAndLookupFailsClosed:59366ca0 -->
- Passed: production catalog discovery, non-vacuous classification, stable
  ordering, defensive copying, and fail-closed lookup.
- Passed: empty, unclassified, unknown-class, rationale-free, duplicate,
  malformed, scope-suffixed, and unsorted fixtures each reject under their
  intended stable category.
- Failed: none.
- Skipped: none in this milestone.
<!-- docref: end -->

## Rejection paths

| Input or state | Expected outcome |
|---|---|
| Empty catalog | Guard failure; never a vacuous pass |
| Permission with no or unknown classification | Validation failure |
| Global-only permission with blank rationale | Validation failure |
| Duplicate or malformed permission name | Validation failure |
| Permission name containing a scope suffix | Validation failure |
| Empty, malformed, or unknown lookup | Not found; no default permission |

## Out of scope

- role, grant, group-membership, or scope persistence and resolution (M2);
- interceptor/RPC permission binding (M3);
- handler scope predicates and denial mapping (M4);
- last-admin protection and grant mutation handlers (M5–M6);
- system-managed object filtering (M7);
- CRUD domain registration and domain-specific permissions (SPEC-009).
