# Plan — SPEC-001 M1: storage + purity guards, boundary registry data

Milestone: SPEC-001 §9 M1 (G-001-1 storage-dependency allowlist, G-001-3
gateway purity, B1–B11 as machine-readable registry data). Delta only; the
spec is authoritative.

## Files

- `sdk/guardtest/arch.go` — library:
  - `Boundaries` — B1–B11 registry data (ID → one-line summary), the
    machine-readable form of SPEC-001 §3.4; M2's G-001-2 joins listener
    registrations against it.
  - `ModuleRequires(root)` — depth-1 `*/go.mod` walk (verify.sh shape),
    small line parser for `require` directives (single-line and block;
    comments stripped; no new dependency).
  - `StorageClients(requires)` — classifies module paths against the
    storage/queue/cache/search token deny-list (path-segment matching).
  - `ImportClosure(root, entry, modPrefix)` — transitive in-repo import
    walk from an entry package dir; blank/dot/aliased imports all count
    (linkage is linkage).
- `sdk/guardtest/arch_test.go` — guards + proofs (names below).
- `sdk/guardtest/testdata/arch/` fixtures:
  - `storagedeps/` — module tree with a planted queue-client require
    (block form) and a clean module (single-line innocent require).
  - `gwpure/` — `cmd/gateway` → `internal/relay` → `internal/eventstore`
    chain: the violation is transitive, and one leg is a blank import.

## Tests (scenario matrix)

| Test | Proves |
|---|---|
| `TestGuard_StorageDependencies` | G-001-1: Discover floor 4 modules; per-module allowlist (server: `jackc/pgx`; agent: `modernc.org/sqlite`; contract/sdk: none); zero violations today |
| `TestGuard_StorageDependencies_Liveness` | RequireViolation on the storagedeps fixture (planted redis require flags; innocent require and allowlisted driver do not) |
| `TestStorageClients_ThreatModel` | test-owned threat model: known client paths per family (postgres, mysql, sqlite, redis/valkey, kafka, nats, amqp, elastic/opensearch, memcache, mongo, etcd, bbolt/badger/leveldb, ristretto/bigcache/groupcache) all classify; innocents (cobra, protobuf, x/mod) do not |
| `TestModuleRequires_ParsesForms` | single-line require, block require, `// indirect`, comment-only mention NOT parsed |
| `TestGuard_GatewayPurity` | G-001-3: reported skip while `server/cmd/gateway` is absent; once present, Discover floor ≥1 on the closure and banned-prefix join |
| `TestGuard_GatewayPurity_Liveness` | RequireViolation on the gwpure fixture — transitive reach of the eventstore package flags, incl. via blank import |
| `TestGuard_BoundaryRegistryParity` | exact-set both directions: `Boundaries` keys == `| Bn |` rows parsed from SPEC-001 §3.4 (section-sliced); Discover floor 11 |

All new tests observed red first (missing symbols = compile-red for new
code; fixture liveness proven by the harness's standing red-proof).

## Mechanical spec gaps (fixed in the spec in this PR)

- AC-1's floor ("must at minimum find those two sanctioned drivers")
  cannot hold before SPEC-005 (server pgx) and SPEC-013 (agent sqlite)
  add those dependencies — and adding them now would itself need operator
  sign-off. Mirror AC-2's ratcheting language: floor today = module
  discovery (4) + liveness fixture; rises to the two drivers as the
  owning specs land.
- G-001-3's "non-empty closure" floor applies once `server/cmd/gateway`
  exists; until then the guard reports a skip (verify.sh precedent:
  reported, not hidden).

## Registrations

No §3.4 invariant cites SPEC-001, so these guards carry no `Guards:`
line; they satisfy G-000-3 conformance (harness calls) only. SPEC-001's
AC-4/AC-5 ledger wiring is M3, not this milestone.

## Out of scope

G-001-2 boundary-registry join (M2); any real server/agent code or
dependencies; SPEC-002 module-layout guards.
