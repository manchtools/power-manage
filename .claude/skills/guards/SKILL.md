---
name: guards
description: Self-discovering fitness tests with matches-zero protection — how every invariant in this repo is enforced. Activates whenever an invariant, coverage claim, enumerated list, or "every X must Y" rule is introduced or touched.
---

# Guards: self-discovering, matches-zero

Every "every X must Y" rule in the specs ships an executable guard. A rule
without a guard is a wish.

## The two laws

1. **Self-discovering, never hand-maintained.** The guard discovers its
   population from ground truth — proto descriptors (`protoregistry`), the
   repo layout, AST walks, the permission catalog, the projector registry, DB
   schema introspection — never from a hardcoded list of files/handlers/fields.
   Hand-maintained lists go stale and fail OPEN: the new handler nobody added
   to the list is exactly the one that skips the check.
2. **Matches-zero protection.** A guard whose discovery returns an empty set
   must FAIL, not pass. A refactor that moves the directory or renames the
   convention silently disarms an unprotected guard; the empty-set failure is
   the tripwire.

## Canonical shapes

- **Descriptor walk**: every RPC is classified (public / permission-gated /
  alt-auth) and every classification has the required rejection test.
- **AST scan**: forbidden calls (`context.Background()` in request paths, raw
  `errors.Is(err, sentinel)` outside the recognizer package, `math/rand` for
  security material, naked `time.Now()` outside the clock seam).
- **Registry parity**: every event type has a registered projector; every
  projector has a rebuild target; every signature domain has both a sign site
  and a fail-closed verify site.
- **Schema walk**: every table carries exactly one storage classification;
  unclassified tables are unmergeable.
- **Import archtest**: module dependency direction (contract/sdk import no
  in-repo module; agent/server import only contract+sdk) — discovered from the
  repo layout, matches-zero protected.
- **Exact-set**: registered scenarios == discovered surface, in BOTH
  directions. Superset is as suspicious as subset (an orphan scenario means
  the surface moved under it).

## Writing one

Put guards in the package they protect (or `internal/archtest`). Name them
`TestGuard_<Invariant>`. The failure message must say what to do ("new RPC
Foo.Bar is unclassified — add it to the auth classification with a rejection
test"), because the person who trips it is a future session with no context.

An allowlist inside a guard is acceptable only when keyed by specific function
identity WITH a comment stating why each entry is sanctioned; an allowlist
that grows silently is the hand-maintained list returning through the back
door.
