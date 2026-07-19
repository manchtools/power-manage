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

## The matcher's grammar is the threat model

A syntax-level matcher (AST scan, grep, workflow/YAML probe) models a
language; every construct the model omits is a bypass. This repo's own
history: a name-only call matcher accepted a same-named helper from an
unrelated import; a text probe accepted a comment-only mention as CI
wiring; a callee switch missed generic instantiations
(`*ast.IndexExpr`/`*ast.IndexListExpr`); an erroring-default scan
descended into closures and credited their returns to the enclosing case.

Before a matcher ships, enumerate the input-space families it must decide
and give each an evasion fixture. For Go call matchers: plain call,
aliased import, dot-import, local shadowing, generic instantiation,
parenthesized/indirect callee, the construct inside a closure. For text
probes: the pattern inside a comment or a string literal. Each family is
either handled (fixture proven red) or an explicitly recorded ceiling
with rationale at the call site. Passing fixtures only prove the matcher
catches what you already imagined — the enumeration is how you imagine
the rest.
