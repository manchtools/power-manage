# SPEC-003 M2 — ActionParams + action shape

Milestone: SPEC-003 §9 M2. Builds on M1 (scaffold + guard harness, PR #14).
Delta only; the spec is authoritative.

## Scope

The single oneof registry ([WIRE-12]), the one action shape ([WIRE-13]),
validate tags with descriptor-derived enum bounds ([WIRE-2], AC-2), explicit
presence ([WIRE-6]); G-3 and G-4 green with liveness fixtures. Buf lint in CI
is already satisfied (M1: verify.sh proto stage runs inside CI's verify job).

## Recorded mechanical choices

1. **Structure/semantics split.** M2 ships `ActionParams` with the full
   21-member oneof (catalog order, §3.2 SPEC-014), each member a STUB
   message (`message PackageParams {}` …). Per-type fields and their
   validate tags are SPEC-014 M1's deliverable ("this spec fixes only the
   registry structure they plug into", SPEC-003 §10). The catalog is CLOSED
   at 21 ([CAT-1]), so the member set ships complete and exact-set-pinned
   from day one — no aspirational growth path.
2. **No parallel ActionType enum.** The oneof member set IS the type
   registry: SPEC-014's exact-set guard walks the oneof, and a parallel
   enum is a second registry that can drift — the [WIRE-12] lesson in enum
   form. Type identity on the wire is the set oneof member.
3. **The one Action shape (M2 form).** `Action { string id; string name;
   ActionParams params; }` — id carries the ULID rule ([WIRE-5]), name
   carries min_len 1 / max_len 200, params carries `required`. Everything
   else named anywhere in the series is either per-type semantics
   (desired_state — per-type enums per [ACT-8]; timeouts; lifecycle —
   SPEC-014 M2's executor frame) or enrichment composed AROUND the shape
   (schedule, assignment mode, resolved target — [WIRE-13], [ASG-*]), so
   none of it goes on Action here. SPEC-014 extends composition, never
   this shape.
4. **Enum bounds are descriptor-derived via protovalidate.** Boundary rule
   for every enum-typed reachable field: `enum: { defined_only: true,
   not_in: [0] }` — defined_only makes the bound the descriptor's value set
   with no generation step; not_in 0 makes UNSPECIFIED always invalid at
   boundaries (AC-2, [WIRE-4]). Guard `TestGuard_EnumBounds` enforces the
   tag pair on every enum field of every reachable message; vacuous on the
   real contract until the first enum field lands, proven live by fixture.
5. **G-3 mechanism.** Parameterized descriptor walk anchored on a named
   registry message: (a) exactly one message named `ActionParams` in the
   package; (b) a violation for ANY field outside the registry's own oneof
   whose message type is one of the registry's member types (this single
   rule catches both the direct-embed bypass and the predecessor's
   second-oneof duplication); embedding `ActionParams` itself is the
   conforming form. Runs against the real package and, with a
   fixture-local registry analog, against the fixture package for liveness.
6. **G-4 mechanism.** Descriptor walk over the registry subtree plus every
   action-bearing message: a plain (non-`optional`) `bool` is a violation
   unless allowlisted with a recorded two-value rationale (allowlist starts
   empty). Population anchor is the walked message set (floor ≥ 1 — the
   registry exists), not the bool count, so zero bools stays green while
   zero messages fails.
7. **File layout.** New `contract/proto/powermanage/v1/action.proto`
   (shared types, not a service file). The M1 file-count floor rises 7 → 8
   in the existing G-1/G-2 anchors (test-file change: strengthening only).
8. **Recorded ceilings (review round).** (a) G-4 walks the registry
   subtree plus registry-embedding messages — narrower than the spec's
   "or another state-changing message" wording; no state-changing message
   exists at M2, and the walk must widen when the first SPEC-008/009
   mutation request lands. (b) `reachableMessages` (and therefore the
   enum-bounds walk) does not descend into map VALUES' enum types — enums
   as `map<_, Enum>` values are unwalked; revisit when the first
   enum-valued map field lands. Both vacuous today, recorded so they are
   not silently dropped.

## Files

- `contract/proto/powermanage/v1/action.proto` — new: ActionParams (21 stub
  members), the 21 stub messages, Action.
- `contract/archtest/actionreg.go` — new: `registryMessage`,
  `registryViolations` (G-3), `plainBoolViolations` (G-4),
  `enumBoundViolations` (choice 4).
- `contract/archtest/guards_test.go` — new guards + liveness rows; floor
  bumps.
- `contract/archtest/testdata/fixture/proto/powermanage/fixture/v1/fixture.proto`
  — fixture registry analog + planted violations; regenerate fixturepb.
- `contract/gen/**` — regenerated.
- `docs/content/01-specs/00-index.md` — SPEC-003 → In progress (M2 done).

## Scenario matrix

| # | Test | Proves | Red condition observed |
|---|---|---|---|
| 1 | `TestGuard_ActionRegistry` | oneof ≡ the 21 catalog members, both directions, floor 21 | fails pre-implementation (no ActionParams → Discover floor) |
| 2 | `TestGuard_ActionParamsAuthority` (G-3) | exactly one ActionParams; zero out-of-registry references to member types in the real contract | fails pre-implementation (registry absent) |
| 3 | `TestGuard_ActionParamsAuthority_Liveness` | fixture direct-embed AND second-oneof both flagged; conforming embed clean | planted fixture shapes |
| 4 | `TestGuard_ExplicitPresence` (G-4) | zero plain bools in registry subtree + action-bearing messages; message-set floor | fails pre-implementation (registry absent) |
| 5 | `TestGuard_ExplicitPresence_Liveness` | fixture plain bool flagged; `optional bool` clean | planted fixture shapes |
| 6 | `TestGuard_EnumBounds` | every enum-typed reachable field carries defined_only + not_in 0 | vacuously green on real contract (recorded; first real enum field arms it) |
| 7 | `TestGuard_EnumBounds_Liveness` | fixture enum field without the tag pair flagged; tagged one clean | planted fixture shapes |
| 8 | `TestAction_Shape` | Action has exactly {id, name, params} with the choice-3 tags | fails pre-implementation |
| 9 | M1 guards stay green | G-1/G-2 floors at 8; service surface unchanged | floor bump red-checked against 7-file tree |
