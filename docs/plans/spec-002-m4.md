# Plan — SPEC-002 M4: Config docs generation

Implements SPEC-002 §9 M4 (AC-6; guard G-002-6). Delta only.

## Recorded mechanical choices (spec is silent; rationale inline)

- **Descriptions via a mandatory `doc` struct tag.** Reflection cannot see
  comments; a knob without a `doc` tag fails the generator by name
  (fail closed — an undocumented knob cannot ship). The tag is also where
  the knob's INV-18.6 rationale naturally lives.
- **Read-site = a `.Section.Key` selector chain** anywhere in the owning
  module (tests included) outside the struct's own declaration. The
  loader reads via reflection (no selectors), so it cannot satisfy the
  check itself. Recorded ceiling: matching is syntactic by name chain —
  an unrelated same-named chain counts, go/types would tighten.
- **Staleness = golden diff.** Each config struct's rendered doc is
  committed and diffed by a test; per-binary docs land next to the
  binary as it lands (SPEC-017 CI-4 does repo-wide regeneration later).
- **Per-binary G-002-6 ratchet folds into the existing adoption guard**
  (one cmd/ walk, violation classes `:import:` and `:docs:` for
  colon-boundary locators) — a binary must import the loader AND carry a
  test calling `config.Doc`.

## Design

- **`config.Doc(cfg any) (string, error)`**: calls `derive` first (same
  fail-closed validation), then renders a markdown table in declaration
  order — `| key | env override | type | default | description |` with
  `[section]` group headers; defaults read from the passed struct's
  values; missing `doc` tag → error naming `Section.Key`.
- **Read-site checker (guardtest)**: `ConfigReadViolations(root,
  structName)` — exported (the repo guard lives in `config_test`, which
  owns the demo struct guardtest cannot see) — locates the struct via
  the collected struct decls (factored from the secrets walk),
  enumerates section/key fields (inline + same-package named sections),
  then scans all Go files under root for `<expr>.Section.Key` selector
  chains; a key with zero sites is a violation (INV-18.4: an unread
  knob cannot survive).
- **`TestGuard_ConfigDocs` (sdk/config)**: Discover the demo struct's
  rendered rows (floor ≥1 — the spec's "≥1 documented knob", real today
  via `demoConfig`), rows == derived names, zero read-site violations
  for `demoConfig` across the sdk module. Liveness: guardtest's
  unread-knob fixture (inline + named-section knobs) and the
  stale-fixture assertion inside the golden test.
- **Golden staleness test (sdk/config)**: render `Doc(&demoConfig{…})`
  and byte-diff against committed `testdata/demo.md`; red-proof by
  scoped golden edit.

## Delta

- `sdk/config/config.go`: `Doc`.
- `sdk/config/config_test.go`: `doc` tags on `demoConfig`;
  `TestDoc_GoldenMatch` (staleness + defaults via pre-filled values +
  the stale-fixture assertion), `TestDoc_MissingTagFails`,
  `TestGuard_ConfigDocs`; goldens `sdk/config/testdata/demo.md` and
  deliberately-stale `demo_stale.md`.
- `sdk/guardtest/docs.go` + `docs_test.go`: `collectStructDecls`
  (factored out of secrets.go), exported `ConfigReadViolations`,
  `TestGuard_ConfigReads_Liveness` (unread-knob fixture, inline +
  named-section knobs).
- `sdk/guardtest/secrets.go`: uses the factored `collectStructDecls`
  (no behavior change).
- `sdk/guardtest/adoption.go` + `adoption_test.go`: second violation
  class — each cmd/ binary needs a test file calling `config.Doc`
  (resolved through real imports); class-qualified locators; fixture
  gains `good/main_test.go`, want list becomes
  `bad:import` + `bad:docs`, `good` stays clean.
- Ledger: SPEC-002 → In progress (M4 done); M4 milestone line.

## Scenario matrix (red = stub Doc/scans return nothing)

| # | Test | Expectation |
|---|------|-------------|
| 1 | Doc golden | render == committed testdata/demo.md, byte-exact |
| 2 | Doc missing tag | error naming Section.Key |
| 3 | Doc defaults | pre-populated struct renders its values |
| 4 | G-002-6 repo scan | ≥1 rendered row; demoConfig has zero unread keys |
| 5 | unread-knob fixture | UnreadKnob flagged, UsedKnob clean, exact-set |
| 6 | stale-golden fixture | fixture render ≠ fixture golden → red |
| 7 | adoption fixture | bad:import + bad:docs flagged; good (import + docs test) clean |

## Out of scope

CI conventions + G-002-8 (M5); per-binary doc files under docs/content/
(land with their binaries); repo-wide regeneration lane (SPEC-017 CI-4).
