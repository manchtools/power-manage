# Plan — SPEC-002 M3: Config loader

Implements SPEC-002 §9 M3 (AC-4, AC-5, AC-7; guards G-002-4, G-002-5,
G-002-7). Delta only.

## Recorded mechanical choices (spec is silent; rationale inline)

- **File format: strict INI subset.** `[section]`, `key = value`, `#`
  comment lines, blank lines — nothing else parses. The `PM_<SECTION>_<KEY>`
  derivation [INV-18] mandates a two-level sections→scalar-keys model; the
  INI subset is that model's direct file form. JSON cannot carry comments
  and permits nesting the model forbids; TOML would need a new dependency
  (operator sign-off). The loader surface (`Load(path, cfg)`) is
  format-agnostic if this is ever revisited.
- **Key naming:** Go field `MaxConns` ↔ file key `max_conns` ↔ env
  `PM_<SECTION>_MAX_CONNS` (camel→snake, acronym runs handled:
  `HTTPPort` → `http_port`). Derivation collisions are a load-time error.
- **Supported field kinds:** string, int, bool. Durations et al. are added
  when the first real knob needs them (each knob needs a recorded rationale
  anyway, INV-18.6).
- **Env-read ban set:** the spec names `os.Getenv/LookupEnv/Environ`;
  `os.ExpandEnv` is added — it reads the environment identically.
  Recorded ceiling: `syscall`/x-sys env reads and indirect references
  (`f := os.Getenv; f(...)`) are not matched (same ceiling class as
  `BannedCalls`).

## Design

- **Loader (`sdk/config`, [CFG-1])**: `Load(path string, cfg any) error` —
  parse the one file strictly (unknown section/key, duplicate, malformed
  line, missing file: error naming the offender, AC-5), then one
  `os.Environ()` pass: a `PM_*` name outside the reflection-derived set is
  an error naming the variable (AC-5); a derived name is parsed per field
  type and overrides the file (bad value names the variable).
  `EnvVars(cfg any) ([]string, error)` exposes the derived set (round-trip
  test now, M4 docs generator later). Reflection walk fails closed:
  unexported field, non-struct section, unsupported kind, name collision →
  error.
- **G-002-4 env hygiene (guardtest)**: `envReadSites` — call sites of the
  ban set across all workspace modules' non-test files, resolved through
  `importAliases`/`unwrapExpr` (aliased/dot imports cannot evade;
  same-named symbols from unrelated packages are not flagged), attributed
  to their enclosing declaration via `declUnits`
  (`"<module>/<rel>:<decl>"`). `envReadAllowlist` is keyed by that function
  identity with a rationale per entry (today: the loader's env pass; the
  SDK Runner's curated child-env builder joins with SPEC-004 per CFG-2).
  Exact-set both directions: an unlisted site fails, and an orphan
  allowlist entry fails (the loader moved under it). Floor: ≥1 site — the
  loader's own read must be found.
- **G-002-5 config round-trip**: `TestGuard_ConfigRoundTrip` in
  `sdk/config` — Discover the derived set from a representative
  two-section struct (floor ≥1), prove the loader accepts EXACTLY that
  set: every derived name overrides its field; a non-derived `PM_*` and a
  near-miss (`PM_` + typo) abort with the variable named. Per-binary
  adoption is the ratchet (spec floor: "once a binary exists"):
  `binaryAdoptionViolations` in guardtest discovers `*/cmd/*` main
  packages from the workspace and demands each imports `sdk/config`;
  zero binaries today, fixture proves the demand fires.
- **G-002-7 secret indirection (guardtest)**: walk every struct type
  named `…Config` across all modules (test files included — the loader's
  own test struct is a real subject today), fields resolved recursively
  through inline structs and same-package named section types; a field
  matching the secret pattern set must be path-typed (name ends
  `File`/`Path`). Flag walk: `flag.String`/`flag.StringVar` call sites
  whose name literal matches the pattern set and does not end
  `-file`/`-path`/`_file`/`_path` fail — no secret on argv (AC-7). The
  pattern set is a test-owned threat model with classified + innocent
  rows.

## Delta

- `sdk/config/config.go`: `Load`, `EnvVars`, reflection derivation,
  strict parser, env pass.
- `sdk/config/config_test.go`: scenario matrix below +
  `TestGuard_ConfigRoundTrip` (harness-conforming).
- `sdk/guardtest/env.go` + `env_test.go`: `envReadSites`,
  `envReadAllowlist`, `TestGuard_EnvHygiene` (doc: `Guards: INV-18.`),
  liveness fixture, ban-set threat model.
- `sdk/guardtest/secrets.go` + `secrets_test.go`:
  `secretIndirectionViolations`, `TestGuard_SecretIndirection`, liveness
  fixture, pattern threat model.
- `sdk/guardtest/adoption.go` + `adoption_test.go`:
  `binaryAdoptionViolations`, `TestGuard_ConfigAdoption`, fixture
  workspace.
- Fixtures: `sdk/guardtest/testdata/arch/env/`,
  `.../arch/secrets/`, `.../arch/adoption/`.
- Ledger: SPEC-002 → In progress (M3 done); M3 milestone line.

## Scenario matrix (red = stub Load/EnvVars/scans return nothing)

| # | Test | Expectation |
|---|------|-------------|
| 1 | Load valid file | all sections/keys populated |
| 2 | Round trip | every derived `PM_*` name overrides its field; set is exact both directions |
| 3 | Unknown file key / unknown section | error naming `section.key` / section |
| 4 | Malformed line / duplicate key / missing file | error naming line / key / path |
| 5 | Unknown `PM_*`, near-miss `PM_*`, bad value | error naming the variable; non-`PM_` env ignored |
| 6 | Derivation fail-closed | unexported field, non-struct section, unsupported kind, collision → error |
| 7 | G-002-4 repo scan | exactly the loader's site, allowlisted; orphan entry fails |
| 8 | G-002-4 liveness | plain + aliased + dot-import reads flagged; unrelated same-named func clean |
| 9 | G-002-5 adoption fixture | cmd main package without the loader import flagged; adopted one clean |
| 10 | G-002-7 repo scan | ≥1 Config struct discovered, zero violations |
| 11 | G-002-7 liveness | inline `Token`, named-section `ClientSecret`, secret flag flagged; `TokenFile`, `-file` flag clean |
| 12 | Threat models | every ban-set func and secret pattern classified; innocents clean |

## Out of scope

Docs generation + G-002-6 (M4); CI conventions (M5); per-binary knob
catalogs (owning specs); duration/slice field kinds (first real knob).
