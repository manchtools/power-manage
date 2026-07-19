---
title: "SPEC-002 — Repo, Module, and Config Contract"
---
# SPEC-002 — Repo, Module, and Config Contract

Status: READY FOR IMPLEMENTATION
Builds on: SPEC-000 (M2: guard harness — this spec's guards use its discovery/matches-zero helpers)
Enables: SPEC-003..SPEC-017 (all code lands inside this layout, licensing, and config discipline)
Module(s): repo root + all (`contract/`, `sdk/`, `server/`, `agent/`)

## 1. Scope

The monorepo layout, the module split and directional import allowlist
[SDK-0, INV-19], per-module licensing, the configuration discipline [INV-18],
versioning, and commit conventions. Everything here is enforced by
self-discovering guards per SPEC-000's guard doctrine.

## 2. Context capsule

Power Manage consists of a control server and gateway (one Go module), a root
agent, an OS-capability SDK, and a proto wire contract (SPEC-001, SPEC-003).
Development follows SPEC-000: spec → red test → implementation, every invariant
guard-enforced, guards self-discovering with matches-zero protection,
hand-maintained lists forbidden. The five-actor trust model and boundary
inventory are SPEC-001. The web UI is a **separate repository** with its own
toolchain and licensing; it consumes the contract via a published package and is
out of scope here.

## 3. Requirements

### 3.1 Monorepo layout [REPO-1]

One repository holds four Go modules; nothing else contains code:

```
/                 root: README (license mapping + grant), go.work, CI workflows,
                  scripts/ (incl. scripts/verify.sh), install.sh   — MIT (via root README grant)
/contract         proto sources, buf config, generated Go + TS      — MIT
/sdk              OS-capability library (mechanism, never policy)   — MIT
/server           control + gateway binaries                        — AGPL-3.0
/agent            agent binary                                      — GPL-3.0
```

- **[REPO-2]** The web UI stays in a separate repository (own toolchain,
  direct-to-main flow, separate licensing). The contract's generated TypeScript
  is published as a versioned package on each release so web consumes the
  contract without touching the monorepo.
- **[REPO-3]** A `go.work` at the root includes the four modules. Release
  provenance collapses to monorepo SHA + web SHA (SPEC-017).

### 3.2 Module split at the proto boundary

- **[SDK-0]** Two modules, split at the proto boundary: a `contract` module
  (proto sources, buf config, generated Go + TS — the wire contract of
  SPEC-003, versioned with the release train) and the `sdk` capability library
  (pure OS mechanism with ZERO proto/connect/protobuf imports — guarded by an
  import archtest). Server, agent, and web consume `contract`; only agent and
  server consume `sdk`. The contract is NOT absorbed into the server: it has
  three first-class consumers, and none of them may inherit the server's
  dependency graph.

### 3.3 Directional import allowlist

- **[INV-19]** Directional in-repo import allowlist, enforced by an archtest
  that DISCOVERS modules and packages from the repo layout (never a
  hand-maintained list), matches-zero protected:

| Module | May import (in-repo) |
|---|---|
| `contract` | nothing |
| `sdk` | nothing |
| `agent` | `contract`, `sdk` |
| `server` | `contract`, `sdk` |

  This guard is simultaneously the architecture boundary [SDK-0] and the
  licensing boundary (§3.4): an `agent`→`server` import would silently turn the
  GPL agent binary AGPL. The proto-purity archtest (`sdk` imports no
  proto/connect/protobuf packages) is a separate, narrower check.

### 3.4 Licensing [LIC-1..LIC-4]

- **[LIC-1]** Per-module licenses: `server/` AGPL-3.0, `agent/` GPL-3.0,
  `sdk/` MIT, `contract/` MIT. Each module directory carries its own LICENSE
  file. The agent must be GPL **v3**: its Apache-2.0-licensed Go dependencies
  are incompatible with GPLv2-only.
- **[LIC-2]** The repo root has NO top-level LICENSE file — only a README
  mapping module → license. Everything OUTSIDE the four module directories
  (root README, `go.work`, CI workflows, build scripts, and `install.sh`, which
  lives at the repo root) is granted MIT via that root README mapping, so no
  file in the repo — including the curl-piped installer — is left unlicensed.
- **[LIC-3]** This layout is legal BECAUSE the protos live in `contract/`, not
  in the server [SDK-0]: the permissive modules are dependency LEAVES, and
  permissive→copyleft inclusion (MIT into GPL, MIT into AGPL) is always legal.
  Two rules keep it legal, both enforced by the [INV-19] archtest:
  `contract`/`sdk` never import from `server`/`agent`, and `agent` (GPL) never
  imports `server` (AGPL) code.
- **[LIC-4]** Generated code and the published TS contract package carry the
  contract's MIT license.

### 3.5 Configuration discipline

- **[INV-18]** No env-config sprawl:
  1. Each shipped binary (control, gateway, agent; any optional export binary)
     has ONE typed config struct as the single source of truth, loaded from one
     file.
  2. Env overrides exist, but their names are DERIVED mechanically from the
     struct (`PM_<SECTION>_<KEY>`) — no hand-registered env var anywhere in the
     codebase.
  3. Unknown config key or unrecognized `PM_*` variable = boot failure. Typos
     and stale knobs fail closed, never silently ignored.
  4. The reference config docs are GENERATED from the struct
     (self-discovering); a knob that exists but is never read cannot survive
     the generator.
  5. Secrets are never config VALUES — file-path indirection only, consistent
     with the enrollment token arriving via stdin or `--token-file`, never argv
     (AG-17, SPEC-013). Lesson: a token on argv lands in shell history and `ps`
     output for its whole validity.
  6. Adding a knob requires a recorded rationale; the default is convention
     over configuration ([META-3], SPEC-000: flexibility is a seam, never
     optionality).
- **[CFG-1]** The config loader is implemented ONCE and shared. Its home is
  `sdk` — the only shared, proto-free module both binaries' modules may import
  under [INV-19], and a config loader is pure mechanism (SDK-1, SPEC-004).
- **[CFG-2]** Deployment tooling passes configuration exclusively through this
  contract: one config file per binary plus derived `PM_*` overrides. No
  binary reads any other environment variable, with exactly two sanctioned
  readers of the process environment: the config loader itself (derived `PM_*`
  names) and the SDK Runner's curated child-env builder (SDK-4, SPEC-004),
  which reads named parent variables solely to construct child allowlists.

### 3.6 Versioning and commits

- **[VER-1]** Versions are `vYYYY.MM.PP`. The contract (and its published TS
  package) is versioned with the release train [REPO-2]; release mechanics are
  SPEC-017.
- **[VER-2]** Conventional commits, enforced by CI lint.
- **[META-4]** No AI attribution anywhere: commits, PRs, comments, docs.
  Enforced by a CI trailer/content check.

## 4. Acceptance criteria

- **AC-1** The repo skeleton exists: four module directories, each with
  `go.mod` and its LICENSE per [LIC-1]; `go.work` at the root includes all
  four; NO top-level LICENSE exists; the root README contains the module →
  license mapping and the MIT grant for everything outside the module
  directories.
- **AC-2** The [INV-19] archtest discovers all modules and packages from the
  repo layout and fails on any import outside the allowlist; its liveness
  fixture (an `agent`→`server` import) is detected; discovery of fewer than
  four modules or zero packages workspace-wide fails. Per-module package
  floors ratchet from the current counts (`sdk` ≥ 1 today; the others gain
  theirs as their specs land code), so a code-bearing module can never drop
  to zero packages silently.
- **AC-3** The [SDK-0] proto-purity archtest fails when any `sdk` package
  imports proto/connect/protobuf or generated contract packages; its liveness
  fixture is detected; zero scanned packages fails.
- **AC-4** Each binary boots from exactly one config file; every override name
  is mechanically derived as `PM_<SECTION>_<KEY>`; a reflection round-trip test
  derives the exact override set from the struct and proves the loader accepts
  precisely that set.
- **AC-5** An unknown key in the config file aborts boot with a named-key
  error; an unrecognized `PM_*` variable in the environment aborts boot with a
  named-variable error.
- **AC-6** Reference config docs are generated from the struct; CI fails when
  the generated docs are stale; the generator fails on a struct field with no
  read site outside the loader.
- **AC-7** No secret can be expressed as an inline config value: secret-bearing
  settings exist only as file-path fields; no flag in any binary accepts a
  token/secret value on argv.
- **AC-8** CI enforces conventional commits, the `vYYYY.MM.PP` tag format, and
  the [META-4] attribution rule on every PR.
- **AC-9** The contract module's TS package manifest declares the MIT license
  [LIC-4] (publication mechanics verified in SPEC-017).

## 5. Rejection paths

| Input / state | Required behavior |
|---|---|
| Unknown key in a config file | Boot failure naming the key [INV-18] |
| Unrecognized `PM_*` environment variable | Boot failure naming the variable [INV-18] |
| Hand-registered env var (`os.Getenv` outside the loader) | Guard failure; not merged [INV-18] |
| Secret supplied as an inline config value or argv flag | Unrepresentable (path-typed fields only); any such flag/field fails the guard [INV-18] |
| New config knob without recorded rationale | Not merged [INV-18] |
| `agent` importing `server` (or any allowlist violation) | Archtest failure; not merged [INV-19] |
| `sdk` or `contract` importing any in-repo module | Archtest failure; not merged [INV-19] |
| `sdk` importing proto/connect/protobuf packages | Proto-purity archtest failure; not merged [SDK-0] |
| Top-level LICENSE file added, or a module directory missing its LICENSE | License-layout guard failure; not merged [LIC-1/2] |
| Code placed outside the four module directories (beyond root tooling/scripts) | Not merged [REPO-1] |
| Non-conventional commit message | CI reject [VER-2] |
| Release tag not matching `vYYYY.MM.PP` | CI reject [VER-1] |
| Attribution trailer or disclosure in commit/PR/comment/doc | CI reject [META-4] |
| Proposal to absorb the contract into the server | Reject — recorded decision [SDK-0] |
| Proposal to relicense a module or add a shared top-level license | Reject — recorded decision; operator ADR required (SPEC-000 [PROC-2]) |

## 6. Test plan (TDD)

Write first, confirm red (scoped neutralizing edits, never reverts — SPEC-000
[TEST-1]), then implement:

1. **License-layout guard test**: fixture repo missing a module LICENSE → red;
   fixture with a top-level LICENSE → red; correct layout → green.
2. **[INV-19] archtest**: liveness fixture with an `agent`→`server` import →
   red; module-discovery floor test (a truncated fixture layout with three
   modules) → red.
3. **Proto-purity archtest**: fixture `sdk` package importing
   `google.golang.org/protobuf` → red.
4. **Config loader**: unknown-key and unknown-`PM_*` boot-failure tests written
   before the loader rejects them; reflection round-trip test derives the
   override set and is red while derivation is unimplemented; docs-freshness
   test red against a stale fixture.
5. **Env-hygiene guard**: fixture calling `os.Getenv` outside the loader → red;
   matches-zero floor = the loader's own lookup call must be found.
6. **CI checks**: commit-lint, tag-format, and attribution checks each verified
   red against a violating fixture commit/tag before wiring.

These are pure Go/tooling tests; no real-backend requirement applies
(SPEC-000 §3.5).

## 7. Guards

| Guard | Discovery | Matches-zero floor |
|---|---|---|
| G-002-1 directional imports [INV-19] | Modules from repo layout/`go.work`; packages and imports per module | ≥4 modules; ≥1 package workspace-wide; per-module floors ratchet (`sdk` ≥1 today) |
| G-002-2 proto purity [SDK-0] | All `sdk` packages and their imports | ≥1 `sdk` package scanned |
| G-002-3 license layout [LIC-1/2] | Module dirs from `go.work`; LICENSE presence/identity; root LICENSE absence; README mapping + grant present | ≥4 module dirs |
| G-002-4 env hygiene [INV-18] | AST walk for `os.Getenv`/`os.LookupEnv`/`os.Environ` across all modules, allowlist keyed by function (loader; the SDK Runner's curated env builder) | Must find the loader's own lookup |
| G-002-5 config round-trip [INV-18] | Reflection walk of each binary's config struct → derived `PM_*` set vs. loader-accepted set | ≥1 config struct once a binary exists |
| G-002-6 docs freshness [INV-18] | Regenerate reference docs from the struct; diff against checked-in docs; assert every field has a read site | ≥1 documented knob |
| G-002-7 secret indirection [INV-18] | Walk config structs + registered flags; secret-pattern fields must be path-typed; the pattern set is a test-owned threat model (SPEC-000 [PROC-3]) | ≥1 struct/flag scanned |
| G-002-8 commit/version/attribution | CI lint over commits, tags, PR bodies | ≥1 commit examined |

## 8. Historical lessons

- Hand-registered env vars accumulated for years; typos and stale knobs were
  silently ignored, so misconfiguration failed open. Unknown keys and unknown
  `PM_*` variables now fail boot, and override names are derived, never
  registered.
- A secret passed as an argv flag sits in shell history and `ps` output for its
  whole validity; secrets travel only via file paths or stdin.
- Hand-maintained lists (CI lanes, redaction maps) went stale and failed open;
  every guard here discovers its subjects from the repo layout or AST, with a
  matches-zero floor.
- Housing the protos in the server would force every contract consumer to
  inherit the server's dependency graph — and its AGPL license. The contract is
  a separate MIT leaf module with three first-class consumers.
- One accidental cross-module import is all it takes to relicense a shipped
  binary: the import archtest is a licensing control, not just an architecture
  control.
- Aspirational flexibility (spare config knobs, fallback backends) became
  untested fail-open paths; a knob exists only with a recorded rationale, and
  flexibility lives in seams, not optionality.

## 9. Milestones

Each milestone is one implementation session and ends with a green
`scripts/verify.sh` (SPEC-000 [PROC-5]).

1. **M1 — Repo skeleton**: four module dirs + `go.mod`s, `go.work`, per-module
   LICENSE files, root README mapping + MIT grant, no top-level LICENSE;
   G-002-3 green with red-fixture proof (AC-1).
2. **M2 — Archtests**: G-002-1 and G-002-2 with liveness fixtures (AC-2, AC-3).
3. **M3 — Config loader**: loader in `sdk` [CFG-1]; unknown-key/unknown-`PM_*`
   boot failures; reflection round-trip; G-002-4/5/7 (AC-4, AC-5, AC-7).
   Per-binary adoption ratchets as binaries land in later specs.
4. **M4 — Docs generation**: reference-doc generator + G-002-6 (AC-6).
5. **M5 — CI conventions**: commit-lint, tag-format, attribution checks
   (G-002-8; AC-8) and the contract package manifest license field (AC-9).

## 10. Out of scope

- The web repository entirely (separate repo; consumes the published TS
  contract package).
- Release and publishing mechanics — package publication, provenance,
  draft-then-publish (SPEC-017).
- The contract's proto content and conventions (SPEC-003).
- Per-binary knob catalogs and their values — each owning spec records its
  knobs with rationale under [INV-18].
- Deployment configuration (`setup.sh`, compose) — SPEC-016.
