# Plan — SPEC-002 M5: CI conventions + contract manifest license

Implements SPEC-002 §9 M5 (AC-8 guard G-002-8; AC-9). Delta only.
Flips SPEC-002 to Implemented.

## Recorded mechanical choices (spec is silent; rationale inline)

- **One script, explicit modes.** `scripts/check-conventions.sh` with
  `commits <range>`, `pr-body-file <file>`, `tag <name>` — the workflow
  passes GitHub context in; modes keep the script fixture-testable
  offline, matching the verify.sh self-test pattern.
- **Commit grammar**: subject must match
  `^(build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)(\([a-z0-9._/-]+\))?!?: .+`.
  Merge commits are skipped (`--no-merges`; the repo rebase-merges).
- **Attribution patterns are a test-owned threat model** (same families
  as check-self-contained.sh plus generic "generated with/by" phrasing
  and the robot emoji), applied to commit messages and PR bodies. File
  contents stay check-self-contained.sh's job; the two new script files
  join its exemption list because they name the patterns.
- **Matches-zero floor in the script**: zero commits examined in the
  range fails (G-002-8 "≥1 commit examined"). A push event with an
  unknown `before` SHA falls back to `HEAD~1..HEAD`.
- **Tag grammar**: `^v20[0-9]{2}\.(0[1-9]|1[0-2])\.[0-9]{2}$` — checked
  by a CI job on tag pushes (tags themselves stay operator-only).
- **AC-9 manifest**: `contract/package.json` with `"license": "MIT"`,
  name `@power-manage/contract`, placeholder version `0.0.0` and
  `"private": true` until SPEC-017 wires publication.

## Delta

- `scripts/check-conventions.sh` (modes above) +
  `scripts/check-conventions_test.sh` (fixture repos, red/green rows),
  wired into verify.sh's self-test stage.
- `.github/workflows/ci.yml`: `conventions` job (PR + push + tags
  trigger; tag refs run the tag mode, branches/PRs run commits +
  pr-body modes).
- `sdk/guardtest/cilane_test.go`: `workflowRunsVerify` generalized to
  `workflowRunsScript(root, script)`; `TestGuard_ConventionsLane`
  (G-002-8 wiring demand); wired/commented fixtures gain conventions
  lines.
- `sdk/guardtest/license.go` + `license_test.go`:
  `contractManifestLicense`, `TestGuard_ContractManifestLicense`.
- `contract/package.json`.
- `scripts/check-self-contained.sh`: exclude the two new script files
  (they name the patterns — same exemption the script grants itself).
- Ledger: SPEC-002 → Implemented; M5 line (PR #13).

## Scenario matrix (red = stub script exits 0; guard/manifest absent)

| # | Test | Expectation |
|---|------|-------------|
| 1 | non-conventional subject | rejected naming the commit [VER-2] |
| 2 | conventional subjects | feat(x):, fix:, docs:, revert:, feat!: pass |
| 3 | attribution trailer in a commit message | rejected [META-4] |
| 4 | zero-commit range | rejected — floor (G-002-8) |
| 5 | tags | v2026.07.01 green; v1.2.3, v2026.7.1, 2026.07.01, v2026.13.01 red |
| 6 | PR body | attribution rejected; clean body passes |
| 7 | lane guard | comment-only mention false; wired fixture true; repo ci.yml wired |
| 8 | manifest | license exactly MIT; missing/unparsable manifest red |

## Out of scope

Publication mechanics and release trains (SPEC-017); TS code
generation; retroactive linting of pre-M5 history.
