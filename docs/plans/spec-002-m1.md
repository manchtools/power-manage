# Plan — SPEC-002 M1: Repo skeleton + license-layout guard

Implements SPEC-002 §9 M1 (AC-1; guard G-002-3). Delta only.

## Existing state

The skeleton already exists and conforms: four module dirs with `go.mod` +
correct LICENSE (contract/sdk MIT, server AGPL-3.0, agent GPL-3.0), `go.work`
using all four, no top-level LICENSE, root README with the module→license
table and the outside-the-modules MIT grant. M1's remaining work is the
guard that keeps it that way, with red-fixture proof.

## Delta — all in `sdk/guardtest`

- `license.go`:
  - `workspaceModules(root)` — module dir names parsed from `go.work` `use`
    directives (block + single-line, comments stripped) — the discovery
    ground truth [REPO-3].
  - `moduleLicenses` — the normative [LIC-1] mapping (identity-keyed with
    rationale); a module in `go.work` with no entry is a violation
    (fail closed), so a fifth module cannot land unlicensed.
  - `licenseIdentity(text)` — MIT / AGPL-3.0 / GPL-3.0 by header phrases
    (AGPL checked before GPL: the GPL header is a substring family).
  - `licenseLayoutViolations(root, mods)` — per-module LICENSE presence +
    identity match; root LICENSE/LICENSE.md/LICENSE.txt/COPYING absence
    [LIC-2]; README table row per module naming its license; the MIT grant
    phrase for everything outside the module dirs (exact-phrase probe,
    recorded ceiling).
- `license_test.go`:
  - `TestGuard_LicenseLayout` (G-002-3): Discover(module dirs, floor 4) +
    zero violations on the real repo.
  - `TestGuard_LicenseLayout_Liveness`: bad fixture plants every violation
    class — missing LICENSE, wrong-identity LICENSE, unclassified fifth
    module, top-level LICENSE present, README row missing, grant missing —
    exact-set via `requireFlagged`; good fixture must scan clean.
  - `TestWorkspaceModules_ParsesForms`, `TestLicenseIdentity_ThreatModel`
    (GPL vs AGPL disambiguation, unknown text → "").
- Fixtures `testdata/arch/licenses/{good,bad}/` — minimal license header
  texts, fixture `go.work`s, fixture READMEs.
- Ledger: SPEC-002 → In progress (M1 done); M1 milestone line.

## Scenario matrix (red = stub scan returns nothing)

| # | Test | Expectation |
|---|------|-------------|
| 1 | G-002-3 on this repo | ≥4 modules discovered, zero violations — red while stub (floor) |
| 2 | bad fixture | all six violation classes flagged exact-set — red while stub |
| 3 | good fixture | clean (not always-red) |
| 4 | go.work parse forms | block/single-line/comments — red while stub |
| 5 | identity classifier | MIT/AGPL/GPL/unknown, AGPL≠GPL — red while stub |

## Out of scope

G-002-1/2 archtests (M2); config loader (M3); CI convention checks (M5).
