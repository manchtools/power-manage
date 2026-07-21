---
title: "SPEC-017 — Testing and Release"
---
# SPEC-017 — Testing and Release

Status: See `00-index.md` (single status ledger)
Builds on: SPEC-000..SPEC-016 (capstone — every prior spec's test plan executes inside the structure defined here)
Enables: releases
Module(s): all (monorepo: contract, sdk, server, agent; plus the separately versioned web repo at release time)

## 1. Scope

The system-level testing strategy and the release process: the TDD mechanics
every module follows, the SDK container lanes, the deployment E2E gate, CI
structure (verify gate, per-module lanes, self-contained-repo check), and the
release process (versioning, commit convention, tagging discipline, provenance,
contract-package publication).

## 2. Context capsule

Minimum prior knowledge, restated. The TDD core rules are DEFINED in SPEC-000
§3.5 and are normative everywhere; this spec builds the machinery around them:

- **[TEST-1]** (SPEC-000) Per feature: spec (numbered ACs, rejection-path
  table) → tests written from ACs, confirmed FAILING red for the RIGHT reason
  via a scoped neutralizing edit — never a revert — → minimal implementation →
  verify gate → docs/ADR.
- **[TEST-2]** (SPEC-000) Handler tests use REAL Postgres (testcontainer,
  template-cloned per test) and REAL handlers — never mocks or stubs of
  either. Correct/absent/wrong coverage for every request field ("wrong"
  violates the field's validate tag). A rejection-path test for every
  authorization gate: unauthenticated, wrong role, self-scope override
  attempt, scoped-grant denial, cross-actor → NotFound. This spec ADDS two
  mechanics on top of SPEC-000's rule: ONE shared container per package test
  binary (template-cloning keeps isolation), and one scenario per test
  function, named `Test<Method>_<Scenario>` — the only exception is a
  complementary positive-path sanity check inside a rejection test.
- **[TEST-3]** (SPEC-000) CI gates the FULL unit + arch suite under `-race`; a
  self-discovering CI-lane guard proves every test-bearing package runs in some
  workflow, matches-zero protected.
- **[TEST-5]** (SPEC-000) Tests must fail when the control is absent: no
  fixtures derived from the implementation's own artifacts, no uid-gated
  branches that never run, no assert-first-element-only. Documentation claims
  about controls are doc-anchored and behaviorally tested.
- **[TEST-8]** (SPEC-000) Every bug fix ships a regression test that fails on
  the buggy version. Delegated audit findings are re-verified against the
  actual code before being acted on.
- Guard doctrine (PROC-3, SPEC-000): a guard is a build-failing fitness test
  that DISCOVERS its subjects (AST scan, registry walk, proto-descriptor walk),
  carries matches-zero protection, and has a liveness fixture. Hand-maintained
  lists are forbidden.
- `scripts/verify.sh` is the canonical gate (PROC-4, SPEC-000): vet,
  staticcheck, the full `-race` suite, the entire guard suite, doc-anchor
  checks, generated-artifact freshness — nonzero on any failure; CI runs it on
  every PR.
- Repo layout (SPEC-002): one monorepo with `contract/`, `sdk/`, `server/`,
  `agent/` modules under the INV-19 directional-import archtest; the web UI is
  a separate repo consuming the published contract package.
- Deployment shape and TLS material ownership (OPS-8/9, SPEC-016): compose
  stack, root-owned 0600 keys under the image's dropped UID.

## 3. Requirements

### 3.1 SDK system-surface lanes [TEST-4]

- SDK system-surface tests run INSIDE containers against REAL tools — never
  host-proxied: the test binary executes in the container, next to the package
  manager it drives. Per-distro lanes cover every supported backend family
  (apt, dnf, pacman, zypper, flatpak).
- Fidelity is ROUND-TRIP: emit → real binary → parse. Split emit/parse fixtures
  are forbidden — each half can pass while the pair is wrong.
- Deny-lists (protected paths, sensitive tables) are tested against a
  TEST-OWNED threat model — a fixed list of attacks the test asserts are
  blocked — never by iterating the implementation's own set, which proves only
  self-consistency.
- **[TEST-4a]** Locale lanes: integration lanes run under non-English locales
  (at minimum `de_DE.UTF-8` and one non-Latin locale such as `ja_JP.UTF-8`).
  They exist to prove the Runner's
  forced `LC_ALL=C` / `LANG=C` / `NO_COLOR=1` invariant (SDK-3, SPEC-004)
  actually reaches every parser: parsing prefers exit codes and count-diffs
  over localized strings, and a parser that reads localized output fails the
  lane.
- **[TEST-4b]** Reboot safety: reboot/shutdown tests run through the REAL
  runner, but a REAL shutdown binary is never reachable from any test
  environment — the lane guarantees the invoked path cannot power-cycle the
  test host or container. A test that could reach a live `shutdown` is a
  harness bug.

### 3.2 Deployment E2E gate [TEST-6]

Mandatory for every change touching deploy scripts, compose files, datastore
TLS/auth, container entrypoints, mounted-file permissions, service ACLs, or RPC
wiring — and it is a release gate. Synthetic testcontainer green does NOT
substitute: this gate boots the REAL compose stack from the REAL deploy
artifacts and built images (OPS-8, SPEC-016).

- **[TEST-6a] Exact-set RPC coverage.** A self-discovering registry walks the
  protobuf global file registry and maps EVERY externally reachable RPC to a
  registered E2E scenario, exact-set both ways with matches-zero protection:
  adding an RPC fails CI until its deployed scenario exists; a scenario for a
  removed RPC fails the reconciliation. An execution-completeness ledger
  records that every registered scenario actually ran; server reflection is
  reconciled against the descriptor walk so a service wired but not described
  (or described but not wired) is caught.
- **[TEST-6b] Trust-path drive.** After boot, the suite invokes every
  externally reachable RPC through GENERATED clients and drives every
  service-to-service trust path (browser→control, agent→gateway,
  gateway→control, enrollee→PKI listener, IdP-facing surfaces). Health checks
  and hand-picked probes are insufficient.
- **[TEST-6c] Scenario assertions.** Each deployed scenario asserts the real
  status/output AND its required auth/rejection behavior. Negative probes
  correlate 1:1 with EXPECTED log evidence: a rejected probe must produce
  exactly the predicted log line, proving the guard that fired is the one under
  test.
- **[TEST-6d] Log-evidence failure scan.** The gate fails on any unhealthy
  service and on log evidence of permission failures, connection errors, TLS
  handshake errors, or bad-certificate errors anywhere in the stack —
  including errors no scenario directly provoked.
- **[TEST-6e] Production fidelity.** The gate reproduces deployment
  ownership/modes and image UID drops — root-owned 0600 private keys under the
  dropped container UID (OPS-9, SPEC-016). A world-readable test key cannot
  prove the production container user can read the mounted key. For internal
  service URLs it tests the dial address AND the TLS verification identity
  separately: an IP dial target with a DNS-only certificate is a regression
  even when both endpoints are otherwise reachable.

### 3.3 Release provenance [TEST-7]

- A release records the MONOREPO SHA + the WEB repo SHA at release time — two
  values, total provenance.
- SINGLE-BUILD: artifacts are built once; the digest ledger produced by that
  build is the authority every later step (publish, deploy, verification)
  checks against — nothing is rebuilt on the way out.
- DRAFT-THEN-PUBLISH: a release is assembled and verified as a draft, then
  published as a separate explicit step.
- The FRESH-INSTALL WALKTHROUGH is a release gate: the documented install path
  is executed end-to-end on a clean environment before publish.

### 3.4 Release process [REL-1..5]

- **[REL-1]** Versioning is `vYYYY.MM.PP`. The monorepo carries the release
  tag; the web repo is tagged in step for the same release; provenance per
  [TEST-7].
- **[REL-2]** Commit messages follow the conventional-commit style,
  uniformly, with no attribution trailers of any kind (META-4, SPEC-000).
- **[REL-3]** Tags are created ONLY on explicit operator instruction. No
  tooling, workflow, or session creates or pushes a tag as a side effect of
  anything else.
- **[REL-4]** The generated TypeScript contract is published as a versioned
  package on EVERY release, carrying the contract module's MIT license
  (SPEC-002), so the web repo consumes the wire contract without touching the
  monorepo.
- **[REL-5]** Release-gate order: `scripts/verify.sh` green across all modules
  → deployment E2E gate green → fresh-install walkthrough green → draft
  assembled with digest ledger → operator-instructed tag → publish (artifacts +
  contract package).

### 3.5 CI structure [CI-1..4]

- **[CI-1]** CI runs `scripts/verify.sh` on every PR and blocks merge on red
  (PROC-4, SPEC-000). Lanes are PER-MODULE and DISCOVERED from the repo layout
  — never a hand-maintained module list — with the [TEST-3] CI-lane guard
  proving every test-bearing package is executed by some workflow.
- **[CI-2]** Self-contained-repo check: a CI scan proves the repository
  references NO external issue tracker, repository, or document anywhere in
  specs, docs, comments, or commit-checked files. Every rationale is inlined;
  this repo is legible standalone.
- **[CI-3]** Gate-trigger policy: the SDK container lanes run for SDK and
  contract changes; the deployment E2E gate runs for the change classes in
  §3.2 and for every release; the full guard suite runs always.
- **[CI-4]** Generated-artifact freshness: contract codegen (Go + TS),
  generated config docs (INV-18, SPEC-002), and every other generated artifact
  are regenerated in CI and diffed — a stale committed artifact fails.
  Generated code is never hand-edited.

## 4. Acceptance criteria

- **AC-1** An SDK system-surface test executes inside its distro container
  (verifiable by environment assertion), and each supported package-manager
  family has a lane; removing a lane fails the lane-completeness guard.
- **AC-2** A deliberately localized fake tool output planted in the locale lane
  is caught: the lane fails when a parser consumes localized text instead of
  exit codes/count-diffs.
- **AC-3** The reboot lane proves the invoked shutdown path is unreachable: the
  test asserts the real binary cannot execute, while the runner path itself is
  real.
- **AC-4** Adding a new RPC to the contract with no registered E2E scenario
  fails CI; removing an RPC while its scenario remains fails reconciliation;
  the registry discovering ZERO RPCs fails (matches-zero).
- **AC-5** The execution-completeness ledger fails the gate when a registered
  scenario did not run; reflection reconciliation fails when served and
  described service sets differ.
- **AC-6** A negative probe whose expected log evidence does not appear —
  or appears without the probe — fails the gate (1:1 correlation).
- **AC-7** A planted TLS misconfiguration (bad certificate on one internal
  seam) and a planted permission failure in service logs each fail the gate
  even when every scenario still passes.
- **AC-8** The E2E stack's private keys are root-owned 0600 under the dropped
  UID; replacing one with a world-readable key fails the fixture-fidelity
  guard; an IP-dial + DNS-only-certificate combination on an internal URL
  fails.
- **AC-9** A release build produces a digest ledger; a post-build artifact
  modification is detected at publish; the draft→publish sequence records
  monorepo SHA + web SHA.
- **AC-10** No workflow can create a tag: the release tooling refuses to tag
  without an explicit operator-provided instruction input, and repository
  settings reject tag pushes from CI identities.
- **AC-11** The published contract package for a release matches the release's
  generated TS exactly (digest-compared) and carries the MIT license file.
- **AC-12** The self-contained-repo scan fails on a planted external-tracker
  reference and passes on the clean tree; it discovers a nonzero file set
  (matches-zero).
- **AC-13** A module added to the repo appears in CI lanes without editing any
  workflow list (discovery), and `verify.sh` picks it up unmodified.
- **AC-14** Regenerating all generated artifacts in CI produces an empty diff
  on a clean tree; a hand-edit to generated code fails freshness.

## 5. Rejection paths

| Input / state | Required behavior |
|---|---|
| New externally reachable RPC without a deployed E2E scenario | CI fails until the scenario exists [TEST-6a] |
| E2E scenario registry discovers zero RPCs | Build failure (matches-zero), never a silent pass |
| Registered scenario skipped at gate runtime | Completeness ledger fails the gate |
| Negative probe without its predicted log line (or vice versa) | Gate fails [TEST-6c] |
| Unhealthy service, TLS handshake/bad-certificate/permission/connection error in stack logs | Gate fails [TEST-6d] |
| World-readable key fixture in a TLS test | Fixture-fidelity guard fails [TEST-6e] |
| SDK system test proxying commands to the host | Not merged; tests run inside the container [TEST-4] |
| Parser consuming localized tool output | Locale lane fails [TEST-4a] |
| Test able to reach a real shutdown binary | Harness bug; lane fails [TEST-4b] |
| Deny-list test iterating the implementation's own set | Not merged [TEST-4] |
| Tag creation without explicit operator instruction | Refused by tooling and repo settings [REL-3] |
| Artifact rebuilt after the digest ledger was cut | Publish fails digest comparison [TEST-7] |
| Release attempted with a red gate in the [REL-5] chain | Publish blocked |
| External tracker/repo/document reference committed | Self-contained scan fails [CI-2] |
| Test-bearing package in no CI workflow | CI-lane guard fails [TEST-3] |
| Stale or hand-edited generated artifact | Freshness check fails [CI-4] |
| Bug fix without a fails-on-buggy-version regression test | Not merged [TEST-8] |

## 6. Test plan (TDD)

This spec's machinery is itself built test-first; the harness pieces get
liveness fixtures before they gate anything.

1. **Lane harness tests**: container-execution assertion red on a host-run
   test; lane-completeness guard red before per-distro lanes exist; locale-lane
   planted-localized-output fixture (AC-1, AC-2).
2. **Reboot-safety tests**: unreachable-shutdown assertion red while a
   reachable binary is present in the fixture (AC-3).
3. **E2E registry tests**: descriptor walk vs. scenario set — planted uncovered
   RPC, planted orphan scenario, empty-discovery matches-zero (AC-4);
   completeness ledger and reflection reconciliation with planted skips (AC-5).
4. **Evidence-correlation tests**: probe/log 1:1 with a planted missing line
   and a planted unprovoked line (AC-6); failure scan with planted TLS and
   permission log evidence (AC-7).
5. **Fidelity tests**: key ownership/mode/UID fixture guard with a planted
   world-readable key; dial-vs-identity split with a planted IP+DNS-only pair
   (AC-8).
6. **Release-pipeline tests**: digest-ledger tamper detection, draft→publish
   provenance recording (AC-9); tag-refusal paths (AC-10); contract-package
   digest comparison (AC-11).
7. **CI-structure tests**: self-contained scan fixtures (AC-12); module
   discovery by adding a fixture module (AC-13); generated-artifact freshness
   with a planted hand-edit (AC-14).

## 7. Guards

Self-discovering, matches-zero protected (PROC-3, SPEC-000):

| Guard | Discovery source | Fails when |
|---|---|---|
| E2E exact-set scenario registry | Protobuf global file registry walk | Externally reachable RPC without a scenario, orphan scenario, or zero RPCs discovered |
| Execution-completeness ledger | Registered scenario set at gate runtime | Any registered scenario did not execute |
| Reflection reconciliation | Server reflection vs. descriptor walk | Served and described service sets differ |
| Log-evidence correlation | Negative-probe registry | Probe without predicted evidence, or evidence without its probe |
| Stack failure scan | All service logs post-run | TLS handshake / bad certificate / permission / connection errors; unhealthy service |
| Fixture fidelity | E2E key/material inspection | Key not root-owned 0600 under dropped UID; dial/identity untested pair |
| SDK lane completeness | Supported-backend registry (SDK probe surface, SPEC-004) | A backend family without a container lane; zero backends discovered |
| CI-lane coverage | Repo package walk [TEST-3] | Test-bearing package in no workflow; zero packages discovered |
| Self-contained scan | Full-tree text walk | External tracker/repo/document reference; zero files scanned |
| Generated freshness | Generation manifest walk | Regeneration diff nonzero; zero generated artifacts discovered |
| Tag discipline | Release tooling + repo settings | Tag creation path without operator instruction input |

## 8. Historical lessons

Inlined from the predecessor system's operating history:

- **Lesson [TEST-4]:** Split emit/parse fixtures each passed while the real
  tool round trip was broken — the emitter produced what the parser did not
  read. Round-trip against the real binary or it is not a system test.
- **Lesson [TEST-4]:** A protected-path deny-list test iterated the
  implementation's own list, proving self-consistency while an exact-match
  bypass (a crafted sibling path) sailed through. Threat models belong to the
  test.
- **Lesson [TEST-4a]:** Package-manager parsing silently broke under a German
  locale because tests only ever ran in English; the forced C-locale invariant
  existed but nothing proved it reached every parser. Locale lanes exist to
  catch the drift class, not to localize the product.
- **Lesson [TEST-5]:** A redaction test derived its fixtures from the
  implementation's own emitted artifacts — when the redaction map went dead, the
  fixtures went dead with it and the suite stayed green over a Critical.
- **Lesson [TEST-5]:** Assert-first-element-only tests and uid-gated branches
  that never ran in CI passed for months over broken behavior further down the
  list and behind the gate.
- **Lesson [TEST-3]:** Test-bearing packages were silently absent from every CI
  workflow; their suites rotted unexecuted. The lane guard discovers packages —
  a hand-maintained workflow list goes stale and fails open.
- **Lesson [TEST-3]:** Data races shipped because suites ran partially or
  without the race detector; the full suite under `-race` is the floor, not the
  nightly extra.
- **Lesson [TEST-6]:** Synthetic testcontainer configurations stayed green
  while the deployed stack was broken — TLS trust, file permissions, and
  service ACLs only exist in the real artifacts. Health checks plus hand-picked
  probes let a user-facing surface stay dead for days; only the exact-set
  every-RPC drive bounds that class.
- **Lesson [TEST-6e]:** A TLS test with a world-readable key passed while the
  production container's dropped UID could not read the root-owned 0600 mounted
  key; separately, an IP dial target paired with a DNS-only certificate broke a
  seam whose endpoints were each individually "reachable."
- **Lesson [TEST-7]:** A release-candidate fresh install failed on the
  documented path — bootstrap ordering and secret formatting had drifted from
  reality. The walkthrough is a gate, not a doc.
- **Lesson [TEST-8]:** Delegated audit reports conflated "the production code
  is correct" with "a test proves it," and optimistic verdicts survived until
  the code was read. Findings are re-verified against the actual code and
  tests before action.

## 9. Milestones

Each milestone is one implementation session ending green.

1. **M1 — SDK container lanes**: per-distro containers, in-container execution
   assertion, round-trip harness, locale lane, reboot-safety lane,
   lane-completeness guard. Tests: AC-1..3.
2. **M2 — E2E boot + evidence**: compose boot from real artifacts, health
   monitoring, stack failure scan, fixture-fidelity guard (key modes/UID,
   dial-vs-identity). Tests: AC-7, AC-8.
3. **M3 — E2E scenario registry**: descriptor walk, exact-set reconciliation,
   completeness ledger, reflection reconciliation, negative-probe/log
   correlation; first scenario tranche covering every current RPC and trust
   path. Tests: AC-4..6.
4. **M4 — Release pipeline**: single-build digest ledger, draft-then-publish,
   provenance recording (monorepo SHA + web SHA), tag discipline, contract
   TS-package publication. Tests: AC-9..11.
5. **M5 — CI assembly**: discovered per-module lanes, gate-trigger policy,
   self-contained-repo scan, generated-artifact freshness, [REL-5] gate chain
   wiring. Tests: AC-12..14.

## 10. Out of scope

- The TDD core rules themselves and the guard doctrine — defined in SPEC-000;
  this spec builds their system-level machinery.
- Per-feature test plans — each owning spec's §6.
- The deployment stack's content (compose topology, setup tooling, TLS
  material) — SPEC-016; this spec boots and probes it.
- Proto/codegen toolchain configuration — SPEC-002/003.
- Web-repo internal CI (separate repo); it consumes the published contract
  package [REL-4].
