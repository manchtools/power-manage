# SPEC-004 M6 — Error contracts + container lanes

Milestone: SPEC-004 §9 M6 **[SDK-15..17]**, AC-18..20.

## Files and symbols

<!-- docref: begin src=sdk/pkg/pkg.go#New:d4821cc2,sdk/pkg/exec.go#probe:6877fd86 -->
- `sdk/pkg/{pkg,types,exec,apt,dnf,pacman,zypper,flatpak}.go`
  - explicit `Backend` + injected `New`; no SDK-side backend detection
  - package query/mutation surface used by SPEC-014
  - `readOut`, absence-code classification, strict line/number parsers
<!-- docref: end -->
<!-- docref: begin src=sdk/rollback/rollback.go#Run:56ba97eb -->
- `sdk/rollback/rollback.go`
  - `Step`, `Run`; reverse-order compensation, joined rollback failures
<!-- docref: end -->
<!-- docref: begin src=sdk/validate/names.go#PackageVersion:6827dd9e,sdk/validate/names.go#LocalPackagePath:680e2be5,sdk/validate/names.go#SearchQuery:0ca877d8 -->
- `sdk/validate/names.go`
  - `PackageVersion`, `LocalPackagePath`, `SearchQuery`
<!-- docref: end -->
<!-- docref: begin src=sdk/pkg/container_test.go#TestContainer_PackageManagerRoundTrip:6046636b,sdk/rollback/container_test.go#TestContainer_RollbackRestoresPreState:bac63106 -->
- `sdk/pkg/test/Dockerfile`, `sdk/pkg/test/run.sh`, `.github/workflows/ci.yml`
  - apt/dnf/pacman/zypper/flatpak real-tool matrix; apt lane runs under
    `de_DE.UTF-8`
<!-- docref: end -->
<!-- docref: begin src=sdk/guardtest/package_lanes_test.go#TestGuard_PackageManagerLaneParity:4d3801f0 -->
- `sdk/guardtest/{imports.go,package_lanes_test.go}`
  - sdk package floor 10→12; exact backend-lane coverage with matches-zero
<!-- docref: end -->
- `docs/content/01-specs/00-index.md`
  - status `In progress (M6 done)` and M6 ledger row

## Representative acceptance tests

Backend-specific and cross-backend unit matrices live in each changed
`sdk/pkg/*_test.go`; the acceptance-level entry points are:

- `TestQueries_BackendUnavailable`
- `TestQueries_AbsentVsFailure`
- `TestQueries_NeverNilSuccess`
- `TestParsers_RejectMalformedNumbers`
- `TestList_SkipsOneMalformedEntry`
- `TestList_PreservesDottedVersions`
- `TestRun_RollsBackAppliedStepsInReverseOrder`
- `TestRun_JoinsRollbackFailures`
- `TestContainer_PackageManagerRoundTrip`
- `TestContainer_RollbackRestoresPreState`
- `TestGuard_PackageManagerLaneParity`
