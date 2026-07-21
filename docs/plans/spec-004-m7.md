# SPEC-004 M7 — Policy-file engine

Milestone: SPEC-004 §3.7 **[SDK-18]**, AC-21/AC-22.

## Delta

<!-- docref: begin src=sdk/fsafe/policy_linux.go#Manager.ApplyPolicyFile:c181cc6e,sdk/fsafe/policy_linux.go#@policy-surface-table:8bda7a38,sdk/fsafe/policy_linux.go#@policy-transaction:00908b89 -->
- `sdk/fsafe/policy_linux.go`: `Manager.ApplyPolicyFile`,
  `policy-surface-table`, `policy-transaction`
<!-- docref: end -->
<!-- docref: begin src=sdk/fsafe/replace_linux.go#writeTempFrom:10fb5817 -->
- `sdk/fsafe/replace_linux.go`: `writeTempFrom`
<!-- docref: end -->
<!-- docref: begin src=sdk/fsafe/policy_test.go#TestApplyPolicyFile_HashEqualNoOp:4bf34164,sdk/fsafe/policy_test.go#TestApplyPolicyFile_ValidatorFailureNeverReachesLivePath:803a5fc9,sdk/fsafe/policy_test.go#TestApplyPolicyFile_ReloadFailureRestoresPreviousBytes:a78ad9c7,sdk/fsafe/policy_test.go#TestApplyPolicyFile_RevertReplaysPriorThroughValidator:3f985c0d,sdk/fsafe/policy_test.go#TestApplyPolicyFile_ManagedBlockReplacesMarkedRegion:43c17caa,sdk/fsafe/policy_test.go#TestPolicySurfaceTable_ExactRows:3f77251b -->
- `sdk/fsafe/policy_test.go`: AC-21/AC-22 acceptance tests below
<!-- docref: end -->
<!-- docref: begin src=sdk/fsafe/policy_container_test.go#TestContainer_PolicyValidators:ca24b907 -->
- `sdk/fsafe/policy_container_test.go`, `sdk/fsafe/test/*`, `.github/workflows/ci.yml`:
  `TestContainer_PolicyValidators`
<!-- docref: end -->
<!-- docref: begin src=sdk/guardtest/sdkcore.go#hashImportAllow:8c239381 -->
- `sdk/guardtest/sdkcore.go`: `hashImportAllow`
<!-- docref: end -->
- `docs/content/01-specs/00-index.md`: SPEC-004 status and M7 ledger row

## Acceptance tests

<!-- docref: begin src=sdk/fsafe/policy_test.go#TestApplyPolicyFile_HashEqualNoOp:4bf34164,sdk/fsafe/policy_test.go#TestApplyPolicyFile_ValidatorFailureNeverReachesLivePath:803a5fc9,sdk/fsafe/policy_test.go#TestApplyPolicyFile_ReloadFailureRestoresPreviousBytes:a78ad9c7,sdk/fsafe/policy_test.go#TestApplyPolicyFile_RevertReplaysPriorThroughValidator:3f985c0d,sdk/fsafe/policy_test.go#TestApplyPolicyFile_ManagedBlockReplacesMarkedRegion:43c17caa,sdk/fsafe/policy_test.go#TestPolicySurfaceTable_ExactRows:3f77251b,sdk/fsafe/policy_container_test.go#TestContainer_PolicyValidators:ca24b907 -->
- `TestApplyPolicyFile_HashEqualNoOp`
- `TestApplyPolicyFile_ValidatorFailureNeverReachesLivePath`
- `TestApplyPolicyFile_ReloadFailureRestoresPreviousBytes`
- `TestApplyPolicyFile_RevertReplaysPriorThroughValidator`
- `TestApplyPolicyFile_ManagedBlockReplacesMarkedRegion`
- `TestPolicySurfaceTable_ExactRows`
- `TestContainer_PolicyValidators`
<!-- docref: end -->
