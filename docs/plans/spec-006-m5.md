# SPEC-006 M5 — Agent certificate renewal

Spec milestone: SPEC-006 M5 (`PKI-1a`, `PKI-3`, `PKI-4`; AC-4/AC-5;
GUARD-006-1/GUARD-006-4).

## Files and symbols

<!-- docref: begin src=contract/proto/powermanage/v1/pki.proto#PkiService.RenewAgent:133f0895,server/internal/pki/renewal.go#EnrollmentService.RenewAgent:7edc123d,server/internal/store/device_lifecycle.go#Store.WithDeviceLifecycleLock:15748429,server/internal/store/devices.go#AgentCertificateRenewedEvent:18c28c2f,server/internal/store/devices.go#projectAgentCertificateRenewal:290eaf12,server/internal/store/inventory.go#productionRebuildTargets:09b8d7de -->
- `contract/proto/powermanage/v1/pki.proto`: `PkiService.RenewAgent`,
  `RenewAgentRequest`, and `RenewAgentResponse`; regenerate Go and TypeScript.
- `contract/archtest/pki_test.go`, `contract/archtest/nearcopy_test.go`: service
  shape and reviewed response-shape rationale.
- `server/internal/pki/renewal.go`, `enrollment.go`, `procedures.go`:
  `EnrollmentService.RenewAgent`, renewal limiting, and enrollment lock parity.
- `server/internal/store/device_lifecycle.go`, `devices.go`, `inventory.go`,
  `queries/devices.sql`: `Store.WithDeviceLifecycleLock`,
  `AgentCertificateRenewedEvent`, `projectAgentCertificateRenewal`,
  `productionRebuildTargets`, and generated sqlc output.
<!-- docref: end -->
<!-- docref: begin src=agent/internal/enroll/client.go#Client.Renew:013d601f,agent/internal/enroll/store.go#FileCredentialStore.Load:3d70f3ab,agent/internal/enroll/store.go#FileCredentialStore.Replace:a0586f67,agent/internal/enroll/renewal_loop.go#NewRenewalLoop:55513294,agent/internal/enroll/renewal_loop.go#RenewalLoop.Run:3666a3c3,sdk/fsafe/root_file_linux.go#ReadRootFile:f1a50722,sdk/fsafe/root_file_linux.go#WriteFileAtomic:cbec1c60 -->
- `agent/internal/enroll/client.go`, `store.go`, `renewal_loop.go`:
  `Client.Renew`, `FileCredentialStore.Load`, `FileCredentialStore.Replace`,
  `NewRenewalLoop`, and `RenewalLoop.Run`.
- `sdk/fsafe/root_file_linux.go`: `ReadRootFile` and `WriteFileAtomic`.
<!-- docref: end -->
<!-- docref: begin src=server/internal/pki/lifecycle_guard_test.go#TestGuard_PkiLifecycleHandlersUseDeviceLock:b3ee3191 -->
- `server/internal/pki/lifecycle_guard_test.go`, `server/guards_test.go`:
  `TestGuard_PkiLifecycleHandlersUseDeviceLock` and projection-owner parity.
<!-- docref: end -->
- `docs/error-journal.md`, `.claude/skills/guards/SKILL.md`,
  `.claude/skills/spec-driven-dev/SKILL.md`, and
  `.claude/skills/verification/SKILL.md`: implementation lessons only.

## Tests

<!-- docref: begin src=server/internal/pki/renewal_test.go#TestRenewalHandler_RenewsCurrentIdentityAndRecordsSupersession:691d0583,server/internal/pki/renewal_test.go#TestRenewalHandler_RejectsFingerprintOrPossessionMismatchWithoutStateChange:49664a5b,server/internal/pki/renewal_test.go#TestRenewalHandler_ConcurrentRequestsProduceOneCertificate:649445a8,server/internal/pki/renewal_test.go#TestRenewalHandler_AppendFailureReturnsNoCertificateAndRollsBack:caf258a9,server/internal/pki/renewal_test.go#TestRenewalHandler_RateLimitsNetworkSource:14bc31ce,server/internal/store/devices_test.go#TestDeviceProjection_RenewsAndRebuildsExactState:e4b3a914,server/internal/store/devices_test.go#TestAgentCertificateRenewedEvent_RejectsInvalidTransitionMaterial:ad0c09db,server/internal/store/devices_test.go#TestDeviceLifecycleLock_SerializesSameDeviceOnly:4c191c8f,server/internal/store/devices_test.go#TestDeviceProjection_RejectsWrongRenewalPredecessorWithoutPersistingEvent:8fdf2fc2,server/internal/pki/lifecycle_guard_test.go#TestGuard_PkiLifecycleHandlersUseDeviceLock:b3ee3191,agent/internal/enroll/store_test.go#TestFileCredentialStore_LoadsExactValidatedBundle:125bf1d2,agent/internal/enroll/store_test.go#TestFileCredentialStore_LoadRejectsNonCanonicalOrInvalidPEM:ea362cd1,agent/internal/enroll/store_test.go#TestFileCredentialStore_ReplaceValidatesBeforeAtomicMode0600Write:e0825788,agent/internal/enroll/renewal_client_test.go#TestClient_RenewReusesSigningKeyRotatesSealingAndAtomicallyReplaces:4e6e48da,agent/internal/enroll/renewal_client_test.go#TestClient_RenewRefusesResponseSubstitutionBeforeReplacement:d9e38adb,agent/internal/enroll/renewal_loop_test.go#TestRenewalDelay_UsesExactEightyPercentAndRenewsOverdueImmediately:aef6b9f6,agent/internal/enroll/renewal_loop_test.go#TestRenewalLoop_RetriesHourlyThenReschedulesFromReplacement:73565c11,agent/internal/enroll/renewal_loop_test.go#TestRenewalLoop_CancellationInterruptsInFlightRenewal:0423765a,sdk/fsafe/root_file_test.go#TestValidateRootOnlyFileInfo_RequiresRegularRootOwnedExactModeAndBound:1e932ce0,sdk/fsafe/root_file_test.go#TestReadRootFile_RefusesFinalSymlink:4bba2304,sdk/fsafe/root_file_test.go#TestReadRootFile_ReadsOnlyBoundedMode0600RootFile:122ac108,sdk/fsafe/root_file_test.go#TestWriteFileAtomic_ReplacesSymlinkEntryWithoutTouchingTarget:00e882ce -->
- Server handler: `TestRenewalHandler_RenewsCurrentIdentityAndRecordsSupersession`,
  `TestRenewalHandler_RejectsFingerprintOrPossessionMismatchWithoutStateChange`,
  `TestRenewalHandler_ConcurrentRequestsProduceOneCertificate`,
  `TestRenewalHandler_AppendFailureReturnsNoCertificateAndRollsBack`, and
  `TestRenewalHandler_RateLimitsNetworkSource`.
- Server store/guards: `TestDeviceProjection_RenewsAndRebuildsExactState`,
  `TestAgentCertificateRenewedEvent_RejectsInvalidTransitionMaterial`,
  `TestDeviceProjection_RejectsWrongRenewalPredecessorWithoutPersistingEvent`,
  `TestDeviceLifecycleLock_SerializesSameDeviceOnly`, and
  `TestGuard_PkiLifecycleHandlersUseDeviceLock`.
- Agent custody/client: `TestFileCredentialStore_LoadsExactValidatedBundle`,
  `TestFileCredentialStore_LoadRejectsNonCanonicalOrInvalidPEM`,
  `TestFileCredentialStore_ReplaceValidatesBeforeAtomicMode0600Write`,
  `TestClient_RenewReusesSigningKeyRotatesSealingAndAtomicallyReplaces`, and
  `TestClient_RenewRefusesResponseSubstitutionBeforeReplacement`.
- Agent schedule: `TestRenewalDelay_UsesExactEightyPercentAndRenewsOverdueImmediately`,
  `TestRenewalLoop_RetriesHourlyThenReschedulesFromReplacement`, and
  `TestRenewalLoop_CancellationInterruptsInFlightRenewal`.
- Filesystem: `TestValidateRootOnlyFileInfo_RequiresRegularRootOwnedExactModeAndBound`,
  `TestReadRootFile_RefusesFinalSymlink`,
  `TestReadRootFile_ReadsOnlyBoundedMode0600RootFile`, and
  `TestWriteFileAtomic_ReplacesSymlinkEntryWithoutTouchingTarget`.
<!-- docref: end -->
