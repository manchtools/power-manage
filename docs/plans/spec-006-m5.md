# SPEC-006 M5 — Agent certificate renewal

Spec milestone: SPEC-006 M5 (`PKI-1a`, `PKI-3`, `PKI-4`; AC-4/AC-5;
GUARD-006-1/GUARD-006-4).

## Files and symbols

<!-- docref: begin src=contract/proto/powermanage/v1/pki.proto#PkiService.RenewAgent:133f0895,server/internal/pki/renewal.go#EnrollmentService.RenewAgent:549c15d6,server/internal/store/migrations/007_device_renewal_retry.sql#@device-renewal-retry-schema:af0b97c6,server/internal/store/migrations/008_validate_device_renewal_retry.sql#@device-renewal-retry-validation:55e278f4,server/internal/store/device_lifecycle.go#Store.WithDeviceLifecycleLock:15748429,server/internal/store/devices.go#Device.PreviousCertificateDER:e1e2d576,server/internal/store/devices.go#AgentCertificateRenewedEvent:18c28c2f,server/internal/store/devices.go#projectAgentCertificateRenewal:3bf2aefc,server/internal/store/inventory.go#productionRebuildTargets:1dbaae4e -->
- `contract/proto/powermanage/v1/pki.proto`: `PkiService.RenewAgent`,
  `RenewAgentRequest`, and `RenewAgentResponse`.
- `contract/archtest/pki_test.go`: `TestPkiServiceShape`.
- `contract/archtest/nearcopy_test.go`: `nearCopyAllowlist`.
- `server/internal/pki/renewal.go`, `enrollment.go`, `procedures.go`:
  `EnrollmentService.RenewAgent`, `NewEnrollmentService`, and
  `PublicProcedureLimits`.
- `server/internal/store/migrations/007_device_renewal_retry.sql`,
  `migrations/008_validate_device_renewal_retry.sql`, `device_lifecycle.go`,
  `devices.go`, `inventory.go`, and
  `queries/devices.sql`: `device-renewal-retry-schema`,
  `device-renewal-retry-validation`,
  `Store.WithDeviceLifecycleLock`, `Device.PreviousCertificateDER`,
  `AgentCertificateRenewedEvent`, `projectAgentCertificateRenewal`,
  `productionRebuildTargets`, and `UpdateDeviceRenewal`.
<!-- docref: end -->
<!-- docref: begin src=agent/internal/enroll/client.go#Client.Renew:9186de8f,agent/internal/enroll/store.go#FileCredentialStore.Load:743011b7,agent/internal/enroll/store.go#FileCredentialStore.Replace:a0586f67,agent/internal/enroll/renewal_loop.go#NewRenewalLoop:55513294,agent/internal/enroll/renewal_loop.go#RenewalLoop.Run:dbb84e77,sdk/fsafe/root_file_linux.go#ReadRootFile:f1a50722,sdk/fsafe/root_file_linux.go#WriteFileAtomic:cbec1c60 -->
- `agent/internal/enroll/client.go`, `store.go`, `renewal_loop.go`:
  `Client.Renew`, `FileCredentialStore.Load`, `FileCredentialStore.Replace`,
  `NewRenewalLoop`, and `RenewalLoop.Run`.
- `sdk/fsafe/root_file_linux.go`: `ReadRootFile` and `WriteFileAtomic`.
<!-- docref: end -->
<!-- docref: begin src=server/internal/pki/lifecycle_guard_test.go#TestGuard_PkiLifecycleHandlersUseDeviceLock:f5435030,server/internal/pki/lifecycle_guard_test.go#TestLifecycleLockGuard_FixtureDetected:5b070e4b,server/guards_test.go#TestGuard_ProjectionWritesOnlyFromProjectors:1a8ed391 -->
- `server/internal/pki/lifecycle_guard_test.go`, `server/guards_test.go`:
  `TestGuard_PkiLifecycleHandlersUseDeviceLock`,
  `TestLifecycleLockGuard_FixtureDetected`, and
  `TestGuard_ProjectionWritesOnlyFromProjectors`.
<!-- docref: end -->
- `CLAUDE.md`, `docs/error-journal.md`, `.claude/skills/guards/SKILL.md`,
  `.claude/skills/spec-driven-dev/SKILL.md`, and
  `.claude/skills/verification/SKILL.md`.

## Tests

<!-- docref: begin src=server/internal/pki/renewal_test.go#TestRenewalHandler_RenewsCurrentIdentityAndRecordsSupersession:995e3e7b,server/internal/pki/renewal_test.go#TestRenewalHandler_RetryAfterLostResponseReturnsExistingSuccessor:5ca990ba,server/internal/pki/renewal_test.go#TestRenewalHandler_RejectsFingerprintOrPossessionMismatchWithoutStateChange:09393116,server/internal/pki/renewal_test.go#TestRenewalHandler_ConcurrentRequestsProduceOneCertificate:d0d0a213,server/internal/pki/renewal_test.go#TestRenewalHandler_AppendFailureReturnsNoCertificateAndRollsBack:caf258a9,server/internal/pki/renewal_test.go#TestRenewalHandler_RateLimitsNetworkSource:5bc75014,server/internal/store/devices_test.go#TestDeviceProjection_RenewsAndRebuildsExactState:685c6401,server/internal/store/devices_test.go#TestAgentCertificateRenewedEvent_RejectsInvalidTransitionMaterial:ad0c09db,server/internal/store/devices_test.go#TestDeviceLifecycleLock_SerializesSameDeviceOnly:4c191c8f,server/internal/store/devices_test.go#TestDeviceProjection_RejectsWrongRenewalPredecessorWithoutPersistingEvent:8fdf2fc2,server/internal/pki/lifecycle_guard_test.go#TestGuard_PkiLifecycleHandlersUseDeviceLock:f5435030,server/internal/pki/lifecycle_guard_test.go#TestLifecycleLockGuard_FixtureDetected:5b070e4b,server/guards_test.go#TestGuard_ProjectionWritesOnlyFromProjectors:1a8ed391,agent/internal/enroll/store_test.go#TestAgentCredentialStore_PreservesDistinctGatewayTrustAnchor:7ca38b4e,agent/internal/enroll/store_test.go#TestFileCredentialStore_LoadRejectsNonCanonicalOrInvalidPEM:2ddc9829,agent/internal/enroll/store_test.go#TestFileCredentialStore_ReplaceValidatesBeforeAtomicMode0600Write:e0825788,agent/internal/enroll/renewal_client_test.go#TestClient_RenewReusesSigningKeyRotatesSealingAndAtomicallyReplaces:03fa049d,agent/internal/enroll/renewal_client_test.go#TestClient_RenewReusesPendingSealingKeyAfterRemoteFailure:3b537e53,agent/internal/enroll/renewal_client_test.go#TestClient_RenewRefusesResponseSubstitutionBeforeReplacement:121ea9c9,agent/internal/enroll/renewal_loop_test.go#TestRenewalDelay_UsesExactEightyPercentAndRenewsOverdueImmediately:aef6b9f6,agent/internal/enroll/renewal_loop_test.go#TestRenewalLoop_RetriesHourlyThenReschedulesFromReplacement:5b175f21,agent/internal/enroll/renewal_loop_test.go#TestRenewalLoop_CancellationInterruptsInFlightRenewal:45f60452,agent/internal/enroll/renewal_loop_test.go#TestRenewalLoop_RejectsConcurrentRunExactly:6e5d0490,sdk/fsafe/root_file_test.go#TestValidateRootOnlyFileInfo_RequiresRegularRootOwnedExactModeAndBound:99ead311,sdk/fsafe/root_file_test.go#TestReadRootFile_RefusesFinalSymlink:4bba2304,sdk/fsafe/root_file_test.go#TestReadRootFile_ReadsOnlyBoundedMode0600RootFile:5652bd1e,sdk/fsafe/root_file_test.go#TestWriteFileAtomic_ReplacesSymlinkEntryWithoutTouchingTarget:00e882ce -->
- Server handler: `TestRenewalHandler_RenewsCurrentIdentityAndRecordsSupersession`,
  `TestRenewalHandler_RetryAfterLostResponseReturnsExistingSuccessor`,
  `TestRenewalHandler_RejectsFingerprintOrPossessionMismatchWithoutStateChange`,
  `TestRenewalHandler_ConcurrentRequestsProduceOneCertificate`,
  `TestRenewalHandler_AppendFailureReturnsNoCertificateAndRollsBack`, and
  `TestRenewalHandler_RateLimitsNetworkSource`.
- Server store/guards: `TestDeviceProjection_RenewsAndRebuildsExactState`,
  `TestAgentCertificateRenewedEvent_RejectsInvalidTransitionMaterial`,
  `TestDeviceProjection_RejectsWrongRenewalPredecessorWithoutPersistingEvent`,
  `TestDeviceLifecycleLock_SerializesSameDeviceOnly`,
  `TestGuard_PkiLifecycleHandlersUseDeviceLock`,
  `TestGuard_ProjectionWritesOnlyFromProjectors`, and
  `TestLifecycleLockGuard_FixtureDetected`.
- Agent custody/client: `TestAgentCredentialStore_PreservesDistinctGatewayTrustAnchor`,
  `TestFileCredentialStore_LoadRejectsNonCanonicalOrInvalidPEM`,
  `TestFileCredentialStore_ReplaceValidatesBeforeAtomicMode0600Write`,
  `TestClient_RenewReusesSigningKeyRotatesSealingAndAtomicallyReplaces`,
  `TestClient_RenewReusesPendingSealingKeyAfterRemoteFailure`, and
  `TestClient_RenewRefusesResponseSubstitutionBeforeReplacement`.
- Agent schedule: `TestRenewalDelay_UsesExactEightyPercentAndRenewsOverdueImmediately`,
  `TestRenewalLoop_RetriesHourlyThenReschedulesFromReplacement`,
  `TestRenewalLoop_CancellationInterruptsInFlightRenewal`, and
  `TestRenewalLoop_RejectsConcurrentRunExactly`.
- Filesystem: `TestValidateRootOnlyFileInfo_RequiresRegularRootOwnedExactModeAndBound`,
  `TestReadRootFile_RefusesFinalSymlink`,
  `TestReadRootFile_ReadsOnlyBoundedMode0600RootFile`, and
  `TestWriteFileAtomic_ReplacesSymlinkEntryWithoutTouchingTarget`.
<!-- docref: end -->
