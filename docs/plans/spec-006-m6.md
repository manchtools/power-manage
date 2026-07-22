# SPEC-006 M6 — Control-side revocation and CRL production

Spec milestone: SPEC-006 M6 (`PKI-4`, `PKI-6`; AC-12;
GUARD-006-1/GUARD-006-4).

## Files and symbols

<!-- docref: begin src=contract/proto/powermanage/v1/pki.proto#PkiService.RevokeAgent:6e4346b8,contract/proto/powermanage/v1/pki.proto#PkiService.ForceRenewAgent:c43c2d42,contract/archtest/nearcopy_test.go#nearCopyAllowlist:e9ce5353,server/internal/pki/revocation.go#LifecycleAuthorizer:4f26a045,server/internal/pki/revocation.go#EnrollmentService.RevokeAgent:5d913474,server/internal/pki/revocation.go#EnrollmentService.ForceRenewAgent:1d753013,server/internal/store/devices.go#AgentCertificateRevokedEvent:e97d40f3,server/internal/store/devices.go#AgentCertificateForceRenewalRequiredEvent:f181a74c,server/internal/store/devices.go#projectCertificateRevocation:8d330360,server/internal/store/inventory.go#productionRebuildTargets:b29e2762,server/internal/store/crl.go#Store.CertificateRevocations:593a5fe3,server/internal/store/crl.go#Store.CRLWorkReceipt:92c26a4e,server/internal/store/crl.go#Store.CompareAndSwapCRL:a3becdc2,server/internal/pki/crl.go#CRLIssuer.EnsureCurrent:dd67ba79,server/internal/pki/crl.go#CRLIssuer.HandleAgentCRLWork:109955c4,server/internal/control/crl.go#CRLDistributor.Subscribe:aa4c8d19,server/internal/control/crl.go#CRLDistributor.Publish:c3fff6c1,server/internal/store/migrations/009_certificate_revocations.sql#@certificate-revocations-schema:0adad899,server/internal/store/migrations/010_validate_device_lifecycle_state.sql#@device-lifecycle-state-validation:15982606,server/internal/store/generated/crl.sql.go#Queries.ResetAgentCertificateRevocations:6a7f2efa -->
- `contract/proto/powermanage/v1/pki.proto`: `PkiService.RevokeAgent`,
  `PkiService.ForceRenewAgent`, `RevokeAgentRequest`,
  `ForceRenewAgentRequest`, and their response messages.
- `contract/gen/go/powermanage/v1`,
  `contract/gen/ts/powermanage/v1`: PkiService bindings.
- `contract/archtest/pki_test.go`: `TestPkiServiceShape`.
- `contract/archtest/nearcopy_test.go`: `nearCopyAllowlist`.
- `server/internal/pki/revocation.go`, `enrollment.go`, `renewal.go`,
  `procedures.go`: `LifecycleAuthorizer`, `EnrollmentService.RevokeAgent`,
  `EnrollmentService.ForceRenewAgent`, `NewEnrollmentService`,
  `EnrollmentService.RenewAgent`, and `PublicProcedureLimits`.
- `server/internal/pki/enrollment_test.go`, `procedures_test.go`, and
  `revocation_test.go`.
- `server/internal/store/devices.go`, `inventory.go`, `queries/devices.sql`:
  `DeviceLifecycleState`, `AgentCertificateRevokedEvent`,
  `AgentCertificateForceRenewalRequiredEvent`,
  `projectCertificateRevocation`, and `productionRebuildTargets`.
- `server/internal/store/migrations/009_certificate_revocations.sql`,
  `migrations/010_validate_device_lifecycle_state.sql`, `queries/crl.sql`,
  `classification.go`, `crl.go`, and generated sqlc files:
  `CertificateRevocation`, `SignedCRL`, `Store.CertificateRevocations`,
  `Store.LatestCRL`, `Store.CRLWorkReceipt`,
  `ResetAgentCertificateRevocations`, and
  `Store.CompareAndSwapCRL`.
- `server/internal/store/revocations_test.go`, `classification_test.go`,
  and `inventory_test.go`.
- `server/internal/pki/crl.go`, `crl_test.go`: `CRLPublisher`, `CRLIssuer`,
  `CRLIssuer.EnsureCurrent`, and `CRLIssuer.HandleAgentCRLWork`.
- `server/internal/control/crl.go`: `CRLDistributor.Subscribe` and
  `CRLDistributor.Publish`.
- `server/internal/control/crl_test.go`.
- `server/guards_test.go`: `TestGuard_ProjectionWritesOnlyFromProjectors`.
<!-- docref: end -->
<!-- docref: begin src=agent/internal/enroll/client_test.go#clientRemoteHandler:603fe242,agent/internal/enroll/renewal_client_test.go#renewalClientHandler:1bd9ad9f,server/internal/pki/enrollment_test.go#newEnrollmentHandlerFixture:603ff9a9 -->
- `agent/internal/enroll/client_test.go`, `renewal_client_test.go`:
  `clientRemoteHandler` and `renewalClientHandler`.
- `server/internal/pki/enrollment_test.go`: `newEnrollmentHandlerFixture`.
<!-- docref: end -->
- `CLAUDE.md` and `docs/error-journal.md`.
- `docs/plans/spec-005-m5.md`, `spec-006-m4.md`, and `spec-006-m5.md`.
- `docs/content/01-specs/00-index.md`.

## Tests

<!-- docref: begin src=contract/archtest/pki_test.go#TestPkiServiceShape:bdd5f0c3,contract/archtest/nearcopy_test.go#TestGuard_NearCopies:1340c578,server/internal/store/revocations_test.go#TestDeviceProjection_RevocationAndForceRenewRebuildExactState:a7cb542c,server/internal/store/revocations_test.go#TestDeviceProjection_RevocationRejectsWrongPredecessorWithoutWrites:e01a2cb0,server/internal/store/revocations_test.go#TestDeviceProjection_RenewalSupersessionEnqueuesCRLWorkAtomically:c9e877b8,server/internal/store/revocations_test.go#TestCRLState_CompareAndSwapIsMonotonicUnderConcurrency:700a5581,server/internal/store/revocations_test.go#TestCRLStateSchema_RejectsIncompletePublicationSource:3432d45d,server/internal/store/classification_test.go#TestGuard_TableClassification:fcaffc1b,server/internal/store/inventory_test.go#TestGuard_GoldenEventCorpus:e18a426a,server/internal/store/inventory_test.go#TestGuard_EventPayloadBodiesExcluded:43bf2c53,server/internal/pki/revocation_test.go#TestRevocationHandlers_RequireOperatorAuthorizationAndExactCertificate:fdabfc63,server/internal/pki/revocation_test.go#TestNewEnrollmentService_RequiresLifecycleAuthorizer:94c6f851,server/internal/pki/revocation_test.go#TestForceRenew_AllowsOneReplacementWhileStandaloneRevokeIsTerminal:6689a889,server/internal/pki/revocation_test.go#TestRevocationHandlers_ConcurrentLifecycleOperationsSerialize:6ec73e33,server/internal/pki/revocation_test.go#TestRevocationHandlers_RateLimitNetworkSource:fa89b732,server/internal/pki/crl_test.go#TestCRLIssuer_SignsProjectedRevocationsAndIgnoresStaleWork:9cfc06f4,server/internal/pki/crl_test.go#TestCRLIssuer_EnsureCurrentIssuesClassSeparatedEmptyLists:b214b0e3,server/internal/pki/crl_test.go#TestNewCRLIssuer_RequiresStoreAuthoritiesAndPublisher:5de16330,server/internal/pki/crl_test.go#TestCRLIssuer_RejectsInvalidWorkWithoutPublishing:6d781fdc,server/internal/pki/crl_test.go#TestCRLIssuer_PublishFailureLeavesDurableRetry:c2507b7f,server/internal/pki/crl_test.go#TestRevocationHandlers_PushCRLToConnectedSubscriber:584ad7e5,server/internal/control/crl_test.go#TestCRLDistributor_SendsCurrentOnConnectAndEveryNewerChange:3e803774,server/internal/control/crl_test.go#TestCRLDistributor_RejectsMalformedOrNonMonotonicPublication:fb2015e7,server/internal/control/crl_test.go#TestCRLDistributor_SlowSubscriberRetainsNewestWithoutBlockingPublish:c5bd899d,server/internal/control/crl_test.go#TestCRLDistributor_ExactRedeliveryIsIdempotent:250915f4,server/internal/pki/lifecycle_guard_test.go#TestGuard_PkiLifecycleHandlersUseDeviceLock:956a37fb,server/internal/pki/procedures_test.go#TestGuard_PkiPublicRateLimitRegistration:11bed0f8,server/guards_test.go#TestGuard_ProjectionWritesOnlyFromProjectors:74f34204,server/internal/store/revocations_test.go#TestDeviceRebuild_PreservesGatewayRevocations:d451a216,server/internal/pki/revocation_test.go#TestRenewalHandler_RevokedSuccessorRejectsPredecessorRetry:117cade7,server/internal/pki/revocation_test.go#TestRevocationHandler_ProjectionVersionDriftIsTemporaryFailure:06498432 -->
- Contract:
  `TestPkiServiceShape`.
- Contract guard:
  `TestGuard_NearCopies`.
- Store:
  `TestDeviceProjection_RevocationAndForceRenewRebuildExactState`,
  `TestDeviceProjection_RevocationRejectsWrongPredecessorWithoutWrites`,
  `TestDeviceProjection_RenewalSupersessionEnqueuesCRLWorkAtomically`,
  `TestDeviceRebuild_PreservesGatewayRevocations`,
  `TestCRLState_CompareAndSwapIsMonotonicUnderConcurrency`, and
  `TestCRLStateSchema_RejectsIncompletePublicationSource`.
- Lifecycle handlers:
  `TestRevocationHandlers_RequireOperatorAuthorizationAndExactCertificate`,
  `TestNewEnrollmentService_RequiresLifecycleAuthorizer`,
  `TestForceRenew_AllowsOneReplacementWhileStandaloneRevokeIsTerminal`,
  `TestRenewalHandler_RevokedSuccessorRejectsPredecessorRetry`,
  `TestRevocationHandler_ProjectionVersionDriftIsTemporaryFailure`,
  `TestRevocationHandlers_ConcurrentLifecycleOperationsSerialize`, and
  `TestRevocationHandlers_RateLimitNetworkSource`.
- CRL production and distribution:
  `TestCRLIssuer_SignsProjectedRevocationsAndIgnoresStaleWork`,
  `TestCRLIssuer_EnsureCurrentIssuesClassSeparatedEmptyLists`,
  `TestNewCRLIssuer_RequiresStoreAuthoritiesAndPublisher`,
  `TestCRLIssuer_RejectsInvalidWorkWithoutPublishing`,
  `TestCRLIssuer_PublishFailureLeavesDurableRetry`,
  `TestRevocationHandlers_PushCRLToConnectedSubscriber`,
  `TestCRLDistributor_SendsCurrentOnConnectAndEveryNewerChange`,
  `TestCRLDistributor_RejectsMalformedOrNonMonotonicPublication`,
  `TestCRLDistributor_SlowSubscriberRetainsNewestWithoutBlockingPublish`, and
  `TestCRLDistributor_ExactRedeliveryIsIdempotent`.
- Guards:
  `TestGuard_PkiLifecycleHandlersUseDeviceLock`,
  `TestGuard_PkiPublicRateLimitRegistration`,
  `TestGuard_TableClassification`, `TestGuard_GoldenEventCorpus`,
  `TestGuard_EventPayloadBodiesExcluded`, and
  `TestGuard_ProjectionWritesOnlyFromProjectors`.
<!-- docref: end -->
