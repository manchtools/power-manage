# SPEC-006 M8 — CA continuity and rotation

Spec milestone: SPEC-006 M8 (`PKI-6`, `PKI-7`; AC-13).

## Files and symbols

<!-- docref: begin src=contract/proto/powermanage/v1/pki.proto#CATrustBundle:1ad03835,contract/proto/powermanage/v1/pki.proto#PkiService.ConfirmAgentTrustState:5043f175,contract/sign/trust_state.go#SignTrustState:c725578c,agent/internal/enroll/continuity.go#validateTrustBundle:6b49a136,agent/internal/enroll/store.go#encodeCredentialBundle:504a252f,server/internal/gateway/renewal.go#EnrollmentClient.Renew:c7197d46,server/internal/pki/rotation.go#RotationManager:81dd0d81,server/internal/pki/confirmation.go#EnrollmentService.ConfirmAgentTrustState:cd5936fb,server/internal/pki/confirmation.go#EnrollmentService.confirmTrustState:03a8e9f3,server/internal/pki/crl.go#CRLIssuer.HandleAgentCRLWork:a48834bb,server/internal/store/ca_rotation.go#Store.CARotationState:0c154ddb,server/internal/store/ca_rotation.go#Store.HasControlTrustConfirmation:e0639fd6,server/internal/store/store.go#Store.WithAdvisoryLocks:4007afb8,server/internal/store/store.go#releaseAdvisoryLocks:7ab9d10c,server/internal/store/crl.go#Store.LatestCRL:f973c7bd,server/internal/store/migrations/013_issuer_scoped_crl_state.sql#@issuer-scoped-revocation-schema:9114f063,server/internal/control/crl.go#CRLDistributor.Subscribe:41b3c161 -->
- `docs/content/01-specs/006-pki-and-identity.md`
- `docs/content/01-specs/00-index.md`
- `contract/proto/powermanage/v1/pki.proto`: `CATrustBundle`,
  `PkiService.ConfirmAgentTrustState`, `PkiService.ConfirmGatewayTrustState`
- `contract/gen/go/powermanage/v1/pki.pb.go`
- `contract/gen/go/powermanage/v1/powermanagev1connect/pki.connect.go`
- `contract/gen/ts/powermanage/v1/pki_pb.d.ts`
- `contract/gen/ts/powermanage/v1/pki_pb.js`
- `contract/archtest/pki_test.go`, `contract/archtest/pki_rotation_test.go`
- `contract/sign/trust_state.go`: `SignTrustState`, `VerifyTrustState`
- `contract/identity/identity.go`: `RejectPeerIntermediates`
- `agent/internal/enroll/continuity.go`: `validateTrustBundle`
- `agent/internal/enroll/client.go`: `Client.Enroll`, `Client.Renew`
- `agent/internal/enroll/store.go`: `encodeCredentialBundle`
- `server/internal/gateway/renewal.go`: `EnrollmentClient.Renew`
- `server/internal/pki/rotation.go`: `RotationPhase`, `AuthoritySnapshot`,
  `RotationManager`
- `server/internal/pki/confirmation.go`:
  `EnrollmentService.ConfirmAgentTrustState`,
  `EnrollmentService.ConfirmGatewayTrustState`,
  `EnrollmentService.confirmTrustState`
- `server/internal/pki/authorities.go`, `server/internal/pki/enrollment.go`,
  `server/internal/pki/renewal.go`, `server/internal/pki/gateway.go`,
  `server/internal/pki/crl.go`: `CRLIssuer.HandleAgentCRLWork`
- `server/internal/store/migrations/013_issuer_scoped_crl_state.sql`
- `server/internal/store/queries/crl.sql`
- `server/internal/store/ca_rotation.go`: `Store.CARotationState`,
  `Store.HasControlTrustConfirmation`
- `server/internal/store/store.go`: `Store.WithAdvisoryLocks`,
  `releaseAdvisoryLocks`
- `server/internal/store/crl.go`: `Store.LatestCRL`
- `server/internal/control/crl.go`: `CRLDistributor.Subscribe`
- `server/internal/pki/rotation_guard_test.go`
<!-- docref: end -->

## Test names

<!-- docref: begin src=agent/internal/enroll/continuity_test.go#TestClient_RenewAcceptsProofOnlyForNewOrExactPendingRoot:72d34867,agent/internal/enroll/continuity_test.go#TestClient_RenewAdoptsCrossSignedAgentAndGatewayCAsAtomically:45b7812e,agent/internal/enroll/continuity_test.go#TestClient_EnrollReceivesExactDualGatewayBundleDuringOverlap:4b5663be,agent/internal/enroll/continuity_test.go#TestClient_RenewRejectsInvalidCATransitionWithoutReplacement:11bf254f,server/internal/pki/rotation_test.go#TestRotationManager_TransitionsAbortNormalizeAndRotateAgain:d9dacf74,server/internal/pki/rotation_test.go#TestRotationManager_ConsumerBundlesGateMigrateAbortAndNormalize:c489b23f,server/internal/pki/renewal_rotation_test.go#TestRenewalHandler_MigrationPhaseIssuesFromSuccessorAndReturnsExactProofs:60ef7059,agent/internal/enroll/continuity_test.go#TestClient_RestartRetriesPendingConfirmationBeforeRenewal:fe415b70,server/internal/pki/rotation_fence_test.go#TestRotationManagers_SharedPostgresFenceDrainsIssuanceThroughCommit:34f322ff,server/internal/pki/rotation_fence_test.go#TestRotationManagers_CrossClassConsumerFencesBlockTransitionRaces:76cfe91c,server/internal/pki/crl_rotation_test.go#TestCRLIssuer_MigrationPublishesIssuerScopedLists:ae28a7a2,server/internal/control/crl_rotation_test.go#TestCRLDistributor_OverlapSeedsAndPreservesBothIssuers:6b06ee43,server/internal/store/ca_migration_test.go#TestCAMigrationReport_PaginatesAndClassifiesFromStoredCertificateDER:c27eff0b,server/internal/pki/rotation_test.go#TestRotationManager_RetireRequiresEveryNonRevokedDeviceMigrated:64585029,server/internal/pki/rotation_test.go#TestRotationManager_RestartRebuildsEveryPhaseAndConfirmationGate:19bc6cf2,server/internal/gateway/renewal_continuity_test.go#TestGatewayClient_RenewsPublishesIdentityBeforeConfirmingTrustState:cff19017,server/internal/pki/rotation_guard_test.go#TestGuard_PkiRotationPhasesFencesAndState:b2b3689c -->
- `TestClient_RenewAcceptsProofOnlyForNewOrExactPendingRoot`
- `TestClient_RenewAdoptsCrossSignedAgentAndGatewayCAsAtomically`
- `TestClient_EnrollReceivesExactDualGatewayBundleDuringOverlap`
- `TestClient_RenewRejectsInvalidCATransitionWithoutReplacement`
- `TestRotationManager_TransitionsAbortNormalizeAndRotateAgain`
- `TestRotationManager_ConsumerBundlesGateMigrateAbortAndNormalize`
- `TestRenewalHandler_MigrationPhaseIssuesFromSuccessorAndReturnsExactProofs`
- `TestClient_RestartRetriesPendingConfirmationBeforeRenewal`
- `TestRotationManagers_SharedPostgresFenceDrainsIssuanceThroughCommit`
- `TestRotationManagers_CrossClassConsumerFencesBlockTransitionRaces`
- `TestCRLIssuer_MigrationPublishesIssuerScopedLists`
- `TestCRLDistributor_OverlapSeedsAndPreservesBothIssuers`
- `TestCAMigrationReport_PaginatesAndClassifiesFromStoredCertificateDER`
- `TestRotationManager_RetireRequiresEveryNonRevokedDeviceMigrated`
- `TestRotationManager_RestartRebuildsEveryPhaseAndConfirmationGate`
- `TestGatewayClient_RenewsPublishesIdentityBeforeConfirmingTrustState`
- `TestGuard_PkiRotationPhasesFencesAndState`
<!-- docref: end -->

<!-- docref: begin src=contract/identity/m1_test.go#TestRejectPeerIntermediates_AllowsEmptyVerifiedChain:32302d01,contract/identity/m1_test.go#TestRejectPeerIntermediates_DoesNotMutateInputConfig:51c3505d,server/internal/gateway/enrollment_test.go#TestGatewayClient_FirstRenewalUsesEnrollmentTrustState:ed274c9d,server/internal/control/crl_test.go#TestCRLDistributor_LegacySourceRejectsIssuerScopedLookup:b9cb1e10 -->
- `TestRejectPeerIntermediates_AllowsEmptyVerifiedChain`
- `TestRejectPeerIntermediates_DoesNotMutateInputConfig`
- `TestGatewayClient_FirstRenewalUsesEnrollmentTrustState`
- `TestCRLDistributor_LegacySourceRejectsIssuerScopedLookup`
<!-- docref: end -->

<!-- docref: begin src=agent/internal/enroll/continuity_test.go#TestContinuityValidation_RejectsZeroClock:7f16e860,agent/internal/enroll/continuity_test.go#TestContinuityValidation_RejectsCurrentGenerationWithoutRoots:ced55601,server/internal/store/ca_rotation_confirmation_test.go#TestControlTrustConfirmationLookup_RejectsForbiddenCRLReceipt:608ed269,server/internal/store/migration_guard_test.go#TestCARotationMigration_BackfillsGlobalPositionDeterministically:c8530170,server/internal/store/migration_guard_test.go#TestCARotationMigration_AppliesToEmptyPreUpgradeState:deb715a6,server/internal/store/migration_guard_test.go#TestCARotationMigration_RejectsLegacyRevocationsWithoutIssuerIdentity:eae08584,server/internal/store/store_test.go#TestReleaseAdvisoryLocks_MarksSessionUnusableOnUncertainRelease:af7a23f5 -->
- `TestContinuityValidation_RejectsZeroClock`
- `TestContinuityValidation_RejectsCurrentGenerationWithoutRoots`
- `TestControlTrustConfirmationLookup_RejectsForbiddenCRLReceipt`
- `TestCARotationMigration_BackfillsGlobalPositionDeterministically`
- `TestCARotationMigration_AppliesToEmptyPreUpgradeState`
- `TestCARotationMigration_RejectsLegacyRevocationsWithoutIssuerIdentity`
- `TestReleaseAdvisoryLocks_MarksSessionUnusableOnUncertainRelease`
<!-- docref: end -->
