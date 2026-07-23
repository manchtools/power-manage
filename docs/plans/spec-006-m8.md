# SPEC-006 M8 — CA continuity and rotation

Spec milestone: SPEC-006 M8 (`PKI-6`, `PKI-7`; AC-13; live trust-bundle
reload and per-device CA-migration report).

## Files and symbols

<!-- docref: begin src=contract/proto/powermanage/v1/pki.proto#CATrustBundle:1ad03835,contract/proto/powermanage/v1/pki.proto#PkiService.ConfirmAgentTrustState:5043f175,contract/sign/trust_state.go#SignTrustState:c725578c,agent/internal/enroll/continuity.go#validateTrustBundle:fd0ca314,agent/internal/enroll/store.go#encodeCredentialBundle:f3f8b2af,server/internal/gateway/renewal.go#EnrollmentClient.Renew:c7197d46,server/internal/pki/rotation.go#RotationManager:81dd0d81,server/internal/pki/confirmation.go#EnrollmentService.ConfirmAgentTrustState:09a0bf7e,server/internal/pki/crl.go#CRLIssuer.HandleAgentCRLWork:a48834bb,server/internal/store/ca_rotation.go#Store.CARotationState:0c154ddb,server/internal/store/crl.go#Store.LatestCRL:f973c7bd,server/internal/control/crl.go#CRLDistributor.Subscribe:1dccd5f9 -->
- `docs/content/01-specs/006-pki-and-identity.md`: exact four-phase rotation,
  issuer-scoped CRL, confirmation, fencing, restart, and migration-report
  requirements.
- `contract/proto/powermanage/v1/pki.proto`: `CATrustBundle`, including its
  gateway-consumed issuer-scoped CRL receipt,
  `PkiService.ConfirmAgentTrustState`, and
  `PkiService.ConfirmGatewayTrustState`; generated Go and TypeScript.
- `contract/archtest/pki_test.go` and `nearcopy_test.go`: response and request
  shape guards.
- `contract/sign/trust_state.go`: trust-state signature preimage, sign, and
  verify helpers under `power-manage:trust-state:v1`.
- `agent/internal/enroll/continuity.go`, `client.go`, and `store.go`:
  `validateTrustBundle`, exact versioned agent/gateway trust bundles, atomic
  pending confirmations, and restart retry.
- `server/internal/gateway/renewal.go`: `EnrollmentClient.Renew`, atomic
  identity/trust publication, and gateway pending-confirmation retry.
- `server/internal/pki/rotation.go`: `RotationPhase`, `AuthoritySnapshot`, and
  `RotationManager`.
- `server/internal/pki/confirmation.go`: exact-certificate signed trust-state
  confirmation handlers.
- `server/internal/pki/authorities.go`, `enrollment.go`, `renewal.go`,
  `gateway.go`, and `crl.go`: fenced authority snapshots, transition proofs,
  and issuer-scoped CRL signing.
- `server/internal/store/migrations/013_issuer_scoped_crl_state.sql`,
  `queries/crl.sql`, generated sqlc, and `crl.go`: CRL state keyed by
  certificate class and issuer fingerprint.
- `server/internal/store/ca_rotation.go`, event definitions/projectors,
  inventory rebuild targets, and classification: durable rotation and
  confirmation state, shared and exclusive Postgres rotation fences, and
  bounded DER-derived CA-migration reporting. The M8 schema is consolidated
  in migration 013 so a partial issuer-key/state upgrade cannot exist.
- `server/internal/control/crl.go`: retain and distribute each current
  issuer-scoped CRL.
- `server/internal/pki/rotation_guard_test.go`: phase, transition, fence,
  confirmation-event, CRL-key, and limiter liveness guard.
- `docs/content/01-specs/00-index.md`: completed M8 surface and later
  deployment-activation owner.
<!-- docref: end -->

<!-- docref: begin src=server/internal/store/migrations/013_issuer_scoped_crl_state.sql#@issuer-scoped-revocation-schema:9f7b4640 -->
The consolidated revocation migration scopes leaf-serial uniqueness by the
validated X.509 issuer identifier, scopes CRL state by exact root fingerprint,
and permits one cumulative CRL sequence to acknowledge multiple source events.
<!-- docref: end -->

## Test names

<!-- docref: begin src=agent/internal/enroll/continuity_test.go#TestClient_RenewAcceptsProofOnlyForNewOrExactPendingRoot:72d34867,agent/internal/enroll/continuity_test.go#TestClient_RenewAdoptsCrossSignedAgentAndGatewayCAsAtomically:45b7812e,agent/internal/enroll/continuity_test.go#TestClient_EnrollReceivesExactDualGatewayBundleDuringOverlap:4b5663be,agent/internal/enroll/continuity_test.go#TestClient_RenewRejectsInvalidCATransitionWithoutReplacement:11bf254f,server/internal/pki/rotation_test.go#TestRotationManager_TransitionsAbortNormalizeAndRotateAgain:d9dacf74,server/internal/pki/rotation_test.go#TestRotationManager_ConsumerBundlesGateMigrateAbortAndNormalize:87d8cc0f,server/internal/pki/renewal_rotation_test.go#TestRenewalHandler_MigrationPhaseIssuesFromSuccessorAndReturnsExactProofs:60ef7059,agent/internal/enroll/continuity_test.go#TestClient_RestartRetriesPendingConfirmationBeforeRenewal:fe415b70,server/internal/pki/rotation_fence_test.go#TestRotationManagers_SharedPostgresFenceDrainsIssuanceThroughCommit:ee538847,server/internal/pki/rotation_fence_test.go#TestRotationManagers_CrossClassConsumerFencesBlockTransitionRaces:226a47cb,server/internal/pki/crl_rotation_test.go#TestCRLIssuer_MigrationPublishesIssuerScopedLists:ae28a7a2,server/internal/control/crl_rotation_test.go#TestCRLDistributor_OverlapSeedsAndPreservesBothIssuers:6b06ee43,server/internal/store/ca_migration_test.go#TestCAMigrationReport_PaginatesAndClassifiesFromStoredCertificateDER:c27eff0b,server/internal/pki/rotation_test.go#TestRotationManager_RetireRequiresEveryNonRevokedDeviceMigrated:64585029,server/internal/pki/rotation_test.go#TestRotationManager_RestartRebuildsEveryPhaseAndConfirmationGate:19bc6cf2,server/internal/gateway/renewal_continuity_test.go#TestGatewayClient_RenewsPublishesIdentityBeforeConfirmingTrustState:cff19017,server/internal/pki/rotation_guard_test.go#TestGuard_PkiRotationPhasesFencesAndState:d550bcc7 -->
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

<!-- docref: begin src=contract/identity/m1_test.go#TestRejectPeerIntermediates_AllowsEmptyVerifiedChain:5bef5f61,server/internal/gateway/enrollment_test.go#TestGatewayClient_FirstRenewalUsesEnrollmentTrustState:d1e32055,server/internal/control/crl_test.go#TestCRLDistributor_LegacySourceRejectsIssuerScopedLookup:b9cb1e10 -->
- `TestRejectPeerIntermediates_AllowsEmptyVerifiedChain`
- `TestGatewayClient_FirstRenewalUsesEnrollmentTrustState`
- `TestCRLDistributor_LegacySourceRejectsIssuerScopedLookup`
<!-- docref: end -->

<!-- docref: begin src=agent/internal/enroll/continuity_test.go#TestContinuityValidation_RejectsZeroClock:7f16e860,server/internal/store/migration_guard_test.go#TestCARotationMigration_BackfillsGlobalPositionDeterministically:f2357f23 -->
- `TestContinuityValidation_RejectsZeroClock`
- `TestCARotationMigration_BackfillsGlobalPositionDeterministically`
<!-- docref: end -->

The trust-boundary test writer authors every listed test RED before
implementation, including `TestGuard_PkiRotationPhasesFencesAndState`.
