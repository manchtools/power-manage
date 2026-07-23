# SPEC-006 M8 — CA continuity and rotation

Spec milestone: SPEC-006 M8 (`PKI-6`, `PKI-7`; AC-13; live trust-bundle
reload and per-device CA-migration report).

## Files and symbols

- `docs/content/01-specs/006-pki-and-identity.md`: exact four-phase rotation,
  issuer-scoped CRL, confirmation, fencing, restart, and migration-report
  requirements.
- `contract/proto/powermanage/v1/pki.proto`: `CATrustBundle`,
  `PkiService.ConfirmAgentTrustState`, and
  `PkiService.ConfirmGatewayTrustState`; generated Go and TypeScript.
- `contract/archtest/pki_test.go` and `nearcopy_test.go`: response and request
  shape guards.
- `contract/sign/trust_state.go`: trust-state signature preimage, sign, and
  verify helpers under `power-manage:trust-state:v1`.
- `agent/internal/enroll/continuity.go`, `client.go`, and `store.go`:
  `validateCAAdoption`, exact versioned agent/gateway trust bundles, atomic
  pending confirmations, and restart retry.
- `server/internal/gateway/enrollment.go`: `EnrollmentClient.Renew`, atomic
  identity/trust publication, and gateway pending-confirmation retry.
- `server/internal/pki/rotation.go`: `RotationPhase`, `AuthoritySnapshot`, and
  `RotationManager`.
- `server/internal/pki/confirmation.go`: exact-certificate signed trust-state
  confirmation handlers.
- `server/internal/pki/trust_bundle.go`: typed bundle consumers and
  distributor.
- `server/internal/pki/authorities.go`, `enrollment.go`, `renewal.go`,
  `gateway.go`, and `crl.go`: fenced authority snapshots, transition proofs,
  and issuer-scoped CRL signing.
- `server/internal/store/migrations/013_issuer_scoped_crl_state.sql`,
  `queries/crl.sql`, generated sqlc, and `crl.go`: CRL state keyed by
  certificate class and issuer fingerprint.
- `server/internal/store/migrations/014_ca_rotation_state.sql`,
  `ca_rotation.go`, event definitions/projectors, inventory rebuild targets,
  and classification: durable rotation and confirmation state plus shared and
  exclusive Postgres rotation fences.
- `server/internal/store/queries/devices.sql`, `queries/gateways.sql`,
  generated sqlc, `devices.go`, `gateways.go`, and `ca_migration.go`: bounded,
  DER-derived CA-migration reporting.
- `server/internal/control/crl.go`: retain and distribute each current
  issuer-scoped CRL.
- `server/internal/pki/rotation_guard_test.go`: phase, transition, fence,
  confirmation-event, CRL-key, and limiter liveness guard.
- `docs/content/01-specs/00-index.md`: completed M8 surface and later
  deployment-activation owner.

## Test names

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

The trust-boundary test writer authors every listed test RED before
implementation, including `TestGuard_PkiRotationPhasesFencesAndState`.
