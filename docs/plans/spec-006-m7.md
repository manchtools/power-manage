# SPEC-006 M7 — Gateway identity

Spec milestone: SPEC-006 M7 (`PKI-1`, `PKI-1a`, `PKI-2`–`PKI-4`, gateway
certificate/profile portion of `PKI-5`; AC-10;
GUARD-006-1/GUARD-006-3/GUARD-006-4).

## Files and symbols

<!-- docref: begin src=contract/proto/powermanage/v1/pki.proto#PkiService.EnrollGateway:3c71429b,contract/proto/powermanage/v1/pki.proto#PkiService.RenewGateway:42c005d3,contract/proto/powermanage/v1/pki.proto#PkiService.RevokeGateway:9767f6e6,contract/identity/identity.go#RequireDNSAndURISANs:54e332d1,server/internal/store/migrations/011_gateway_identity.sql#@gateway-identity-schema:ff312931,server/internal/store/migrations/012_validate_gateway_token_constraints.sql#@gateway-token-constraint-validation:8cb3fd2e,server/internal/store/gateways.go#GatewayEnrolledEvent:19a1e36a,server/internal/store/gateways.go#GatewayCertificateRenewedEvent:6ab7b089,server/internal/store/gateways.go#GatewayCertificateRevokedEvent:d0396a00,server/internal/store/gateways.go#Store.Gateway:e6aa450a,server/internal/store/inventory.go#productionRebuildTargets:55895954,server/internal/pki/gateway.go#EnrollmentService.EnrollGateway:aeabfea1,server/internal/pki/gateway.go#EnrollmentService.RenewGateway:650dc7c1,server/internal/pki/gateway.go#EnrollmentService.RevokeGateway:05c5efd7,server/internal/pki/crl.go#CRLIssuer.HandleGatewayCRLWork:4bf37d90,server/internal/gateway/enrollment.go#NewEnrollmentClient:7f2191d6,server/internal/gateway/enrollment.go#EnrollmentClient.Enroll:e5ff4767,agent/internal/enroll/client.go#CredentialBundle.GatewayCertificateAuthorityDER:b6074cd5,agent/internal/enroll/store.go#encodeCredentialBundle:f3f8b2af,agent/internal/enroll/store.go#decodeStoredCredentialBundle:4878573c -->
- `docs/content/01-specs/006-pki-and-identity.md`: AG-17 agent/gateway
  trust-anchor response fields.
- `contract/proto/powermanage/v1/pki.proto`: `PkiService.EnrollGateway`,
  `PkiService.RenewGateway`, `PkiService.RevokeGateway`, and generated Go/TS.
- `contract/identity/identity.go`: `RequireDNSAndURISANs`.
- `server/internal/pki/registration_tokens.go`: agent/gateway token purpose and
  gateway DNS metadata.
- `server/internal/store/migrations/011_gateway_identity.sql`,
  `migrations/012_validate_gateway_token_constraints.sql`,
  `queries/registration_tokens.sql`, `queries/gateways.sql`, generated sqlc,
  `registration_tokens.go`, `gateways.go`, `device_lifecycle.go`,
  `inventory.go`, and `classification.go`: gateway events, projections,
  lifecycle capability, rebuild, and classification entries.
- `server/internal/pki/gateway.go`, `enrollment.go`, `procedures.go`, and
  `crl.go`: `EnrollmentService.EnrollGateway`,
  `EnrollmentService.RenewGateway`, `EnrollmentService.RevokeGateway`, and
  `CRLIssuer.HandleGatewayCRLWork`.
- `server/internal/gateway/enrollment.go`: `NewEnrollmentClient` and
  `EnrollmentClient.Enroll`.
- `agent/internal/enroll/client.go` and `store.go`:
  `CredentialBundle.GatewayCertificateAuthorityDER`, `encodeCredentialBundle`,
  and `decodeStoredCredentialBundle`.
- `contract/archtest`, `server` guard files, and
  `docs/content/01-specs/00-index.md`.
<!-- docref: end -->

## Test names

<!-- docref: begin src=server/internal/pki/registration_tokens_test.go#TestGatewayRegistrationToken_CrossPurposeUseRejectsWithoutConsumption:f0d177ec,server/internal/pki/registration_tokens_test.go#TestRegistrationTokens_MintGatewayWithoutDNSRejectsAtPKIBoundary:a4c752f0,server/internal/store/registration_tokens_test.go#TestGatewayRegistrationToken_RebuildPreservesPurposeAndDNSNames:b6cbab2d,server/internal/pki/gateway_test.go#TestGatewayEnrollment_IssuesFreshControlAuthoredDualEKUIdentity:76f57276,server/internal/pki/gateway_test.go#TestGatewayEnrollment_RejectsMalformedProofBeforeTokenUse:3178d523,server/internal/pki/gateway_test.go#TestGatewayEnrollment_VerifiesWithGatewayCAAndNoSystemRoots:d9fab8a9,server/internal/pki/gateway_test.go#TestGatewayRenewal_RequiresFingerprintAndPossessionAndRevokesPredecessor:8b427d56,server/internal/pki/gateway_test.go#TestGatewayRevocation_ProducesGatewayCRLWork:ca84d0d6,server/internal/store/gateways_test.go#TestGatewayProjection_RebuildsExactLifecycleState:099815a8,server/internal/store/gateways_test.go#TestGatewayProjectors_RejectPartiallyMatchingCorruptIdempotencyState:55656f68,server/internal/store/gateways_test.go#TestGatewayEvents_RejectUnexpectedEKUAndNonDNSSANs:7610f292,server/internal/store/gateways_test.go#TestGatewayEvents_RejectUnsupportedRawSANGeneralNames:c0d517d9,server/internal/store/revocations_test.go#TestDeviceRebuild_PreservesGatewayRevocations:5914f84f,server/internal/pki/gateway_test.go#TestEnrollmentHandlers_CrossPurposeTokensRejectWithoutIdentityWrites:e66d4cd9,server/internal/gateway/enrollment_test.go#TestGatewayClient_EachEnrollmentCreatesFreshValidatedIdentity:5e0d20d1,agent/internal/enroll/store_test.go#TestAgentCredentialStore_PreservesDistinctGatewayTrustAnchor:7ca38b4e,agent/internal/enroll/client_test.go#TestClient_EnrolledCredentialBundleVerifiesGatewayWithProductionTLSConfig:5573404b,contract/archtest/pki_test.go#TestPkiServiceShape:5041625c,contract/archtest/nearcopy_test.go#TestGuard_NearCopies:d6c8f231,contract/identity/m1_test.go#TestRequireDNSAndURISANs_RequiresPresentNonEmptyExactExtension:53442f16,server/internal/store/migration_guard_test.go#TestGatewayTokenChecks_UseDeferredValidationMigration:f0b18d8b,server/internal/pki/lifecycle_guard_test.go#TestGuard_PkiLifecycleHandlersUseDeviceLock:f5435030,server/internal/pki/procedures_test.go#TestGuard_PkiPublicRateLimitRegistration:f1a2fefc,server/guards_test.go#TestGuard_ProjectionWritesOnlyFromProjectors:1631421e -->
- `TestGatewayRegistrationToken_CrossPurposeUseRejectsWithoutConsumption`
- `TestRegistrationTokens_MintGatewayWithoutDNSRejectsAtPKIBoundary`
- `TestGatewayRegistrationToken_RebuildPreservesPurposeAndDNSNames`
- `TestGatewayEnrollment_IssuesFreshControlAuthoredDualEKUIdentity`
- `TestGatewayEnrollment_RejectsMalformedProofBeforeTokenUse`
- `TestGatewayEnrollment_VerifiesWithGatewayCAAndNoSystemRoots`
- `TestGatewayRenewal_RequiresFingerprintAndPossessionAndRevokesPredecessor`
- `TestGatewayRevocation_ProducesGatewayCRLWork`
- `TestGatewayProjection_RebuildsExactLifecycleState`
- `TestGatewayProjectors_RejectPartiallyMatchingCorruptIdempotencyState`
- `TestGatewayEvents_RejectUnexpectedEKUAndNonDNSSANs`
- `TestGatewayEvents_RejectUnsupportedRawSANGeneralNames`
- `TestDeviceRebuild_PreservesGatewayRevocations`
- `TestEnrollmentHandlers_CrossPurposeTokensRejectWithoutIdentityWrites`
- `TestGatewayClient_EachEnrollmentCreatesFreshValidatedIdentity`
- `TestAgentCredentialStore_PreservesDistinctGatewayTrustAnchor`
- `TestClient_EnrolledCredentialBundleVerifiesGatewayWithProductionTLSConfig`
- `TestPkiServiceShape`
- `TestGuard_NearCopies`
- `TestRequireDNSAndURISANs_RequiresPresentNonEmptyExactExtension`
- `TestGatewayTokenChecks_UseDeferredValidationMigration`
- `TestGuard_PkiLifecycleHandlersUseDeviceLock`
- `TestGuard_PkiPublicRateLimitRegistration`
- `TestGuard_ProjectionWritesOnlyFromProjectors`
<!-- docref: end -->
