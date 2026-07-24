# SPEC-007 M1 — Token primitives

Spec milestone: SPEC-007 M1 (`AUTH-1`; AC-1..AC-3; GUARD-007-6).

## Files and symbols

<!-- docref: begin src=server/internal/auth/tokens.go#Claims:fbbdb7b1,server/internal/auth/tokens.go#Signer:8e8b587e,server/internal/auth/tokens.go#Verifier:cf5fcba2,server/internal/auth/tokens.go#GenerateSigningKey:0e6ca735,server/internal/auth/tokens.go#NewSigner:27875d91,server/internal/auth/tokens.go#NewVerifier:5ca4b460,server/internal/auth/tokens.go#Signer.MintAccess:40ad3549,server/internal/auth/tokens.go#Signer.MintRefresh:64230e56,server/internal/auth/tokens.go#Verifier.VerifyAccess:b8900acd,server/internal/auth/tokens.go#Verifier.VerifyRefresh:20bd79c0,server/internal/auth/tokens.go#ErrExpired:4a7eec08,server/internal/auth/tokens.go#ErrInvalid:4a7eec08,server/internal/auth/tokens.go#ErrInvalidKey:4a7eec08,server/internal/auth/tokens.go#ErrClockNotWired:4a7eec08,contract/archtest/descwalk.go#allMessages:98b321b1,contract/archtest/descwalk.go#localCredentialFieldViolations:6e5cf3cd,contract/archtest/domainscan.go#approvedRawSignatureSites:6f36584a,contract/archtest/guards_test.go#TestGuard_SignatureDomains:ca9a81fc -->
- `docs/content/01-specs/007-authentication.md`
- `docs/content/01-specs/00-index.md`
- `server/internal/auth/tokens.go`: `Claims`, `Signer`, `Verifier`,
  `GenerateSigningKey`, `NewSigner`, `NewVerifier`, `Signer.MintAccess`,
  `Signer.MintRefresh`, `Verifier.VerifyAccess`, `Verifier.VerifyRefresh`,
  `ErrExpired`, `ErrInvalid`, `ErrInvalidKey`, `ErrClockNotWired`
- `server/internal/auth/tokens_test.go`
- `contract/archtest/descwalk.go`: `allMessages`,
  `localCredentialFieldViolations`
- `contract/archtest/domainscan.go`: `approvedRawSignatureSites`
- `contract/archtest/guards_test.go`: `TestGuard_SignatureDomains`
- `contract/archtest/m5helpers_test.go`
- `contract/archtest/auth_test.go`
<!-- docref: end -->

## Test names

<!-- docref: begin src=server/internal/auth/tokens_test.go#TestTokenService_MintsAndVerifiesPinnedTypesAndLifetimes:d7c541a9,server/internal/auth/tokens_test.go#TestTokenService_RejectsNonES256AlgorithmsIncludingPublicKeyHMAC:f76c2172,server/internal/auth/tokens_test.go#TestTokenService_ExposesOnlyExpiryAsDistinct:c3fe98e9,server/internal/auth/tokens_test.go#TestTokenService_RejectsCrossTypeUse:02c6dab6,server/internal/auth/tokens_test.go#TestTokenService_RejectsInvalidConstructionAndClaims:781ecb71,contract/archtest/auth_test.go#TestGuard_NoLocalCredentialSurface:d71da4ac,contract/archtest/auth_test.go#TestGuard_NoLocalCredentialSurface_Liveness:15183b00 -->
- `TestTokenService_MintsAndVerifiesPinnedTypesAndLifetimes`
- `TestTokenService_RejectsNonES256AlgorithmsIncludingPublicKeyHMAC`
- `TestTokenService_ExposesOnlyExpiryAsDistinct`
- `TestTokenService_RejectsCrossTypeUse`
- `TestTokenService_RejectsInvalidConstructionAndClaims`
- `TestGuard_NoLocalCredentialSurface`
- `TestGuard_NoLocalCredentialSurface_Liveness`
<!-- docref: end -->
