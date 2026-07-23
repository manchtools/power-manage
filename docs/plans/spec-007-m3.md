# SPEC-007 M3 — Public authentication rate-limit ladder

Spec milestone: SPEC-007 M3 (AC-15; GUARD-007-2; LIM-4).

## Delta

<!-- docref: begin src=server/internal/auth/ratelimit.go#FailureLimit:2d3e067d,server/internal/auth/ratelimit.go#RateLimitPolicy:e0b065bf,server/internal/auth/ratelimit.go#AuthenticationAttempt:28eadbe8,server/internal/auth/ratelimit.go#FailureLadder:2648bf6c,server/internal/auth/ratelimit.go#NewFailureLadder:0f7648fc,server/internal/auth/ratelimit.go#FailureLadder.Allow:a58ec99e,server/internal/auth/ratelimit.go#ClientIPResolver:090d8c2a,server/internal/auth/ratelimit.go#NewClientIPResolver:ec0908d4,server/internal/auth/ratelimit.go#ClientIPResolver.Resolve:57a7db29,server/internal/control/ratelimit.go#PublicRateLimitPolicies:35cefa1b,server/internal/pki/enrollment.go#NewEnrollmentServiceWithTrustedProxies:01d1ab44,server/internal/pki/public_auth.go#EnrollmentService.applyPublicAuthenticationLimit:6a7256e3,server/internal/pki/registration_tokens.go#RegistrationTokens.Consume:9ef59cfc -->
- `server/internal/auth/ratelimit.go`
  - `FailureLimit`, `RateLimitPolicy`, `AuthenticationAttempt`
  - `FailureLadder`, `NewFailureLadder`, `FailureLadder.Allow`
  - `ClientIPResolver`, `NewClientIPResolver`, `ClientIPResolver.Resolve`
- `server/internal/auth/ratelimit_test.go`
- `server/internal/control/ratelimit.go`
  - `PublicRateLimitPolicies`
- `server/internal/control/ratelimit_test.go`
- `server/internal/pki/enrollment.go`
  - `EnrollmentService`, `NewEnrollmentServiceWithTrustedProxies`,
    `EnrollmentService.EnrollAgent`
- `server/internal/pki/gateway.go`
  - `EnrollmentService.EnrollGateway`, `EnrollmentService.RenewGateway`,
    `EnrollmentService.RevokeGateway`
- `server/internal/pki/renewal.go`
  - `EnrollmentService.RenewAgent`
- `server/internal/pki/revocation.go`
  - `EnrollmentService.RevokeAgent`, `EnrollmentService.ForceRenewAgent`
- `server/internal/pki/confirmation.go`
  - `EnrollmentService.ConfirmAgentTrustState`,
    `EnrollmentService.ConfirmGatewayTrustState`
- `server/internal/pki/public_auth.go`
  - `newPublicFailureLadder`, `EnrollmentService.resolvePublicClientIP`,
    `EnrollmentService.applyPublicAuthenticationLimit`
- `server/internal/pki/public_auth_guard_test.go`
- `server/internal/pki/registration_tokens.go`
  - `RegistrationTokens.Consume`
- affected PKI handler and token tests
- `docs/content/01-specs/00-index.md`
<!-- docref: end -->

## Tests

<!-- docref: begin src=server/internal/auth/ratelimit_test.go#TestFailureLadder_ThrottlesFailedAccountsWithoutLockout:514779ee,server/internal/auth/ratelimit_test.go#TestFailureLadder_EnforcesIPAndAccountIndependently:91abe476,server/internal/auth/ratelimit_test.go#TestFailureLadder_ExpiresSlidingWindows:5ffb9435,server/internal/auth/ratelimit_test.go#TestFailureLadder_RejectedFailuresExtendSlidingWindowWithoutLockout:5a713ebe,server/internal/auth/ratelimit_test.go#TestFailureLadder_FailsClosedForInvalidInputAndCapacity:5aaae84e,server/internal/auth/ratelimit_test.go#TestFailureLadder_DefensivelyCopiesPolicies:68452399,server/internal/auth/ratelimit_test.go#TestClientIPResolver_IgnoresForwardedForFromUntrustedPeer:cb91737d,server/internal/auth/ratelimit_test.go#TestClientIPResolver_WalksTrustedChainRightToLeft:218c9b12,server/internal/auth/ratelimit_test.go#TestClientIPResolver_RejectsMalformedTrustedChain:595832eb,server/internal/auth/ratelimit_test.go#TestClientIPResolver_RejectsInvalidConfiguration:f134969a,server/internal/auth/ratelimit_test.go#TestClientIPResolver_BoundsTrustedForwardedChain:b13a61ab,server/internal/control/ratelimit_test.go#TestGuard_PublicProceduresHaveCompleteRateLimitPolicies:ed4710be,server/internal/control/ratelimit_test.go#TestPublicRateLimitPolicies_DefensivelyCopied:c108e965,server/internal/pki/enrollment_test.go#TestEnrollmentHandler_FailureLadderDoesNotLockOutCorrectToken:088fcfa3,server/internal/pki/renewal_test.go#TestRenewalHandler_FailureLadderDoesNotLockOutCorrectCredential:ccf41997,server/internal/pki/public_auth_guard_test.go#TestPublicPKIHandlers_ReportAuthenticationOutcomes:55ff6758,server/internal/pki/public_auth_guard_test.go#TestPKIConfirmationOutcomeGuard_RejectsNestedReturnBypass:8996fe1a,server/internal/pki/enrollment_test.go#TestEnrollmentHandler_UsesTrustedProxyClientIP:a17d8fbf,server/internal/pki/enrollment_test.go#TestEnrollmentHandler_UsesAllForwardedForHeaderValues:90af11b5,server/internal/pki/revocation_test.go#TestRevocationHandler_SameIdentityCertificatesShareAccountFailureBucket:14462dde,server/internal/pki/rotation_test.go#exercisePkiServiceTrustConfirmationHandlers:d4207fe6 -->
- `TestFailureLadder_ThrottlesFailedAccountsWithoutLockout`
- `TestFailureLadder_EnforcesIPAndAccountIndependently`
- `TestFailureLadder_ExpiresSlidingWindows`
- `TestFailureLadder_RejectedFailuresExtendSlidingWindowWithoutLockout`
- `TestFailureLadder_FailsClosedForInvalidInputAndCapacity`
- `TestFailureLadder_DefensivelyCopiesPolicies`
- `TestClientIPResolver_IgnoresForwardedForFromUntrustedPeer`
- `TestClientIPResolver_WalksTrustedChainRightToLeft`
- `TestClientIPResolver_RejectsMalformedTrustedChain`
- `TestClientIPResolver_RejectsInvalidConfiguration`
- `TestClientIPResolver_BoundsTrustedForwardedChain`
- `TestGuard_PublicProceduresHaveCompleteRateLimitPolicies`
- `TestPublicRateLimitPolicies_DefensivelyCopied`
- `TestEnrollmentHandler_FailureLadderDoesNotLockOutCorrectToken`
- `TestRenewalHandler_FailureLadderDoesNotLockOutCorrectCredential`
- `TestPublicPKIHandlers_ReportAuthenticationOutcomes`
- `TestPKIConfirmationOutcomeGuard_RejectsNestedReturnBypass`
- `TestEnrollmentHandler_UsesTrustedProxyClientIP`
- `TestEnrollmentHandler_UsesAllForwardedForHeaderValues`
- `TestRevocationHandler_SameIdentityCertificatesShareAccountFailureBucket`
- `exercisePkiServiceTrustConfirmationHandlers` / missing failure ladder
  rejects before persistence
<!-- docref: end -->
