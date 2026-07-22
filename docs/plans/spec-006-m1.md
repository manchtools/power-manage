# SPEC-006 M1 — Identity primitives

Spec milestone: SPEC-006 M1 — certificate identity primitives, TLS class
separation, and the self-asserted identity guard.

## Delta

<!-- docref: begin src=contract/identity/identity.go#Class:ab995898,contract/identity/identity.go#StampCertificateIdentity:37ab3943,contract/identity/identity.go#ParseCertificateIdentity:e218f88e,contract/identity/identity.go#RequireCertificateClass:c1d99430,contract/identity/identity.go#ServerTLSConfig:ceec623c,contract/identity/identity.go#ClientTLSConfig:152623b5,contract/identity/identity.go#IsCanonicalULID:2a655dde,contract/sign/sign.go#CommandPreimage:aa6a2069,contract/sign/result.go#ResultPreimage:69b9b46f -->
- `contract/identity/identity.go`
  - add a closed agent/gateway/control certificate class type;
  - stamp an X.509 certificate template with exactly one class SPIFFE URI SAN
    and a canonical ULID common name;
  - parse and class-check that identity profile fail-closed;
  - build TLS 1.3 client and mutual-TLS server configurations that retain
    standard chain/DNS verification and reject the wrong peer class;
  - expose the existing canonical ULID predicate here and reuse it from the
    signing package instead of keeping a second implementation.
<!-- docref: end -->
<!-- docref: begin src=contract/archtest/denylist_test.go#TestGuard_DenyList:2ceb431f,contract/archtest/denylist_test.go#TestGuard_DenyList_Liveness:3f5a1148 -->
- `contract/archtest/denylist_test.go`, descriptor-walk helpers and fixtures
  - extend the existing self-discovering deny-list walk for GUARD-006-3 rather
    than adding a parallel walker;
  - continue banning `auth_token` globally and reject `device_id` or
    `gateway_id` from every PkiService request closure;
  - keep the walk matches-zero protected and prove all three field-name
    families with the existing fixture service.
<!-- docref: end -->

## Acceptance tests

<!-- docref: begin src=contract/identity/m1_test.go#TestStampCertificateIdentity_CanonicalProfile:91d802f2,contract/identity/m1_test.go#TestStampCertificateIdentity_RejectsInvalidInput:d4f1a738,contract/identity/m1_test.go#TestParseCertificateIdentity_RejectsMalformedProfile:eaaecbf0,contract/identity/m1_test.go#TestRequireCertificateClass_RejectsWrongClass:46af7fc6,contract/identity/m1_test.go#TestServerTLSConfig_RequiresTLS13AndClientCertificate:dc56f6b7,contract/identity/m1_test.go#TestServerTLSConfig_RejectsWrongClientClassBeforeUse:bac8dcb1,contract/identity/m1_test.go#TestClientTLSConfig_UsesEnrolledCAAndGatewayClass:98361ce1,contract/identity/m1_test.go#TestClientTLSConfig_RejectsWrongServerClass:77648143 -->
- `TestStampCertificateIdentity_CanonicalProfile`
- `TestStampCertificateIdentity_RejectsInvalidInput`
- `TestParseCertificateIdentity_RejectsMalformedProfile`
- `TestRequireCertificateClass_RejectsWrongClass`
- `TestServerTLSConfig_RequiresTLS13AndClientCertificate`
- `TestServerTLSConfig_RejectsWrongClientClassBeforeUse`
- `TestClientTLSConfig_UsesEnrolledCAAndGatewayClass`
- `TestClientTLSConfig_RejectsWrongServerClass`
- `TestGuard_DenyList` extended with GUARD-006-3 coverage
- `TestGuard_DenyList_Liveness` extended with PkiService identity-field
  fixtures
<!-- docref: end -->

The TLS cases use real handshakes and locally issued certificates. Rejection
tests assert that the handshake fails before application data is accepted.

## Scope boundary

- M1 does not issue certificates, hold CA keys, add PkiService procedures, or
  implement enrollment. It supplies the profile and TLS seams those later
  milestones consume.
- The production PkiService currently has no procedures. The descriptor guard
  scans the existing non-empty contract surface now and automatically applies
  its stricter identity-field rule when M4 adds production request messages;
  the separate FixtureService procedure exists only to prove that walk live.
