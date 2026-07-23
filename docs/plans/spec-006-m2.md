# SPEC-006 M2 — CA custody and signing surfaces

Spec milestone: SPEC-006 M2 — three control-only signing authorities,
cross-module signature chokepoints, approved-key boot validation, and
GUARD-006-2/6.

## Delta

<!-- docref: begin src=server/internal/pki/authorities.go#Authorities:c41e0997,server/internal/pki/authorities.go#NewAuthorities:37e0db0d,server/internal/pki/authorities.go#Authorities.SignCommand:b652ca7b,server/internal/pki/authorities.go#Authorities.SignAgentRevocationList:2c392969,server/internal/pki/authorities.go#Authorities.SignGatewayRevocationList:9cd832db,server/internal/pki/authorities.go#DERResultVerifier.VerifyResult:a5882d43 -->
- `server/internal/pki/authorities.go`
  - add an opaque control-side authority set holding the agent CA certificate
    and signer, gateway CA certificate and signer, and command signer;
  - parse CA certificates from exact DER, require CA and certificate/CRL key
    usages and a CRL authority-key identifier, validate every key through
    `contract/sign.ValidateSigningKey`,
    require each signer to match its certificate, and reject key reuse across
    the three authorities;
  - expose only purpose-specific command-signing and agent/gateway CRL-signing
    methods, rejecting raw extensions that could override the signed authority
    key identifier or monotonic CRL number; no CA private-key accessor exists;
  - add the control result-verification chokepoint which derives the verifying
    key by parsing the supplied stored certificate DER on every call.
<!-- docref: end -->
<!-- docref: begin src=agent/internal/signing/signing.go#Profile:04f78893,agent/internal/signing/signing.go#NewProfile:6a764dec,agent/internal/signing/signing.go#Profile.VerifyCommand:6ecf5e08,agent/internal/signing/signing.go#Profile.SignResult:bcfe4b69 -->
- `agent/internal/signing/signing.go`
  - add the agent signing profile constructed from the command public key and
    the device's own private signer;
  - validate both at construction and expose the sole agent command-verify and
    result-sign chokepoints; no CA private key is accepted or held.
<!-- docref: end -->
<!-- docref: begin src=server/internal/control/runtime.go#NewRuntime:3f4f9b43 -->
- `server/internal/control/runtime.go`
  - add the control composition-root constructor with narrow interfaces for
    device-signature verification, device/gateway binding resolution, and CRL
    signing;
  - reject nil and typed-nil dependencies before a runtime can be returned.
<!-- docref: end -->
<!-- docref: begin src=contract/archtest/domainscan.go#ScanSignatureSites:35881f7a,contract/archtest/guards_test.go#TestGuard_SignatureDomains:ca9a81fc,contract/archtest/guards_test.go#TestSignatureSiteScan_Liveness:3cfce2fa -->
- `contract/archtest/domainscan.go`, `contract/archtest/guards_test.go`, and a
  focused matcher fixture
  - extend the self-discovered signature-domain guard to inventory production
    references to the four shared signing functions across `server/` and
    `agent/`;
  - require exactly one ownership-correct chokepoint for each family:
    control signs commands, agent verifies commands, agent signs results, and
    control verifies results;
  - reject indirect references, dot imports, direct preimage/domain-helper use,
    and lower-level ECDSA/Ed25519/RSA/`crypto.Signer`/`crypto.MessageSigner`
    primitives outside an explicit exact-site owner, so a second hidden sign
    or verify path cannot evade the count;
    type-check complete packages to distinguish imports from local shadows and
    unrelated methods split across sibling files, and prove the matcher with
    liveness fixtures;
  - retain the existing generated pairwise-isolation matrix over every
    discovered `*SignatureDomain` constant.
<!-- docref: end -->

No external dependency is added. Certificate issuance, enrollment handlers,
token admission, renewal, and CRL distribution remain in their later
milestones.

## Acceptance tests

<!-- docref: begin src=server/internal/pki/authorities_test.go#TestNewAuthorities_AcceptsThreeDistinctApprovedAuthorities:4a701c7e,server/internal/pki/authorities_test.go#TestNewAuthorities_RejectsInvalidCA:6d6ae3b5,server/internal/pki/authorities_test.go#TestNewAuthorities_RejectsMismatchedOrReusedKeys:aacbb8a0,server/internal/pki/authorities_test.go#TestNewAuthorities_RejectsUnsupportedSigningProfiles:a3b141e7,server/internal/pki/authorities_test.go#TestAuthorities_SignCommandUsesCommandAuthority:922929a4,server/internal/pki/authorities_test.go#TestAuthorities_SignRevocationListsWithClassCA:1f5a4a40,server/internal/pki/authorities_test.go#TestDERResultVerifier_ParsesStoredCertificateEveryCall:35730aca,server/internal/pki/authorities_test.go#TestDERResultVerifier_FailsClosed:a41a662d,agent/internal/signing/signing_test.go#TestNewProfile_RejectsUnsupportedSigningProfiles:35f42a22,agent/internal/signing/signing_test.go#TestProfile_VerifiesCommandsAndSignsResults:3227e9fe,agent/internal/signing/signing_test.go#TestProfile_FailsClosedOnInvalidSignatures:644130cd,server/internal/control/runtime_test.go#TestNewRuntime_RequiresSecurityDependencies:06b94d3b,server/internal/control/runtime_test.go#TestNewRuntime_AcceptsWiredSecurityDependencies:4b6395cf,contract/archtest/guards_test.go#TestGuard_SignatureDomains:ca9a81fc,contract/archtest/guards_test.go#TestSignatureSiteScan_Liveness:3cfce2fa,contract/sign/sign_test.go#TestValidateSigningKey_RejectsMalformedPrivateKeys:e73883cd,server/internal/pki/authorities_test.go#TestAuthorities_SignRevocationListsRejectReservedExtensions:36be50d2,server/internal/pki/authorities_test.go#TestAuthorities_KeepPrivateKeysOpaque:a0fc89b6 -->
- `TestValidateSigningKey_RejectsMalformedPrivateKeys`
- `TestNewAuthorities_AcceptsThreeDistinctApprovedAuthorities`
- `TestNewAuthorities_RejectsInvalidCA`
- `TestNewAuthorities_RejectsMismatchedOrReusedKeys`
- `TestNewAuthorities_RejectsUnsupportedSigningProfiles`
- `TestAuthorities_SignCommandUsesCommandAuthority`
- `TestAuthorities_SignRevocationListsWithClassCA`
- `TestAuthorities_SignRevocationListsRejectReservedExtensions`
- `TestAuthorities_KeepPrivateKeysOpaque`
- `TestDERResultVerifier_ParsesStoredCertificateEveryCall`
- `TestDERResultVerifier_FailsClosed`
- `TestNewProfile_RejectsUnsupportedSigningProfiles`
- `TestProfile_VerifiesCommandsAndSignsResults`
- `TestProfile_FailsClosedOnInvalidSignatures`
- `TestNewRuntime_RequiresSecurityDependencies`
- `TestNewRuntime_AcceptsWiredSecurityDependencies`
- `TestGuard_SignatureDomains` extended with cross-module exact-site parity
- `TestSignatureSiteScan_Liveness`
<!-- docref: end -->

Negative cases assert the intended rejection category, not merely that an
error occurred. Key-profile rows include nil and typed-nil values, Ed25519,
P-224, RSA-1024, malformed ECDSA points, and signer/certificate mismatch.
Valid rows cover ECDSA P-256/P-384/P-521 and RSA-2048 across the shared key
gate without duplicating its implementation.

## Scope boundary

- The CA holders provide only command and revocation-list signing in M2;
  certificate issuance is added with the CSR-only enrollment path in M4 so no
  broad issuer API can bypass identity stamping.
- The result verifier accepts certificate DER rather than a projected public
  key. Loading that DER from durable device state is wired with the lifecycle
  handlers in M4/M5; GUARD-006-5 arms when those call sites exist.
- The runtime constructor is the boot fail-closed seam. Listener startup and
  the three service binaries land in their owning milestones.
