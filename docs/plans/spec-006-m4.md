# SPEC-006 M4 — PkiService agent enrollment

Spec milestone: SPEC-006 M4 (`PKI-1a`, `PKI-2`, `PKI-4`, `AG-17`;
AC-1/AC-2/AC-16; GUARD-006-1).

## Scope

<!-- docref: begin src=contract/proto/powermanage/v1/pki.proto#PkiService.EnrollAgent:d1089b10,server/internal/pki/enrollment.go#EnrollmentService.EnrollAgent:1083a818,server/internal/pki/server.go#NewServer:252d1c8f,server/internal/pki/server.go#Server.ListenAndServe:7b018804,server/internal/pki/procedures.go#PublicProcedureLimits:648fb4f4 -->
- Add one `PkiService.EnrollAgent` Connect RPC. The request carries only a
  registration token, exact DER PKCS#10 CSR, and a 32-byte X25519 public key.
  The response carries the exact DER agent certificate and issuing agent CA.
  Every field has a bounded Protovalidate rule; malformed token shapes still
  reach the uniform token-admission path.
- Add the real Connect handler and server-auth-only TLS 1.3 listener on the
  default `:8083` address. The network source is derived from the HTTP peer,
  never request data. The existing registration-token service remains the
  sole authorization and server-side five-per-minute admission gate.
- Parse the CSR as exact DER, verify its signature, reject every form of SAN
  request before token consumption, and accept only the existing approved
  ECDSA/RSA key profile. Control ignores the CSR subject, mints a fresh ULID,
  stamps exactly the agent SPIFFE URI plus CN, and issues a one-year
  ClientAuth certificate from the agent CA.
<!-- docref: end -->
<!-- docref: begin src=server/internal/store/migrations/006_devices.sql#@devices-schema:f36bec6f,server/internal/store/devices.go#AgentEnrolledEvent:5763ffe4,server/internal/store/devices.go#Store.Device:320327d5,server/internal/store/devices.go#projectAgentEnrollment:6f5d031d -->
- Persist `AgentEnrolled` as the sole durable enrollment mutation. Its device
  projection stores exact certificate DER, a SHA-256 certificate fingerprint,
  the 32-byte sealing public key, token locator/owner provenance, and
  projection version. Rebuild, golden-event, table-classification, static-SQL,
  and recovery registries expand with the projection.
<!-- docref: end -->
<!-- docref: begin src=contract/seal/x25519.go#ValidateX25519PublicKey:8ad04b05,agent/internal/enroll/client.go#Client.Enroll:7e2c9279,agent/internal/enroll/client.go#validateEnrollmentResponse:b7f812e5,agent/internal/enroll/store.go#FileCredentialStore.Create:0c1160f4,sdk/fsafe/write_new_linux.go#WriteFileNew:e284194b -->
- Add an agent enrollment client that generates the ECDSA P-256 mTLS key and
  X25519 sealing key locally, sends only the CSR/public key, validates the
  returned CA/certificate/profile/key match, applies optional SHA-256 CA
  fingerprint pinning, and atomically creates one root-only credential bundle.
  Existing credentials are never overwritten: reset remains the only route to
  fresh enrollment.
<!-- docref: end -->
<!-- docref: begin src=agent/internal/enroll/relay.go#Relay.Serve:149922e5,agent/internal/enroll/relay.go#Submit:0926d685,agent/internal/enroll/relay.go#decodeLocalEnrollmentResponse:d75fabad,agent/internal/enroll/relay.go#removeStaleSocket:fd80bcd8,agent/internal/enroll/relay.go#validateRelayParent:9b3d0d17,agent/cmd/power-manage-agent/main.go#run:d2ed7925,agent/cmd/power-manage-agent/main.go#readTokenFile:43bc66a9,sdk/guardtest/listeners.go#ListenerRegistrations:fb31987d,server/internal/pki/procedures_test.go#TestGuard_PkiPublicRateLimitRegistration:11bed0f8 -->
- Add the `/run/pm-agent/enroll.sock` relay at exact mode `0666`, with an
  independent five-attempt sliding-minute limiter and a bounded context per
  attempt. The parent is root-owned/non-writable, live sockets are never
  unlinked, and the local request/response framing is bounded and exact. Add
  the `power-manage-agent enroll` client surface with token intake from a
  no-follow bounded `--token-file` or stdin only; TTY input is prompted without
  echo. There is no token-valued argv option.
- Register the Pki listener as boundary B10 and the local relay as B5. Add a
  descriptor-driven exact-set guard joining every PkiService procedure to the
  declared public rate-limit ladder; zero procedures is a failure.
<!-- docref: end -->

The control composition binary, agent daemon boot wiring, installer reset,
renewal loop, and deployment stack remain in their owning later milestones.
The M4 listener and relay are production constructors exercised over real TLS
and Unix sockets; later composition supplies their configured key/file paths.
GUARD-006-4 arms in M5 when renewal introduces competing operations against an
already-issued device identity. A fresh enrollment has no caller-selected
device ID; a ULID collision is rejected by the version-zero device stream.

## Acceptance tests — red first

<!-- docref: begin src=contract/archtest/pki_test.go#TestPkiServiceShape:bdd5f0c3,server/internal/pki/enrollment_test.go#TestEnrollmentHandler_IssuesAndPersistsAgentIdentity:d8017d47,server/internal/pki/enrollment_test.go#TestEnrollmentHandler_RejectsMalformedProofBeforeTokenUse:89374116,server/internal/pki/enrollment_test.go#TestEnrollmentHandler_ConcurrentTokenUseBoundsCertificates:df12a775,server/internal/pki/enrollment_test.go#TestEnrollmentHandler_RateLimitsNetworkSource:84b72fc9,server/internal/pki/server_test.go#TestServer_ServesTLS13WithoutClientCertificate:f345f6db,server/internal/pki/server_test.go#TestNewServer_RejectsUnwiredTLSOrHandler:5fd54171,agent/internal/enroll/client_test.go#TestClient_EnrollKeepsPrivateKeysLocalAndStoresVerifiedIdentity:f818a4cc,agent/internal/enroll/client_test.go#TestClient_EnrollRefusesPinAndResponseSubstitutionBeforeStorage:b4c14544,agent/internal/enroll/relay_test.go#TestRelay_SocketModeAndFivePerMinuteLimit:530326c9,agent/internal/enroll/relay_test.go#TestRelay_ReplacesOnlyStaleSocketEntries:6a33ba28,agent/internal/enroll/relay_test.go#TestRelay_BoundsEachEnrollmentWithADeadline:c1edb055,agent/internal/enroll/relay_test.go#TestRelay_RefusesWritableSocketParent:414e6d19,agent/internal/enroll/relay_test.go#TestSubmit_RejectsTrailingLocalResponse:9d67c0b8,agent/cmd/power-manage-agent/main_test.go#TestRunEnroll_AcceptsOnlyStdinOrTokenFile:df66128d,agent/cmd/power-manage-agent/main_test.go#TestRunEnroll_HasNoTokenValuedArgvFlag:37c79ba7,server/internal/store/devices_test.go#TestDeviceProjection_RebuildsEnrollmentState:f1d2022a,server/internal/store/devices_test.go#TestDeviceProjection_RejectsInvalidEnrollmentEvents:20e6488f,sdk/fsafe/write_new_test.go#TestWriteFileNew_AtomicallyRefusesOverwrite:0fdc32ed -->
1. **Contract and guard shape.** Descriptor tests pin exactly one M4 procedure,
   request/response field names and validation rules, the absence of
   self-asserted identity fields, and exact public rate-limit registration.
   Listener discovery must join the two new production sites to B10 and B5.
2. **Real enrollment handler.** Through a TLS Connect client and real Postgres,
   a valid request returns an agent-class certificate with a new canonical
   ULID CN, the CSR public key, one-year ClientAuth profile, and the expected
   issuing CA. The device projection/event contain the exact DER/fingerprint
   and sealing key but no private key or raw registration token.
3. **CSR refusal.** Absent, trailing-data, bad-signature, unsupported-key, and
   every SAN-bearing CSR form are rejected before token consumption and before
   any device event/projection row. A CSR subject CN is ignored and replaced.
   Empty, malformed, all-zero/low-order, and wrong-length sealing keys reject
   without durable change.
4. **Admission behavior.** Absent, malformed, unknown, expired, disabled,
   exhausted, and losing-race tokens receive the established uniform
   rejection. Six requests from one source are rate-limited; independent
   sources do not share capacity. With `max_uses=N`, `N+k` real concurrent RPCs
   against Postgres produce exactly N returned certificates and N device rows.
5. **TLS boundary.** TLS below 1.3 fails, a client certificate is not required,
   normal hostname verification remains active, and clean cancellation shuts
   down the listener. Unwired service/certificate inputs fail construction.
   The boundary registry discovers both listener sites.
6. **Agent custody and TOFU.** The client proves neither private key crosses
   the RPC, validates certificate/CSR key equality and agent identity, stores
   the returned approved-profile CA on first enrollment, refuses a mismatched
   explicit CA pin, refuses malformed/mismatched responses, creates the
   credential bundle as root-only `0600`, and never overwrites an existing
   bundle.
7. **Local relay and CLI.** A real Unix socket is exactly `0666`; five attempts
   reach the enroller and the sixth is rejected. Stale sockets are replaced but
   active sockets, symlinks, non-sockets, and writable parents are refused.
   Relay work gets a finite deadline and trailing local protocol data is
   rejected. Stdin pipe, TTY password input, and a bounded regular no-follow
   token file succeed; missing/unreadable/symlinked/oversized files fail. The
   flag registry contains no token-valued argv flag.
8. **Store discipline.** Real-Postgres tests pin event transition validation,
   projection rebuild byte equality, golden payloads, exact table class, and
   the CLI recovery target. Corrupt certificate/sealing-key events fail the
   append transaction with no partial row.
<!-- docref: end -->

Focused package tests are followed by all four module race suites,
`./scripts/verify.sh`, strict docref, and local review before the branch is
committed or published.

## Security ordering

The handler performs bounded message validation plus CSR
signature/profile/SAN and sealing-key validation before token authorization.
Certificate signing happens only after authorization, so an unauthenticated
caller cannot drive the CA signer. Token consumption occurs before certificate
issuance and the device event append; any infrastructure failure thereafter
fails closed and returns no certificate. No rejected pre-authorization input
consumes a token. Token-state errors expose one response; request-shape errors
expose only stable categories and never echo the token, CSR, key material,
source address, or certificate bytes.

## Out of scope

- Agent renewal, proof-of-possession, supersession revocation, per-device
  advisory locking, and the renewal loop (M5).
- CRL issuance/distribution, gateway identity, and CA continuity (M6–M8).
- Gateway enrollment and DNS SAN issuance (M7).
- The reusable cross-service rate-limit implementation (SPEC-007). M4 owns the
  Pki procedure registry and the two required enrollment admission limits.
- `install.sh --reset`, full agent daemon lifecycle, and credential loading by
  the runtime (SPEC-013). M4 preserves the no-overwrite boundary they consume.
- Compose/deployment E2E wiring (SPEC-017); no deployment artifacts exist yet.
