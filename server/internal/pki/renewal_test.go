package pki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/identity"
)

// TestRenewalHandler_RenewsCurrentIdentityAndRecordsSupersession exercises the
// real Connect handler, CA signer, lifecycle transaction, and Postgres
// projection as one renewal boundary.
func TestRenewalHandler_RenewsCurrentIdentityAndRecordsSupersession(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	currentKey, currentCertificate, deviceID := enrollRenewalFixture(t, fixture)
	newSealingKey := newEnrollmentSealingKey(t)

	response, err := fixture.client.RenewAgent(context.Background(), connect.NewRequest(&powermanagev1.RenewAgentRequest{
		CertificateDer:               currentCertificate,
		CertificateSigningRequestDer: newEnrollmentCSR(t, currentKey, pkix.Name{CommonName: "ignored"}, nil),
		SealingPublicKey:             newSealingKey,
	}))
	if err != nil {
		t.Fatalf("RenewAgent: %v", err)
	}
	renewed := parseEnrollmentCertificate(t, response.Msg.GetCertificateDer())
	class, renewedID, err := identity.ParseCertificateIdentity(renewed)
	if err != nil {
		t.Fatalf("parse renewed identity: %v", err)
	}
	if class != identity.AgentClass || renewedID != deviceID {
		t.Fatalf("renewed identity = (%q, %q); want agent %q", class, renewedID, deviceID)
	}
	if renewed.IsCA || !renewed.BasicConstraintsValid || renewed.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		len(renewed.ExtKeyUsage) != 1 || renewed.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		renewed.NotAfter.Sub(renewed.NotBefore) != agentCertificateLifetime {
		t.Fatalf("renewed certificate profile = %+v; want one-year agent ClientAuth", renewed)
	}
	if !publicKeysEqual(t, renewed.PublicKey, currentKey.Public()) {
		t.Fatal("renewed certificate key differs from enrolled key")
	}
	if bytes.Equal(renewed.Raw, currentCertificate) {
		t.Fatal("renewal returned the superseded certificate")
	}
	if !bytes.Equal(response.Msg.GetCertificateAuthorityDer(), fixture.agentCA.Raw) {
		t.Fatal("renewal returned a different agent CA")
	}

	persisted, err := fixture.eventStore.Device(context.Background(), deviceID)
	if err != nil {
		t.Fatalf("read renewed device: %v", err)
	}
	wantFingerprint := sha256.Sum256(renewed.Raw)
	if persisted.ProjectionVersion != 2 || persisted.CertificateFingerprint != wantFingerprint ||
		!bytes.Equal(persisted.CertificateDER, renewed.Raw) ||
		!bytes.Equal(persisted.PreviousCertificateDER, currentCertificate) ||
		!bytes.Equal(persisted.SealingPublicKey, newSealingKey) {
		t.Fatalf("renewed projection = %+v; want version two with exact replacement state", persisted)
	}

	var eventType string
	var payload []byte
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT event_type, payload
		FROM events
		WHERE stream_type = 'device' AND stream_id = $1 AND stream_version = 2`, deviceID).Scan(&eventType, &payload); err != nil {
		t.Fatalf("read renewal event: %v", err)
	}
	durable := decodeDurableRenewalEvent(t, payload)
	if eventType != "AgentCertificateRenewed" || !bytes.Equal(durable.CertificateDER, renewed.Raw) ||
		!bytes.Equal(durable.SealingPublicKey, newSealingKey) || !bytes.Equal(durable.SupersededCertificateDER, currentCertificate) {
		t.Fatalf("renewal event = %q %+v; want exact replacement and superseded DER", eventType, durable)
	}
}

func TestRenewalHandler_RetryAfterLostResponseReturnsExistingSuccessor(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	currentKey, currentCertificate, deviceID := enrollRenewalFixture(t, fixture)
	request := &powermanagev1.RenewAgentRequest{
		CertificateDer:               currentCertificate,
		CertificateSigningRequestDer: newEnrollmentCSR(t, currentKey, pkix.Name{}, nil),
		SealingPublicKey:             newEnrollmentSealingKey(t),
	}

	first, err := fixture.client.RenewAgent(context.Background(), connect.NewRequest(proto.Clone(request).(*powermanagev1.RenewAgentRequest)))
	if err != nil {
		t.Fatalf("first RenewAgent: %v", err)
	}
	retryRequest := proto.Clone(request).(*powermanagev1.RenewAgentRequest)
	retryRequest.CertificateSigningRequestDer = newEnrollmentCSR(t, currentKey, pkix.Name{}, nil)
	retry, err := fixture.client.RenewAgent(context.Background(), connect.NewRequest(retryRequest))
	if err != nil {
		t.Fatalf("retry RenewAgent: %v", err)
	}
	if !bytes.Equal(retry.Msg.GetCertificateDer(), first.Msg.GetCertificateDer()) ||
		!bytes.Equal(retry.Msg.GetCertificateAuthorityDer(), first.Msg.GetCertificateAuthorityDer()) {
		t.Fatal("renewal retry did not return the exact existing successor")
	}

	mismatched := proto.Clone(request).(*powermanagev1.RenewAgentRequest)
	mismatched.SealingPublicKey = newEnrollmentSealingKey(t)
	if _, err := fixture.client.RenewAgent(context.Background(), connect.NewRequest(mismatched)); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("mismatched retry code = %v (error %v); want unauthenticated", connect.CodeOf(err), err)
	}
	var events int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM events WHERE stream_type = 'device' AND stream_id = $1`, deviceID).Scan(&events); err != nil {
		t.Fatalf("count device events: %v", err)
	}
	if events != 2 {
		t.Fatalf("device events = %d; want enrollment plus one renewal", events)
	}
}

func TestRenewalHandler_RejectsFingerprintOrPossessionMismatchWithoutStateChange(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*testing.T, enrollmentHandlerFixture, *ecdsa.PrivateKey, string, *powermanagev1.RenewAgentRequest)
		wantCode connect.Code
	}{
		{
			name: "CSR key differs from current certificate",
			mutate: func(t *testing.T, _ enrollmentHandlerFixture, _ *ecdsa.PrivateKey, _ string, request *powermanagev1.RenewAgentRequest) {
				request.CertificateSigningRequestDer = newEnrollmentCSR(t, newEnrollmentSigningKey(t), pkix.Name{}, nil)
			},
			wantCode: connect.CodeUnauthenticated,
		},
		{
			name: "CSR contains SAN",
			mutate: func(t *testing.T, _ enrollmentHandlerFixture, key *ecdsa.PrivateKey, _ string, request *powermanagev1.RenewAgentRequest) {
				request.CertificateSigningRequestDer = newEnrollmentCSR(t, key, pkix.Name{}, func(template *x509.CertificateRequest) {
					template.DNSNames = []string{"attacker.invalid"}
				})
			},
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name: "CSR signature is invalid",
			mutate: func(t *testing.T, _ enrollmentHandlerFixture, key *ecdsa.PrivateKey, _ string, request *powermanagev1.RenewAgentRequest) {
				request.CertificateSigningRequestDer = corruptRenewalCSRSignature(t, newEnrollmentCSR(t, key, pkix.Name{}, nil))
			},
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name: "CSR is malformed",
			mutate: func(_ *testing.T, _ enrollmentHandlerFixture, _ *ecdsa.PrivateKey, _ string, request *powermanagev1.RenewAgentRequest) {
				request.CertificateSigningRequestDer = []byte("bad")
			},
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name: "certificate contains trailing DER",
			mutate: func(_ *testing.T, _ enrollmentHandlerFixture, _ *ecdsa.PrivateKey, _ string, request *powermanagev1.RenewAgentRequest) {
				request.CertificateDer = append(bytes.Clone(request.CertificateDer), 0)
			},
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name: "certificate is malformed",
			mutate: func(_ *testing.T, _ enrollmentHandlerFixture, _ *ecdsa.PrivateKey, _ string, request *powermanagev1.RenewAgentRequest) {
				request.CertificateDer = []byte("bad")
			},
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name: "certificate has gateway class",
			mutate: func(t *testing.T, _ enrollmentHandlerFixture, key *ecdsa.PrivateKey, deviceID string, request *powermanagev1.RenewAgentRequest) {
				request.CertificateDer = newPresentedRenewalCertificate(t, request.CertificateDer, key, identity.GatewayClass, deviceID, 81)
			},
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name: "presented certificate is substituted",
			mutate: func(t *testing.T, _ enrollmentHandlerFixture, key *ecdsa.PrivateKey, deviceID string, request *powermanagev1.RenewAgentRequest) {
				request.CertificateDer = newPresentedRenewalCertificate(t, request.CertificateDer, key, identity.AgentClass, deviceID, 82)
			},
			wantCode: connect.CodeUnauthenticated,
		},
		{
			name: "sealing key is low-order",
			mutate: func(_ *testing.T, _ enrollmentHandlerFixture, _ *ecdsa.PrivateKey, _ string, request *powermanagev1.RenewAgentRequest) {
				request.SealingPublicKey = make([]byte, 32)
			},
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name: "stored fingerprint differs",
			mutate: func(t *testing.T, fixture enrollmentHandlerFixture, _ *ecdsa.PrivateKey, _ string, _ *powermanagev1.RenewAgentRequest) {
				if _, err := fixture.pool.Exec(context.Background(), `UPDATE devices SET certificate_fingerprint = $1`, make([]byte, sha256.Size)); err != nil {
					t.Fatalf("corrupt stored fingerprint: %v", err)
				}
			},
			wantCode: connect.CodeUnauthenticated,
		},
		{
			name: "stored certificate DER differs",
			mutate: func(t *testing.T, fixture enrollmentHandlerFixture, key *ecdsa.PrivateKey, deviceID string, request *powermanagev1.RenewAgentRequest) {
				differentDER := newPresentedRenewalCertificate(t, request.CertificateDer, key, identity.AgentClass, deviceID, 83)
				if _, err := fixture.pool.Exec(context.Background(), `UPDATE devices SET certificate_der = $1`, differentDER); err != nil {
					t.Fatalf("corrupt stored certificate DER: %v", err)
				}
			},
			wantCode: connect.CodeUnauthenticated,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEnrollmentHandlerFixture(t, 1)
			currentKey, currentCertificate, deviceID := enrollRenewalFixture(t, fixture)
			request := &powermanagev1.RenewAgentRequest{
				CertificateDer:               currentCertificate,
				CertificateSigningRequestDer: newEnrollmentCSR(t, currentKey, pkix.Name{}, nil),
				SealingPublicKey:             newEnrollmentSealingKey(t),
			}
			test.mutate(t, fixture, currentKey, deviceID, request)
			before := readRenewalState(t, fixture, deviceID)
			_, err := fixture.client.RenewAgent(context.Background(), connect.NewRequest(request))
			if connect.CodeOf(err) != test.wantCode {
				t.Fatalf("RenewAgent code = %v (error %v); want %v", connect.CodeOf(err), err, test.wantCode)
			}
			wantError := test.wantCode.String() + ": renewal request rejected"
			if test.wantCode == connect.CodeUnauthenticated {
				wantError = test.wantCode.String() + ": renewal authorization rejected"
			}
			if err.Error() != wantError {
				t.Fatalf("RenewAgent error = %q; want uniform %q", err, wantError)
			}
			assertRenewalStateUnchanged(t, fixture, deviceID, before)
		})
	}
}

func TestRenewalHandler_AppendFailureReturnsNoCertificateAndRollsBack(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	currentKey, currentCertificate, deviceID := enrollRenewalFixture(t, fixture)
	before := readRenewalState(t, fixture, deviceID)
	if _, err := fixture.pool.Exec(context.Background(), `
		CREATE FUNCTION reject_agent_certificate_renewed() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.event_type = 'AgentCertificateRenewed' THEN
				RAISE EXCEPTION 'forced renewal append failure';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER reject_agent_certificate_renewed
		BEFORE INSERT ON events
		FOR EACH ROW EXECUTE FUNCTION reject_agent_certificate_renewed()`); err != nil {
		t.Fatalf("install renewal append-failure trigger: %v", err)
	}
	response, err := fixture.client.RenewAgent(context.Background(), connect.NewRequest(&powermanagev1.RenewAgentRequest{
		CertificateDer:               currentCertificate,
		CertificateSigningRequestDer: newEnrollmentCSR(t, currentKey, pkix.Name{}, nil),
		SealingPublicKey:             newEnrollmentSealingKey(t),
	}))
	wantError := connect.CodeInternal.String() + ": " + errRenewalTemporarilyFailed.Error()
	if err == nil || response != nil || connect.CodeOf(err) != connect.CodeInternal || err.Error() != wantError {
		t.Fatalf("RenewAgent = (%v, %v); want no certificate and %q", response, err, wantError)
	}
	assertRenewalStateUnchanged(t, fixture, deviceID, before)
}

func TestRenewalHandler_RateLimitsNetworkSource(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	currentKey, currentCertificate, _ := enrollRenewalFixture(t, fixture)
	request := &powermanagev1.RenewAgentRequest{
		CertificateDer:               currentCertificate,
		CertificateSigningRequestDer: newEnrollmentCSR(t, currentKey, pkix.Name{}, nil),
		SealingPublicKey:             newEnrollmentSealingKey(t),
	}
	for attempt := 1; attempt <= 6; attempt++ {
		attemptRequest := proto.Clone(request).(*powermanagev1.RenewAgentRequest)
		if attempt > 1 {
			attemptRequest.SealingPublicKey = newEnrollmentSealingKey(t)
		}
		_, err := fixture.client.RenewAgent(context.Background(), connect.NewRequest(attemptRequest))
		if attempt == 1 {
			if err != nil {
				t.Fatalf("attempt 1 renewal: %v", err)
			}
			continue
		}
		want := connect.CodeUnauthenticated
		wantReason := errRenewalAuthRejected
		if attempt == 6 {
			want = connect.CodeResourceExhausted
			wantReason = errRenewalRateLimited
		}
		wantError := want.String() + ": " + wantReason.Error()
		if err == nil || connect.CodeOf(err) != want || err.Error() != wantError {
			t.Fatalf("attempt %d error = %v; want %q", attempt, err, wantError)
		}
	}
}

func TestRenewalHandler_ConcurrentRequestsProduceOneCertificate(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	currentKey, currentCertificate, deviceID := enrollRenewalFixture(t, fixture)
	request := &powermanagev1.RenewAgentRequest{
		CertificateDer:               currentCertificate,
		CertificateSigningRequestDer: newEnrollmentCSR(t, currentKey, pkix.Name{}, nil),
		SealingPublicKey:             newEnrollmentSealingKey(t),
	}
	start := make(chan struct{})
	type renewalResult struct {
		response *connect.Response[powermanagev1.RenewAgentResponse]
		err      error
	}
	results := make(chan renewalResult, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			cloned := proto.Clone(request).(*powermanagev1.RenewAgentRequest)
			response, err := fixture.client.RenewAgent(context.Background(), connect.NewRequest(cloned))
			results <- renewalResult{response: response, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var certificateDER []byte
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent renewal error = %v; want idempotent success", result.err)
		}
		if certificateDER == nil {
			certificateDER = bytes.Clone(result.response.Msg.GetCertificateDer())
			continue
		}
		if !bytes.Equal(result.response.Msg.GetCertificateDer(), certificateDER) {
			t.Fatal("concurrent renewal returned more than one successor certificate")
		}
	}
	var events int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM events WHERE stream_type = 'device' AND stream_id = $1`, deviceID).Scan(&events); err != nil {
		t.Fatalf("count device events: %v", err)
	}
	if events != 2 {
		t.Fatalf("device events = %d; want enrollment plus one renewal", events)
	}
	device, err := fixture.eventStore.Device(context.Background(), deviceID)
	if err != nil {
		t.Fatalf("read renewed device: %v", err)
	}
	if device.ProjectionVersion != 2 {
		t.Fatalf("device projection version = %d; want two", device.ProjectionVersion)
	}
}

func enrollRenewalFixture(t *testing.T, fixture enrollmentHandlerFixture) (*ecdsa.PrivateKey, []byte, string) {
	t.Helper()
	key := newEnrollmentSigningKey(t)
	response, err := fixture.client.EnrollAgent(context.Background(), connect.NewRequest(&powermanagev1.EnrollAgentRequest{
		RegistrationToken:            fixture.token,
		CertificateSigningRequestDer: newEnrollmentCSR(t, key, pkix.Name{}, nil),
		SealingPublicKey:             newEnrollmentSealingKey(t),
	}))
	if err != nil {
		t.Fatalf("enroll renewal fixture: %v", err)
	}
	certificate := parseEnrollmentCertificate(t, response.Msg.GetCertificateDer())
	_, deviceID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil {
		t.Fatalf("parse renewal fixture identity: %v", err)
	}
	return key, bytes.Clone(certificate.Raw), deviceID
}

type renewalState struct {
	certificateDER         []byte
	certificateFingerprint []byte
	sealingPublicKey       []byte
	registrationTokenID    string
	owner                  string
	version                int64
	events                 int
}

func readRenewalState(t *testing.T, fixture enrollmentHandlerFixture, deviceID string) renewalState {
	t.Helper()
	var state renewalState
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT certificate_der, certificate_fingerprint, sealing_public_key,
		       registration_token_id, owner, projection_version
		FROM devices WHERE device_id = $1`, deviceID).Scan(
		&state.certificateDER,
		&state.certificateFingerprint,
		&state.sealingPublicKey,
		&state.registrationTokenID,
		&state.owner,
		&state.version,
	); err != nil {
		t.Fatalf("read device after rejected renewal: %v", err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM events WHERE stream_type = 'device' AND stream_id = $1`, deviceID).Scan(&state.events); err != nil {
		t.Fatalf("count events after rejected renewal: %v", err)
	}
	return state
}

func assertRenewalStateUnchanged(t *testing.T, fixture enrollmentHandlerFixture, deviceID string, want renewalState) {
	t.Helper()
	got := readRenewalState(t, fixture, deviceID)
	if got.version != want.version || got.events != want.events || got.registrationTokenID != want.registrationTokenID || got.owner != want.owner ||
		!bytes.Equal(got.certificateDER, want.certificateDER) || !bytes.Equal(got.certificateFingerprint, want.certificateFingerprint) ||
		!bytes.Equal(got.sealingPublicKey, want.sealingPublicKey) {
		t.Fatalf("renewal rejection changed durable state: got %+v, want %+v", got, want)
	}
}

func corruptRenewalCSRSignature(t *testing.T, der []byte) []byte {
	t.Helper()
	corrupt := bytes.Clone(der)
	corrupt[len(corrupt)-1] ^= 0xff
	request, err := x509.ParseCertificateRequest(corrupt)
	if err != nil {
		t.Fatalf("corrupt CSR fixture no longer parses: %v", err)
	}
	if request.CheckSignature() == nil {
		t.Fatal("corrupt CSR fixture still has a valid signature")
	}
	return corrupt
}

func newPresentedRenewalCertificate(
	t *testing.T,
	currentDER []byte,
	key *ecdsa.PrivateKey,
	class identity.Class,
	deviceID string,
	serial int64,
) []byte {
	t.Helper()
	current := parseEnrollmentCertificate(t, currentDER)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		NotBefore:             current.NotBefore,
		NotAfter:              current.NotAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if err := identity.StampCertificateIdentity(template, class, deviceID); err != nil {
		t.Fatalf("stamp presented renewal certificate: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create presented renewal certificate: %v", err)
	}
	return der
}
