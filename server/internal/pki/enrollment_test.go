package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/server/internal/store"
)

// TestEnrollmentHandler_IssuesAndPersistsAgentIdentity exercises the real
// Connect handler, registration-token service, CA signer, and Postgres event
// store as one enrollment boundary.
func TestEnrollmentHandler_IssuesAndPersistsAgentIdentity(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	key := newEnrollmentSigningKey(t)
	csr := newEnrollmentCSR(t, key, pkix.Name{CommonName: "caller-controlled"}, nil)
	sealingKey := newEnrollmentSealingKey(t)

	response, err := fixture.client.EnrollAgent(context.Background(), connect.NewRequest(&powermanagev1.EnrollAgentRequest{
		RegistrationToken:            fixture.token,
		CertificateSigningRequestDer: csr,
		SealingPublicKey:             sealingKey,
	}))
	if err != nil {
		t.Fatalf("EnrollAgent: %v", err)
	}
	certificate := parseEnrollmentCertificate(t, response.Msg.GetCertificateDer())
	class, deviceID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil {
		t.Fatalf("parse issued certificate identity: %v", err)
	}
	if class != identity.AgentClass || !identity.IsCanonicalULID(deviceID) || deviceID == "caller-controlled" {
		t.Fatalf("issued identity = (%q, %q); want agent and fresh server ULID", class, deviceID)
	}
	if !publicKeysEqual(t, certificate.PublicKey, key.Public()) {
		t.Fatal("issued certificate public key differs from CSR key")
	}
	if certificate.IsCA || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("issued certificate profile = CA:%v KU:%v EKU:%v; want agent ClientAuth", certificate.IsCA, certificate.KeyUsage, certificate.ExtKeyUsage)
	}
	if got := certificate.NotAfter.Sub(certificate.NotBefore); got != 365*24*time.Hour {
		t.Fatalf("issued certificate lifetime = %v; want one year", got)
	}
	if err := certificate.CheckSignatureFrom(fixture.agentCA); err != nil {
		t.Fatalf("verify issued certificate with agent CA: %v", err)
	}
	if !bytes.Equal(response.Msg.GetCertificateAuthorityDer(), fixture.agentCA.Raw) {
		t.Fatal("enrollment response returned a different agent CA")
	}
	if !bytes.Equal(response.Msg.GetGatewayCertificateAuthorityDer(), fixture.gatewayCA.Raw) {
		t.Fatal("enrollment response returned a different gateway CA")
	}

	persisted, err := fixture.eventStore.Device(context.Background(), deviceID)
	if err != nil {
		t.Fatalf("read enrolled device: %v", err)
	}
	wantFingerprint := sha256.Sum256(certificate.Raw)
	if !bytes.Equal(persisted.CertificateDER, certificate.Raw) || persisted.CertificateFingerprint != wantFingerprint || !bytes.Equal(persisted.SealingPublicKey, sealingKey) {
		t.Fatalf("persisted device binding = %+v; want issued DER/fingerprint/sealing key", persisted)
	}
	if bytes.Contains(persisted.CertificateDER, []byte(fixture.token)) {
		t.Fatal("raw registration token leaked into device projection")
	}
	tokenState, err := fixture.eventStore.RegistrationToken(context.Background(), fixture.tokenID)
	if err != nil {
		t.Fatalf("read consumed registration token: %v", err)
	}
	if tokenState.Uses != 1 {
		t.Fatalf("registration token uses = %d; want one", tokenState.Uses)
	}
}

// TestEnrollmentHandler_RejectsMalformedProofBeforeTokenUse covers every
// request field and every caller-controlled CSR identity channel.
func TestEnrollmentHandler_RejectsMalformedProofBeforeTokenUse(t *testing.T) {
	validKey := newEnrollmentSigningKey(t)
	validCSR := newEnrollmentCSR(t, validKey, pkix.Name{}, nil)
	validSealingKey := newEnrollmentSealingKey(t)
	sanURI, err := url.Parse("spiffe://attacker.invalid/agent")
	if err != nil {
		t.Fatalf("parse SAN URI fixture: %v", err)
	}
	badSignature := append([]byte(nil), validCSR...)
	badSignature[len(badSignature)-1] ^= 0xff
	_, ed25519Private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate unsupported CSR signer: %v", err)
	}
	tests := []struct {
		name     string
		request  func(string) *powermanagev1.EnrollAgentRequest
		wantCode connect.Code
	}{
		{name: "absent token", request: func(string) *powermanagev1.EnrollAgentRequest {
			return &powermanagev1.EnrollAgentRequest{CertificateSigningRequestDer: validCSR, SealingPublicKey: validSealingKey}
		}, wantCode: connect.CodeUnauthenticated},
		{name: "absent CSR", request: func(token string) *powermanagev1.EnrollAgentRequest {
			return &powermanagev1.EnrollAgentRequest{RegistrationToken: token, SealingPublicKey: validSealingKey}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "malformed CSR", request: func(token string) *powermanagev1.EnrollAgentRequest {
			return &powermanagev1.EnrollAgentRequest{RegistrationToken: token, CertificateSigningRequestDer: []byte("bad"), SealingPublicKey: validSealingKey}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "CSR trailing data", request: func(token string) *powermanagev1.EnrollAgentRequest {
			return &powermanagev1.EnrollAgentRequest{RegistrationToken: token, CertificateSigningRequestDer: append(append([]byte(nil), validCSR...), 0), SealingPublicKey: validSealingKey}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "CSR bad signature", request: func(token string) *powermanagev1.EnrollAgentRequest {
			return &powermanagev1.EnrollAgentRequest{RegistrationToken: token, CertificateSigningRequestDer: badSignature, SealingPublicKey: validSealingKey}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "unsupported CSR key", request: func(token string) *powermanagev1.EnrollAgentRequest {
			return &powermanagev1.EnrollAgentRequest{RegistrationToken: token, CertificateSigningRequestDer: newEnrollmentCSR(t, ed25519Private, pkix.Name{}, nil), SealingPublicKey: validSealingKey}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "DNS SAN", request: func(token string) *powermanagev1.EnrollAgentRequest {
			return &powermanagev1.EnrollAgentRequest{RegistrationToken: token, CertificateSigningRequestDer: newEnrollmentCSR(t, validKey, pkix.Name{}, func(template *x509.CertificateRequest) { template.DNSNames = []string{"attacker.invalid"} }), SealingPublicKey: validSealingKey}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "email SAN", request: func(token string) *powermanagev1.EnrollAgentRequest {
			return &powermanagev1.EnrollAgentRequest{RegistrationToken: token, CertificateSigningRequestDer: newEnrollmentCSR(t, validKey, pkix.Name{}, func(template *x509.CertificateRequest) { template.EmailAddresses = []string{"agent@attacker.invalid"} }), SealingPublicKey: validSealingKey}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "IP SAN", request: func(token string) *powermanagev1.EnrollAgentRequest {
			return &powermanagev1.EnrollAgentRequest{RegistrationToken: token, CertificateSigningRequestDer: newEnrollmentCSR(t, validKey, pkix.Name{}, func(template *x509.CertificateRequest) { template.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")} }), SealingPublicKey: validSealingKey}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "URI SAN", request: func(token string) *powermanagev1.EnrollAgentRequest {
			return &powermanagev1.EnrollAgentRequest{RegistrationToken: token, CertificateSigningRequestDer: newEnrollmentCSR(t, validKey, pkix.Name{}, func(template *x509.CertificateRequest) { template.URIs = []*url.URL{sanURI} }), SealingPublicKey: validSealingKey}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "absent sealing key", request: func(token string) *powermanagev1.EnrollAgentRequest {
			return &powermanagev1.EnrollAgentRequest{RegistrationToken: token, CertificateSigningRequestDer: validCSR}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "short sealing key", request: func(token string) *powermanagev1.EnrollAgentRequest {
			return &powermanagev1.EnrollAgentRequest{RegistrationToken: token, CertificateSigningRequestDer: validCSR, SealingPublicKey: make([]byte, 31)}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "low-order sealing key", request: func(token string) *powermanagev1.EnrollAgentRequest {
			return &powermanagev1.EnrollAgentRequest{RegistrationToken: token, CertificateSigningRequestDer: validCSR, SealingPublicKey: make([]byte, 32)}
		}, wantCode: connect.CodeInvalidArgument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEnrollmentHandlerFixture(t, 1)
			_, err := fixture.client.EnrollAgent(context.Background(), connect.NewRequest(test.request(fixture.token)))
			if connect.CodeOf(err) != test.wantCode {
				t.Fatalf("EnrollAgent code = %v (error %v); want %v", connect.CodeOf(err), err, test.wantCode)
			}
			tokenState, err := fixture.eventStore.RegistrationToken(context.Background(), fixture.tokenID)
			if err != nil {
				t.Fatalf("read token after rejected enrollment: %v", err)
			}
			if tokenState.Uses != 0 {
				t.Fatalf("rejected enrollment consumed %d token uses; want zero", tokenState.Uses)
			}
			var devices int
			if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM devices`).Scan(&devices); err != nil {
				t.Fatalf("count devices: %v", err)
			}
			if devices != 0 {
				t.Fatalf("rejected enrollment persisted %d devices; want zero", devices)
			}
		})
	}
}

// TestEnrollmentHandler_ConcurrentTokenUseBoundsCertificates proves the full
// RPC path preserves M3's expected-version bound under real concurrency.
func TestEnrollmentHandler_ConcurrentTokenUseBoundsCertificates(t *testing.T) {
	const allowed = 3
	const attempts = 5
	fixture := newEnrollmentHandlerFixture(t, allowed)
	requests := make([]*powermanagev1.EnrollAgentRequest, attempts)
	for i := range requests {
		key := newEnrollmentSigningKey(t)
		requests[i] = &powermanagev1.EnrollAgentRequest{
			RegistrationToken:            fixture.token,
			CertificateSigningRequestDer: newEnrollmentCSR(t, key, pkix.Name{}, nil),
			SealingPublicKey:             newEnrollmentSealingKey(t),
		}
	}
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wait sync.WaitGroup
	for _, request := range requests {
		wait.Add(1)
		go func(request *powermanagev1.EnrollAgentRequest) {
			defer wait.Done()
			<-start
			_, err := fixture.client.EnrollAgent(context.Background(), connect.NewRequest(request))
			results <- err
		}(request)
	}
	close(start)
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("losing enrollment error = %v; want uniform unauthenticated rejection", err)
		}
	}
	if successes != allowed {
		t.Fatalf("successful enrollments = %d; want exactly %d", successes, allowed)
	}
	var devices int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM devices`).Scan(&devices); err != nil {
		t.Fatalf("count enrolled devices: %v", err)
	}
	if devices != allowed {
		t.Fatalf("persisted devices = %d; want exactly %d", devices, allowed)
	}
}

func TestEnrollmentHandler_RateLimitsNetworkSource(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 10)
	request := &powermanagev1.EnrollAgentRequest{
		RegistrationToken:            "invalid",
		CertificateSigningRequestDer: newEnrollmentCSR(t, newEnrollmentSigningKey(t), pkix.Name{}, nil),
		SealingPublicKey:             newEnrollmentSealingKey(t),
	}
	for attempt := 1; attempt <= 6; attempt++ {
		_, err := fixture.client.EnrollAgent(context.Background(), connect.NewRequest(proto.Clone(request).(*powermanagev1.EnrollAgentRequest)))
		want := connect.CodeUnauthenticated
		if attempt == 6 {
			want = connect.CodeResourceExhausted
		}
		if connect.CodeOf(err) != want {
			t.Fatalf("attempt %d code = %v (error %v); want %v", attempt, connect.CodeOf(err), err, want)
		}
	}
}

func TestEnrollmentHandler_FailureLadderDoesNotLockOutCorrectToken(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	tokenID, secret := decodeMintedToken(t, fixture.token)
	secret[0] ^= 0xff
	wrongToken := tokenID + "." + base64.RawURLEncoding.EncodeToString(secret)
	request := &powermanagev1.EnrollAgentRequest{
		RegistrationToken:            wrongToken,
		CertificateSigningRequestDer: newEnrollmentCSR(t, newEnrollmentSigningKey(t), pkix.Name{}, nil),
		SealingPublicKey:             newEnrollmentSealingKey(t),
	}
	wantRejection := connect.CodeUnauthenticated.String() + ": " + errEnrollmentAuthRejected.Error()
	for attempt := 1; attempt <= 5; attempt++ {
		_, err := fixture.client.EnrollAgent(
			context.Background(),
			connect.NewRequest(proto.Clone(request).(*powermanagev1.EnrollAgentRequest)),
		)
		if connect.CodeOf(err) != connect.CodeUnauthenticated || err.Error() != wantRejection {
			t.Fatalf("wrong-secret attempt %d error = %v; want %q", attempt, err, wantRejection)
		}
	}

	request.RegistrationToken = fixture.token
	response, err := fixture.client.EnrollAgent(context.Background(), connect.NewRequest(request))
	if err != nil {
		t.Fatalf("correct token after five failures: %v", err)
	}
	if response == nil || len(response.Msg.GetCertificateDer()) == 0 {
		t.Fatal("correct token after five failures returned no certificate")
	}
}

func TestEnrollmentHandler_UsesTrustedProxyClientIP(t *testing.T) {
	fixture := newEnrollmentHandlerFixtureWithTrustedProxies(t, 1, []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	})
	request := &powermanagev1.EnrollAgentRequest{
		CertificateSigningRequestDer: newEnrollmentCSR(t, newEnrollmentSigningKey(t), pkix.Name{}, nil),
		SealingPublicKey:             newEnrollmentSealingKey(t),
	}
	wantRejection := connect.CodeUnauthenticated.String() + ": " + errEnrollmentAuthRejected.Error()
	for attempt := 1; attempt <= 6; attempt++ {
		minted, err := fixture.service.tokens.Mint(context.Background(), RegistrationTokenOptions{
			Purpose:   RegistrationTokenPurposeAgent,
			MaxUses:   1,
			ExpiresAt: time.Now().Add(time.Hour),
		})
		if err != nil {
			t.Fatalf("mint proxy attempt %d token: %v", attempt, err)
		}
		tokenID, secret := decodeMintedToken(t, minted.Token)
		secret[0] ^= 0xff
		request.RegistrationToken = tokenID + "." + base64.RawURLEncoding.EncodeToString(secret)
		connectRequest := connect.NewRequest(proto.Clone(request).(*powermanagev1.EnrollAgentRequest))
		connectRequest.Header().Set(
			"X-Forwarded-For",
			netip.AddrFrom4([4]byte{198, 51, 100, byte(attempt)}).String(),
		)
		_, err = fixture.client.EnrollAgent(context.Background(), connectRequest)
		if connect.CodeOf(err) != connect.CodeUnauthenticated || err.Error() != wantRejection {
			t.Fatalf("trusted-proxy attempt %d error = %v; want independent-client rejection %q", attempt, err, wantRejection)
		}
	}
}

func TestEnrollmentHandler_UsesAllForwardedForHeaderValues(t *testing.T) {
	fixture := newEnrollmentHandlerFixtureWithTrustedProxies(t, 1, []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("10.0.0.0/8"),
	})
	request := &powermanagev1.EnrollAgentRequest{
		CertificateSigningRequestDer: newEnrollmentCSR(t, newEnrollmentSigningKey(t), pkix.Name{}, nil),
		SealingPublicKey:             newEnrollmentSealingKey(t),
	}
	wantRejection := connect.CodeUnauthenticated.String() + ": " + errEnrollmentAuthRejected.Error()
	for attempt := 1; attempt <= 6; attempt++ {
		minted, err := fixture.service.tokens.Mint(context.Background(), RegistrationTokenOptions{
			Purpose:   RegistrationTokenPurposeAgent,
			MaxUses:   1,
			ExpiresAt: time.Now().Add(time.Hour),
		})
		if err != nil {
			t.Fatalf("mint multi-value X-Forwarded-For attempt %d token: %v", attempt, err)
		}
		tokenID, secret := decodeMintedToken(t, minted.Token)
		secret[0] ^= 0xff
		request.RegistrationToken = tokenID + "." + base64.RawURLEncoding.EncodeToString(secret)
		connectRequest := connect.NewRequest(proto.Clone(request).(*powermanagev1.EnrollAgentRequest))
		connectRequest.Header().Add("X-Forwarded-For", "10.0.0.2")
		connectRequest.Header().Add(
			"X-Forwarded-For",
			netip.AddrFrom4([4]byte{198, 51, 100, byte(attempt)}).String(),
		)
		_, err = fixture.client.EnrollAgent(context.Background(), connectRequest)
		if connect.CodeOf(err) != connect.CodeUnauthenticated || err.Error() != wantRejection {
			t.Fatalf("multi-value X-Forwarded-For attempt %d error = %v; want independent-client rejection %q",
				attempt, err, wantRejection)
		}
	}
}

type enrollmentHandlerFixture struct {
	client     powermanagev1connect.PkiServiceClient
	service    *EnrollmentService
	server     *httptest.Server
	pool       *pgxpool.Pool
	eventStore *store.Store
	agentCA    *x509.Certificate
	gatewayCA  *x509.Certificate
	tokenID    string
	token      string
	authorizer *testLifecycleAuthorizer
}

func newEnrollmentHandlerFixture(t *testing.T, maxUses int32) enrollmentHandlerFixture {
	t.Helper()
	return newEnrollmentHandlerFixtureForToken(t, RegistrationTokenOptions{
		Purpose:   RegistrationTokenPurposeAgent,
		MaxUses:   maxUses,
		ExpiresAt: time.Now().Add(time.Hour),
		Owner:     "owner@example.com",
	})
}

func newEnrollmentHandlerFixtureWithTrustedProxies(
	t *testing.T,
	maxUses int32,
	trustedProxies []netip.Prefix,
) enrollmentHandlerFixture {
	t.Helper()
	return newEnrollmentHandlerFixtureForTokenWithTrustedProxies(t, RegistrationTokenOptions{
		Purpose:   RegistrationTokenPurposeAgent,
		MaxUses:   maxUses,
		ExpiresAt: time.Now().Add(time.Hour),
		Owner:     "owner@example.com",
	}, trustedProxies)
}

func newGatewayEnrollmentHandlerFixture(t *testing.T, maxUses int32, dnsNames []string) enrollmentHandlerFixture {
	t.Helper()
	return newEnrollmentHandlerFixtureForToken(t, RegistrationTokenOptions{
		Purpose:   RegistrationTokenPurposeGateway,
		MaxUses:   maxUses,
		ExpiresAt: time.Now().Add(time.Hour),
		Owner:     "gateway-owner@example.com",
		DNSNames:  dnsNames,
	})
}

func newEnrollmentHandlerFixtureForToken(t *testing.T, options RegistrationTokenOptions) enrollmentHandlerFixture {
	t.Helper()
	return newEnrollmentHandlerFixtureForTokenWithTrustedProxies(t, options, nil)
}

func newEnrollmentHandlerFixtureForTokenWithTrustedProxies(
	t *testing.T,
	options RegistrationTokenOptions,
	trustedProxies []netip.Prefix,
) enrollmentHandlerFixture {
	t.Helper()
	pool := registrationPostgres.Database(t, store.Migrate)
	eventStore, err := store.NewProduction(pool)
	if err != nil {
		t.Fatalf("create production event store: %v", err)
	}
	tokens, err := NewRegistrationTokens(eventStore)
	if err != nil {
		t.Fatalf("create registration-token service: %v", err)
	}
	minted, err := tokens.Mint(context.Background(), options)
	if err != nil {
		t.Fatalf("mint registration token: %v", err)
	}
	agentCA, agentSigner := newEnrollmentCA(t, "agent enrollment CA")
	gatewayCA, gatewaySigner := newEnrollmentCA(t, "gateway enrollment CA")
	authorities, err := NewAuthorities(agentCA.Raw, agentSigner, gatewayCA.Raw, gatewaySigner, newEnrollmentSigningKey(t))
	if err != nil {
		t.Fatalf("create authorities: %v", err)
	}
	authorizer := &testLifecycleAuthorizer{allow: true}
	var service *EnrollmentService
	if trustedProxies == nil {
		service, err = NewEnrollmentService(tokens, eventStore, authorities, authorizer)
	} else {
		service, err = NewEnrollmentServiceWithTrustedProxies(
			tokens,
			eventStore,
			authorities,
			authorizer,
			trustedProxies,
		)
	}
	if err != nil {
		t.Fatalf("create enrollment service: %v", err)
	}
	path, handler := NewEnrollmentHTTPHandler(service)
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	return enrollmentHandlerFixture{
		client:     powermanagev1connect.NewPkiServiceClient(server.Client(), server.URL),
		service:    service,
		server:     server,
		pool:       pool,
		eventStore: eventStore,
		agentCA:    agentCA,
		gatewayCA:  gatewayCA,
		tokenID:    minted.TokenID,
		token:      minted.Token,
		authorizer: authorizer,
	}
}

type testLifecycleAuthorizer struct {
	mu          sync.Mutex
	allow       bool
	credentials []string
	procedures  []string
	deviceIDs   []string
}

func (a *testLifecycleAuthorizer) AuthorizeCertificateLifecycle(_ context.Context, credential, procedure, deviceID string) error {
	if a == nil {
		return errors.New("nil test lifecycle authorizer")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.credentials = append(a.credentials, credential)
	a.procedures = append(a.procedures, procedure)
	a.deviceIDs = append(a.deviceIDs, deviceID)
	if !a.allow {
		return errors.New("test lifecycle authorization denied")
	}
	return nil
}

func newEnrollmentCA(t *testing.T, name string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	signer := newEnrollmentSigningKey(t)
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatalf("marshal CA public key: %v", err)
	}
	keyID := sha256.Sum256(publicDER)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(2 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          append([]byte(nil), keyID[:20]...),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatalf("create enrollment CA: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse enrollment CA: %v", err)
	}
	return certificate, signer
}

func newEnrollmentSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate enrollment signing key: %v", err)
	}
	return key
}

func newEnrollmentCSR(t *testing.T, signer crypto.Signer, subject pkix.Name, mutate func(*x509.CertificateRequest)) []byte {
	t.Helper()
	template := &x509.CertificateRequest{Subject: subject}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		t.Fatalf("create enrollment CSR: %v", err)
	}
	return der
}

func newEnrollmentSealingKey(t *testing.T) []byte {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate enrollment sealing key: %v", err)
	}
	return key.PublicKey().Bytes()
}

func parseEnrollmentCertificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	if !bytes.Equal(certificate.Raw, der) {
		t.Fatal("issued certificate contains trailing DER data")
	}
	return certificate
}

func publicKeysEqual(t *testing.T, first, second crypto.PublicKey) bool {
	t.Helper()
	firstDER, err := x509.MarshalPKIXPublicKey(first)
	if err != nil {
		t.Fatalf("marshal first public key: %v", err)
	}
	secondDER, err := x509.MarshalPKIXPublicKey(second)
	if err != nil {
		t.Fatalf("marshal second public key: %v", err)
	}
	return bytes.Equal(firstDER, secondDER)
}
