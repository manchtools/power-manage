package pki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/server/internal/store"
)

func TestGatewayEnrollment_IssuesFreshControlAuthoredDualEKUIdentity(t *testing.T) {
	dnsNames := []string{"gateway-1.internal.example", "gateway-1.backup.internal.example"}
	fixture := newGatewayEnrollmentHandlerFixture(t, 2, dnsNames)
	issuedIDs := make(map[string]struct{}, 2)
	for enrollment := range 2 {
		key := newEnrollmentSigningKey(t)
		response, err := fixture.client.EnrollGateway(context.Background(), connect.NewRequest(&powermanagev1.EnrollGatewayRequest{
			RegistrationToken:            fixture.token,
			CertificateSigningRequestDer: newEnrollmentCSR(t, key, pkix.Name{CommonName: "caller-controlled"}, nil),
		}))
		if err != nil {
			t.Fatalf("EnrollGateway %d: %v", enrollment+1, err)
		}
		certificate := parseEnrollmentCertificate(t, response.Msg.GetCertificateDer())
		class, gatewayID, err := identity.ParseCertificateIdentity(certificate)
		if err != nil {
			t.Fatalf("parse gateway identity %d: %v", enrollment+1, err)
		}
		if class != identity.GatewayClass || !identity.IsCanonicalULID(gatewayID) || gatewayID == "caller-controlled" {
			t.Fatalf("issued gateway identity = (%q, %q); want fresh gateway ULID", class, gatewayID)
		}
		if _, exists := issuedIDs[gatewayID]; exists {
			t.Fatalf("gateway enrollment reused identity %q", gatewayID)
		}
		issuedIDs[gatewayID] = struct{}{}
		if !publicKeysEqual(t, certificate.PublicKey, key.Public()) {
			t.Fatal("issued gateway certificate public key differs from CSR key")
		}
		if certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
			!gatewayExtKeyUsagesExact(certificate.ExtKeyUsage) || certificate.NotAfter.Sub(certificate.NotBefore) != 45*24*time.Hour {
			t.Fatalf("gateway certificate profile = CA:%v KU:%v EKU:%v lifetime:%s; want 45-day dual EKU", certificate.IsCA, certificate.KeyUsage, certificate.ExtKeyUsage, certificate.NotAfter.Sub(certificate.NotBefore))
		}
		if !slices.Equal(certificate.DNSNames, dnsNames) || len(certificate.EmailAddresses) != 0 || len(certificate.IPAddresses) != 0 {
			t.Fatalf("gateway certificate SANs = DNS:%v email:%v IP:%v; want exact control DNS %v", certificate.DNSNames, certificate.EmailAddresses, certificate.IPAddresses, dnsNames)
		}
		if err := certificate.CheckSignatureFrom(fixture.gatewayCA); err != nil {
			t.Fatalf("verify gateway certificate with gateway CA: %v", err)
		}
		if !bytes.Equal(response.Msg.GetCertificateAuthorityDer(), fixture.gatewayCA.Raw) {
			t.Fatal("gateway enrollment returned a different gateway CA")
		}
		persisted, err := fixture.eventStore.Gateway(context.Background(), gatewayID)
		if err != nil {
			t.Fatalf("read enrolled gateway: %v", err)
		}
		fingerprint := sha256.Sum256(certificate.Raw)
		if persisted.GatewayID != gatewayID || persisted.CertificateFingerprint != fingerprint ||
			!bytes.Equal(persisted.CertificateDER, certificate.Raw) || !slices.Equal(persisted.DNSNames, dnsNames) ||
			persisted.RegistrationTokenID != fixture.tokenID || persisted.Owner != "gateway-owner@example.com" ||
			persisted.LifecycleState != store.GatewayLifecycleActive || persisted.ProjectionVersion != 1 {
			t.Fatalf("persisted gateway = %+v; want exact enrolled identity", persisted)
		}
	}
}

func TestGatewayEnrollment_RejectsMalformedProofBeforeTokenUse(t *testing.T) {
	validKey := newEnrollmentSigningKey(t)
	validCSR := newEnrollmentCSR(t, validKey, pkix.Name{}, nil)
	badSignature := bytes.Clone(validCSR)
	badSignature[len(badSignature)-1] ^= 0xff
	_, unsupportedKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate unsupported gateway signer: %v", err)
	}
	sanURI, err := url.Parse("spiffe://attacker.invalid/gateway")
	if err != nil {
		t.Fatalf("parse attacker SAN URI: %v", err)
	}
	tests := []struct {
		name     string
		request  func(string) *powermanagev1.EnrollGatewayRequest
		wantCode connect.Code
	}{
		{name: "absent token", request: func(string) *powermanagev1.EnrollGatewayRequest {
			return &powermanagev1.EnrollGatewayRequest{CertificateSigningRequestDer: validCSR}
		}, wantCode: connect.CodeUnauthenticated},
		{name: "absent CSR", request: func(token string) *powermanagev1.EnrollGatewayRequest {
			return &powermanagev1.EnrollGatewayRequest{RegistrationToken: token}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "malformed CSR", request: func(token string) *powermanagev1.EnrollGatewayRequest {
			return &powermanagev1.EnrollGatewayRequest{RegistrationToken: token, CertificateSigningRequestDer: []byte("bad")}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "CSR trailing data", request: func(token string) *powermanagev1.EnrollGatewayRequest {
			return &powermanagev1.EnrollGatewayRequest{RegistrationToken: token, CertificateSigningRequestDer: append(bytes.Clone(validCSR), 0)}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "CSR bad signature", request: func(token string) *powermanagev1.EnrollGatewayRequest {
			return &powermanagev1.EnrollGatewayRequest{RegistrationToken: token, CertificateSigningRequestDer: badSignature}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "unsupported CSR key", request: func(token string) *powermanagev1.EnrollGatewayRequest {
			return &powermanagev1.EnrollGatewayRequest{RegistrationToken: token, CertificateSigningRequestDer: newEnrollmentCSR(t, unsupportedKey, pkix.Name{}, nil)}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "DNS SAN", request: func(token string) *powermanagev1.EnrollGatewayRequest {
			return &powermanagev1.EnrollGatewayRequest{RegistrationToken: token, CertificateSigningRequestDer: newEnrollmentCSR(t, validKey, pkix.Name{}, func(request *x509.CertificateRequest) { request.DNSNames = []string{"attacker.invalid"} })}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "email SAN", request: func(token string) *powermanagev1.EnrollGatewayRequest {
			return &powermanagev1.EnrollGatewayRequest{RegistrationToken: token, CertificateSigningRequestDer: newEnrollmentCSR(t, validKey, pkix.Name{}, func(request *x509.CertificateRequest) { request.EmailAddresses = []string{"attacker@example.com"} })}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "IP SAN", request: func(token string) *powermanagev1.EnrollGatewayRequest {
			return &powermanagev1.EnrollGatewayRequest{RegistrationToken: token, CertificateSigningRequestDer: newEnrollmentCSR(t, validKey, pkix.Name{}, func(request *x509.CertificateRequest) { request.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")} })}
		}, wantCode: connect.CodeInvalidArgument},
		{name: "URI SAN", request: func(token string) *powermanagev1.EnrollGatewayRequest {
			return &powermanagev1.EnrollGatewayRequest{RegistrationToken: token, CertificateSigningRequestDer: newEnrollmentCSR(t, validKey, pkix.Name{}, func(request *x509.CertificateRequest) { request.URIs = []*url.URL{sanURI} })}
		}, wantCode: connect.CodeInvalidArgument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGatewayEnrollmentHandlerFixture(t, 1, []string{"gateway.internal.example"})
			response, err := fixture.client.EnrollGateway(context.Background(), connect.NewRequest(test.request(fixture.token)))
			if response != nil || connect.CodeOf(err) != test.wantCode {
				t.Fatalf("EnrollGateway = (%v, %v); want nil and %v", response, err, test.wantCode)
			}
			tokenState, err := fixture.eventStore.RegistrationToken(context.Background(), fixture.tokenID)
			if err != nil {
				t.Fatalf("read gateway token after rejection: %v", err)
			}
			if tokenState.Uses != 0 || pkiEventCount(t, fixture, "gateway") != 0 {
				t.Fatalf("rejected gateway enrollment effects = %d uses, %d events; want zero", tokenState.Uses, pkiEventCount(t, fixture, "gateway"))
			}
		})
	}
}

func TestEnrollmentHandlers_CrossPurposeTokensRejectWithoutIdentityWrites(t *testing.T) {
	t.Run("gateway token cannot enroll agent", func(t *testing.T) {
		fixture := newGatewayEnrollmentHandlerFixture(t, 1, []string{"gateway.internal.example"})
		response, err := fixture.client.EnrollAgent(context.Background(), connect.NewRequest(&powermanagev1.EnrollAgentRequest{
			RegistrationToken:            fixture.token,
			CertificateSigningRequestDer: newEnrollmentCSR(t, newEnrollmentSigningKey(t), pkix.Name{}, nil),
			SealingPublicKey:             newEnrollmentSealingKey(t),
		}))
		if response != nil || connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("EnrollAgent with gateway token = (%v, %v); want unauthenticated", response, err)
		}
		assertCrossPurposeEnrollmentWroteNothing(t, fixture)
	})

	t.Run("agent token cannot enroll gateway", func(t *testing.T) {
		fixture := newEnrollmentHandlerFixture(t, 1)
		response, err := fixture.client.EnrollGateway(context.Background(), connect.NewRequest(&powermanagev1.EnrollGatewayRequest{
			RegistrationToken:            fixture.token,
			CertificateSigningRequestDer: newEnrollmentCSR(t, newEnrollmentSigningKey(t), pkix.Name{}, nil),
		}))
		if response != nil || connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("EnrollGateway with agent token = (%v, %v); want unauthenticated", response, err)
		}
		assertCrossPurposeEnrollmentWroteNothing(t, fixture)
	})
}

func TestGatewayEnrollment_VerifiesWithGatewayCAAndNoSystemRoots(t *testing.T) {
	dnsName := "gateway-tls.internal.example"
	fixture := newGatewayEnrollmentHandlerFixture(t, 1, []string{dnsName})
	gatewayKey, gatewayCertificateDER, _ := enrollGatewayFixture(t, fixture)
	agentToken, err := fixture.service.tokens.Mint(context.Background(), RegistrationTokenOptions{
		Purpose: RegistrationTokenPurposeAgent, MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour), Owner: "tls-agent@example.com",
	})
	if err != nil {
		t.Fatalf("mint agent enrollment token: %v", err)
	}
	agentKey := newEnrollmentSigningKey(t)
	agentEnrollment, err := fixture.client.EnrollAgent(context.Background(), connect.NewRequest(&powermanagev1.EnrollAgentRequest{
		RegistrationToken:            agentToken.Token,
		CertificateSigningRequestDer: newEnrollmentCSR(t, agentKey, pkix.Name{}, nil),
		SealingPublicKey:             newEnrollmentSealingKey(t),
	}))
	if err != nil {
		t.Fatalf("enroll agent TLS credential: %v", err)
	}
	agentCertificateDER := agentEnrollment.Msg.GetCertificateDer()
	agentCA := parseEnrollmentCertificate(t, agentEnrollment.Msg.GetCertificateAuthorityDer())
	gatewayCA := parseEnrollmentCertificate(t, agentEnrollment.Msg.GetGatewayCertificateAuthorityDer())
	agentRoots := x509.NewCertPool()
	agentRoots.AddCert(agentCA)
	serverTLS, err := identity.ServerTLSConfig(tls.Certificate{
		Certificate: [][]byte{bytes.Clone(gatewayCertificateDER)},
		PrivateKey:  gatewayKey,
	}, agentRoots, identity.AgentClass)
	if err != nil {
		t.Fatalf("build production gateway TLS server config: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = serverTLS
	server.StartTLS()
	t.Cleanup(server.Close)

	gatewayRoots := x509.NewCertPool()
	gatewayRoots.AddCert(gatewayCA)
	agentTLSCertificate := tls.Certificate{Certificate: [][]byte{bytes.Clone(agentCertificateDER)}, PrivateKey: agentKey}
	clientTLS, err := identity.ClientTLSConfig(agentTLSCertificate, gatewayRoots, dnsName, identity.GatewayClass)
	if err != nil {
		t.Fatalf("build production agent TLS client config: %v", err)
	}
	transport := &http.Transport{TLSClientConfig: clientTLS}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("dial reachable gateway IP with enrolled DNS verification identity: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("close gateway TLS response: %v", err)
	}
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("gateway TLS response = %d; want 204", response.StatusCode)
	}

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse gateway server URL: %v", err)
	}
	wrongIdentityTLS, err := identity.ClientTLSConfig(agentTLSCertificate, gatewayRoots, serverURL.Hostname(), identity.GatewayClass)
	if err != nil {
		t.Fatalf("build wrong-identity production TLS client config: %v", err)
	}
	wrongIdentityTransport := &http.Transport{TLSClientConfig: wrongIdentityTLS}
	t.Cleanup(wrongIdentityTransport.CloseIdleConnections)
	if response, err := (&http.Client{Transport: wrongIdentityTransport}).Get(server.URL); err == nil {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Fatalf("close wrong-identity TLS response: %v", closeErr)
		}
		t.Fatal("gateway certificate verified against the dial IP without an IP SAN")
	}
}

func TestGatewayRenewal_RequiresFingerprintAndPossessionAndRevokesPredecessor(t *testing.T) {
	t.Run("success and lost-response retry", func(t *testing.T) {
		fixture := newGatewayEnrollmentHandlerFixture(t, 1, []string{"gateway.internal.example"})
		key, predecessorDER, gatewayID := enrollGatewayFixture(t, fixture)
		request := &powermanagev1.RenewGatewayRequest{
			CertificateDer:               predecessorDER,
			CertificateSigningRequestDer: newEnrollmentCSR(t, key, pkix.Name{}, nil),
		}
		first, err := fixture.client.RenewGateway(context.Background(), connect.NewRequest(proto.Clone(request).(*powermanagev1.RenewGatewayRequest)))
		if err != nil {
			t.Fatalf("RenewGateway: %v", err)
		}
		retry, err := fixture.client.RenewGateway(context.Background(), connect.NewRequest(proto.Clone(request).(*powermanagev1.RenewGatewayRequest)))
		if err != nil {
			t.Fatalf("retry RenewGateway: %v", err)
		}
		if !bytes.Equal(first.Msg.GetCertificateDer(), retry.Msg.GetCertificateDer()) || !bytes.Equal(first.Msg.GetCertificateAuthorityDer(), retry.Msg.GetCertificateAuthorityDer()) {
			t.Fatal("gateway renewal retry did not return the exact existing successor")
		}
		renewed := parseEnrollmentCertificate(t, first.Msg.GetCertificateDer())
		class, renewedID, err := identity.ParseCertificateIdentity(renewed)
		if err != nil {
			t.Fatalf("parse renewed gateway identity: %v", err)
		}
		if class != identity.GatewayClass || renewedID != gatewayID || !publicKeysEqual(t, renewed.PublicKey, key.Public()) || bytes.Equal(renewed.Raw, predecessorDER) {
			t.Fatalf("renewed gateway identity = (%q, %q); want same gateway and key with new certificate", class, renewedID)
		}
		gateway, err := fixture.eventStore.Gateway(context.Background(), gatewayID)
		if err != nil {
			t.Fatalf("read renewed gateway: %v", err)
		}
		if gateway.ProjectionVersion != 2 || !bytes.Equal(gateway.CertificateDER, renewed.Raw) || !bytes.Equal(gateway.PreviousCertificateDER, predecessorDER) || gateway.LifecycleState != store.GatewayLifecycleActive {
			t.Fatalf("renewed gateway projection = %+v; want exact version-two successor", gateway)
		}
		revocations, err := fixture.eventStore.CertificateRevocations(context.Background(), store.CertificateClassGateway)
		if err != nil {
			t.Fatalf("read gateway renewal revocations: %v", err)
		}
		if len(revocations) != 1 || !bytes.Equal(revocations[0].CertificateDER, predecessorDER) || revocations[0].ReasonCode != 4 {
			t.Fatalf("gateway renewal revocations = %+v; want exact superseded predecessor", revocations)
		}
		if countPkiWork(t, fixture, store.PublishGatewayCRLWorkKind) != 1 || pkiEventCountForStream(t, fixture, "gateway", gatewayID) != 2 {
			t.Fatal("gateway renewal did not create exactly one successor event and gateway CRL work item")
		}
	})

	tests := []struct {
		name     string
		mutate   func(*testing.T, *ecdsa.PrivateKey, []byte, string, *powermanagev1.RenewGatewayRequest)
		wantCode connect.Code
	}{
		{name: "fingerprint mismatch", mutate: func(t *testing.T, key *ecdsa.PrivateKey, current []byte, gatewayID string, request *powermanagev1.RenewGatewayRequest) {
			request.CertificateDer = newPresentedGatewayCertificate(t, current, key, gatewayID, 91)
		}, wantCode: connect.CodeUnauthenticated},
		{name: "proof of possession mismatch", mutate: func(t *testing.T, _ *ecdsa.PrivateKey, _ []byte, _ string, request *powermanagev1.RenewGatewayRequest) {
			request.CertificateSigningRequestDer = newEnrollmentCSR(t, newEnrollmentSigningKey(t), pkix.Name{}, nil)
		}, wantCode: connect.CodeUnauthenticated},
		{name: "unknown extended key usage", mutate: func(t *testing.T, key *ecdsa.PrivateKey, current []byte, gatewayID string, request *powermanagev1.RenewGatewayRequest) {
			request.CertificateDer = newPresentedGatewayCertificateWithMutation(t, current, key, gatewayID, 92, func(certificate *x509.Certificate) {
				certificate.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 55555, 2}}
			})
		}, wantCode: connect.CodeInvalidArgument},
		{name: "email SAN", mutate: func(t *testing.T, key *ecdsa.PrivateKey, current []byte, gatewayID string, request *powermanagev1.RenewGatewayRequest) {
			request.CertificateDer = newPresentedGatewayCertificateWithMutation(t, current, key, gatewayID, 93, func(certificate *x509.Certificate) {
				certificate.EmailAddresses = []string{"gateway@attacker.invalid"}
			})
		}, wantCode: connect.CodeInvalidArgument},
		{name: "IP SAN", mutate: func(t *testing.T, key *ecdsa.PrivateKey, current []byte, gatewayID string, request *powermanagev1.RenewGatewayRequest) {
			request.CertificateDer = newPresentedGatewayCertificateWithMutation(t, current, key, gatewayID, 94, func(certificate *x509.Certificate) {
				certificate.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")}
			})
		}, wantCode: connect.CodeInvalidArgument},
		{name: "raw SAN otherName", mutate: func(t *testing.T, key *ecdsa.PrivateKey, current []byte, gatewayID string, request *powermanagev1.RenewGatewayRequest) {
			request.CertificateDer = newPresentedGatewayCertificateWithUnsupportedSAN(t, current, key, gatewayID, 95, "otherName")
		}, wantCode: connect.CodeInvalidArgument},
		{name: "raw SAN directoryName", mutate: func(t *testing.T, key *ecdsa.PrivateKey, current []byte, gatewayID string, request *powermanagev1.RenewGatewayRequest) {
			request.CertificateDer = newPresentedGatewayCertificateWithUnsupportedSAN(t, current, key, gatewayID, 96, "directoryName")
		}, wantCode: connect.CodeInvalidArgument},
		{name: "raw SAN registeredID", mutate: func(t *testing.T, key *ecdsa.PrivateKey, current []byte, gatewayID string, request *powermanagev1.RenewGatewayRequest) {
			request.CertificateDer = newPresentedGatewayCertificateWithUnsupportedSAN(t, current, key, gatewayID, 97, "registeredID")
		}, wantCode: connect.CodeInvalidArgument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGatewayEnrollmentHandlerFixture(t, 1, []string{"gateway.internal.example"})
			key, certificateDER, gatewayID := enrollGatewayFixture(t, fixture)
			before, err := fixture.eventStore.Gateway(context.Background(), gatewayID)
			if err != nil {
				t.Fatalf("read gateway before rejected renewal: %v", err)
			}
			request := &powermanagev1.RenewGatewayRequest{
				CertificateDer:               bytes.Clone(certificateDER),
				CertificateSigningRequestDer: newEnrollmentCSR(t, key, pkix.Name{}, nil),
			}
			test.mutate(t, key, certificateDER, gatewayID, request)
			response, err := fixture.client.RenewGateway(context.Background(), connect.NewRequest(request))
			if response != nil || connect.CodeOf(err) != test.wantCode {
				t.Fatalf("rejected RenewGateway = (%v, %v); want %v", response, err, test.wantCode)
			}
			after, err := fixture.eventStore.Gateway(context.Background(), gatewayID)
			if err != nil {
				t.Fatalf("read gateway after rejected renewal: %v", err)
			}
			if after.ProjectionVersion != before.ProjectionVersion || !bytes.Equal(after.CertificateDER, before.CertificateDER) ||
				!bytes.Equal(after.PreviousCertificateDER, before.PreviousCertificateDER) || countPkiWork(t, fixture, store.PublishGatewayCRLWorkKind) != 0 {
				t.Fatalf("rejected gateway renewal changed state: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestGatewayRenewal_ConcurrentRetryReturnsOneSuccessor(t *testing.T) {
	fixture := newGatewayEnrollmentHandlerFixture(t, 1, []string{"gateway.internal.example"})
	key, predecessorDER, gatewayID := enrollGatewayFixture(t, fixture)
	request := &powermanagev1.RenewGatewayRequest{
		CertificateDer:               predecessorDER,
		CertificateSigningRequestDer: newEnrollmentCSR(t, key, pkix.Name{}, nil),
	}
	type renewalResult struct {
		response *connect.Response[powermanagev1.RenewGatewayResponse]
		err      error
	}
	start := make(chan struct{})
	results := make(chan renewalResult, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for range 2 {
		go func() {
			select {
			case <-start:
			case <-ctx.Done():
				results <- renewalResult{err: ctx.Err()}
				return
			}
			response, err := fixture.client.RenewGateway(ctx, connect.NewRequest(proto.Clone(request).(*powermanagev1.RenewGatewayRequest)))
			results <- renewalResult{response: response, err: err}
		}()
	}
	close(start)
	var successor []byte
	for range 2 {
		var got renewalResult
		select {
		case got = <-results:
		case <-ctx.Done():
			t.Fatalf("concurrent RenewGateway timed out: %v", ctx.Err())
		}
		if got.err != nil || got.response == nil {
			t.Fatalf("concurrent RenewGateway = (%v, %v); want success", got.response, got.err)
		}
		if successor == nil {
			successor = bytes.Clone(got.response.Msg.GetCertificateDer())
		} else if !bytes.Equal(successor, got.response.Msg.GetCertificateDer()) {
			t.Fatal("concurrent gateway renewal minted more than one successor")
		}
	}
	if pkiEventCountForStream(t, fixture, "gateway", gatewayID) != 2 || countPkiWork(t, fixture, store.PublishGatewayCRLWorkKind) != 1 {
		t.Fatal("concurrent gateway renewal did not serialize to one event and one CRL work item")
	}
}

func TestGatewayRevocation_ProducesGatewayCRLWork(t *testing.T) {
	fixture := newGatewayEnrollmentHandlerFixture(t, 1, []string{"gateway.internal.example"})
	key, certificateDER, gatewayID := enrollGatewayFixture(t, fixture)
	missing := connect.NewRequest(&powermanagev1.RevokeGatewayRequest{CertificateDer: bytes.Clone(certificateDER)})
	if _, err := fixture.client.RevokeGateway(context.Background(), missing); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("RevokeGateway without operator authorization = %v; want unauthenticated", err)
	}
	substituted := newPresentedGatewayCertificate(t, certificateDER, key, gatewayID, 92)
	if _, err := fixture.client.RevokeGateway(context.Background(), authorizedRevokeGatewayRequest(substituted)); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("RevokeGateway with substituted certificate = %v; want unauthenticated", err)
	}
	if _, err := fixture.client.RevokeGateway(context.Background(), authorizedRevokeGatewayRequest(certificateDER)); err != nil {
		t.Fatalf("RevokeGateway: %v", err)
	}
	gateway, err := fixture.eventStore.Gateway(context.Background(), gatewayID)
	if err != nil {
		t.Fatalf("read revoked gateway: %v", err)
	}
	if gateway.LifecycleState != store.GatewayLifecycleRevoked || gateway.ProjectionVersion != 2 || !bytes.Equal(gateway.CertificateDER, certificateDER) {
		t.Fatalf("revoked gateway projection = %+v; want terminal exact-certificate state", gateway)
	}
	if countPkiWork(t, fixture, store.PublishGatewayCRLWorkKind) != 1 {
		t.Fatal("gateway revocation did not enqueue exactly one gateway CRL work item")
	}
	publisher := &crlPublisherStub{}
	issuer, err := NewCRLIssuer(fixture.eventStore, fixture.service.authorities, publisher)
	if err != nil {
		t.Fatalf("create CRL issuer: %v", err)
	}
	issuer.now = func() time.Time { return time.Now().UTC().Add(time.Minute).Truncate(time.Second) }
	queue, err := store.NewWorkQueue(fixture.pool, issuer.WorkHandlers())
	if err != nil {
		t.Fatalf("create gateway CRL work queue: %v", err)
	}
	if processed, err := queue.RunOnce(context.Background()); !processed || err != nil {
		t.Fatalf("publish gateway CRL = (%v, %v); want success", processed, err)
	}
	if len(publisher.published) != 1 || publisher.published[0].Class != store.CertificateClassGateway {
		t.Fatalf("published gateway CRLs = %+v; want one gateway-class CRL", publisher.published)
	}
	list, err := parseExactRevocationList(publisher.published[0].DER)
	if err != nil {
		t.Fatalf("parse gateway CRL: %v", err)
	}
	certificate := parseEnrollmentCertificate(t, certificateDER)
	if list.CheckSignatureFrom(fixture.gatewayCA) != nil || len(list.RevokedCertificateEntries) != 1 || list.RevokedCertificateEntries[0].SerialNumber.Cmp(certificate.SerialNumber) != 0 {
		t.Fatalf("gateway CRL = %+v; want gateway-CA signature and exact revoked serial", list)
	}
}

func gatewayExtKeyUsagesExact(usages []x509.ExtKeyUsage) bool {
	return len(usages) == 2 && slices.Contains(usages, x509.ExtKeyUsageServerAuth) && slices.Contains(usages, x509.ExtKeyUsageClientAuth)
}

func enrollGatewayFixture(t *testing.T, fixture enrollmentHandlerFixture) (*ecdsa.PrivateKey, []byte, string) {
	t.Helper()
	key := newEnrollmentSigningKey(t)
	response, err := fixture.client.EnrollGateway(context.Background(), connect.NewRequest(&powermanagev1.EnrollGatewayRequest{
		RegistrationToken:            fixture.token,
		CertificateSigningRequestDer: newEnrollmentCSR(t, key, pkix.Name{}, nil),
	}))
	if err != nil {
		t.Fatalf("enroll gateway fixture: %v", err)
	}
	certificate := parseEnrollmentCertificate(t, response.Msg.GetCertificateDer())
	_, gatewayID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil {
		t.Fatalf("parse enrolled gateway identity: %v", err)
	}
	return key, bytes.Clone(certificate.Raw), gatewayID
}

func newPresentedGatewayCertificate(t *testing.T, currentDER []byte, key *ecdsa.PrivateKey, gatewayID string, serial int64) []byte {
	t.Helper()
	return newPresentedGatewayCertificateWithMutation(t, currentDER, key, gatewayID, serial, nil)
}

func newPresentedGatewayCertificateWithMutation(
	t *testing.T,
	currentDER []byte,
	key *ecdsa.PrivateKey,
	gatewayID string,
	serial int64,
	mutate func(*x509.Certificate),
) []byte {
	t.Helper()
	current := parseEnrollmentCertificate(t, currentDER)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		NotBefore:             current.NotBefore,
		NotAfter:              current.NotAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              slices.Clone(current.DNSNames),
	}
	if err := identity.StampCertificateIdentity(template, identity.GatewayClass, gatewayID); err != nil {
		t.Fatalf("stamp presented gateway certificate: %v", err)
	}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create presented gateway certificate: %v", err)
	}
	return der
}

func newPresentedGatewayCertificateWithUnsupportedSAN(
	t *testing.T,
	currentDER []byte,
	key *ecdsa.PrivateKey,
	gatewayID string,
	serial int64,
	unsupportedKind string,
) []byte {
	t.Helper()
	current := parseEnrollmentCertificate(t, currentDER)
	certificateDER := newPresentedGatewayCertificateWithMutation(t, currentDER, key, gatewayID, serial, func(certificate *x509.Certificate) {
		certificate.ExtraExtensions = []pkix.Extension{unsupportedGatewaySANExtension(t, current.DNSNames[0], unsupportedKind)}
	})
	assertUnsupportedGatewaySANFixture(t, certificateDER, gatewayID, current.DNSNames[0], unsupportedKind)
	return certificateDER
}

func unsupportedGatewaySANExtension(t *testing.T, dnsName, unsupportedKind string) pkix.Extension {
	t.Helper()
	unsupported := unsupportedGatewayGeneralName(t, unsupportedKind)
	value, err := asn1.Marshal([]asn1.RawValue{
		{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(dnsName)},
		{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(identity.GatewaySPIFFEURI)},
		unsupported,
	})
	if err != nil {
		t.Fatalf("marshal unsupported gateway SAN extension: %v", err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: value}
}

func unsupportedGatewayGeneralName(t *testing.T, kind string) asn1.RawValue {
	t.Helper()
	switch kind {
	case "otherName":
		utf8DER, err := asn1.Marshal("unsupported")
		if err != nil {
			t.Fatalf("marshal otherName value: %v", err)
		}
		otherNameDER, err := asn1.Marshal(struct {
			TypeID asn1.ObjectIdentifier
			Value  asn1.RawValue
		}{
			TypeID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 4},
			Value: asn1.RawValue{
				Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: utf8DER,
			},
		})
		if err != nil {
			t.Fatalf("marshal otherName: %v", err)
		}
		var sequence asn1.RawValue
		if rest, err := asn1.Unmarshal(otherNameDER, &sequence); err != nil || len(rest) != 0 {
			t.Fatalf("parse otherName sequence = %x, %v", rest, err)
		}
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sequence.Bytes}
	case "directoryName":
		directoryDER, err := asn1.Marshal(pkix.Name{CommonName: "unsupported"}.ToRDNSequence())
		if err != nil {
			t.Fatalf("marshal directoryName: %v", err)
		}
		var sequence asn1.RawValue
		if rest, err := asn1.Unmarshal(directoryDER, &sequence); err != nil || len(rest) != 0 {
			t.Fatalf("parse directoryName sequence = %x, %v", rest, err)
		}
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: sequence.Bytes}
	case "registeredID":
		identifierDER, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 5})
		if err != nil {
			t.Fatalf("marshal registeredID: %v", err)
		}
		var identifier asn1.RawValue
		if rest, err := asn1.Unmarshal(identifierDER, &identifier); err != nil || len(rest) != 0 {
			t.Fatalf("parse registeredID = %x, %v", rest, err)
		}
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 8, Bytes: identifier.Bytes}
	default:
		t.Fatalf("unknown unsupported GeneralName fixture %q", kind)
		return asn1.RawValue{}
	}
}

func assertUnsupportedGatewaySANFixture(t *testing.T, certificateDER []byte, gatewayID, dnsName, unsupportedKind string) {
	t.Helper()
	certificate := parseEnrollmentCertificate(t, certificateDER)
	class, parsedID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil || class != identity.GatewayClass || parsedID != gatewayID ||
		!slices.Equal(certificate.DNSNames, []string{dnsName}) || len(certificate.EmailAddresses) != 0 || len(certificate.IPAddresses) != 0 {
		t.Fatalf("unsupported %s SAN fixture parsed as identity (%q, %q), DNS %v, email %v, IP %v: %v", unsupportedKind, class, parsedID, certificate.DNSNames, certificate.EmailAddresses, certificate.IPAddresses, err)
	}
	found := false
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		var names []asn1.RawValue
		if rest, err := asn1.Unmarshal(extension.Value, &names); err != nil || len(rest) != 0 {
			t.Fatalf("parse unsupported SAN extension = %x, %v", rest, err)
		}
		for _, name := range names {
			if name.Class == asn1.ClassContextSpecific && name.Tag == map[string]int{"otherName": 0, "directoryName": 4, "registeredID": 8}[unsupportedKind] {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("unsupported %s GeneralName is absent from raw SAN extension", unsupportedKind)
	}
}

func authorizedRevokeGatewayRequest(certificateDER []byte) *connect.Request[powermanagev1.RevokeGatewayRequest] {
	request := connect.NewRequest(&powermanagev1.RevokeGatewayRequest{CertificateDer: bytes.Clone(certificateDER)})
	request.Header().Set("Authorization", "Bearer operator-proof")
	return request
}

func pkiEventCount(t *testing.T, fixture enrollmentHandlerFixture, streamType string) int {
	t.Helper()
	var count int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM events WHERE stream_type = $1`, streamType).Scan(&count); err != nil {
		t.Fatalf("count %s events: %v", streamType, err)
	}
	return count
}

func pkiEventCountForStream(t *testing.T, fixture enrollmentHandlerFixture, streamType, streamID string) int {
	t.Helper()
	var count int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM events WHERE stream_type = $1 AND stream_id = $2`, streamType, streamID).Scan(&count); err != nil {
		t.Fatalf("count %s/%s events: %v", streamType, streamID, err)
	}
	return count
}

func countPkiWork(t *testing.T, fixture enrollmentHandlerFixture, kind string) int {
	t.Helper()
	var count int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM work_items WHERE work_kind = $1`, kind).Scan(&count); err != nil {
		t.Fatalf("count %s work: %v", kind, err)
	}
	return count
}

func assertCrossPurposeEnrollmentWroteNothing(t *testing.T, fixture enrollmentHandlerFixture) {
	t.Helper()
	tokenState, err := fixture.eventStore.RegistrationToken(context.Background(), fixture.tokenID)
	if err != nil {
		t.Fatalf("read cross-purpose token: %v", err)
	}
	var identityEvents, devices, gateways int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM events WHERE stream_type IN ('device', 'gateway')`).Scan(&identityEvents); err != nil {
		t.Fatalf("count cross-purpose identity events: %v", err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM devices`).Scan(&devices); err != nil {
		t.Fatalf("count cross-purpose device projections: %v", err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM gateways`).Scan(&gateways); err != nil {
		t.Fatalf("count cross-purpose gateway projections: %v", err)
	}
	if tokenState.Uses != 0 || tokenState.ProjectionVersion != 1 || identityEvents != 0 || devices != 0 || gateways != 0 {
		t.Fatalf(
			"cross-purpose rejection state = token uses %d/version %d, events %d, devices %d, gateways %d; want untouched token and no identity writes",
			tokenState.Uses,
			tokenState.ProjectionVersion,
			identityEvents,
			devices,
			gateways,
		)
	}
}
