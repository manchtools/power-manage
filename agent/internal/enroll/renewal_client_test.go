package enroll

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/contract/identity"
)

func TestClient_RenewReusesSigningKeyRotatesSealingAndAtomicallyReplaces(t *testing.T) {
	fixture := newRenewalClientFixture(t)
	oldSealingKey := bytes.Clone(fixture.store.bundle.SealingPrivateKey.Bytes())
	oldSigner := fixture.store.bundle.PrivateKey

	if err := fixture.client.Renew(context.Background()); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if fixture.handler.calls != 1 || fixture.handler.request == nil || fixture.store.replaceCalls != 1 {
		t.Fatalf("renewal effects = (%d remote, %d replace); want one each", fixture.handler.calls, fixture.store.replaceCalls)
	}
	request := fixture.handler.request
	if !bytes.Equal(request.GetCertificateDer(), fixture.currentCertificateDER) {
		t.Fatal("renewal did not present the exact current certificate")
	}
	csr, err := x509.ParseCertificateRequest(request.GetCertificateSigningRequestDer())
	if err != nil {
		t.Fatalf("parse renewal CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("renewal CSR proof-of-possession signature: %v", err)
	}
	if !publicKeysMatch(t, csr.PublicKey, oldSigner.Public()) {
		t.Fatal("renewal CSR does not reuse the enrolled mTLS key")
	}
	if bytes.Equal(request.GetSealingPublicKey(), oldSealingKey) {
		t.Fatal("renewal reused the old X25519 sealing key")
	}
	if fixture.store.bundle.PrivateKey != oldSigner || bytes.Equal(fixture.store.bundle.SealingPrivateKey.Bytes(), oldSealingKey) {
		t.Fatal("replacement did not retain the mTLS key and rotate the sealing key")
	}
	if !bytes.Equal(fixture.store.bundle.CertificateAuthorityDER, fixture.ca.Raw) || fixture.store.bundle.DeviceID != enrolledClientDeviceID {
		t.Fatal("replacement changed the enrolled CA or device identity")
	}
}

func TestClient_RenewReusesPendingSealingKeyAfterRemoteFailure(t *testing.T) {
	fixture := newRenewalClientFixture(t)
	fixture.handler.failAfterIssue = 1

	if err := fixture.client.Renew(context.Background()); err == nil ||
		connect.CodeOf(err) != connect.CodeUnavailable ||
		!strings.Contains(err.Error(), "response lost after issuance") {
		t.Fatalf("first Renew error = %v; want unavailable response-lost-after-issuance failure", err)
	}
	if fixture.store.replaceCalls != 0 {
		t.Fatalf("replace calls after lost response = %d; want 0", fixture.store.replaceCalls)
	}
	if err := fixture.client.Renew(context.Background()); err != nil {
		t.Fatalf("retry Renew: %v", err)
	}
	if fixture.handler.calls != 2 || fixture.store.replaceCalls != 1 {
		t.Fatalf("retry effects = (%d remote, %d replace); want (2, 1)", fixture.handler.calls, fixture.store.replaceCalls)
	}
	if len(fixture.handler.sealingPublicKeys) != 2 ||
		!bytes.Equal(fixture.handler.sealingPublicKeys[0], fixture.handler.sealingPublicKeys[1]) {
		t.Fatal("renewal retry did not reuse the pending sealing key")
	}
}

func TestClient_RenewRefusesResponseSubstitutionBeforeReplacement(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *renewalClientHandler)
		want   string
	}{
		{name: "different identity", mutate: func(_ *testing.T, handler *renewalClientHandler) { handler.deviceID = "01ARZ3NDEKTSV4RRFFQ69G5FAX" }, want: "device ID mismatch"},
		{name: "different class", mutate: func(_ *testing.T, handler *renewalClientHandler) { handler.class = identity.GatewayClass }, want: "is not agent"},
		{name: "different certificate key", mutate: func(_ *testing.T, handler *renewalClientHandler) { handler.substituteKey = true }, want: "public key mismatch"},
		{name: "invalid certificate profile", mutate: func(_ *testing.T, handler *renewalClientHandler) { handler.omitClientAuth = true }, want: "invalid agent profile"},
		{name: "different CA", mutate: func(t *testing.T, handler *renewalClientHandler) {
			otherCA, otherSigner := newClientTestCA(t)
			handler.ca = otherCA
			handler.caSigner = otherSigner
		}, want: "differs from enrolled authority"},
		{name: "malformed certificate", mutate: func(_ *testing.T, handler *renewalClientHandler) { handler.responseCertificate = []byte("bad") }, want: "parse issued certificate"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRenewalClientFixture(t)
			before := fixture.store.bundle
			test.mutate(t, fixture.handler)
			err := fixture.client.Renew(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Renew error = %v; want category %q", err, test.want)
			}
			if fixture.store.replaceCalls != 0 || !bytes.Equal(fixture.store.bundle.CertificateDER, before.CertificateDER) ||
				!bytes.Equal(fixture.store.bundle.CertificateAuthorityDER, before.CertificateAuthorityDER) ||
				fixture.store.bundle.PrivateKey != before.PrivateKey || fixture.store.bundle.SealingPrivateKey != before.SealingPrivateKey {
				t.Fatal("rejected renewal changed stored credentials")
			}
		})
	}
}

type renewalClientFixture struct {
	client                *Client
	store                 *capturingCredentialStore
	handler               *renewalClientHandler
	ca                    *x509.Certificate
	currentCertificateDER []byte
}

type renewalClientHandler struct {
	ca                  *x509.Certificate
	caSigner            crypto.Signer
	class               identity.Class
	deviceID            string
	responseCA          []byte
	responseCertificate []byte
	substituteKey       bool
	omitClientAuth      bool
	failAfterIssue      int
	calls               int
	request             *powermanagev1.RenewAgentRequest
	sealingPublicKeys   [][]byte
}

func newRenewalClientFixture(t *testing.T) renewalClientFixture {
	t.Helper()
	ca, caSigner := newClientTestCA(t)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate current mTLS key: %v", err)
	}
	sealingKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate current sealing key: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	currentCertificateDER := newRenewalClientCertificate(t, ca, caSigner, privateKey.Public(), identity.AgentClass, enrolledClientDeviceID, now, 17)
	store := &capturingCredentialStore{bundle: CredentialBundle{
		DeviceID:                enrolledClientDeviceID,
		CertificateDER:          currentCertificateDER,
		CertificateAuthorityDER: bytes.Clone(ca.Raw),
		PrivateKey:              privateKey,
		SealingPrivateKey:       sealingKey,
	}}
	handler := &renewalClientHandler{ca: ca, caSigner: caSigner, class: identity.AgentClass, deviceID: enrolledClientDeviceID}
	path, httpHandler := powermanagev1connect.NewPkiServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, httpHandler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client, err := NewClient(powermanagev1connect.NewPkiServiceClient(server.Client(), server.URL), store)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.now = func() time.Time { return now }
	return renewalClientFixture{client: client, store: store, handler: handler, ca: ca, currentCertificateDER: currentCertificateDER}
}

func (h *renewalClientHandler) EnrollAgent(context.Context, *connect.Request[powermanagev1.EnrollAgentRequest]) (*connect.Response[powermanagev1.EnrollAgentResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (h *renewalClientHandler) RenewAgent(_ context.Context, request *connect.Request[powermanagev1.RenewAgentRequest]) (*connect.Response[powermanagev1.RenewAgentResponse], error) {
	h.calls++
	h.request = request.Msg
	h.sealingPublicKeys = append(h.sealingPublicKeys, bytes.Clone(request.Msg.GetSealingPublicKey()))
	csr, err := x509.ParseCertificateRequest(request.Msg.GetCertificateSigningRequestDer())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	publicKey := csr.PublicKey
	if h.substituteKey {
		key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			return nil, connect.NewError(connect.CodeInternal, keyErr)
		}
		publicKey = key.Public()
	}
	certificateDER := h.responseCertificate
	if certificateDER == nil {
		certificateDER, err = newRenewalClientCertificateForHandler(h, publicKey)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		h.responseCertificate = bytes.Clone(certificateDER)
	}
	caDER := h.responseCA
	if caDER == nil {
		caDER = h.ca.Raw
	}
	if h.failAfterIssue > 0 {
		h.failAfterIssue--
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("response lost after issuance"))
	}
	return connect.NewResponse(&powermanagev1.RenewAgentResponse{
		CertificateDer:          certificateDER,
		CertificateAuthorityDer: caDER,
	}), nil
}

func newRenewalClientCertificateForHandler(h *renewalClientHandler, publicKey crypto.PublicKey) ([]byte, error) {
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(18),
		Subject:               pkix.Name{},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(-time.Minute).Add(agentCertificateLifetime),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if h.omitClientAuth {
		template.ExtKeyUsage = nil
	}
	if err := identity.StampCertificateIdentity(template, h.class, h.deviceID); err != nil {
		return nil, err
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, h.ca, publicKey, h.caSigner)
	if err != nil {
		return nil, err
	}
	return certificateDER, nil
}

func newRenewalClientCertificate(
	t *testing.T,
	ca *x509.Certificate,
	caSigner crypto.Signer,
	publicKey crypto.PublicKey,
	class identity.Class,
	deviceID string,
	now time.Time,
	serial int64,
) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(-time.Hour).Add(agentCertificateLifetime),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if err := identity.StampCertificateIdentity(template, class, deviceID); err != nil {
		t.Fatalf("stamp renewal client certificate: %v", err)
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caSigner)
	if err != nil {
		t.Fatalf("create renewal client certificate: %v", err)
	}
	return certificateDER
}
