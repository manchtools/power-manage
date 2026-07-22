package enroll

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
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/contract/identity"
)

const enrolledClientDeviceID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

func TestClient_EnrollKeepsPrivateKeysLocalAndStoresVerifiedIdentity(t *testing.T) {
	remote := newClientRemoteFixture(t)
	store := &capturingCredentialStore{}
	client, err := NewClient(remote.client, store)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	pin := sha256.Sum256(remote.ca.Raw)
	deviceID, err := client.Enroll(context.Background(), "registration-token", "sha256:"+fmt.Sprintf("%x", pin))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if deviceID != enrolledClientDeviceID || store.calls != 1 {
		t.Fatalf("enrollment result = (%q, %d store calls); want issued ID and one create", deviceID, store.calls)
	}
	if remote.handler.calls != 1 || remote.handler.request == nil {
		t.Fatal("remote enrollment handler did not receive one request")
	}
	csr, err := x509.ParseCertificateRequest(remote.handler.request.GetCertificateSigningRequestDer())
	if err != nil {
		t.Fatalf("parse captured CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("captured CSR signature: %v", err)
	}
	if len(csr.DNSNames) != 0 || len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 || len(csr.Extensions) != 0 {
		t.Fatalf("captured CSR contains caller identity extensions: %+v", csr)
	}
	if store.bundle.PrivateKey == nil || store.bundle.SealingPrivateKey == nil {
		t.Fatal("stored bundle is missing locally generated private keys")
	}
	if !publicKeysMatch(t, store.bundle.PrivateKey.Public(), csr.PublicKey) {
		t.Fatal("stored mTLS private key does not match CSR public key")
	}
	if !bytes.Equal(store.bundle.SealingPrivateKey.PublicKey().Bytes(), remote.handler.request.GetSealingPublicKey()) {
		t.Fatal("stored sealing private key does not match submitted public key")
	}
	if !bytes.Equal(store.bundle.CertificateDER, remote.handler.certificateDER) || !bytes.Equal(store.bundle.CertificateAuthorityDER, remote.ca.Raw) {
		t.Fatal("stored bundle differs from verified response material")
	}
}

func TestClient_EnrollRefusesPinAndResponseSubstitutionBeforeStorage(t *testing.T) {
	tests := []struct {
		name   string
		pin    string
		mutate func(*clientRemoteHandler)
		want   string
	}{
		{name: "CA pin mismatch", pin: strings.Repeat("0", 64), want: "fingerprint"},
		{name: "malformed CA", mutate: func(handler *clientRemoteHandler) { handler.responseCA = []byte("bad") }, want: "certificate authority"},
		{name: "substituted certificate key", mutate: func(handler *clientRemoteHandler) { handler.substituteKey = true }, want: "public key"},
		{name: "wrong certificate class", mutate: func(handler *clientRemoteHandler) { handler.class = identity.GatewayClass }, want: "agent"},
		{name: "unsupported CA key", mutate: func(handler *clientRemoteHandler) {
			_, signer, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("generate unsupported CA key: %v", err)
			}
			handler.ca, handler.caSigner = newClientTestCAWithSigner(t, signer)
		}, want: "certificate authority key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			remote := newClientRemoteFixture(t)
			if test.mutate != nil {
				test.mutate(remote.handler)
			}
			store := &capturingCredentialStore{}
			client, err := NewClient(remote.client, store)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			_, err = client.Enroll(context.Background(), "registration-token", test.pin)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.want)) {
				t.Fatalf("Enroll error = %v; want category %q", err, test.want)
			}
			if store.calls != 0 {
				t.Fatalf("rejected enrollment stored %d bundles; want zero", store.calls)
			}
		})
	}
}

func TestFileCredentialStore_EncodesRootOnlyNoOverwriteBundle(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate mTLS key: %v", err)
	}
	sealingKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sealing key: %v", err)
	}
	ca, caSigner := newClientTestCA(t)
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(-time.Minute).Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if err := identity.StampCertificateIdentity(template, identity.AgentClass, enrolledClientDeviceID); err != nil {
		t.Fatalf("stamp credential certificate identity: %v", err)
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caSigner)
	if err != nil {
		t.Fatalf("create credential certificate: %v", err)
	}
	bundle := CredentialBundle{
		DeviceID:                enrolledClientDeviceID,
		CertificateDER:          certificateDER,
		CertificateAuthorityDER: ca.Raw,
		PrivateKey:              key,
		SealingPrivateKey:       sealingKey,
	}
	var gotPath string
	var gotData []byte
	var gotMode os.FileMode
	create := func(path string, data []byte, mode os.FileMode) error {
		gotPath, gotData, gotMode = path, append([]byte(nil), data...), mode
		return nil
	}
	store, err := newFileCredentialStore("/var/lib/power-manage/identity.pem", create)
	if err != nil {
		t.Fatalf("newFileCredentialStore: %v", err)
	}
	if err := store.Create(context.Background(), bundle); err != nil {
		t.Fatalf("Create credential bundle: %v", err)
	}
	if gotPath != "/var/lib/power-manage/identity.pem" || gotMode != 0o600 {
		t.Fatalf("credential create = (%q, %o); want production path and 0600", gotPath, gotMode)
	}
	blocks := decodeCredentialPEM(t, gotData)
	if len(blocks) != 4 || blocks[0].Type != "POWER MANAGE AGENT CERTIFICATE" || blocks[1].Type != "POWER MANAGE AGENT PRIVATE KEY" || blocks[2].Type != "POWER MANAGE AGENT CA CERTIFICATE" || blocks[3].Type != "POWER MANAGE SEALING PRIVATE KEY" {
		t.Fatalf("credential PEM blocks = %v; want exact four-block bundle", blocks)
	}
}

type capturingCredentialStore struct {
	calls  int
	bundle CredentialBundle
}

func (s *capturingCredentialStore) Create(_ context.Context, bundle CredentialBundle) error {
	s.calls++
	s.bundle = bundle
	return nil
}

type clientRemoteFixture struct {
	client  powermanagev1connect.PkiServiceClient
	ca      *x509.Certificate
	handler *clientRemoteHandler
}

type clientRemoteHandler struct {
	ca             *x509.Certificate
	caSigner       crypto.Signer
	class          identity.Class
	responseCA     []byte
	substituteKey  bool
	calls          int
	request        *powermanagev1.EnrollAgentRequest
	certificateDER []byte
}

func (h *clientRemoteHandler) EnrollAgent(_ context.Context, request *connect.Request[powermanagev1.EnrollAgentRequest]) (*connect.Response[powermanagev1.EnrollAgentResponse], error) {
	h.calls++
	h.request = request.Msg
	csr, err := x509.ParseCertificateRequest(request.Msg.GetCertificateSigningRequestDer())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	publicKey := csr.PublicKey
	if h.substituteKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		publicKey = key.Public()
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(365*24*time.Hour - time.Minute),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if err := identity.StampCertificateIdentity(template, h.class, enrolledClientDeviceID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, h.ca, publicKey, h.caSigner)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	h.certificateDER = certificateDER
	caDER := h.responseCA
	if caDER == nil {
		caDER = h.ca.Raw
	}
	return connect.NewResponse(&powermanagev1.EnrollAgentResponse{
		CertificateDer:          certificateDER,
		CertificateAuthorityDer: caDER,
	}), nil
}

func newClientRemoteFixture(t *testing.T) clientRemoteFixture {
	t.Helper()
	ca, signer := newClientTestCA(t)
	handler := &clientRemoteHandler{ca: ca, caSigner: signer, class: identity.AgentClass}
	path, httpHandler := powermanagev1connect.NewPkiServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, httpHandler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return clientRemoteFixture{
		client:  powermanagev1connect.NewPkiServiceClient(server.Client(), server.URL),
		ca:      ca,
		handler: handler,
	}
}

func newClientTestCA(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test CA key: %v", err)
	}
	return newClientTestCAWithSigner(t, signer)
}

func newClientTestCAWithSigner(t *testing.T, signer crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "agent test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(2 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatalf("create test CA: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test CA: %v", err)
	}
	return certificate, signer
}

func publicKeysMatch(t *testing.T, first, second crypto.PublicKey) bool {
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

func decodeCredentialPEM(t *testing.T, data []byte) []*pem.Block {
	t.Helper()
	var blocks []*pem.Block
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			t.Fatalf("credential bundle contains invalid PEM near %q", data)
		}
		blocks = append(blocks, block)
		data = rest
	}
	return blocks
}
