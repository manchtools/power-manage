package gateway

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/contract/identity"
)

const gatewayClientFirstID = "01ARZ3NDEKTSV4RRFFQ69G5FB0"

func TestGatewayClient_EachEnrollmentCreatesFreshValidatedIdentity(t *testing.T) {
	t.Run("fresh local identity", func(t *testing.T) {
		fixture := newGatewayClientFixture(t)
		first, err := fixture.client.Enroll(context.Background(), "gateway-registration-token")
		if err != nil {
			t.Fatalf("first Enroll: %v", err)
		}
		second, err := fixture.client.Enroll(context.Background(), "gateway-registration-token")
		if err != nil {
			t.Fatalf("second Enroll: %v", err)
		}
		if first.GatewayID == second.GatewayID || bytes.Equal(first.CertificateDER, second.CertificateDER) ||
			publicKeysEqual(first.PrivateKey.Public(), second.PrivateKey.Public()) {
			t.Fatal("successive gateway enrollments reused identity, certificate, or private key")
		}
		if fixture.handler.calls != 2 || len(fixture.handler.requests) != 2 {
			t.Fatalf("gateway enrollment calls = %d; want two", fixture.handler.calls)
		}
		for index, request := range fixture.handler.requests {
			if request.GetRegistrationToken() != "gateway-registration-token" {
				t.Fatalf("request %d token = %q; want exact token", index, request.GetRegistrationToken())
			}
			csr, err := x509.ParseCertificateRequest(request.GetCertificateSigningRequestDer())
			if err != nil || csr.CheckSignature() != nil {
				t.Fatalf("request %d CSR = (%v, %v); want valid local proof", index, csr, err)
			}
			if len(csr.DNSNames) != 0 || len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 || len(csr.Extensions) != 0 {
				t.Fatalf("request %d CSR contains caller-authored SANs: %+v", index, csr)
			}
		}
	})

	tests := []struct {
		name   string
		mutate func(*gatewayClientHandler)
		want   string
	}{
		{name: "substituted CA", mutate: func(handler *gatewayClientHandler) {
			handler.responseCA, _ = newGatewayClientCA(t, "substituted gateway CA")
		}, want: "verify"},
		{name: "substituted public key", mutate: func(handler *gatewayClientHandler) { handler.substituteKey = true }, want: "public key"},
		{name: "substituted DNS", mutate: func(handler *gatewayClientHandler) { handler.dnsNames = []string{"attacker.invalid"} }, want: "DNS"},
		{name: "agent identity class", mutate: func(handler *gatewayClientHandler) { handler.class = identity.AgentClass }, want: "gateway"},
		{name: "missing ServerAuth", mutate: func(handler *gatewayClientHandler) { handler.omitServerAuth = true }, want: "profile"},
		{name: "missing ClientAuth", mutate: func(handler *gatewayClientHandler) { handler.omitClientAuth = true }, want: "profile"},
		{name: "unknown extended key usage", mutate: func(handler *gatewayClientHandler) {
			handler.unknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 55555, 3}}
		}, want: "profile"},
		{name: "email SAN", mutate: func(handler *gatewayClientHandler) {
			handler.emailAddresses = []string{"gateway@attacker.invalid"}
		}, want: "profile"},
		{name: "IP SAN", mutate: func(handler *gatewayClientHandler) {
			handler.ipAddresses = []net.IP{net.ParseIP("192.0.2.1")}
		}, want: "profile"},
		{name: "raw SAN otherName", mutate: func(handler *gatewayClientHandler) {
			handler.unsupportedSANKind = "otherName"
			handler.extraExtensions = []pkix.Extension{unsupportedGatewaySANExtension(t, "gateway.internal.example", "otherName")}
		}, want: "profile"},
		{name: "raw SAN directoryName", mutate: func(handler *gatewayClientHandler) {
			handler.unsupportedSANKind = "directoryName"
			handler.extraExtensions = []pkix.Extension{unsupportedGatewaySANExtension(t, "gateway.internal.example", "directoryName")}
		}, want: "profile"},
		{name: "raw SAN registeredID", mutate: func(handler *gatewayClientHandler) {
			handler.unsupportedSANKind = "registeredID"
			handler.extraExtensions = []pkix.Extension{unsupportedGatewaySANExtension(t, "gateway.internal.example", "registeredID")}
		}, want: "profile"},
		{name: "wrong lifetime", mutate: func(handler *gatewayClientHandler) { handler.lifetime = 44 * 24 * time.Hour }, want: "profile"},
		{name: "malformed CA", mutate: func(handler *gatewayClientHandler) { handler.responseCADER = []byte("bad") }, want: "certificate authority"},
		{name: "missing agent trust bundle", mutate: func(handler *gatewayClientHandler) { handler.omitAgentTrust = true }, want: "agent trust bundle"},
		{name: "missing gateway trust bundle", mutate: func(handler *gatewayClientHandler) { handler.omitGatewayTrust = true }, want: "gateway trust bundle"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGatewayClientFixture(t)
			test.mutate(fixture.handler)
			got, err := fixture.client.Enroll(context.Background(), "gateway-registration-token")
			if fixture.handler.unsupportedSANKind != "" {
				assertUnsupportedGatewaySANFixture(
					t,
					fixture.handler.responseCertificateDER,
					fixture.handler.dnsNames[0],
					fixture.handler.unsupportedSANKind,
				)
			}
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.want)) {
				t.Fatalf(
					"Enroll returned ID %q, %d certificate bytes, private key %t, error %v; want rejection category %q",
					got.GatewayID,
					len(got.CertificateDER),
					got.PrivateKey != nil,
					err,
					test.want,
				)
			}
			if got.GatewayID != "" || len(got.CertificateDER) != 0 || got.PrivateKey != nil {
				t.Fatalf("rejected enrollment returned identity %+v", got)
			}
		})
	}
}

func TestGatewayClient_FirstRenewalUsesEnrollmentTrustState(t *testing.T) {
	fixture := newGatewayClientFixture(t)
	publisher := &gatewayEnrollmentPublisher{}
	fixture.client.publisher = publisher
	current, err := fixture.client.Enroll(context.Background(), "gateway-registration-token")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if current.AgentTrustBundle.Generation == 0 || current.GatewayTrustBundle.Generation == 0 {
		t.Fatalf("enrollment omitted trust state: %+v", current)
	}

	renewed, err := fixture.client.Renew(context.Background(), current)
	if err != nil {
		t.Fatalf("first Renew after Enroll: %v", err)
	}
	if fixture.handler.renewCalls != 1 || fixture.handler.confirmCalls != 2 {
		t.Fatalf("renew/confirmation calls = (%d,%d); want (1,2)", fixture.handler.renewCalls, fixture.handler.confirmCalls)
	}
	if publisher.calls != 2 || renewed.PendingAgentTrustConfirmation != nil || renewed.PendingGatewayTrustConfirmation != nil {
		t.Fatalf("published/renewed state = (%d,%+v); want atomic replacement then cleared confirmations", publisher.calls, renewed)
	}
}

type gatewayClientFixture struct {
	client  *EnrollmentClient
	handler *gatewayClientHandler
}

type gatewayClientHandler struct {
	powermanagev1connect.UnimplementedPkiServiceHandler

	ca                     *x509.Certificate
	caSigner               crypto.Signer
	agentCA                *x509.Certificate
	responseCA             *x509.Certificate
	responseCADER          []byte
	dnsNames               []string
	emailAddresses         []string
	ipAddresses            []net.IP
	class                  identity.Class
	lifetime               time.Duration
	substituteKey          bool
	omitServerAuth         bool
	omitClientAuth         bool
	unknownExtKeyUsage     []asn1.ObjectIdentifier
	unsupportedSANKind     string
	extraExtensions        []pkix.Extension
	responseCertificateDER []byte
	now                    time.Time
	calls                  int
	requests               []*powermanagev1.EnrollGatewayRequest
	renewCalls             int
	confirmCalls           int
	omitAgentTrust         bool
	omitGatewayTrust       bool
}

func newGatewayClientFixture(t *testing.T) gatewayClientFixture {
	t.Helper()
	ca, signer := newGatewayClientCA(t, "gateway client CA")
	agentCA, _ := newGatewayClientCA(t, "agent client CA")
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	handler := &gatewayClientHandler{
		ca: ca, caSigner: signer, agentCA: agentCA, dnsNames: []string{"gateway.internal.example"},
		class: identity.GatewayClass, lifetime: 45 * 24 * time.Hour, now: now,
	}
	path, connectHandler := powermanagev1connect.NewPkiServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, connectHandler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client, err := NewEnrollmentClient(
		powermanagev1connect.NewPkiServiceClient(server.Client(), server.URL),
		[]string{"gateway.internal.example"},
	)
	if err != nil {
		t.Fatalf("NewEnrollmentClient: %v", err)
	}
	client.now = func() time.Time { return now }
	return gatewayClientFixture{client: client, handler: handler}
}

func (h *gatewayClientHandler) EnrollGateway(_ context.Context, request *connect.Request[powermanagev1.EnrollGatewayRequest]) (*connect.Response[powermanagev1.EnrollGatewayResponse], error) {
	h.calls++
	h.requests = append(h.requests, request.Msg)
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
	extendedKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	if h.omitServerAuth {
		extendedKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if h.omitClientAuth {
		extendedKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(h.calls + 10)),
		NotBefore:             h.now.Add(-time.Minute),
		NotAfter:              h.now.Add(-time.Minute).Add(h.lifetime),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           extendedKeyUsage,
		DNSNames:              slices.Clone(h.dnsNames),
		EmailAddresses:        slices.Clone(h.emailAddresses),
		IPAddresses:           slices.Clone(h.ipAddresses),
		UnknownExtKeyUsage:    slices.Clone(h.unknownExtKeyUsage),
	}
	gatewayID := gatewayClientFirstID
	if h.calls > 1 {
		gatewayID = "01ARZ3NDEKTSV4RRFFQ69G5FB1"
	}
	if err := identity.StampCertificateIdentity(template, h.class, gatewayID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	template.ExtraExtensions = slices.Clone(h.extraExtensions)
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, h.ca, publicKey, h.caSigner)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	h.responseCertificateDER = bytes.Clone(certificateDER)
	caDER := h.responseCADER
	if caDER == nil {
		ca := h.ca
		if h.responseCA != nil {
			ca = h.responseCA
		}
		caDER = ca.Raw
	}
	agentTrust, gatewayTrust := h.trustBundles()
	if h.omitAgentTrust {
		agentTrust = nil
	}
	if h.omitGatewayTrust {
		gatewayTrust = nil
	}
	return connect.NewResponse(&powermanagev1.EnrollGatewayResponse{
		CertificateDer:          certificateDER,
		CertificateAuthorityDer: caDER,
		AgentTrustBundle:        agentTrust,
		GatewayTrustBundle:      gatewayTrust,
	}), nil
}

func (h *gatewayClientHandler) RenewGateway(_ context.Context, request *connect.Request[powermanagev1.RenewGatewayRequest]) (*connect.Response[powermanagev1.RenewGatewayResponse], error) {
	h.renewCalls++
	presented, err := x509.ParseCertificate(request.Msg.GetCertificateDer())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	class, gatewayID, err := identity.ParseCertificateIdentity(presented)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if class != identity.GatewayClass {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("presented identity is not a gateway"))
	}
	csr, err := x509.ParseCertificateRequest(request.Msg.GetCertificateSigningRequestDer())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(100 + h.renewCalls)),
		NotBefore:    h.now.Add(-time.Minute), NotAfter: h.now.Add(-time.Minute).Add(45 * 24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    slices.Clone(h.dnsNames),
	}
	if err := identity.StampCertificateIdentity(template, identity.GatewayClass, gatewayID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, h.ca, csr.PublicKey, h.caSigner)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	agentTrust, gatewayTrust := h.trustBundles()
	return connect.NewResponse(&powermanagev1.RenewGatewayResponse{
		CertificateDer: certificateDER, CertificateAuthorityDer: h.ca.Raw,
		AgentTrustBundle: agentTrust, GatewayTrustBundle: gatewayTrust,
	}), nil
}

func (h *gatewayClientHandler) ConfirmGatewayTrustState(context.Context, *connect.Request[powermanagev1.ConfirmTrustStateRequest]) (*connect.Response[powermanagev1.ConfirmTrustStateResponse], error) {
	h.confirmCalls++
	return connect.NewResponse(&powermanagev1.ConfirmTrustStateResponse{}), nil
}

func (h *gatewayClientHandler) trustBundles() (*powermanagev1.CATrustBundle, *powermanagev1.CATrustBundle) {
	return &powermanagev1.CATrustBundle{
			Generation: 1, Revision: 1, RootCertificateDer: [][]byte{h.agentCA.Raw},
			CrlIssuerFingerprint: sha256FingerprintBytes(h.agentCA.Raw), CrlSequence: 1,
		}, &powermanagev1.CATrustBundle{
			Generation: 1, Revision: 1, RootCertificateDer: [][]byte{h.ca.Raw},
		}
}

type gatewayEnrollmentPublisher struct {
	calls int
}

func (p *gatewayEnrollmentPublisher) Publish(context.Context, Identity) error {
	p.calls++
	return nil
}

func newGatewayClientCA(t *testing.T, name string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate gateway client CA key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatalf("marshal gateway client CA key: %v", err)
	}
	keyID := sha256.Sum256(publicDER)
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:       x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:     0,
		MaxPathLenZero: true,
		SubjectKeyId:   bytes.Clone(keyID[:20]),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatalf("create gateway client CA: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse gateway client CA: %v", err)
	}
	return certificate, signer
}

func publicKeysEqual(first, second crypto.PublicKey) bool {
	firstDER, err := x509.MarshalPKIXPublicKey(first)
	if err != nil {
		return false
	}
	secondDER, err := x509.MarshalPKIXPublicKey(second)
	return err == nil && bytes.Equal(firstDER, secondDER)
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

func assertUnsupportedGatewaySANFixture(t *testing.T, certificateDER []byte, dnsName, unsupportedKind string) {
	t.Helper()
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("parse unsupported SAN gateway fixture: %v", err)
	}
	class, gatewayID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil || class != identity.GatewayClass || gatewayID != gatewayClientFirstID ||
		!slices.Equal(certificate.DNSNames, []string{dnsName}) || len(certificate.EmailAddresses) != 0 || len(certificate.IPAddresses) != 0 {
		t.Fatalf("unsupported %s SAN fixture parsed as identity (%q, %q), DNS %v, email %v, IP %v: %v", unsupportedKind, class, gatewayID, certificate.DNSNames, certificate.EmailAddresses, certificate.IPAddresses, err)
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
