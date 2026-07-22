package identity_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/manchtools/power-manage/contract/identity"
)

const (
	testAgentID    = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	testGatewayID  = "01BX5ZZKBKACTAV9WEVGEMMVRZ"
	testControlID  = "01D78XYFJ1PRM1WPBCBT3VHMNV"
	testGatewayDNS = "gateway.internal.test"
	testControlDNS = "control.internal.test"
)

// TestStampCertificateIdentity_CanonicalProfile pins the control-authored
// WIRE-18 profile: canonical CN, exactly one class URI, and DNS SANs left as
// names rather than identity.
func TestStampCertificateIdentity_CanonicalProfile(t *testing.T) {
	template := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "caller-supplied"},
		DNSNames: []string{testGatewayDNS},
	}
	if err := identity.StampCertificateIdentity(template, identity.GatewayClass, testGatewayID); err != nil {
		t.Fatalf("StampCertificateIdentity: %v", err)
	}
	if template.Subject.CommonName != testGatewayID {
		t.Fatalf("common name = %q; want canonical ULID %q", template.Subject.CommonName, testGatewayID)
	}
	if len(template.URIs) != 1 || template.URIs[0].String() != identity.GatewaySPIFFEURI {
		t.Fatalf("URI SANs = %v; want exactly %q", template.URIs, identity.GatewaySPIFFEURI)
	}
	if len(template.DNSNames) != 1 || template.DNSNames[0] != testGatewayDNS {
		t.Fatalf("DNS SANs = %v; want server name %q preserved", template.DNSNames, testGatewayDNS)
	}
	class, instanceID, err := identity.ParseCertificateIdentity(template)
	if err != nil {
		t.Fatalf("ParseCertificateIdentity(stamped template): %v", err)
	}
	if class != identity.GatewayClass || instanceID != testGatewayID {
		t.Fatalf("parsed identity = (%q, %q); want (%q, %q)", class, instanceID, identity.GatewayClass, testGatewayID)
	}
}

// TestStampCertificateIdentity_RejectsInvalidInput pins the fail-closed mint
// boundary: nil templates, unknown classes, and non-canonical ULIDs cannot be
// stamped into a certificate profile.
func TestStampCertificateIdentity_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name     string
		template *x509.Certificate
		class    identity.Class
		id       string
		wantErr  string
	}{
		{name: "nil template", class: identity.AgentClass, id: testAgentID, wantErr: "nil certificate template"},
		{name: "unknown class", template: &x509.Certificate{}, class: identity.Class("relay"), id: testAgentID, wantErr: `unsupported certificate class "relay"`},
		{name: "empty ULID", template: &x509.Certificate{}, class: identity.AgentClass, wantErr: "instance ID is not a canonical ULID"},
		{name: "lowercase is not canonical", template: &x509.Certificate{}, class: identity.AgentClass, id: "01arz3ndektsv4rrffq69g5fav", wantErr: "instance ID is not a canonical ULID"},
		{name: "forbidden Crockford character", template: &x509.Certificate{}, class: identity.AgentClass, id: "01ARZ3NDEKTSV4RRFFQ69G5FAI", wantErr: "instance ID is not a canonical ULID"},
		{name: "ULID overflow", template: &x509.Certificate{}, class: identity.AgentClass, id: "8ZZZZZZZZZZZZZZZZZZZZZZZZZ", wantErr: "instance ID is not a canonical ULID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := identity.StampCertificateIdentity(test.template, test.class, test.id)
			if err == nil {
				t.Fatal("StampCertificateIdentity accepted an invalid profile input")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("StampCertificateIdentity error = %q; want substring %q", err, test.wantErr)
			}
		})
	}
}

// TestStampCertificateIdentity_RejectsRawCommonNameOverride pins the raw-DER
// bypass: pkix.Name.ExtraNames can replace Subject.CommonName during X.509
// serialization, so stamping must reject it before mutating the template.
func TestStampCertificateIdentity_RejectsRawCommonNameOverride(t *testing.T) {
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "before-stamp",
			ExtraNames: []pkix.AttributeTypeAndValue{{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
				Value: testControlID,
			}},
		},
	}
	proof := *template
	proof.Subject.CommonName = testAgentID
	proof.URIs = []*url.URL{mustURL(t, identity.AgentSPIFFEURI)}
	parsed := serializeCertificateTemplate(t, &proof)
	if parsed.Subject.CommonName != testControlID {
		t.Fatalf("raw-CN fixture parsed common name = %q; want override %q", parsed.Subject.CommonName, testControlID)
	}

	before := *template
	err := identity.StampCertificateIdentity(template, identity.AgentClass, testAgentID)
	if !reflect.DeepEqual(template, &before) {
		t.Errorf("StampCertificateIdentity mutated template before rejecting raw common-name override")
	}
	if err == nil {
		t.Fatal("StampCertificateIdentity accepted Subject.ExtraNames common-name override")
	}
	if !strings.Contains(err.Error(), "Subject.ExtraNames overrides common name") {
		t.Fatalf("StampCertificateIdentity error = %q; want raw common-name override reason", err)
	}
}

// TestStampCertificateIdentity_RejectsRawSubjectOverride pins the broader
// raw-DER bypass: Certificate.RawSubject takes precedence over every parsed
// Subject field during serialization, including the stamped common name.
func TestStampCertificateIdentity_RejectsRawSubjectOverride(t *testing.T) {
	rawSubject, err := asn1.Marshal(pkix.Name{CommonName: testControlID}.ToRDNSequence())
	if err != nil {
		t.Fatalf("marshal raw-subject fixture: %v", err)
	}
	template := &x509.Certificate{
		Subject:    pkix.Name{CommonName: "before-stamp"},
		RawSubject: rawSubject,
	}
	proof := *template
	proof.Subject.CommonName = testAgentID
	proof.URIs = []*url.URL{mustURL(t, identity.AgentSPIFFEURI)}
	parsed := serializeCertificateTemplate(t, &proof)
	if parsed.Subject.CommonName != testControlID {
		t.Fatalf("raw-subject fixture parsed common name = %q; want override %q", parsed.Subject.CommonName, testControlID)
	}

	before := *template
	err = identity.StampCertificateIdentity(template, identity.AgentClass, testAgentID)
	if !reflect.DeepEqual(template, &before) {
		t.Errorf("StampCertificateIdentity mutated template before rejecting RawSubject override")
	}
	if err == nil {
		t.Fatal("StampCertificateIdentity accepted RawSubject override")
	}
	if !strings.Contains(err.Error(), "RawSubject overrides subject") {
		t.Fatalf("StampCertificateIdentity error = %q; want RawSubject override reason", err)
	}
}

// TestStampCertificateIdentity_RejectsRawSANOverride pins the sibling raw-DER
// bypass: ExtraExtensions subjectAltName replaces template.URIs during X.509
// serialization, so stamping must reject it before mutating the template.
func TestStampCertificateIdentity_RejectsRawSANOverride(t *testing.T) {
	sanDER, err := asn1.Marshal([]asn1.RawValue{{
		Class: asn1.ClassContextSpecific,
		Tag:   6,
		Bytes: []byte(identity.GatewaySPIFFEURI),
	}})
	if err != nil {
		t.Fatalf("marshal raw SAN fixture: %v", err)
	}
	template := &x509.Certificate{
		Subject: pkix.Name{CommonName: "before-stamp"},
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
			Value: sanDER,
		}},
	}
	proof := *template
	proof.Subject.CommonName = testAgentID
	proof.URIs = []*url.URL{mustURL(t, identity.AgentSPIFFEURI)}
	parsed := serializeCertificateTemplate(t, &proof)
	if len(parsed.URIs) != 1 || parsed.URIs[0].String() != identity.GatewaySPIFFEURI {
		t.Fatalf("raw-SAN fixture parsed URIs = %v; want override %q", parsed.URIs, identity.GatewaySPIFFEURI)
	}

	before := *template
	err = identity.StampCertificateIdentity(template, identity.AgentClass, testAgentID)
	if !reflect.DeepEqual(template, &before) {
		t.Errorf("StampCertificateIdentity mutated template before rejecting raw SAN override")
	}
	if err == nil {
		t.Fatal("StampCertificateIdentity accepted ExtraExtensions subjectAltName override")
	}
	if !strings.Contains(err.Error(), "ExtraExtensions overrides subjectAltName") {
		t.Fatalf("StampCertificateIdentity error = %q; want raw SAN override reason", err)
	}
}

// TestParseCertificateIdentity_RejectsMalformedProfile pins exact parsing:
// one known SPIFFE URI and one canonical CN are required; DNS, duplicate SANs,
// query variants, and unknown classes cannot substitute for that profile.
func TestParseCertificateIdentity_RejectsMalformedProfile(t *testing.T) {
	tests := []struct {
		name    string
		cert    func(t *testing.T) *x509.Certificate
		wantErr string
	}{
		{name: "nil certificate", wantErr: "nil certificate"},
		{name: "missing common name", cert: func(t *testing.T) *x509.Certificate {
			cert := stampedProfile(t, identity.AgentClass, testAgentID)
			cert.Subject.CommonName = ""
			return cert
		}, wantErr: "certificate common name is not a canonical ULID"},
		{name: "lowercase common name", cert: func(t *testing.T) *x509.Certificate {
			cert := stampedProfile(t, identity.AgentClass, testAgentID)
			cert.Subject.CommonName = "01arz3ndektsv4rrffq69g5fav"
			return cert
		}, wantErr: "certificate common name is not a canonical ULID"},
		{name: "missing URI SAN", cert: func(t *testing.T) *x509.Certificate {
			cert := stampedProfile(t, identity.AgentClass, testAgentID)
			cert.URIs = nil
			cert.DNSNames = []string{"agent"}
			return cert
		}, wantErr: "certificate must contain exactly one SPIFFE URI SAN"},
		{name: "duplicate URI SAN", cert: func(t *testing.T) *x509.Certificate {
			cert := stampedProfile(t, identity.AgentClass, testAgentID)
			cert.URIs = append(cert.URIs, mustURL(t, identity.AgentSPIFFEURI))
			return cert
		}, wantErr: "certificate must contain exactly one SPIFFE URI SAN"},
		{name: "multiple classes", cert: func(t *testing.T) *x509.Certificate {
			cert := stampedProfile(t, identity.AgentClass, testAgentID)
			cert.URIs = append(cert.URIs, mustURL(t, identity.GatewaySPIFFEURI))
			return cert
		}, wantErr: "certificate must contain exactly one SPIFFE URI SAN"},
		{name: "unknown class", cert: func(t *testing.T) *x509.Certificate {
			cert := stampedProfile(t, identity.AgentClass, testAgentID)
			cert.URIs = []*url.URL{mustURL(t, "spiffe://power-manage/relay")}
			return cert
		}, wantErr: `unsupported SPIFFE URI SAN "spiffe://power-manage/relay"`},
		{name: "query variant", cert: func(t *testing.T) *x509.Certificate {
			cert := stampedProfile(t, identity.AgentClass, testAgentID)
			cert.URIs = []*url.URL{mustURL(t, identity.AgentSPIFFEURI+"?class=gateway")}
			return cert
		}, wantErr: `unsupported SPIFFE URI SAN "spiffe://power-manage/agent?class=gateway"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var cert *x509.Certificate
			if test.cert != nil {
				cert = test.cert(t)
			}
			_, _, err := identity.ParseCertificateIdentity(cert)
			if err == nil {
				t.Fatal("ParseCertificateIdentity accepted a malformed certificate profile")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ParseCertificateIdentity error = %q; want substring %q", err, test.wantErr)
			}
		})
	}
}

// TestRequireCertificateClass_RejectsWrongClass pins WIRE-19 class
// separation independently of chain verification.
func TestRequireCertificateClass_RejectsWrongClass(t *testing.T) {
	cert := stampedProfile(t, identity.AgentClass, testAgentID)
	if err := identity.RequireCertificateClass(cert, identity.AgentClass); err != nil {
		t.Fatalf("RequireCertificateClass rejected the matching agent class: %v", err)
	}
	if err := identity.RequireCertificateClass(cert, identity.GatewayClass); err == nil {
		t.Fatal("RequireCertificateClass accepted an agent certificate as gateway-class")
	}
}

// TestIsCanonicalULID_ProfileGrammar keeps certificate IDs on the same exact
// uppercase Crockford grammar consumed by command/result verification.
func TestIsCanonicalULID_ProfileGrammar(t *testing.T) {
	for _, id := range []string{testAgentID, testGatewayID, "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"} {
		if !identity.IsCanonicalULID(id) {
			t.Errorf("IsCanonicalULID(%q) = false; want true", id)
		}
	}
	for _, id := range []string{
		"", "01arz3ndektsv4rrffq69g5fav", "01ARZ3NDEKTSV4RRFFQ69G5FAI",
		"01ARZ3NDEKTSV4RRFFQ69G5FA", "8ZZZZZZZZZZZZZZZZZZZZZZZZZ",
	} {
		if identity.IsCanonicalULID(id) {
			t.Errorf("IsCanonicalULID(%q) = true; want false", id)
		}
	}
}

// TestServerTLSConfig_RequiresTLS13AndClientCertificate proves the server
// builder's TLS 1.3 and verified-client-certificate requirements with real
// handshakes, not config inspection alone.
func TestServerTLSConfig_RequiresTLS13AndClientCertificate(t *testing.T) {
	ca := newTestCA(t, "enrolled-internal-ca")
	serverCert := ca.issue(t, identity.GatewayClass, testGatewayID, []string{testGatewayDNS}, x509.ExtKeyUsageServerAuth)
	agentCert := ca.issue(t, identity.AgentClass, testAgentID, nil, x509.ExtKeyUsageClientAuth)

	serverConfig, err := identity.ServerTLSConfig(serverCert, ca.pool, identity.AgentClass)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	if serverConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("server MinVersion = %#x; want TLS 1.3", serverConfig.MinVersion)
	}
	if serverConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("server ClientAuth = %v; want RequireAndVerifyClientCert", serverConfig.ClientAuth)
	}

	clientConfig := standardClientConfig(agentCert, ca.pool, testGatewayDNS)
	result := realTLSHandshake(t, clientConfig, serverConfig)
	if result.clientErr != nil || result.serverErr != nil {
		t.Fatalf("TLS 1.3 mTLS handshake failed: client=%v server=%v", result.clientErr, result.serverErr)
	}
	if result.clientState.Version != tls.VersionTLS13 || result.serverState.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated versions client=%#x server=%#x; want TLS 1.3", result.clientState.Version, result.serverState.Version)
	}

	withoutCertificate := standardClientConfig(tls.Certificate{}, ca.pool, testGatewayDNS)
	missing := realTLSHandshake(t, withoutCertificate, serverConfig)
	if missing.serverErr == nil {
		t.Fatal("server accepted a TLS client without a certificate")
	}

	tls12Only := standardClientConfig(agentCert, ca.pool, testGatewayDNS)
	tls12Only.MinVersion = tls.VersionTLS12
	tls12Only.MaxVersion = tls.VersionTLS12
	legacy := realTLSHandshake(t, tls12Only, serverConfig)
	if legacy.clientErr == nil && legacy.serverErr == nil {
		t.Fatal("server negotiated TLS 1.2 despite the TLS 1.3 minimum")
	}
}

// TestServerTLSConfig_RejectsWrongClientClassBeforeUse is AC-6 at a real TLS
// boundary: a chain-valid agent certificate cannot authenticate to the
// gateway-only InternalService surface.
func TestServerTLSConfig_RejectsWrongClientClassBeforeUse(t *testing.T) {
	ca := newTestCA(t, "enrolled-internal-ca")
	serverCert := ca.issue(t, identity.ControlClass, testControlID, []string{testControlDNS}, x509.ExtKeyUsageServerAuth)
	wrongClient := ca.issue(t, identity.AgentClass, testAgentID, nil, x509.ExtKeyUsageClientAuth)
	serverConfig, err := identity.ServerTLSConfig(serverCert, ca.pool, identity.GatewayClass)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	result := realTLSHandshake(t, standardClientConfig(wrongClient, ca.pool, testControlDNS), serverConfig)
	assertClassMismatch(t, result.serverErr, identity.AgentClass, identity.GatewayClass)
}

// TestServerTLSConfig_RejectsGatewayClassOnAgentSurface pins the sibling
// WIRE-19 rejection path: gateway identity cannot cross an agent-only seam.
func TestServerTLSConfig_RejectsGatewayClassOnAgentSurface(t *testing.T) {
	ca := newTestCA(t, "enrolled-internal-ca")
	serverCert := ca.issue(t, identity.GatewayClass, testGatewayID, []string{testGatewayDNS}, x509.ExtKeyUsageServerAuth)
	wrongClient := ca.issue(t, identity.GatewayClass, "01BX5ZZKBKACTAV9WEVGEMMVS0", nil, x509.ExtKeyUsageClientAuth)
	serverConfig, err := identity.ServerTLSConfig(serverCert, ca.pool, identity.AgentClass)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	result := realTLSHandshake(t, standardClientConfig(wrongClient, ca.pool, testGatewayDNS), serverConfig)
	assertClassMismatch(t, result.serverErr, identity.GatewayClass, identity.AgentClass)
}

// TestServerTLSConfig_RejectsUnenrolledClientCA proves class checks do not
// replace standard chain validation: the right class from another CA fails.
func TestServerTLSConfig_RejectsUnenrolledClientCA(t *testing.T) {
	enrolled := newTestCA(t, "enrolled-internal-ca")
	foreign := newTestCA(t, "foreign-ca")
	serverCert := enrolled.issue(t, identity.GatewayClass, testGatewayID, []string{testGatewayDNS}, x509.ExtKeyUsageServerAuth)
	foreignAgent := foreign.issue(t, identity.AgentClass, testAgentID, nil, x509.ExtKeyUsageClientAuth)
	serverConfig, err := identity.ServerTLSConfig(serverCert, enrolled.pool, identity.AgentClass)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	foreignClientConfig := standardClientConfig(foreignAgent, enrolled.pool, testGatewayDNS)
	foreignClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &foreignAgent, nil
	}
	result := realTLSHandshake(t, foreignClientConfig, serverConfig)
	assertErrorContains(t, result.serverErr, "certificate signed by unknown authority")
}

// TestClientTLSConfig_UsesEnrolledCAAndGatewayClass proves the client trusts
// its enrolled CA directly, negotiates TLS 1.3, and rejects the same gateway
// profile when it is signed by a different root.
func TestClientTLSConfig_UsesEnrolledCAAndGatewayClass(t *testing.T) {
	enrolled := newTestCA(t, "enrolled-internal-ca")
	foreign := newTestCA(t, "system-like-foreign-ca")
	agentCert := enrolled.issue(t, identity.AgentClass, testAgentID, nil, x509.ExtKeyUsageClientAuth)
	gatewayCert := enrolled.issue(t, identity.GatewayClass, testGatewayID, []string{testGatewayDNS}, x509.ExtKeyUsageServerAuth)

	clientConfig, err := identity.ClientTLSConfig(agentCert, enrolled.pool, testGatewayDNS, identity.GatewayClass)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	if clientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("client MinVersion = %#x; want TLS 1.3", clientConfig.MinVersion)
	}
	if clientConfig.RootCAs == nil || !clientConfig.RootCAs.Equal(enrolled.pool) {
		t.Fatal("client RootCAs contains roots other than the enrolled internal CA")
	}
	if clientConfig.ServerName != testGatewayDNS {
		t.Fatalf("client ServerName = %q; want %q", clientConfig.ServerName, testGatewayDNS)
	}

	result := realTLSHandshake(t, clientConfig, standardServerConfig(gatewayCert, enrolled.pool))
	if result.clientErr != nil || result.serverErr != nil {
		t.Fatalf("enrolled-CA gateway handshake failed: client=%v server=%v", result.clientErr, result.serverErr)
	}
	if result.clientState.Version != tls.VersionTLS13 {
		t.Fatalf("client negotiated %#x; want TLS 1.3", result.clientState.Version)
	}

	foreignGateway := foreign.issue(t, identity.GatewayClass, testGatewayID, []string{testGatewayDNS}, x509.ExtKeyUsageServerAuth)
	untrusted := realTLSHandshake(t, clientConfig, standardServerConfig(foreignGateway, enrolled.pool))
	assertErrorContains(t, untrusted.clientErr, "certificate signed by unknown authority")
}

// TestClientTLSConfig_RejectsWrongServerClass proves a DNS- and chain-valid
// control certificate cannot serve the gateway-class surface.
func TestClientTLSConfig_RejectsWrongServerClass(t *testing.T) {
	ca := newTestCA(t, "enrolled-internal-ca")
	agentCert := ca.issue(t, identity.AgentClass, testAgentID, nil, x509.ExtKeyUsageClientAuth)
	wrongServer := ca.issue(t, identity.ControlClass, testControlID, []string{testGatewayDNS}, x509.ExtKeyUsageServerAuth)
	clientConfig, err := identity.ClientTLSConfig(agentCert, ca.pool, testGatewayDNS, identity.GatewayClass)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}

	result := realTLSHandshake(t, clientConfig, standardServerConfig(wrongServer, ca.pool))
	assertClassMismatch(t, result.clientErr, identity.ControlClass, identity.GatewayClass)
}

// TestClientTLSConfig_RejectsWrongDNSName proves the class callback retains
// Go's standard DNS-name verification rather than replacing it.
func TestClientTLSConfig_RejectsWrongDNSName(t *testing.T) {
	ca := newTestCA(t, "enrolled-internal-ca")
	agentCert := ca.issue(t, identity.AgentClass, testAgentID, nil, x509.ExtKeyUsageClientAuth)
	gatewayCert := ca.issue(t, identity.GatewayClass, testGatewayID, []string{testGatewayDNS}, x509.ExtKeyUsageServerAuth)
	clientConfig, err := identity.ClientTLSConfig(agentCert, ca.pool, "other.internal.test", identity.GatewayClass)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}

	result := realTLSHandshake(t, clientConfig, standardServerConfig(gatewayCert, ca.pool))
	assertErrorContains(t, result.clientErr, "certificate is valid for", "not other.internal.test")
}

func stampedProfile(t *testing.T, class identity.Class, id string) *x509.Certificate {
	t.Helper()
	cert := &x509.Certificate{}
	if err := identity.StampCertificateIdentity(cert, class, id); err != nil {
		t.Fatalf("stamp test certificate profile: %v", err)
	}
	return cert
}

func assertClassMismatch(t *testing.T, err error, actual, required identity.Class) {
	t.Helper()
	want := `certificate class "` + string(actual) + `" is not required class "` + string(required) + `"`
	if err == nil {
		t.Fatalf("TLS handshake accepted %q certificate on %q-only surface", actual, required)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("TLS handshake error = %q; want class mismatch substring %q", err, want)
	}
}

func assertErrorContains(t *testing.T, err error, want ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("TLS handshake returned nil error; want rejection containing %q", want)
	}
	for _, substring := range want {
		if !strings.Contains(err.Error(), substring) {
			t.Fatalf("TLS handshake error = %q; want substring %q", err, substring)
		}
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse test URI %q: %v", raw, err)
	}
	return u
}

func serializeCertificateTemplate(t *testing.T, template *x509.Certificate) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate raw-override fixture key: %v", err)
	}
	copy := *template
	copy.SerialNumber = big.NewInt(99)
	copy.NotBefore = time.Now().Add(-time.Hour)
	copy.NotAfter = time.Now().Add(time.Hour)
	copy.KeyUsage = x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, &copy, &copy, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("serialize raw-override fixture certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse raw-override fixture certificate: %v", err)
	}
	return cert
}

type testCA struct {
	cert       *x509.Certificate
	key        *ecdsa.PrivateKey
	pool       *x509.CertPool
	nextSerial int64
}

func newTestCA(t *testing.T, commonName string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool, nextSerial: 2}
}

func (ca *testCA) issue(t *testing.T, class identity.Class, id string, dnsNames []string, usages ...x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(ca.nextSerial),
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usages,
		DNSNames:     dnsNames,
	}
	ca.nextSerial++
	if err := identity.StampCertificateIdentity(template, class, id); err != nil {
		t.Fatalf("stamp leaf identity: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, ca.cert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

func standardClientConfig(certificate tls.Certificate, roots *x509.CertPool, serverName string) *tls.Config {
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: serverName,
	}
	if certificate.PrivateKey != nil {
		config.Certificates = []tls.Certificate{certificate}
	}
	return config
}

func standardServerConfig(certificate tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
}

type tlsHandshakeResult struct {
	clientState tls.ConnectionState
	serverState tls.ConnectionState
	clientErr   error
	serverErr   error
}

func realTLSHandshake(t *testing.T, clientConfig, serverConfig *tls.Config) tlsHandshakeResult {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	client := tls.Client(clientConn, clientConfig.Clone())
	server := tls.Server(serverConn, serverConfig.Clone())

	type endpointResult struct {
		client   bool
		state    tls.ConnectionState
		err      error
		closeErr error
	}
	results := make(chan endpointResult, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		err := client.HandshakeContext(ctx)
		results <- endpointResult{client: true, state: client.ConnectionState(), err: err, closeErr: clientConn.Close()}
	}()
	go func() {
		err := server.HandshakeContext(ctx)
		results <- endpointResult{state: server.ConnectionState(), err: err, closeErr: serverConn.Close()}
	}()

	var out tlsHandshakeResult
	for range 2 {
		select {
		case result := <-results:
			if result.closeErr != nil {
				t.Errorf("close TLS endpoint connection: %v", result.closeErr)
			}
			if result.client {
				out.clientState, out.clientErr = result.state, result.err
			} else {
				out.serverState, out.serverErr = result.state, result.err
			}
		case <-ctx.Done():
			clientCloseErr := clientConn.Close()
			serverCloseErr := serverConn.Close()
			t.Fatalf("real TLS handshake timed out: %v (close client=%v server=%v)", ctx.Err(), clientCloseErr, serverCloseErr)
		}
	}
	return out
}
