// Package identity implements the certificate identity profile of SPEC-006:
// SPIFFE URI SAN = class, CN = instance ULID, and DNS SAN = server name only.
package identity

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net/url"
)

const (
	// SPIFFETrustDomain is the single trust domain of the deployment.
	SPIFFETrustDomain = "power-manage"

	// The three certificate classes. The URI SAN carries exactly one of
	// these; the instance identity is the CN ULID, never a URI path.
	AgentSPIFFEURI   = "spiffe://power-manage/agent"
	GatewaySPIFFEURI = "spiffe://power-manage/gateway"
	ControlSPIFFEURI = "spiffe://power-manage/control"
)

// Class is one of the three closed certificate identity classes.
type Class string

const (
	AgentClass   Class = "agent"
	GatewayClass Class = "gateway"
	ControlClass Class = "control"
)

// IsCanonicalULID reports whether id is a canonical uppercase Crockford ULID.
func IsCanonicalULID(id string) bool {
	if len(id) != 26 || id[0] < '0' || id[0] > '7' {
		return false
	}
	for i := 1; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z' && c != 'I' && c != 'L' && c != 'O' && c != 'U':
		default:
			return false
		}
	}
	return true
}

// StampCertificateIdentity replaces template's certificate identity with the
// control-authored class and instance ID. DNS names remain caller-owned server
// names and are not used as identity.
func StampCertificateIdentity(template *x509.Certificate, class Class, instanceID string) error {
	if template == nil {
		return fmt.Errorf("identity: nil certificate template")
	}
	if len(template.RawSubject) != 0 {
		return fmt.Errorf("identity: RawSubject overrides subject")
	}
	for _, name := range template.Subject.ExtraNames {
		if name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}) {
			return fmt.Errorf("identity: Subject.ExtraNames overrides common name")
		}
	}
	for _, extension := range template.ExtraExtensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			return fmt.Errorf("identity: ExtraExtensions overrides subjectAltName")
		}
	}
	uri, err := classURI(class)
	if err != nil {
		return err
	}
	if !IsCanonicalULID(instanceID) {
		return fmt.Errorf("identity: instance ID is not a canonical ULID")
	}
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("identity: parse class URI: %w", err)
	}
	template.Subject.CommonName = instanceID
	template.URIs = []*url.URL{parsedURI}
	return nil
}

// ParseCertificateIdentity returns the exact class and instance ID stamped in
// cert, rejecting ambiguous or non-canonical profiles.
func ParseCertificateIdentity(cert *x509.Certificate) (Class, string, error) {
	if cert == nil {
		return "", "", fmt.Errorf("identity: nil certificate")
	}
	if !IsCanonicalULID(cert.Subject.CommonName) {
		return "", "", fmt.Errorf("identity: certificate common name is not a canonical ULID")
	}
	if len(cert.URIs) != 1 || cert.URIs[0] == nil {
		return "", "", fmt.Errorf("identity: certificate must contain exactly one SPIFFE URI SAN")
	}
	class, err := classFromURI(cert.URIs[0].String())
	if err != nil {
		return "", "", err
	}
	return class, cert.Subject.CommonName, nil
}

// RequireDNSAndURISANs rejects certificate SAN encodings that contain any
// GeneralName kind other than dNSName or uniformResourceIdentifier. Parsed
// x509 fields omit several GeneralName kinds, so callers enforcing an exact
// server certificate profile must inspect the raw extension.
func RequireDNSAndURISANs(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("identity: nil certificate")
	}
	subjectAlternativeNameOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	found := false
	for _, extension := range cert.Extensions {
		if !extension.Id.Equal(subjectAlternativeNameOID) {
			continue
		}
		if found {
			return fmt.Errorf("identity: certificate contains duplicate subjectAltName extensions")
		}
		found = true

		var names []asn1.RawValue
		rest, err := asn1.Unmarshal(extension.Value, &names)
		if err != nil || len(rest) != 0 {
			return fmt.Errorf("identity: certificate subjectAltName extension is malformed")
		}
		if len(names) == 0 {
			return fmt.Errorf("identity: certificate subjectAltName extension is empty")
		}
		for _, name := range names {
			if name.Class != asn1.ClassContextSpecific || name.IsCompound || (name.Tag != 2 && name.Tag != 6) {
				return fmt.Errorf("identity: certificate subjectAltName contains an unsupported GeneralName")
			}
		}
	}
	if !found {
		return fmt.Errorf("identity: certificate subjectAltName extension is missing")
	}
	return nil
}

// RequireCertificateClass rejects cert unless its exact identity profile has
// the expected class.
func RequireCertificateClass(cert *x509.Certificate, expected Class) error {
	if _, err := classURI(expected); err != nil {
		return err
	}
	actual, _, err := ParseCertificateIdentity(cert)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("identity: certificate class %q is not required class %q", actual, expected)
	}
	return nil
}

// ServerTLSConfig builds a TLS 1.3 mutual-TLS server configuration that
// verifies client chains against clientCAs and enforces the expected class.
func ServerTLSConfig(certificate tls.Certificate, clientCAs *x509.CertPool, clientClass Class) (*tls.Config, error) {
	if err := validateTLSCertificate(certificate); err != nil {
		return nil, err
	}
	if certPoolEmpty(clientCAs) {
		return nil, fmt.Errorf("identity: client CA pool is empty")
	}
	if _, err := classURI(clientClass); err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs.Clone(),
		VerifyConnection: func(state tls.ConnectionState) error {
			return requirePeerClass(state, clientClass)
		},
	}, nil
}

// ClientTLSConfig builds a TLS 1.3 mutual-TLS client configuration that uses
// only rootCAs, retains standard DNS verification, and enforces serverClass.
func ClientTLSConfig(certificate tls.Certificate, rootCAs *x509.CertPool, serverName string, serverClass Class) (*tls.Config, error) {
	if err := validateTLSCertificate(certificate); err != nil {
		return nil, err
	}
	if certPoolEmpty(rootCAs) {
		return nil, fmt.Errorf("identity: root CA pool is empty")
	}
	if serverName == "" {
		return nil, fmt.Errorf("identity: TLS server name is empty")
	}
	if _, err := classURI(serverClass); err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      rootCAs.Clone(),
		ServerName:   serverName,
		VerifyConnection: func(state tls.ConnectionState) error {
			return requirePeerClass(state, serverClass)
		},
	}, nil
}

// RejectPeerIntermediates returns a cloned TLS configuration with an exact-DER
// denylist. CA transition certificates are continuity proofs only; they must
// never become general peer-chain intermediates.
func RejectPeerIntermediates(config *tls.Config, certificateDER ...[]byte) (*tls.Config, error) {
	if config == nil {
		return nil, fmt.Errorf("identity: nil TLS config")
	}
	denied := make([][]byte, len(certificateDER))
	for index, der := range certificateDER {
		certificate, err := x509.ParseCertificate(der)
		if err != nil || !bytes.Equal(certificate.Raw, der) {
			return nil, fmt.Errorf("identity: transition certificate %d is not exact DER", index)
		}
		denied[index] = bytes.Clone(der)
	}
	next := config.Clone()
	previous := next.VerifyConnection
	next.VerifyConnection = func(state tls.ConnectionState) error {
		if previous != nil {
			if err := previous(state); err != nil {
				return err
			}
		}
		if len(state.PeerCertificates) == 0 {
			return nil
		}
		for _, peer := range state.PeerCertificates[1:] {
			for _, proof := range denied {
				if bytes.Equal(peer.Raw, proof) {
					return fmt.Errorf("identity: CA transition proof is forbidden as a peer-chain intermediate")
				}
			}
		}
		return nil
	}
	return next, nil
}

func classURI(class Class) (string, error) {
	switch class {
	case AgentClass:
		return AgentSPIFFEURI, nil
	case GatewayClass:
		return GatewaySPIFFEURI, nil
	case ControlClass:
		return ControlSPIFFEURI, nil
	default:
		return "", fmt.Errorf("identity: unsupported certificate class %q", class)
	}
}

func classFromURI(uri string) (Class, error) {
	switch uri {
	case AgentSPIFFEURI:
		return AgentClass, nil
	case GatewaySPIFFEURI:
		return GatewayClass, nil
	case ControlSPIFFEURI:
		return ControlClass, nil
	default:
		return "", fmt.Errorf("identity: unsupported SPIFFE URI SAN %q", uri)
	}
}

func validateTLSCertificate(certificate tls.Certificate) error {
	if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return fmt.Errorf("identity: TLS certificate or private key is missing")
	}
	return nil
}

func certPoolEmpty(pool *x509.CertPool) bool {
	return pool == nil || pool.Equal(x509.NewCertPool())
}

func requirePeerClass(state tls.ConnectionState, expected Class) error {
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("identity: peer certificate is missing")
	}
	return RequireCertificateClass(state.PeerCertificates[0], expected)
}
