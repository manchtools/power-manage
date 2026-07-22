// Package gateway owns the gateway-local, per-boot enrollment identity.
package gateway

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/contract/sign"
)

const (
	maxRegistrationTokenBytes  = 512
	gatewayCertificateLifetime = 45 * 24 * time.Hour
)

// Identity is one validated, in-memory gateway certificate and private key.
type Identity struct {
	GatewayID               string
	CertificateDER          []byte
	CertificateAuthorityDER []byte
	DNSNames                []string
	PrivateKey              crypto.Signer
}

// EnrollmentClient creates a fresh key and identity for each gateway boot.
type EnrollmentClient struct {
	remote           powermanagev1connect.PkiServiceClient
	expectedDNSNames []string
	now              func() time.Time
}

// NewEnrollmentClient pins the independently configured DNS identities that
// control must return in the token-authorized gateway certificate.
func NewEnrollmentClient(
	remote powermanagev1connect.PkiServiceClient,
	expectedDNSNames []string,
) (*EnrollmentClient, error) {
	if dependencyNil(remote) {
		return nil, errors.New("gateway: nil PkiService client")
	}
	if len(expectedDNSNames) == 0 {
		return nil, errors.New("gateway: expected DNS names are empty")
	}
	for _, name := range expectedDNSNames {
		if name == "" {
			return nil, errors.New("gateway: expected DNS name is empty")
		}
	}
	return &EnrollmentClient{remote: remote, expectedDNSNames: slices.Clone(expectedDNSNames), now: time.Now}, nil
}

// Enroll creates local proof, validates every returned trust-bearing field,
// and retains the private key only in the returned in-memory identity.
func (c *EnrollmentClient) Enroll(ctx context.Context, token string) (Identity, error) {
	if c == nil || dependencyNil(c.remote) || len(c.expectedDNSNames) == 0 || c.now == nil {
		return Identity{}, errors.New("gateway: enrollment client is not wired")
	}
	if ctx == nil {
		return Identity{}, errors.New("gateway: nil enrollment context")
	}
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	if token == "" || len(token) > maxRegistrationTokenBytes {
		return Identity{}, errors.New("gateway: registration token is invalid")
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("gateway: generate mTLS private key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, privateKey)
	if err != nil {
		return Identity{}, fmt.Errorf("gateway: create certificate signing request: %w", err)
	}
	response, err := c.remote.EnrollGateway(ctx, connect.NewRequest(&powermanagev1.EnrollGatewayRequest{
		RegistrationToken: token, CertificateSigningRequestDer: csrDER,
	}))
	if err != nil {
		return Identity{}, fmt.Errorf("gateway: PkiService enrollment: %w", err)
	}
	if response == nil || response.Msg == nil {
		return Identity{}, errors.New("gateway: PkiService returned an empty response")
	}
	gatewayID, err := validateEnrollmentResponse(
		response.Msg.GetCertificateDer(),
		response.Msg.GetCertificateAuthorityDer(),
		privateKey.Public(),
		c.expectedDNSNames,
		c.now(),
	)
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		GatewayID: gatewayID, CertificateDER: bytes.Clone(response.Msg.GetCertificateDer()),
		CertificateAuthorityDER: bytes.Clone(response.Msg.GetCertificateAuthorityDer()),
		DNSNames:                slices.Clone(c.expectedDNSNames), PrivateKey: privateKey,
	}, nil
}

func validateEnrollmentResponse(
	certificateDER []byte,
	certificateAuthorityDER []byte,
	expectedPublicKey crypto.PublicKey,
	expectedDNSNames []string,
	now time.Time,
) (string, error) {
	authority, err := parseExactCertificate(certificateAuthorityDER)
	if err != nil {
		return "", fmt.Errorf("gateway: parse certificate authority: %w", err)
	}
	if !authority.IsCA || !authority.BasicConstraintsValid || authority.KeyUsage&x509.KeyUsageCertSign == 0 {
		return "", errors.New("gateway: certificate authority profile is invalid")
	}
	if err := sign.ValidateSigningKey(authority.PublicKey); err != nil {
		return "", fmt.Errorf("gateway: validate certificate authority key: %w", err)
	}
	if now.Before(authority.NotBefore) || now.After(authority.NotAfter) {
		return "", errors.New("gateway: certificate authority is not currently valid")
	}
	certificate, err := parseExactCertificate(certificateDER)
	if err != nil {
		return "", fmt.Errorf("gateway: parse issued certificate: %w", err)
	}
	if !samePublicKey(certificate.PublicKey, expectedPublicKey) {
		return "", errors.New("gateway: issued certificate public key mismatch")
	}
	class, gatewayID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil || class != identity.GatewayClass {
		return "", errors.New("gateway: issued certificate identity is not gateway")
	}
	if certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		certificate.NotAfter.Sub(certificate.NotBefore) != gatewayCertificateLifetime ||
		!exactGatewayEKUs(certificate.ExtKeyUsage) || len(certificate.UnknownExtKeyUsage) != 0 ||
		len(certificate.EmailAddresses) != 0 || len(certificate.IPAddresses) != 0 {
		return "", errors.New("gateway: issued certificate profile is invalid")
	}
	if err := identity.RequireDNSAndURISANs(certificate); err != nil {
		return "", fmt.Errorf("gateway: issued certificate profile is invalid: %w", err)
	}
	if !slices.Equal(certificate.DNSNames, expectedDNSNames) {
		return "", errors.New("gateway: issued certificate DNS names differ from configured identity")
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority)
	if _, err := certificate.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: now, DNSName: expectedDNSNames[0],
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return "", fmt.Errorf("gateway: verify issued certificate: %w", err)
	}
	return gatewayID, nil
}

func exactGatewayEKUs(usages []x509.ExtKeyUsage) bool {
	return len(usages) == 2 && slices.Contains(usages, x509.ExtKeyUsageServerAuth) && slices.Contains(usages, x509.ExtKeyUsageClientAuth)
}

func parseExactCertificate(der []byte) (*x509.Certificate, error) {
	owned := bytes.Clone(der)
	certificate, err := x509.ParseCertificate(owned)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(certificate.Raw, owned) {
		return nil, errors.New("certificate DER contains trailing data")
	}
	return certificate, nil
}

func samePublicKey(first, second crypto.PublicKey) bool {
	firstDER, err := x509.MarshalPKIXPublicKey(first)
	if err != nil {
		return false
	}
	secondDER, err := x509.MarshalPKIXPublicKey(second)
	return err == nil && bytes.Equal(firstDER, secondDER)
}

func dependencyNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
